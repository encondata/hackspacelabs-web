import {test,before,after} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import express from 'express';
import session from 'express-session';
import request from 'supertest';
import {createApp} from '../server/app.mjs';
import {createOidc} from '../server/oidc.mjs';
import {identityFromClaims,readConfig} from '../server/security.mjs';
import {startIssuer} from './oidc-fixture.mjs';

let issuer,oidc,config,publicDir,upstream,upstreamServer;const seen=[];
before(async()=>{
 issuer=await startIssuer();publicDir=await mkdtemp(path.join(os.tmpdir(),'hsl-slipway-tests-'));await writeFile(path.join(publicDir,'index.html'),'<html>Portal</html>');
 const fake=express();fake.use(express.raw({type:()=>true}));
 fake.all('/{*rest}',(req,res)=>{
  seen.push({method:req.method,url:req.originalUrl,headers:req.headers,body:Buffer.isBuffer(req.body)?req.body.toString():''});
  if(req.path==='/api/v1/auth/github/callback')return res.redirect(302,'/portal?github=linked');
  if(req.path==='/api/v1/offsite')return res.redirect(302,'https://evil.example/');
  if(req.path==='/api/v1/missing')return res.status(404).json({detail:'Host not found'});
  res.set('set-cookie','leak=1').json({ok:true,path:req.path});
 });
 upstreamServer=fake.listen(0,'127.0.0.1');await new Promise(r=>upstreamServer.once('listening',r));upstream=`http://127.0.0.1:${upstreamServer.address().port}`;
 config={production:false,origin:'http://127.0.0.1:3000',issuer:issuer.issuer,clientId:'hackspacelabs-web',clientSecret:randomBytes(32).toString('hex'),sessionSecret:randomBytes(48).toString('hex'),encryptionKey:randomBytes(32).toString('base64'),idleMs:1800000,absoluteMs:28800000,refreshMs:60000,slipwayUrl:upstream};
 oidc=await createOidc(config);
});
after(async()=>{await issuer.close();await new Promise(r=>upstreamServer.close(r));await rm(publicDir,{recursive:true,force:true})});

function fixture({slipwayRoles=['developer'],...overrides}={}){
 Object.assign(issuer.state,{roles:['customer'],slipwayRoles,verified:true,fault:null,revoked:false,subject:'sample-user'});seen.length=0;
 const app=createApp({config:{...config,...overrides},store:new session.MemoryStore(),oidc,publicDir,log:{error(){}}});
 return {agent:request.agent(app),app};
}
async function login(agent){
 const start=await agent.get('/api/auth/login');const redirect=await fetch(start.headers.location,{redirect:'manual'});const callback=new URL(redirect.headers.get('location'));
 await agent.get(callback.pathname+callback.search);
 return (await agent.get('/api/auth/session')).body;
}

test('identity carries only known Slipway roles',()=>{
 const identity=identityFromClaims({sub:'u1',preferred_username:'ada',hsl_roles:['customer'],slipway_roles:['viewer','root','admin','viewer']});
 assert.deepEqual(identity.apps,{slipway:['admin','viewer']});
 assert.deepEqual(identityFromClaims({sub:'u2',hsl_roles:['admin']}).apps,{slipway:[]});
});

test('SLIPWAY_URL must be a bare http(s) origin',()=>{
 const env={AUTH_LOCAL_TEST:'1',APP_ORIGIN:'http://127.0.0.1:3000',OIDC_ISSUER:'http://127.0.0.1:8080/realms/x',SESSION_SECRET:'s'.repeat(48),OIDC_CLIENT_SECRET:'c'.repeat(32),DATABASE_URL:'postgres://x',TOKEN_ENCRYPTION_KEY:randomBytes(32).toString('base64')};
 assert.equal(readConfig(env).slipwayUrl,null);
 assert.equal(readConfig({...env,SLIPWAY_URL:'http://slipway:8000'}).slipwayUrl,'http://slipway:8000');
 for(const bad of ['http://slipway:8000/api','ftp://slipway','http://user:pw@slipway:8000'])assert.throws(()=>readConfig({...env,SLIPWAY_URL:bad}),/SLIPWAY_URL/,bad);
});

test('anonymous requests are refused without reaching Slipway',async()=>{
 const {agent}=fixture();
 const api=await agent.get('/api/slipway/hosts');assert.equal(api.status,401);
 const page=await agent.get('/api/slipway/auth/github/callback?code=x&state=y').set('Accept','text/html');
 assert.equal(page.status,303);assert.equal(page.headers.location,'/login?returnTo=%2Fportal');
 assert.equal(seen.length,0);
});

test('signed-in users without a Slipway role are refused',async()=>{
 const {agent}=fixture({slipwayRoles:[]});await login(agent);
 assert.equal((await agent.get('/api/slipway/hosts')).status,403);assert.equal(seen.length,0);
});

test('reads are forwarded with the access token and nothing from the browser session',async()=>{
 const {agent}=fixture();const signedIn=await login(agent);
 assert.deepEqual(signedIn.user.apps,{slipway:['developer']});
 const result=await agent.get('/api/slipway/hosts?status=online').set('Cookie','extra=1');
 assert.equal(result.status,200);assert.deepEqual(result.body,{ok:true,path:'/api/v1/hosts'});
 assert.equal(result.headers['cache-control'],'no-store');assert.ok(!(result.headers['set-cookie']||[]).some(c=>c.startsWith('leak=')),'Slipway cookies are dropped');
 const [call]=seen;assert.equal(call.url,'/api/v1/hosts?status=online');
 assert.equal(call.headers.authorization,'Bearer '+issuer.state.accessToken);
 assert.equal(call.headers.cookie,undefined);assert.equal(call.headers['x-csrf-token'],undefined);
 assert.equal((await agent.get('/api/slipway/missing')).status,404);
});

test('writes need the portal origin and CSRF token, and keep their body intact',async()=>{
 const {agent}=fixture();const {csrfToken}=await login(agent);
 const payload=JSON.stringify({name:'web-1',private_key:'-----BEGIN KEY-----\n'+'a'.repeat(9000)});
 assert.equal((await agent.post('/api/slipway/hosts').set('Content-Type','application/json').send(payload)).status,403);
 assert.equal((await agent.post('/api/slipway/hosts').set('Origin','https://evil.example').set('x-csrf-token',csrfToken).set('Content-Type','application/json').send(payload)).status,403);
 assert.equal(seen.length,0);
 const ok=await agent.post('/api/slipway/hosts').set('Origin',config.origin).set('x-csrf-token',csrfToken).set('Content-Type','application/json').send(payload);
 assert.equal(ok.status,200);assert.equal(seen[0].method,'POST');assert.equal(seen[0].body,payload);assert.equal(seen[0].headers['content-type'],'application/json');
 const del=await agent.delete('/api/slipway/hosts/1').set('Origin',config.origin).set('x-csrf-token',csrfToken);
 assert.equal(del.status,200);assert.equal(seen[1].method,'DELETE');
});

test('API tokens pass through without a session; other bearer tokens are refused',async()=>{
 const {agent}=fixture();const pat='Bearer slipway_pat_'+randomBytes(32).toString('base64url');
 const result=await agent.post('/api/slipway/deployments').set('Authorization',pat).set('Content-Type','application/json').send('{"instance_id":"x"}');
 assert.equal(result.status,200);assert.equal(seen[0].headers.authorization,pat);assert.equal(seen[0].body,'{"instance_id":"x"}');
 for(const header of ['Bearer eyJhbGciOiJSUzI1NiJ9.e30.sig','Basic YTpi','Bearer slipway_pat_short'])assert.equal((await agent.get('/api/slipway/hosts').set('Authorization',header)).status,401,header);
 assert.equal(seen.length,1);
});

test('only same-origin redirects reach the browser',async()=>{
 const {agent}=fixture();await login(agent);
 const back=await agent.get('/api/slipway/auth/github/callback?code=c&state=s');
 assert.equal(back.status,302);assert.equal(back.headers.location,'/portal?github=linked');
 const offsite=await agent.get('/api/slipway/offsite');assert.equal(offsite.status,302);assert.equal(offsite.headers.location,undefined);
});

test('a refreshed session forwards the new access token',async()=>{
 const {agent}=fixture({refreshMs:0});await login(agent);const first=issuer.state.accessToken;
 await agent.get('/api/slipway/hosts');
 assert.notEqual(issuer.state.accessToken,first);assert.equal(seen.at(-1).headers.authorization,'Bearer '+issuer.state.accessToken);
 issuer.state.slipwayRoles=[];assert.equal((await agent.get('/api/slipway/hosts')).status,403);
});

test('an unreachable Slipway is reported as unavailable',async()=>{
 const {agent}=fixture({slipwayUrl:'http://127.0.0.1:9'});await login(agent);
 const result=await agent.get('/api/slipway/hosts');assert.equal(result.status,502);assert.match(result.body.error,/unavailable/);
});

test('without SLIPWAY_URL the path is not proxied',async()=>{
 const {agent}=fixture({slipwayUrl:null});await login(agent);
 assert.equal((await agent.get('/api/slipway/hosts')).status,404);assert.equal(seen.length,0);
});
