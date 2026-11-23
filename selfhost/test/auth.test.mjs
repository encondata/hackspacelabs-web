import {test,before,after} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import session from 'express-session';
import request from 'supertest';
import {createApp} from '../server/app.mjs';
import {createOidc} from '../server/oidc.mjs';
import {identityFromClaims,readConfig,tokenCipher,safeDestination,canAccess,landing} from '../server/security.mjs';
import {loadSuiteApps} from '../server/suite-apps.mjs';
import {startIssuer} from './oidc-fixture.mjs';
let issuer;let publicDir;let oidc;let config;
before(async()=>{issuer=await startIssuer();publicDir=await mkdtemp(path.join(os.tmpdir(),'hsl-auth-tests-'));await writeFile(path.join(publicDir,'index.html'),'<html>Sample application</html>');config={production:false,origin:'http://127.0.0.1:3000',issuer:issuer.issuer,clientId:'hackspacelabs-web',clientSecret:randomBytes(32).toString('hex'),sessionSecret:randomBytes(48).toString('hex'),encryptionKey:randomBytes(32).toString('base64'),refreshMs:60000,suiteApps:loadSuiteApps().map(app=>({...app,url:{switchyard:'http://10.0.0.5:8080',tideline:'https://tideline.example'}[app.id]||null}))};oidc=await createOidc(config)});
after(async()=>{await issuer.close();await rm(publicDir,{recursive:true,force:true})});
function fixture(overrides={}){Object.assign(issuer.state,{roles:['customer'],apps:undefined,verified:true,fault:null,revoked:false,down:false,refreshExpiresIn:345600,subject:'sample-user'});const store=new session.MemoryStore();const warnings=[];const app=createApp({config:{...config,...overrides},store,oidc,publicDir,log:{error(){},warn:(...args)=>warnings.push(args)}});return {agent:request.agent(app),store,app,warnings}}
async function authorization(agent,returnTo=''){const start=await agent.get('/api/auth/login'+(returnTo?'?returnTo='+encodeURIComponent(returnTo):''));assert.equal(start.status,303);const authorize=new URL(start.headers.location);assert.equal(authorize.searchParams.get('code_challenge_method'),'S256');assert.ok(authorize.searchParams.get('nonce'));assert.ok(authorize.searchParams.get('state'));const redirect=await fetch(start.headers.location,{redirect:'manual'});const callback=new URL(redirect.headers.get('location'));return callback.pathname+callback.search}
async function login(agent,returnTo=''){return agent.get(await authorization(agent,returnTo))}
const allSessions=store=>new Promise((resolve,reject)=>store.all((e,s)=>e?reject(e):resolve(s)));
test('anonymous users cannot access protected routes or session data',async()=>{const {agent}=fixture();for(const route of ['/admin','/portal']){const r=await agent.get(route);assert.equal(r.status,303);assert.match(r.headers.location,/^\/login\?returnTo=/)}assert.equal((await agent.get('/api/auth/session')).status,401);assert.equal((await agent.get('/api/tickets')).status,404);assert.equal((await agent.get('/%61dmin')).status,400);assert.equal((await agent.get('/')).status,200)});
test('authorization code + PKCE signs in a customer and enforces admin denial',async()=>{const {agent,store}=fixture();const result=await login(agent);assert.equal(result.headers.location,'/portal');assert.equal((await agent.get('/portal')).status,200);assert.equal((await agent.get('/admin?role=admin')).status,403);const resultSession=await agent.get('/api/auth/session');assert.deepEqual(resultSession.body.user.roles,['customer']);assert.ok(resultSession.body.csrfToken);assert.equal(resultSession.body.tokens,undefined);const saved=Object.values(await allSessions(store))[0];assert.equal(typeof saved.tokens,'string');assert.equal(saved.tokens.includes('refreshToken'),false);assert.ok(tokenCipher(config.encryptionKey).open(saved.tokens).refreshToken);assert.match(result.headers['set-cookie'].join(';'),/HttpOnly/);assert.match(result.headers['set-cookie'].join(';'),/SameSite=Lax/)});
test('explicit admin role allows admin and customer views',async()=>{const {agent}=fixture();issuer.state.roles=['admin'];assert.equal((await login(agent)).headers.location,'/admin');assert.equal((await agent.get('/admin')).status,200);assert.equal((await agent.get('/portal')).status,200)});
test('role, signature, issuer, audience, and nonce failures deny sign-in',async()=>{for(const fault of ['role','signature','issuer','audience','nonce']){const {agent}=fixture();if(fault==='role')issuer.state.roles=[];else issuer.state.fault=fault;const result=await login(agent);assert.equal(result.headers.location,'/login?error=signin',fault);assert.equal((await agent.get('/api/auth/session')).status,401,fault)}});
test('state tampering and callback replay are rejected',async()=>{const {agent}=fixture();const callback=await authorization(agent);const altered=new URL(callback,config.origin);altered.searchParams.set('state','tampered');assert.equal((await agent.get(altered.pathname+altered.search)).headers.location,'/login?error=signin');assert.equal((await agent.get(callback)).headers.location,'/login?error=expired');const good=await authorization(agent);assert.equal((await agent.get(good)).headers.location,'/portal');assert.equal((await agent.get(good)).headers.location,'/login?error=expired')});
test('sessions rotate after login and logout requires origin plus CSRF',async()=>{const {agent}=fixture();const start=await agent.get('/api/auth/login');const beforeCookie=start.headers['set-cookie'][0].split(';')[0];const authorized=await fetch(start.headers.location,{redirect:'manual'});const url=new URL(authorized.headers.get('location'));const signed=await agent.get(url.pathname+url.search);assert.notEqual(signed.headers['set-cookie'][0].split(';')[0],beforeCookie);const s=await agent.get('/api/auth/session');assert.equal((await agent.post('/api/auth/logout')).status,403);assert.equal((await agent.post('/api/auth/logout').set('Origin','https://evil.example').set('x-csrf-token',s.body.csrfToken)).status,403);const result=await agent.post('/api/auth/logout').set('Origin',config.origin).set('x-csrf-token',s.body.csrfToken);assert.equal(result.status,200);assert.equal(new URL(result.body.redirect).pathname,'/logout');assert.equal((await agent.get('/api/auth/session')).status,401)});
test('refresh rechecks roles and fails closed on revoked identity sessions',async()=>{const {agent}=fixture({refreshMs:0});issuer.state.roles=['admin'];await login(agent);issuer.state.roles=['customer'];assert.equal((await agent.get('/admin')).status,403);assert.deepEqual((await agent.get('/api/auth/session')).body.user.roles,['customer']);issuer.state.revoked=true;assert.equal((await agent.get('/api/auth/session')).status,401);issuer.state.revoked=false;assert.equal((await agent.get('/api/auth/login')).status,303)});
test('the session ends when the Keycloak session does, even while active',async()=>{const {agent}=fixture();issuer.state.refreshExpiresIn=1;await login(agent);assert.equal((await agent.get('/api/auth/session')).status,200);await new Promise(r=>setTimeout(r,1100));assert.equal((await agent.get('/api/auth/session')).status,401)});
test('return targets are restricted and cannot redirect off-site',async()=>{assert.equal(safeDestination('//evil.example'),null);assert.equal(safeDestination('/admin'),'/admin');const {agent}=fixture();assert.equal((await login(agent,'https://evil.example')).headers.location,'/portal')});
test('encrypted tokens reject tampering and production configuration rejects HTTP',()=>{const box=tokenCipher(config.encryptionKey);const value=box.seal({refreshToken:'secret'});assert.deepEqual(box.open(value),{refreshToken:'secret'});const parts=value.split('.');parts[2]=Buffer.from('tampered').toString('base64url');assert.throws(()=>box.open(parts.join('.')));assert.throws(()=>readConfig({NODE_ENV:'production',APP_ORIGIN:'http://hackspacelabs.com',OIDC_ISSUER:'https://auth.hackspacelabs.com/realms/hackspacelabs'}),/HTTPS/);assert.throws(()=>identityFromClaims({sub:'1',email:'a@example.com',email_verified:true,hsl_roles:['administrator']}),/role/)});

test('username accounts can sign in without verified email',async()=>{const {agent}=fixture();issuer.state.verified=false;issuer.state.roles=['admin'];assert.equal((await login(agent)).headers.location,'/admin');assert.equal((await agent.get('/admin')).status,200);const identity=identityFromClaims({sub:'admin-id',preferred_username:'admin',hsl_roles:['admin']});assert.equal(identity.name,'admin');assert.equal(identity.email,'');assert.throws(()=>identityFromClaims({sub:'admin-id',preferred_username:'admin',hsl_roles:[]}),/role/)});


test('personal account page is protected and supports both portal roles',async()=>{
 for(const role of ['customer','admin']){
  const {agent}=fixture();issuer.state.roles=[role];
  const anonymous=await agent.get('/me');assert.equal(anonymous.status,303);assert.equal(anonymous.headers.location,'/login?returnTo=%2Fme');
  assert.equal((await login(agent,'/me')).headers.location,'/me');
  const page=await agent.get('/me');assert.equal(page.status,200);assert.equal(page.headers['cache-control'],'no-store');
  assert.equal((await agent.get('/api/auth/account')).headers.location,'/me');
 }
 assert.equal(safeDestination('/me'),'/me');assert.equal(safeDestination('/me?user=other'),null);
});

const expiresIn=response=>{const cookie=(response.headers['set-cookie']||[]).find(c=>c.startsWith('hsl.test.sid='));const match=cookie&&/Expires=([^;]+)/.exec(cookie);return match?(Date.parse(match[1])-Date.now())/1000:null};
test('the cookie lasts as long as the Keycloak session: 96 hours, 30 days with Remember me, 96 hours if not given',async()=>{
 for(const [given,wanted] of [[345600,345600],[2592000,2592000],[null,345600]]){
  const {agent}=fixture();issuer.state.refreshExpiresIn=given;const signed=await login(agent);
  assert.ok(Math.abs(expiresIn(signed)-wanted)<5,given+': cookie lasts '+expiresIn(signed)+'s');
  // Not rolling: ordinary requests do not push it out, and the server-side limit is the same number.
  assert.equal(expiresIn(await agent.get('/')),null);assert.equal(expiresIn(await agent.get('/api/auth/session')),null);
 }
});
test('a recheck keeps the cookie expiry at the Keycloak session end instead of extending it',async()=>{
 const {agent,store}=fixture({refreshMs:0});const signed=await login(agent);const first=expiresIn(signed);
 await new Promise(r=>setTimeout(r,1100));const again=await agent.get('/api/auth/session');assert.equal(again.status,200);
 const later=expiresIn(again);assert.ok(later!==null&&Math.abs(later-(first-1.1))<3&&later<=345600,'after a recheck the cookie lasts '+later+'s, before '+first+'s');
 const saved=Object.values(await allSessions(store))[0];assert.ok(Math.abs(saved.sessionExpiresAt-Date.now()-345600000)<5000);assert.equal(saved.lastSeen,undefined);
});
test('a Keycloak outage keeps the session and waits a full interval before checking again',async()=>{
 const {agent,warnings}=fixture({refreshMs:300});issuer.state.roles=['admin'];await login(agent);
 issuer.state.down=true;await new Promise(r=>setTimeout(r,350));
 assert.equal((await agent.get('/api/auth/session')).status,200);assert.equal((await agent.get('/admin')).status,200);assert.equal(warnings.length,1,'one deferred check, not one per request');
 assert.ok(!JSON.stringify(warnings).includes('refresh'),'no token contents in the log');
 issuer.state.down=false;issuer.state.revoked=true;assert.equal((await agent.get('/api/auth/session')).status,200,'not rechecked before the interval');
 await new Promise(r=>setTimeout(r,350));assert.equal((await agent.get('/api/auth/session')).status,401,'invalid_grant ends it');
});
test('a refreshed token with a bad signature, or for a different person, ends the session',async()=>{
 for(const change of [s=>{s.fault='signature'},s=>{s.subject='someone-else'}]){
  const {agent}=fixture({refreshMs:0});await login(agent);change(issuer.state);assert.equal((await agent.get('/api/auth/session')).status,401);
 }
});
test('staff with only app roles reach the launcher and their account page, not the portals',async()=>{
 const {agent}=fixture();issuer.state.roles=[];issuer.state.apps={switchyard:['editor'],slipway:['viewer'],unknown:['admin']};
 const signed=await login(agent);assert.equal(signed.headers.location,'/apps');
 for(const [page,status] of [['/apps',200],['/me',200],['/portal',403],['/admin',403]])assert.equal((await agent.get(page)).status,status,page);
 const state=await agent.get('/api/auth/session');assert.deepEqual(state.body.user.roles,[]);assert.deepEqual(state.body.user.apps,['slipway','switchyard']);
 // Slipway's origin is not configured, so only Switchyard is offered.
 assert.deepEqual(state.body.apps,[{id:'switchyard',name:'Switchyard',description:'Proxy hosts and certificates',url:'http://10.0.0.5:8080'}]);
 const empty=fixture();issuer.state.roles=[];issuer.state.apps={switchyard:[]};assert.equal((await login(empty.agent)).headers.location,'/login?error=signin','an empty app claim is no access');
});
test('administrators see every configured app; customers none and no launcher',async()=>{
 const admin=fixture();issuer.state.roles=['admin'];await login(admin.agent);
 assert.deepEqual((await admin.agent.get('/api/auth/session')).body.apps.map(a=>a.id),['switchyard','tideline']);assert.equal((await admin.agent.get('/apps')).status,200);
 const customer=fixture();await login(customer.agent);const body=(await customer.agent.get('/api/auth/session')).body;
 assert.deepEqual(body.apps,[]);assert.deepEqual(body.user.apps,[]);assert.equal((await customer.agent.get('/apps')).status,403);
 const both=fixture();issuer.state.apps={tideline:['viewer']};assert.equal((await login(both.agent)).headers.location,'/apps','staff who are also customers land on the launcher');
});
test('page rules, landing pages and destinations include the launcher',()=>{
 assert.equal(safeDestination('/apps'),'/apps');assert.equal(safeDestination('/apps/x'),null);
 const staff={roles:[],apps:['tideline']},customer={roles:['customer'],apps:[]},admin={roles:['admin'],apps:[]},legacy={roles:['customer']};
 assert.deepEqual(['/admin','/portal','/me','/apps'].map(p=>[canAccess(staff,p),canAccess(customer,p),canAccess(admin,p),canAccess(legacy,p)]),[[false,false,true,false],[false,true,true,true],[true,true,true,true],[true,false,true,false]]);
 assert.deepEqual([staff,customer,admin,legacy].map(landing),['/apps','/portal','/admin','/portal']);
 assert.deepEqual(identityFromClaims({sub:'s',hsl_roles:[],hsl_apps:{tideline:['viewer','bogus'],switchyard:['bogus']}},loadSuiteApps()).apps,['tideline']);
 assert.throws(()=>identityFromClaims({sub:'s',hsl_apps:{switchyard:['bogus']}},loadSuiteApps()),/role/);
});
test('suite app origins come from the environment and must be bare origins',()=>{
 const env={AUTH_LOCAL_TEST:'1',APP_ORIGIN:'http://127.0.0.1:3000',OIDC_ISSUER:'http://127.0.0.1:8080/realms/x',SESSION_SECRET:'s'.repeat(48),OIDC_CLIENT_SECRET:'c'.repeat(32),DATABASE_URL:'postgres://x',TOKEN_ENCRYPTION_KEY:randomBytes(32).toString('base64')};
 assert.deepEqual(readConfig(env).suiteApps.map(a=>a.url),[null,null,null,null]);
 assert.deepEqual(readConfig({...env,SWITCHYARD_ORIGIN:'http://192.168.1.10:8080/',TIDELINE_ORIGIN:'https://tideline.example'}).suiteApps.filter(a=>a.url).map(a=>[a.id,a.url]),[['switchyard','http://192.168.1.10:8080'],['tideline','https://tideline.example']]);
 assert.throws(()=>readConfig({...env,SLIPWAY_ORIGIN:'https://slipway.example/app'}),/SLIPWAY_ORIGIN/);
});
