import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import session from 'express-session';
import request from 'supertest';
import {createApp} from '../server/app.mjs';
import {readConfig} from '../server/security.mjs';

const SECRET=randomBytes(32).toString('hex');
const SUB='4b9f2c1e-2d7a-4a8e-9f0b-1c2d3e4f5a6b';
function fixture({secret=SECRET,users={[SUB]:{id:SUB,username:'ada',email:'ada@example.com',firstName:'Ada',lastName:'L',enabled:true}},roles=[{name:'developer'},{name:'service-account'},{name:'viewer'}],fail=false}={}){
 const calls=[];
 const api=async route=>{
  calls.push(route);
  if(fail)throw Object.assign(new Error('Identity service request failed'),{status:503});
  if(route==='/clients?clientId=slipway')return [{id:'slipway-uuid'}];
  const user=route.match(/^\/users\/([^/]+)$/);
  if(user){if(users[decodeURIComponent(user[1])])return users[decodeURIComponent(user[1])];throw Object.assign(new Error('Identity service request failed'),{status:404})}
  if(route.endsWith('/role-mappings/clients/slipway-uuid/composite'))return roles;
  return null;
 };
 const config={production:false,origin:'http://127.0.0.1:3000',issuer:'http://127.0.0.1:1/realms/x',clientId:'hackspacelabs-web',clientSecret:randomBytes(32).toString('hex'),sessionSecret:randomBytes(48).toString('hex'),encryptionKey:randomBytes(32).toString('base64'),idleMs:1800000,absoluteMs:28800000,refreshMs:60000,slipwayInternalSecret:secret};
 const app=createApp({config,store:new session.MemoryStore(),oidc:{},management:api,publicDir:'.',log:{error(){},info(){}}});
 return {app,calls};
}
const ask=(app,sub,headers={})=>{let r=request(app).get('/internal/slipway/owners/'+sub);for(const [k,v] of Object.entries(headers))r=r.set(k,v);return r};

test('owner status reports enabled flag, profile and effective Slipway roles only',async()=>{
 const {app,calls}=fixture();
 const r=await ask(app,SUB,{Authorization:'Bearer '+SECRET});
 assert.equal(r.status,200);assert.equal(r.headers['cache-control'],'no-store');
 assert.deepEqual(r.body,{exists:true,enabled:true,username:'ada',email:'ada@example.com',firstName:'Ada',lastName:'L',roles:['developer','viewer']});
 assert.ok(calls.includes(`/users/${SUB}/role-mappings/clients/slipway-uuid/composite`));
});

test('unknown accounts and service accounts do not exist; disabled accounts say so',async()=>{
 const {app}=fixture({users:{[SUB]:{id:SUB,username:'ada',enabled:false},'svc':{id:'svc',username:'service-account-x',serviceAccountClientId:'c',enabled:true}}});
 assert.equal((await ask(app,SUB,{Authorization:'Bearer '+SECRET})).body.enabled,false);
 assert.deepEqual((await ask(app,'svc',{Authorization:'Bearer '+SECRET})).body,{exists:false});
 assert.deepEqual((await ask(app,'nobody',{Authorization:'Bearer '+SECRET})).body,{exists:false});
});

test('the endpoint is hidden without the secret or when reached through the public proxy',async()=>{
 const {app,calls}=fixture();
 for(const headers of [{},{Authorization:'Bearer wrong'},{Authorization:SECRET},{Authorization:'Bearer '+SECRET,'X-Forwarded-For':'203.0.113.9'},{Authorization:'Bearer '+SECRET,Forwarded:'for=203.0.113.9'}]){
  assert.equal((await ask(app,SUB,headers)).status,404,JSON.stringify(headers));
 }
 assert.equal(calls.length,0);
 assert.equal((await ask(app,'bad%2Fsub',{Authorization:'Bearer '+SECRET})).status,400);
});

test('identity outages are 503, never an answer',async()=>{
 const {app}=fixture({fail:true});
 assert.equal((await ask(app,SUB,{Authorization:'Bearer '+SECRET})).status,503);
});

test('without SLIPWAY_INTERNAL_SECRET the endpoint does not exist',async()=>{
 const {app,calls}=fixture({secret:null});
 assert.equal((await ask(app,SUB,{Authorization:'Bearer '+SECRET})).status,404);assert.equal(calls.length,0);
 const env={AUTH_LOCAL_TEST:'1',APP_ORIGIN:'http://127.0.0.1:3000',OIDC_ISSUER:'http://127.0.0.1:8080/realms/x',SESSION_SECRET:'s'.repeat(48),OIDC_CLIENT_SECRET:'c'.repeat(32),DATABASE_URL:'postgres://x',TOKEN_ENCRYPTION_KEY:randomBytes(32).toString('base64')};
 assert.equal(readConfig(env).slipwayInternalSecret,null);
 assert.throws(()=>readConfig({...env,SLIPWAY_INTERNAL_SECRET:'short'}),/SLIPWAY_INTERNAL_SECRET/);
});
