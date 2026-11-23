import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,createHmac} from 'node:crypto';
import session from 'express-session';
import request from 'supertest';
import {createApp} from '../server/app.mjs';
const CLIENT_SECRET=randomBytes(48).toString('hex');
const secretFor=app=>createHmac('sha256',CLIENT_SECRET).update(app+'-v1').digest('hex');
const SUB='4b9f2c1e-2d7a-4a8e-9f0b-1c2d3e4f5a6b';
function fixture({users={[SUB]:{id:SUB,username:'ada',email:'ada@example.com',firstName:'Ada',enabled:true}},roles=[{name:'viewer'},{name:'service-account'},{name:'editor'}],fail=false,clients=['switchyard','tideline','slipway','harbormaster']}={}){
 const calls=[];
 const api=async route=>{
  calls.push(route);
  if(fail)throw Object.assign(new Error('Identity service request failed'),{status:503});
  const client=/^\/clients\?clientId=(.+)$/.exec(route);if(client)return clients.includes(client[1])?[{id:client[1]+'-uuid'}]:[];
  const user=route.match(/^\/users\/([^/]+)$/);
  if(user){if(users[decodeURIComponent(user[1])])return users[decodeURIComponent(user[1])];throw Object.assign(new Error('Identity service request failed'),{status:404})}
  if(route.endsWith('/composite'))return roles;
  return null;
 };
 const config={production:false,origin:'http://127.0.0.1:3000',issuer:'http://127.0.0.1:1/realms/x',clientId:'hackspacelabs-web',clientSecret:CLIENT_SECRET,sessionSecret:randomBytes(48).toString('hex'),encryptionKey:randomBytes(32).toString('base64'),refreshMs:60000};
 const app=createApp({config,store:new session.MemoryStore(),oidc:{},management:api,publicDir:'.',log:{error(){},info(){}}});
 return {app,calls};
}
const ask=(app,path,headers={})=>{let r=request(app).get('/internal/apps/'+path);for(const [k,v] of Object.entries(headers))r=r.set(k,v);return r};
test('owner check answers only enabled and the app\'s effective roles, highest first',async()=>{
 const {app,calls}=fixture();
 const r=await ask(app,'switchyard/owners/'+SUB,{Authorization:'Bearer '+secretFor('switchyard')});
 assert.equal(r.status,200);assert.equal(r.headers['cache-control'],'no-store');assert.equal(r.headers['set-cookie'],undefined);
 assert.deepEqual(r.body,{enabled:true,roles:['editor','viewer']});
 assert.ok(calls.includes(`/users/${SUB}/role-mappings/clients/switchyard-uuid/composite`),'effective roles, so groups count');
});
test('disabled, unknown and service accounts are not enabled; an app without a client gives no roles',async()=>{
 const {app}=fixture({users:{[SUB]:{id:SUB,username:'ada',enabled:false},svc:{id:'svc',username:'service-account-x',serviceAccountClientId:'c',enabled:true}}});
 const auth={Authorization:'Bearer '+secretFor('tideline')};
 assert.deepEqual((await ask(app,'tideline/owners/'+SUB,auth)).body,{enabled:false,roles:['editor','viewer']});
 assert.deepEqual((await ask(app,'tideline/owners/svc',auth)).body,{enabled:false,roles:[]});
 assert.deepEqual((await ask(app,'tideline/owners/nobody',auth)).body,{enabled:false,roles:[]});
 const none=fixture({clients:[]});assert.deepEqual((await ask(none.app,'tideline/owners/'+SUB,auth)).body,{enabled:true,roles:[]});
});
test('each app must present its own secret, and proxied requests are refused, all as a plain 404',async()=>{
 const {app,calls}=fixture();const good='Bearer '+secretFor('slipway');
 for(const [path,headers] of [['slipway/owners/'+SUB,{}],['slipway/owners/'+SUB,{Authorization:'Bearer wrong'}],['slipway/owners/'+SUB,{Authorization:secretFor('slipway')}],['slipway/owners/'+SUB,{Authorization:'Bearer '+secretFor('harbormaster')}],['slipway/owners/'+SUB,{Authorization:'Bearer '+CLIENT_SECRET}],['unknown/owners/'+SUB,{Authorization:good}],['slipway/owners/'+SUB,{Authorization:good,'X-Forwarded-For':'203.0.113.9'}],['slipway/owners/'+SUB,{Authorization:good,Forwarded:'for=203.0.113.9'}],['slipway/owners/'+SUB,{Authorization:good,'X-Real-IP':'203.0.113.9'}],['slipway/other',{Authorization:good}]]){
  const r=await ask(app,path,headers);assert.equal(r.status,404,path+' '+JSON.stringify(headers));assert.equal(r.text,'Page not found');
 }
 assert.equal(calls.length,0);
 assert.equal((await ask(app,'slipway/owners/bad_sub!',{Authorization:good})).status,400);
});
test('identity outages are 503, never an answer',async()=>{
 const {app}=fixture({fail:true});
 assert.equal((await ask(app,'harbormaster/owners/'+SUB,{Authorization:'Bearer '+secretFor('harbormaster')})).status,503);
});
test('without the management API the endpoint does not exist',async()=>{
 const config={production:false,origin:'http://127.0.0.1:3000',issuer:'http://127.0.0.1:1/realms/x',clientId:'hackspacelabs-web',clientSecret:CLIENT_SECRET,sessionSecret:randomBytes(48).toString('hex'),encryptionKey:randomBytes(32).toString('base64'),refreshMs:60000};
 const app=createApp({config,store:new session.MemoryStore(),oidc:{},publicDir:'.',log:{error(){}}});
 assert.equal((await ask(app,'slipway/owners/'+SUB,{Authorization:'Bearer '+secretFor('slipway')})).status,404);
});
