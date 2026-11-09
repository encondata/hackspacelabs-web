import {test} from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {randomBytes} from 'node:crypto';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import session from 'express-session';
import request from 'supertest';
import {deferredOidc} from '../server/deferred-oidc.mjs';
import {createApp} from '../server/app.mjs';

const settings=()=>({production:true,origin:'https://web.not-configured.invalid',issuer:'https://auth.not-configured.invalid/realms/hackspacelabs',sessionSecret:randomBytes(48).toString('hex'),encryptionKey:randomBytes(32).toString('base64'),idleMs:1800000});

test('OIDC discovery is deferred, shared, and retried after DNS failure',async()=>{
  let attempts=0;
  const client=deferredOidc(settings(),async()=>{
    attempts++;
    if(attempts===1)throw new Error('DNS not configured');
    return {begin:async()=>({url:'https://auth.example/login'}),logout:()=> 'https://auth.example/logout'};
  });
  assert.equal(attempts,0);
  await assert.rejects(client.begin(),/DNS not configured/);
  const results=await Promise.all([client.begin(),client.begin()]);
  assert.equal(attempts,2);
  assert.equal(results[0].url,'https://auth.example/login');
  assert.equal(await client.logout(),'https://auth.example/logout');
});

test('direct HTTP serves homepage and liveness without discovery while auth remains protected',async t=>{
  const dir=await mkdtemp(path.join(tmpdir(),'hsl-startup-'));
  t.after(()=>rm(dir,{recursive:true,force:true}));
  await writeFile(path.join(dir,'index.html'),'HackSpaceLabs');
  let attempts=0;
  const config=settings();
  const app=createApp({config,store:new session.MemoryStore(),publicDir:dir,oidc:deferredOidc(config,async()=>{attempts++;throw new Error('No DNS')})});
  const home=await request(app).get('/').set('Host','192.0.2.1:8088').expect(200);
  assert.equal(home.text,'HackSpaceLabs');
  assert.ok(!home.headers['content-security-policy'].includes('upgrade-insecure-requests'));
  await request(app).get('/healthz').expect(200);
  await request(app).get('/admin').expect(400);
  await request(app).get('/api/auth/login').expect(400);
  assert.equal(attempts,0);
});

test('production entrypoint listens on 0.0.0.0 with unavailable DNS and database', {timeout:10000}, async t=>{
  const config=settings();
  const child=spawn(process.execPath,[fileURLToPath(new URL('../server/index.mjs',import.meta.url))],{
    env:{...process.env,NODE_ENV:'production',PORT:'0',APP_ORIGIN:config.origin,OIDC_ISSUER:config.issuer,
      DATABASE_URL:'postgres://unavailable:unavailable@127.0.0.1:1/unavailable',
      OIDC_CLIENT_SECRET:randomBytes(32).toString('hex'),SESSION_SECRET:config.sessionSecret,TOKEN_ENCRYPTION_KEY:config.encryptionKey},
    stdio:['ignore','pipe','pipe']
  });
  t.after(async()=>{if(child.exitCode===null){const closed=once(child,'exit');child.kill('SIGTERM');await closed}});
  const port=await new Promise((resolve,reject)=>{
    let output='';
    child.stdout.on('data',data=>{output+=data;const match=output.match(/listening on 0\.0\.0\.0:(\d+)/);if(match)resolve(match[1])});
    child.once('error',reject);
    child.once('exit',code=>reject(new Error('Gateway exited before listening: '+code)));
  });
  const response=await fetch('http://127.0.0.1:'+port+'/healthz');
  assert.equal(response.status,200);
  assert.deepEqual(await response.json(),{status:'ok'});
});
