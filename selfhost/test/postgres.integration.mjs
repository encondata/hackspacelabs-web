import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import path from 'node:path';
import pg from 'pg';
import session from 'express-session';
import connectPgSimple from 'connect-pg-simple';
import request from 'supertest';
import {createApp} from '../server/app.mjs';
import {createOidc} from '../server/oidc.mjs';
import {startIssuer} from './oidc-fixture.mjs';
test('PostgreSQL sessions persist across gateway instances and are deleted on logout',async()=>{
 assert.ok(process.env.TEST_DATABASE_URL,'Supply a dedicated test database URL');
 const pool=new pg.Pool({connectionString:process.env.TEST_DATABASE_URL});const fixture=await startIssuer();
 const config={production:false,origin:'http://127.0.0.1:3000',issuer:fixture.issuer,clientId:'hackspacelabs-web',clientSecret:randomBytes(32).toString('hex'),sessionSecret:randomBytes(48).toString('hex'),encryptionKey:randomBytes(32).toString('base64'),idleMs:1800000,absoluteMs:28800000,refreshMs:60000};
 const PgStore=connectPgSimple(session);const firstStore=new PgStore({pool,tableName:'web_sessions',pruneSessionInterval:false});const secondStore=new PgStore({pool,tableName:'web_sessions',pruneSessionInterval:false});
 try{
  const oidc=await createOidc(config);const make=store=>createApp({config,store,oidc,publicDir:path.resolve('selfhost/dist/public')});
  const agent=request.agent(make(firstStore));const start=await agent.get('/api/auth/login');const provider=await fetch(start.headers.location,{redirect:'manual'});const callback=new URL(provider.headers.get('location'));const signed=await agent.get(callback.pathname+callback.search);assert.equal(signed.headers.location,'/portal');
  const cookie=signed.headers['set-cookie'][0].split(';')[0];const rows=await pool.query('SELECT sess FROM web_sessions');assert.equal(rows.rows.length,1);assert.equal(typeof rows.rows[0].sess.tokens,'string');assert.equal(rows.rows[0].sess.tokens.includes('refreshToken'),false);
  const second=request(make(secondStore));const restored=await second.get('/api/auth/session').set('Cookie',cookie);assert.equal(restored.status,200);assert.equal(restored.body.user.email,'sample@example.com');
  await second.post('/api/auth/logout').set('Cookie',cookie).set('Origin',config.origin).set('x-csrf-token',restored.body.csrfToken).expect(200);
  assert.equal((await pool.query('SELECT count(*)::int n FROM web_sessions')).rows[0].n,0);
  await second.get('/api/auth/session').set('Cookie',cookie).expect(401);
  await assert.rejects(pool.query('CREATE DATABASE should_not_be_allowed'));
 }finally{firstStore.close();secondStore.close();await pool.end();await fixture.close()}
});
