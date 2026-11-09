// Loopback-only integration preview with a simulated issuer; NOT a production login provider.
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import session from 'express-session';
import connectPgSimple from 'connect-pg-simple';
import pg from 'pg';
import {startIssuer} from './oidc-fixture.mjs';
import {createOidc} from '../server/oidc.mjs';
import {createApp} from '../server/app.mjs';
if(!process.env.TEST_DATABASE_URL)throw new Error('A disposable TEST_DATABASE_URL is required');
const provider=await startIssuer();provider.state.roles=['admin'];
const config={production:false,origin:'http://127.0.0.1:5181',issuer:provider.issuer,clientId:'hackspacelabs-web',clientSecret:randomBytes(32).toString('hex'),sessionSecret:randomBytes(48).toString('hex'),encryptionKey:randomBytes(32).toString('base64'),idleMs:1800000,absoluteMs:28800000,refreshMs:60000};
const pool=new pg.Pool({connectionString:process.env.TEST_DATABASE_URL});const PgStore=connectPgSimple(session);const store=new PgStore({pool,tableName:'web_sessions',pruneSessionInterval:false});
const app=createApp({config,store,oidc:await createOidc(config),publicDir:path.resolve('selfhost/dist/public')});
const server=app.listen(5181,'127.0.0.1',()=>console.log('Protocol-test preview only: http://127.0.0.1:5181/login'));
for(const sig of ['SIGTERM','SIGINT'])process.on(sig,()=>server.close(async()=>{store.close();await pool.end();await provider.close();process.exit(0)}));
