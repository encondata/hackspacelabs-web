import {readFileSync,writeFileSync} from 'node:fs';
import {randomBytes} from 'node:crypto';
const directory=new URL('../',import.meta.url);
let contents=readFileSync(new URL('.env.example',directory),'utf8');
for(const name of ['POSTGRES_PASSWORD','KEYCLOAK_DB_PASSWORD','APP_DB_PASSWORD','KEYCLOAK_BOOTSTRAP_PASSWORD','OIDC_CLIENT_SECRET','SESSION_SECRET'])contents=contents.replace(new RegExp('^'+name+'=$','m'),name+'='+randomBytes(48).toString('hex'));
contents=contents.replace(/^TOKEN_ENCRYPTION_KEY=$/m,'TOKEN_ENCRYPTION_KEY='+randomBytes(32).toString('base64'));
writeFileSync(new URL('.env',directory),contents,{flag:'wx',mode:0o600});
console.log('Created deployment/.env with private random secrets. Set hostnames and ports before starting. Existing files are never overwritten.');
