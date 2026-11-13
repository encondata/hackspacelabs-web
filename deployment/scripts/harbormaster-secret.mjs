#!/usr/bin/env node
// Writes Harbor Master's HackSpaceLabs sign-in settings into Harbor Master's .env, without printing the secret.
// Usage (from the deployment folder): node scripts/harbormaster-secret.mjs /path/to/harbormaster/.env
// The secret is derived from OIDC_CLIENT_SECRET exactly as configure-auth.mjs sets it in Keycloak.
import {readFileSync,writeFileSync,existsSync,statSync,chmodSync} from 'node:fs';
import {createHmac} from 'node:crypto';
const target=process.argv[2];
if(!target){console.error('Usage: node scripts/harbormaster-secret.mjs /path/to/harbormaster/.env');process.exit(2)}
// Read deployment/.env as data, never as shell code.
const values={};
for(const line of readFileSync(new URL('../.env',import.meta.url),'utf8').split(/\r?\n/)){
  const match=/^([A-Z0-9_]+)=(.*)$/.exec(line);
  if(match)values[match[1]]=match[2].replace(/^(['"])(.*)\1$/,'$2');
}
if(!values.OIDC_CLIENT_SECRET)throw new Error('deployment/.env has no OIDC_CLIENT_SECRET');
if(!values.HARBORMASTER_ORIGIN)throw new Error('Set HARBORMASTER_ORIGIN in deployment/.env and rerun the installer first');
const authOrigin=(values.AUTH_ORIGIN||'https://'+(values.AUTH_HOST||'auth.hackspacelabs.com')).replace(/\/+$/,'');
const settings={
  HSL_OIDC_ISSUER:authOrigin+'/realms/hackspacelabs',
  HSL_OIDC_CLIENT_ID:'harbormaster',
  HSL_OIDC_CLIENT_SECRET:createHmac('sha256',values.OIDC_CLIENT_SECRET).update('harbormaster-v1').digest('hex'),
};
let contents=existsSync(target)?readFileSync(target,'utf8'):'';
for(const [name,value] of Object.entries(settings)){
  const pattern=new RegExp('^'+name+'=.*$','m');
  contents=pattern.test(contents)?contents.replace(pattern,()=>name+'='+value):contents.replace(/\n?$/,'\n')+name+'='+value+'\n';
}
writeFileSync(target,contents,{mode:0o600});
if((statSync(target).mode&0o077)!==0)chmodSync(target,0o600);
console.log('Wrote HSL_OIDC_ISSUER, HSL_OIDC_CLIENT_ID and HSL_OIDC_CLIENT_SECRET to '+target+'. Restart Harbor Master\'s api container to use them.');
