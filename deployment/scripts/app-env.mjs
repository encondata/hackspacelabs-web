#!/usr/bin/env node
// Writes one suite app's HackSpaceLabs sign-in settings (PLAN.md 5.1) into that app's .env, without printing secrets.
// Usage (from the deployment folder): node scripts/app-env.mjs <app> /path/to/that/app/.env
// <app> is an id from suite-apps.json: slipway, switchyard, harbormaster or tideline. Rerun it after the installer
// whenever this site's addresses or the app's origin change. Values are derived exactly as configure-auth.mjs sets
// them in Keycloak, so nothing new has to be stored. Other settings in the app's .env are left as they are.
import {readFileSync,writeFileSync,existsSync,statSync,renameSync,rmSync} from 'node:fs';
import {createHmac,randomBytes} from 'node:crypto';
import path from 'node:path';
const [id,target]=process.argv.slice(2);
const fail=message=>{console.error(message);process.exit(1)};
if(!id||!target)fail('Usage: node scripts/app-env.mjs <slipway|switchyard|harbormaster|tideline> /path/to/that/app/.env');
const registry=JSON.parse(readFileSync(new URL('../suite-apps.json',import.meta.url),'utf8'));
const app=registry.find(entry=>entry.id===id);
if(!app)fail('Unknown app "'+id+'". Use one of: '+registry.map(entry=>entry.id).join(', '));
// Read .env files as data, never as shell code. DEPLOYMENT_ENV_FILE is only for tests.
function parse(contents){
  const values={};
  for(const line of contents.split(/\r?\n/)){const match=/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line);if(match)values[match[1]]=match[2].trim().replace(/^(['"])(.*)\1$/,'$2')}
  return values;
}
const deployment=parse(readFileSync(process.env.DEPLOYMENT_ENV_FILE||new URL('../.env',import.meta.url),'utf8'));
function origin(value,name){
  const text=String(value||'').trim().replace(/\/+$/,'');if(!text)return null;
  let url;try{url=new URL(text)}catch{fail(name+' is not a valid URL')}
  if(!['http:','https:'].includes(url.protocol)||url.origin!==text)fail(name+' must be an origin such as https://app.example.com, with no path');
  return url.origin;
}
if(!deployment.OIDC_CLIENT_SECRET)fail('deployment/.env has no OIDC_CLIENT_SECRET');
const appOrigin=origin(deployment[app.originEnv],app.originEnv);
if(!appOrigin)fail('Set '+app.originEnv+' in deployment/.env and rerun the installer first, so '+app.name+'\'s sign-in client exists.');
const portal=origin(deployment.APP_ORIGIN||'https://'+(deployment.APP_HOST||'hackspacelabs.com'),'APP_ORIGIN');
const auth=origin(deployment.AUTH_ORIGIN||'https://'+(deployment.AUTH_HOST||'auth.hackspacelabs.com'),'AUTH_ORIGIN');
// The switcher list: the portal's app launcher, then every app whose origin is set (id|name|url, comma separated).
const apps=['portal|HackSpaceLabs|'+portal+'/apps',...registry.flatMap(entry=>{const url=origin(deployment[entry.originEnv],entry.originEnv);return url?[entry.id+'|'+entry.name+'|'+url]:[]})].join(',');
const settings={
  HSL_OIDC_ISSUER:auth+'/realms/hackspacelabs',
  HSL_OIDC_CLIENT_ID:app.id,
  HSL_OIDC_CLIENT_SECRET:createHmac('sha256',deployment.OIDC_CLIENT_SECRET).update(app.id+'-v1').digest('hex'),
  HSL_PORTAL_URL:portal,
  HSL_SUITE_APPS:apps,
};
// Slipway and Harbor Master tie API tokens to a person, so they ask this site's gateway whether a token's owner
// still has access (PLAN.md D18, selfhost/server/owners.mjs). That call must reach the gateway directly, never
// through the proxy, which refuses it. PORTAL_INTERNAL_URL names that address; in LAN mode the site's own
// address already is the gateway. Without it the owner check stays off and the app says so at start.
const personalTokens=new Set(['slipway','harbormaster']);
const portalInternal=origin(deployment.PORTAL_INTERNAL_URL,'PORTAL_INTERNAL_URL')||(deployment.AUTH_MODE==='lan'?portal:null);
// Written only when this site knows the address, so a value set by hand in the app's .env is never blanked.
if(personalTokens.has(app.id)&&portalInternal)settings.HSL_PORTAL_INTERNAL_URL=portalInternal;
const contents=existsSync(target)?readFileSync(target,'utf8'):'';
const current=parse(contents);
// The app's own address. Switchyard and Tideline get new variables nobody else sets (without them SSO stays off).
// Slipway and Harbor Master already have one that other things depend on, so it is only checked, never changed.
const ownAddress=new Set(['CPM_PUBLIC_URL','TIDELINE_PUBLIC_URL']);
if(ownAddress.has(app.publicUrlEnv))settings[app.publicUrlEnv]=appOrigin;
else{
  const own=String(current[app.publicUrlEnv]||'').trim().replace(/\/+$/,'');
  if(own!==appOrigin)fail(app.name+'\'s '+app.publicUrlEnv+' is '+(own?'"'+own+'"':'not set')+' but '+app.originEnv+' in deployment/.env is "'+appOrigin+'". They must be the same address: Keycloak only returns to '+appOrigin+'. Fix whichever is wrong, rerun the installer if '+app.originEnv+' changed, then run this again. Nothing was written.');
}
let next=contents;
for(const [name,value] of Object.entries(settings)){
  const pattern=new RegExp('^\\s*(?:export\\s+)?'+name+'=.*$','m');
  next=pattern.test(next)?next.replace(pattern,()=>name+'='+value):next.replace(/\n?$/,next?'\n':'')+name+'='+value+'\n';
}
// Replace the file in one step, private to its owner.
const temporary=path.join(path.dirname(path.resolve(target)),'.'+path.basename(target)+'.'+randomBytes(6).toString('hex')+'.tmp');
try{writeFileSync(temporary,next,{mode:0o600,flag:'wx'});renameSync(temporary,target)}finally{rmSync(temporary,{force:true})}
if((statSync(target).mode&0o077)!==0)fail('Could not make '+target+' private (mode 600)');
console.log('Wrote '+Object.keys(settings).join(', ')+' to '+target+'.');
if(!ownAddress.has(app.publicUrlEnv))console.log(app.publicUrlEnv+' already matches '+app.originEnv+'.');
if(personalTokens.has(app.id)&&!portalInternal)console.log(current.HSL_PORTAL_INTERNAL_URL?app.name+'\'s HSL_PORTAL_INTERNAL_URL was left as it is (no PORTAL_INTERNAL_URL in deployment/.env).':'No PORTAL_INTERNAL_URL in deployment/.env, so '+app.name+' cannot check whether an API token\'s owner still has access. Set it to the gateway\'s direct address, e.g. http://192.168.1.10:8088, and run this again.');
if(app.id==='switchyard'&&!current.CPM_SECRET_KEY)console.log('Switchyard\'s .env has no CPM_SECRET_KEY. HackSpaceLabs sign-in stays off until it has one (32 random bytes, base64; its installer normally writes it).');
console.log('Recreate '+app.name+'\'s containers to use them: in its folder, docker compose up -d (a plain restart does not reread .env).');
