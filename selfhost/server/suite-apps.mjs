import {readFileSync,existsSync} from 'node:fs';
import {createHmac} from 'node:crypto';
// The HSL Suite app registry (deployment/suite-apps.json): the apps that sign in through this realm, their Keycloak
// client ids, callback paths and roles. The web image carries it next to server/; in a checkout it is in deployment/.
// Roles are listed highest first.
const candidates=[new URL('../suite-apps.json',import.meta.url),new URL('../../deployment/suite-apps.json',import.meta.url)];
const ID=/^[a-z][a-z0-9-]{1,40}$/;const ENV=/^[A-Z][A-Z0-9_]{1,63}$/;const ROLE=/^[a-z][a-z0-9-]{0,40}$/;
export function validateSuiteApps(list){
 if(!Array.isArray(list)||!list.length)throw new Error('Suite app registry must be a non-empty list');
 const seen=new Set();
 for(const app of list){
  if(!app||!ID.test(app.id)||seen.has(app.id))throw new Error('Suite app registry: invalid or duplicate id');seen.add(app.id);
  // Names travel in HSL_SUITE_APPS as id|name|url entries separated by commas.
  if(typeof app.name!=='string'||!app.name.trim()||/[|,\r\n]/.test(app.name))throw new Error('Suite app registry: invalid name for '+app.id);
  if(typeof app.description!=='string'||!app.description.trim()||/[\r\n]/.test(app.description))throw new Error('Suite app registry: invalid description for '+app.id);
  for(const key of ['originEnv','publicUrlEnv'])if(!ENV.test(app[key]||''))throw new Error('Suite app registry: invalid '+key+' for '+app.id);
  if(typeof app.callbackPath!=='string'||!/^\/[A-Za-z0-9/_-]+$/.test(app.callbackPath))throw new Error('Suite app registry: invalid callbackPath for '+app.id);
  const roles=Object.entries(app.roles||{});if(!roles.length||roles.some(([name,text])=>!ROLE.test(name)||typeof text!=='string'||!text.trim()))throw new Error('Suite app registry: invalid roles for '+app.id);
 }
 return list.map(app=>Object.freeze({...app,roles:Object.freeze({...app.roles})}));
}
export function loadSuiteApps(file=process.env.HSL_SUITE_APPS_FILE){
 const path=file||candidates.find(candidate=>existsSync(candidate));
 if(!path)throw new Error('Suite app registry (suite-apps.json) not found');
 return validateSuiteApps(JSON.parse(readFileSync(path,'utf8')));
}
// A bare http(s) origin such as https://slipway.example.com, or null when blank.
export function bareOrigin(value,name){
 const text=String(value??'').trim().replace(/\/+$/,'');if(!text)return null;
 let url;try{url=new URL(text)}catch{throw new Error(name+' is not a valid URL')}
 if(!['http:','https:'].includes(url.protocol)||url.origin!==text)throw new Error(name+' must be an origin such as https://app.example.com, with no path');
 return url.origin;
}
// Each app's confidential client secret is derived from the portal's OIDC_CLIENT_SECRET (PLAN.md 5.2).
export const appClientSecret=(secret,id)=>createHmac('sha256',secret).update(id+'-v1').digest('hex');
// Highest role first, as listed in the registry.
export const highestRole=(app,roles)=>Object.keys(app.roles).find(name=>roles.includes(name))||null;
