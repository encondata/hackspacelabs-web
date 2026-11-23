import {createHmac} from 'node:crypto';
import {existsSync,readFileSync} from 'node:fs';
// One-shot client URL migration. Never creates users, changes passwords, or prints tokens.
// KEYCLOAK_URL is only for running this script against a disposable Keycloak outside the compose network.
const base=process.env.KEYCLOAK_URL||'http://keycloak:8080';
const app=process.env.APP_ORIGIN;
const auth=process.env.AUTH_ORIGIN;
if(!app||!auth)throw new Error('Application and authentication origins are required');
let token;
for(let attempt=0;attempt<60;attempt++){
  try{
    const response=await fetch(base+'/realms/master/protocol/openid-connect/token',{
      method:'POST',body:new URLSearchParams({grant_type:'password',client_id:'admin-cli',username:process.env.ADMIN_USERNAME,password:process.env.ADMIN_PASSWORD}),signal:AbortSignal.timeout(5000)
    });
    if(response.ok){token=(await response.json()).access_token;break}
    if(response.status===401||response.status===400)throw new Error('ADMIN_CREDENTIALS_REJECTED');
  }catch(error){if(error.message==='ADMIN_CREDENTIALS_REJECTED')throw new Error('Keycloak administrator credentials rejected. Update the private bootstrap credentials to a valid infrastructure administrator before retrying. No user passwords were changed.')}
  await new Promise(resolve=>setTimeout(resolve,2000));
}
if(!token)throw new Error('Local Keycloak did not become ready; retry the installer after checking its logs.');
async function api(route,options={}){
  const response=await fetch(base+'/admin/realms/hackspacelabs'+route,{...options,headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},signal:AbortSignal.timeout(10000)});
  if(!response.ok)throw new Error('Keycloak configuration request failed with status '+response.status);
  const contents=await response.text();return contents?JSON.parse(contents):undefined;
}
const clients=await api('/clients?clientId=hackspacelabs-web');
if(clients.length!==1)throw new Error('Expected one HackSpaceLabs website client');
const client=clients[0];
await api('/clients/'+encodeURIComponent(client.id),{method:'PUT',body:JSON.stringify({rootUrl:app,baseUrl:app+'/',redirectUris:[app+'/api/auth/callback'],webOrigins:[app],attributes:{...client.attributes,'post.logout.redirect.uris':app+'/login'}})});
const realm=await api('');
await api('',{method:'PUT',body:JSON.stringify({verifyEmail:false,resetPasswordAllowed:false,loginWithEmailAllowed:false,attributes:{...realm.attributes,frontendUrl:auth}})});
// Remove the unrequested email/profile gates from both new and existing accounts.
const unwanted=new Set(['VERIFY_EMAIL','UPDATE_PROFILE','VERIFY_PROFILE']);
const profile=await api('/users/profile');
for(const attribute of profile.attributes||[]){
  if(['email','firstName','lastName'].includes(attribute.name))delete attribute.required;
}
await api('/users/profile',{method:'PUT',body:JSON.stringify(profile)});
for(const action of await api('/authentication/required-actions')){
  if(unwanted.has(action.alias))await api('/authentication/required-actions/'+encodeURIComponent(action.alias),{method:'PUT',body:JSON.stringify({...action,enabled:false,defaultAction:false})});
}
let adjusted=0;
for(let first=0;;first+=100){
  const users=await api('/users?first='+first+'&max=100');
  for(const user of users){
    const actions=user.requiredActions||[];
    const keep=actions.filter(action=>!unwanted.has(action));
    if(keep.length!==actions.length){
      await api('/users/'+encodeURIComponent(user.id),{method:'PUT',body:JSON.stringify({requiredActions:keep})});
      adjusted++;
    }
  }
  if(users.length<100)break;
}
const policy=await api('');
if(policy.verifyEmail||policy.resetPasswordAllowed)throw new Error('Email-free login policy verification failed');
const updated=await api('/clients/'+encodeURIComponent(client.id));
if(updated.redirectUris?.[0]!==app+'/api/auth/callback'||updated.webOrigins?.[0]!==app)throw new Error('Keycloak client URL verification failed');
console.log('Configured username/password login without email or profile requirements. Removed obsolete actions from '+adjusted+' account(s). Existing passwords, roles, and pending password changes were preserved.');

// Dedicated realm-scoped service account; bootstrap credentials never enter the web container.
const managementId='hackspacelabs-management';
const managementSecret=createHmac('sha256',process.env.OIDC_CLIENT_SECRET).update('hackspacelabs-management-v1').digest('hex');
const representation={clientId:managementId,protocol:'openid-connect',enabled:true,publicClient:false,secret:managementSecret,serviceAccountsEnabled:true,standardFlowEnabled:false,directAccessGrantsEnabled:false,implicitFlowEnabled:false};
let [management]=await api('/clients?clientId='+managementId);
if(!management){await api('/clients',{method:'POST',body:JSON.stringify(representation)});[management]=await api('/clients?clientId='+managementId)}
else await api('/clients/'+management.id,{method:'PUT',body:JSON.stringify(representation)});
const adminScope=(await api('/client-scopes')).find(scope=>scope.name==='kc-admin-api');
if(!adminScope)throw new Error('Keycloak admin API scope is missing');
await api('/clients/'+management.id+'/default-client-scopes/'+adminScope.id,{method:'PUT'});
const service=await api('/clients/'+management.id+'/service-account-user');
const [realmManagement]=await api('/clients?clientId=realm-management');
const role=await api('/clients/'+realmManagement.id+'/roles/realm-admin');
await api('/users/'+service.id+'/role-mappings/clients/'+realmManagement.id,{method:'POST',body:JSON.stringify([role])});
console.log('Portal identity management configured.');

// First-party Android app (HackSpaceLabs-Android). A public client: Authorization Code + PKCE S256 in a Custom Tab,
// returning to the app's private-use scheme (RFC 8252 section 7.1), which the portal's Connected apps form doesn't
// accept. offline_access lets the app's biometric sign-in outlive Keycloak's browser session.
const androidId='hackspacelabs-android';
const androidRedirect='com.hackspacelabs.app:/oauth2redirect';
const androidRepresentation={clientId:androidId,name:'HackSpaceLabs for Android',protocol:'openid-connect',enabled:true,publicClient:true,standardFlowEnabled:true,directAccessGrantsEnabled:false,implicitFlowEnabled:false,serviceAccountsEnabled:false,consentRequired:false,fullScopeAllowed:false,redirectUris:[androidRedirect],webOrigins:[],attributes:{'pkce.code.challenge.method':'S256','post.logout.redirect.uris':'com.hackspacelabs.app:/logout'}};
let [android]=await api('/clients?clientId='+androidId);
if(!android){await api('/clients',{method:'POST',body:JSON.stringify(androidRepresentation)});[android]=await api('/clients?clientId='+androidId)}
else await api('/clients/'+android.id,{method:'PUT',body:JSON.stringify({...android,...androidRepresentation,attributes:{...android.attributes,...androidRepresentation.attributes}})});
const scopeIds=new Map((await api('/client-scopes')).map(scope=>[scope.name,scope.id]));
for(const name of ['basic','profile','email'])if(scopeIds.has(name))await api('/clients/'+android.id+'/default-client-scopes/'+scopeIds.get(name),{method:'PUT'});
if(!scopeIds.has('offline_access'))throw new Error('Keycloak offline_access scope is missing');
await api('/clients/'+android.id+'/optional-client-scopes/'+scopeIds.get('offline_access'),{method:'PUT'});
const androidCheck=await api('/clients/'+android.id);
if(!androidCheck.publicClient||androidCheck.directAccessGrantsEnabled||androidCheck.redirectUris?.length!==1||androidCheck.redirectUris[0]!==androidRedirect)throw new Error('Android app client verification failed');
// fullScopeAllowed is off, so the app's tokens carry only the roles it is scoped to; offline_access must be one.
const offlineRole=await api('/roles/offline_access');
await api('/clients/'+android.id+'/scope-mappings/realm',{method:'POST',body:JSON.stringify([offlineRole])});
// Accounts created through the portal get the realm's default role (offline_access, uma_authorization) from
// Keycloak; accounts imported with the realm, such as the seeded admin, never did. Give them the same baseline,
// so every account can keep the Android app's biometric sign-in. Other roles are untouched.
const defaultRole=await api('/roles/'+encodeURIComponent(realm.defaultRole?.name||'default-roles-hackspacelabs'));
let baselined=0;
for(let first=0;;first+=100){
  const users=await api('/users?first='+first+'&max=100&briefRepresentation=true');
  for(const user of users){
    if(user.username?.startsWith('service-account-'))continue;
    const realmRoles=await api('/users/'+encodeURIComponent(user.id)+'/role-mappings/realm');
    if(!realmRoles.some(role=>role.id===defaultRole.id)){
      await api('/users/'+encodeURIComponent(user.id)+'/role-mappings/realm',{method:'POST',body:JSON.stringify([defaultRole])});
      baselined++;
    }
  }
  if(users.length<100)break;
}
console.log('HackSpaceLabs Android app sign-in configured'+(baselined?'; gave '+baselined+' imported account(s) the realm default role.':'.'));

// ---- HSL Suite (PLAN.md work package 1): session policy, app clients, the portal's view of app roles ----
const derive=message=>createHmac('sha256',process.env.OIDC_CLIENT_SECRET).update(message).digest('hex');
// Realm attributes mark one-time steps, so reruns of the installer never undo what an administrator changed later.
async function markRealm(name){const fresh=await api('');await api('',{method:'PUT',body:JSON.stringify({attributes:{...fresh.attributes,[name]:'1'}})})}

// Session policy, once per realm: Keycloak is the single clock for every app's session (D2, D3, D4).
const sessionPolicy={rememberMe:true,ssoSessionIdleTimeout:345600,ssoSessionMaxLifespan:345600,ssoSessionIdleTimeoutRememberMe:2592000,ssoSessionMaxLifespanRememberMe:2592000,clientSessionIdleTimeout:0,clientSessionMaxLifespan:0};
const policyRealm=await api('');
if(policyRealm.attributes?.['hsl.sessionPolicy']!=='1'){
  await api('',{method:'PUT',body:JSON.stringify({...sessionPolicy,attributes:{...policyRealm.attributes,'hsl.sessionPolicy':'1'}})});
  const applied=await api('');
  if(Object.entries(sessionPolicy).some(([key,value])=>applied[key]!==value)||applied.attributes?.['hsl.sessionPolicy']!=='1')throw new Error('Session policy verification failed');
  console.log('Applied the suite session policy: 96 hours, or 30 days with "Remember me".');
}else console.log('Suite session policy was applied before; current session lengths were kept.');

// App registry: next to this script in the configure-auth container (/tools), one folder up in a checkout.
const registryFile=[new URL('./suite-apps.json',import.meta.url),new URL('../suite-apps.json',import.meta.url)].find(file=>existsSync(file));
if(!registryFile)throw new Error('suite-apps.json is missing; it must be mounted next to configure-auth.mjs');
const suiteApps=JSON.parse(readFileSync(registryFile,'utf8'));
if(!Array.isArray(suiteApps)||suiteApps.some(app=>!/^[a-z][a-z0-9-]{1,40}$/.test(app?.id)||!/^[A-Z][A-Z0-9_]+$/.test(app.originEnv)||!/^\/[A-Za-z0-9/_-]+$/.test(app.callbackPath)||!Object.keys(app.roles||{}).length))throw new Error('suite-apps.json is invalid');
const suiteScopes=new Map((await api('/client-scopes')).map(scope=>[scope.name,scope.id]));
const appRolesMapper=(clientId,claim,name)=>({name,protocol:'openid-connect',protocolMapper:'oidc-usermodel-client-role-mapper',consentRequired:false,config:{'usermodel.clientRoleMapping.clientId':clientId,'claim.name':claim,'jsonType.label':'String',multivalued:'true','id.token.claim':'true','access.token.claim':'true','userinfo.token.claim':'true'}});
async function ensureMapper(clientUuid,mapper){
  const present=(await api('/clients/'+clientUuid+'/protocol-mappers/models')).find(m=>m.name===mapper.name);
  if(present)await api('/clients/'+clientUuid+'/protocol-mappers/models/'+present.id,{method:'PUT',body:JSON.stringify({...mapper,id:present.id})});
  else await api('/clients/'+clientUuid+'/protocol-mappers/models',{method:'POST',body:JSON.stringify(mapper)});
}
// Portal administrators by effective role (direct, through groups or composites), found once and only when needed.
let portalAdmins;
async function effectivePortalAdmins(){
  if(portalAdmins)return portalAdmins;portalAdmins=[];
  for(let first=0;;first+=100){
    const users=await api('/users?first='+first+'&max=100&briefRepresentation=true');
    for(const user of users){
      if(user.username?.startsWith('service-account-'))continue;
      if((await api('/users/'+encodeURIComponent(user.id)+'/role-mappings/clients/'+client.id+'/composite')).some(role=>role.name==='admin'))portalAdmins.push(user.id);
    }
    if(users.length<100)break;
  }
  return portalAdmins;
}
for(const app of suiteApps){
  const raw=(process.env[app.originEnv]||'').trim().replace(/\/+$/,'');
  let [existing]=await api('/clients?clientId='+encodeURIComponent(app.id));
  if(raw){
    let parsed;try{parsed=new URL(raw)}catch{throw new Error(app.originEnv+' is not a valid URL')}
    if(parsed.origin!==raw||!['https:','http:'].includes(parsed.protocol))throw new Error(app.originEnv+' must be an origin such as https://'+app.id+'.example.com, with no path');
    const origin=parsed.origin;const secret=derive(app.id+'-v1');const redirect=origin+app.callbackPath;const signedOut=origin+'/signed-out';
    const representation={clientId:app.id,name:app.name,description:app.description,protocol:'openid-connect',enabled:true,publicClient:false,clientAuthenticatorType:'client-secret',secret,standardFlowEnabled:true,directAccessGrantsEnabled:false,implicitFlowEnabled:false,serviceAccountsEnabled:false,consentRequired:false,fullScopeAllowed:false,rootUrl:origin,baseUrl:origin+'/',redirectUris:[redirect],webOrigins:[origin],attributes:{'pkce.code.challenge.method':'S256','post.logout.redirect.uris':signedOut,'oauth2.device.authorization.grant.enabled':'false','oidc.ciba.grant.enabled':'false'}};
    if(!existing){await api('/clients',{method:'POST',body:JSON.stringify(representation)});[existing]=await api('/clients?clientId='+encodeURIComponent(app.id))}
    else await api('/clients/'+existing.id,{method:'PUT',body:JSON.stringify({...existing,...representation,attributes:{...existing.attributes,...representation.attributes}})});
    const id=existing.id;
    const present=new Set((await api('/clients/'+id+'/roles')).map(role=>role.name));
    for(const [name,description] of Object.entries(app.roles))if(!present.has(name))await api('/clients/'+id+'/roles',{method:'POST',body:JSON.stringify({name,description})});
    // Same mapper name as the dev workspace provisions, so the two never make duplicates.
    await ensureMapper(id,appRolesMapper(app.id,'hsl_roles','HSL app roles'));
    for(const name of ['basic','profile','email'])if(suiteScopes.has(name))await api('/clients/'+id+'/default-client-scopes/'+suiteScopes.get(name),{method:'PUT'});
    const check=await api('/clients/'+id);const stored=await api('/clients/'+id+'/client-secret');
    const roles=new Set((await api('/clients/'+id+'/roles')).map(role=>role.name));
    const mapper=(await api('/clients/'+id+'/protocol-mappers/models')).find(m=>m.name==='HSL app roles');
    if(check.publicClient||check.directAccessGrantsEnabled||check.implicitFlowEnabled||!check.standardFlowEnabled||check.fullScopeAllowed||check.redirectUris?.length!==1||check.redirectUris[0]!==redirect||check.attributes?.['pkce.code.challenge.method']!=='S256'||check.attributes?.['post.logout.redirect.uris']!==signedOut||stored?.value!==secret||Object.keys(app.roles).some(name=>!roles.has(name))||mapper?.config?.['claim.name']!=='hsl_roles')throw new Error(app.name+' client verification failed');
    console.log(app.name+' sign-in client configured for '+origin+'. Run scripts/app-env.mjs '+app.id+' to give '+app.name+' its settings.');
    // First rollout only, once per client: current portal administrators become this app's administrators, so
    // someone can use it. Afterwards roles are only changed by administrators, even if a client is emptied on purpose.
    const fresh=await api('');
    if(fresh.attributes?.['hsl.firstGrant.'+app.id]!=='1'){
      const adminRole=await api('/clients/'+id+'/roles/admin');const admins=await effectivePortalAdmins();
      for(const user of admins)await api('/users/'+encodeURIComponent(user)+'/role-mappings/clients/'+id,{method:'POST',body:JSON.stringify([adminRole])});
      await markRealm('hsl.firstGrant.'+app.id);
      console.log('First rollout: granted the '+app.name+' admin role to '+admins.length+' portal administrator(s).');
    }
  }else console.log(app.originEnv+' is not set; '+app.name+' sign-in client left unchanged.');
  // The portal shows each person the apps they can use: its tokens carry hsl_apps.<id> with that app's roles.
  // Its client has fullScopeAllowed off, so it also needs a scope mapping to them (PLAN.md appendix B row 12).
  if(existing){
    const appRoles=(await api('/clients/'+existing.id+'/roles')).filter(role=>Object.hasOwn(app.roles,role.name));
    if(appRoles.length)await api('/clients/'+client.id+'/scope-mappings/clients/'+existing.id,{method:'POST',body:JSON.stringify(appRoles)});
    await ensureMapper(client.id,appRolesMapper(app.id,'hsl_apps.'+app.id,'HSL apps: '+app.id));
  }
}
console.log('HSL Suite apps configured.');
