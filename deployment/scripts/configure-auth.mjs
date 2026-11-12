import {createHmac} from 'node:crypto';
// One-shot client URL migration. Never creates users, changes passwords, or prints tokens.
const base='http://keycloak:8080';
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

// Slipway deployment API: a bearer-only client that holds the Slipway roles. Access tokens issued to the website
// client carry audience "slipway" and a slipway_roles claim; the gateway forwards them to Slipway, which verifies them.
const slipwayRoles={admin:"Slipway: full control, including users' tokens and audit",maintainer:'Slipway: manage hosts, instances and deployments',developer:'Slipway: sync repositories, operate instances and deploy',viewer:'Slipway: read-only access'};
const slipwaySecret=process.env.SLIPWAY_OIDC_CLIENT_SECRET;
if(!slipwaySecret||slipwaySecret.length<32)throw new Error('SLIPWAY_OIDC_CLIENT_SECRET is required');
// Confidential, no browser flows. Its read-only service account lets Slipway confirm an API token's owner is still enabled.
const slipwayRepresentation={clientId:'slipway',name:'Slipway',protocol:'openid-connect',enabled:true,bearerOnly:false,publicClient:false,clientAuthenticatorType:'client-secret',secret:slipwaySecret,standardFlowEnabled:false,directAccessGrantsEnabled:false,implicitFlowEnabled:false,serviceAccountsEnabled:true,fullScopeAllowed:false};
let [slipway]=await api('/clients?clientId=slipway');
if(!slipway){await api('/clients',{method:'POST',body:JSON.stringify(slipwayRepresentation)});[slipway]=await api('/clients?clientId=slipway')}
else await api('/clients/'+slipway.id,{method:'PUT',body:JSON.stringify({...slipway,...slipwayRepresentation})});
const presentRoles=new Set((await api('/clients/'+slipway.id+'/roles')).map(role=>role.name));
for(const [name,description] of Object.entries(slipwayRoles))if(!presentRoles.has(name))await api('/clients/'+slipway.id+'/roles',{method:'POST',body:JSON.stringify({name,description})});
const slipwayService=await api('/clients/'+slipway.id+'/service-account-user');
const [realmAdmin]=await api('/clients?clientId=realm-management');
const readOnly=await Promise.all(['view-users'].map(name=>api('/clients/'+realmAdmin.id+'/roles/'+name)));
await api('/users/'+slipwayService.id+'/role-mappings/clients/'+realmAdmin.id,{method:'POST',body:JSON.stringify(readOnly)});
// Its tokens must be addressed to the admin API (kc-admin-api) and, as fullScopeAllowed is false, carry view-users
// through an explicit scope mapping; otherwise Keycloak rejects them with 401. No client access is granted.
await api('/clients/'+slipway.id+'/default-client-scopes/'+adminScope.id,{method:'PUT'});
await api('/clients/'+slipway.id+'/scope-mappings/clients/'+realmAdmin.id,{method:'POST',body:JSON.stringify(readOnly)});
// Marker role so Slipway can find its own client id from its service account's role mappings (view-users only).
if(!presentRoles.has('service-account'))await api('/clients/'+slipway.id+'/roles',{method:'POST',body:JSON.stringify({name:'service-account',description:'Internal: identifies Slipway\'s own service account. Grants nothing.'})});
await api('/users/'+slipwayService.id+'/role-mappings/clients/'+slipway.id,{method:'POST',body:JSON.stringify([await api('/clients/'+slipway.id+'/roles/service-account')])});
const slipwayRoleList=await Promise.all(Object.keys(slipwayRoles).map(name=>api('/clients/'+slipway.id+'/roles/'+name)));
// The website client has fullScopeAllowed=false, so it may only carry Slipway roles it is scoped to.
await api('/clients/'+client.id+'/scope-mappings/clients/'+slipway.id,{method:'POST',body:JSON.stringify(slipwayRoleList)});
// "basic" puts sub and auth_time into access tokens (Keycloak 25+); Slipway keys accounts by sub.
const basicScope=(await api('/client-scopes')).find(scope=>scope.name==='basic');
if(basicScope)await api('/clients/'+client.id+'/default-client-scopes/'+basicScope.id,{method:'PUT'});
const wantedMappers=[
  {name:'Slipway audience',protocol:'openid-connect',protocolMapper:'oidc-audience-mapper',consentRequired:false,config:{'included.client.audience':'slipway','id.token.claim':'false','access.token.claim':'true','introspection.token.claim':'true'}},
  {name:'Slipway roles',protocol:'openid-connect',protocolMapper:'oidc-usermodel-client-role-mapper',consentRequired:false,config:{'usermodel.clientRoleMapping.clientId':'slipway','claim.name':'slipway_roles','jsonType.label':'String',multivalued:'true','id.token.claim':'true','access.token.claim':'true','userinfo.token.claim':'true'}}
];
const presentMappers=await api('/clients/'+client.id+'/protocol-mappers/models');
for(const mapper of wantedMappers){
  const present=presentMappers.find(m=>m.name===mapper.name);
  if(present)await api('/clients/'+client.id+'/protocol-mappers/models/'+present.id,{method:'PUT',body:JSON.stringify({...mapper,id:present.id})});
  else await api('/clients/'+client.id+'/protocol-mappers/models',{method:'POST',body:JSON.stringify(mapper)});
}
// First rollout only: while nobody holds any Slipway role, portal admins become Slipway admins so someone can use it.
// Once any Slipway role is assigned, roles are only ever changed by administrators.
let slipwayAssigned=false;
for(const name of Object.keys(slipwayRoles)){if((await api('/clients/'+slipway.id+'/roles/'+name+'/users?first=0&max=1')).length){slipwayAssigned=true;break}}
let promoted=0;
if(!slipwayAssigned){
  const slipwayAdmin=slipwayRoleList.find(role=>role.name==='admin');
  for(let first=0;;first+=100){
    const admins=await api('/clients/'+client.id+'/roles/admin/users?first='+first+'&max=100');
    for(const user of admins){await api('/users/'+user.id+'/role-mappings/clients/'+slipway.id,{method:'POST',body:JSON.stringify([slipwayAdmin])});promoted++}
    if(admins.length<100)break;
  }
}
console.log('Slipway access configured'+(promoted?'; granted the Slipway admin role to '+promoted+' portal administrator(s).':'.'));
