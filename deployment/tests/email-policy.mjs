// Isolated CI realm only. Seed the old email gate, then verify migration removes it.
const base=process.env.KEYCLOAK_URL||'http://keycloak:8080';
const response=await fetch(base+'/realms/master/protocol/openid-connect/token',{method:'POST',body:new URLSearchParams({grant_type:'password',client_id:'admin-cli',username:process.env.ADMIN_USERNAME,password:process.env.ADMIN_PASSWORD})});
if(!response.ok)throw new Error('Test administrator login failed');
const token=(await response.json()).access_token;
async function api(route,options={}){
 const result=await fetch(base+'/admin/realms/hackspacelabs'+route,{...options,headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'}});
 if(!result.ok)throw new Error('Test API returned '+result.status+' for '+route);
 return result.status===204?undefined:result.json();
}
const [admin]=await api('/users?username=admin&exact=true');
if(!admin)throw new Error('Seed administrator is missing');
const profile=await api('/users/profile');
if(process.argv[2]==='seed'){
 await api('',{method:'PUT',body:JSON.stringify({verifyEmail:true,resetPasswordAllowed:true})});
 await api('/users/'+admin.id,{method:'PUT',body:JSON.stringify({requiredActions:['UPDATE_PASSWORD','VERIFY_EMAIL','UPDATE_PROFILE']})});
 for(const attribute of profile.attributes||[])if(['email','firstName','lastName'].includes(attribute.name))attribute.required={roles:['user','admin']};
 await api('/users/profile',{method:'PUT',body:JSON.stringify(profile)});
 console.log('Seeded legacy email/profile gate in disposable CI realm.');
}else{
 const realm=await api('');
 if(realm.verifyEmail||realm.resetPasswordAllowed)throw new Error('Email dependency remains');
 if(JSON.stringify(admin.requiredActions)!==JSON.stringify(['UPDATE_PASSWORD']))throw new Error('Password-change-only requirement was not preserved');
 if(admin.email)throw new Error('Test admin unexpectedly has email');
 for(const attribute of profile.attributes||[])if(['email','firstName','lastName'].includes(attribute.name)&&attribute.required)throw new Error('Profile field remains mandatory: '+attribute.name);
 for(const action of await api('/authentication/required-actions'))if(['VERIFY_EMAIL','UPDATE_PROFILE','VERIFY_PROFILE'].includes(action.alias)&&(action.enabled||action.defaultAction))throw new Error('Unrequested action remains enabled');
 console.log('Existing email/profile gates removed; admin still requires password change, without an email address.');
 const [android]=await api('/clients?clientId=hackspacelabs-android');
 if(!android?.publicClient||android.directAccessGrantsEnabled||JSON.stringify(android.redirectUris)!=='["com.hackspacelabs.app:/oauth2redirect"]'||android.attributes?.['pkce.code.challenge.method']!=='S256')throw new Error('Android app client is missing or misconfigured');
 if(!(await api('/clients/'+android.id+'/optional-client-scopes')).some(scope=>scope.name==='offline_access'))throw new Error('Android app cannot request offline_access');
 if(!(await api('/clients/'+android.id+'/scope-mappings/realm')).some(role=>role.name==='offline_access'))throw new Error('Android app tokens cannot carry offline_access');
 if(!(await api('/users/'+admin.id+'/role-mappings/realm/composite')).some(role=>role.name==='offline_access'))throw new Error('Seeded admin cannot get offline tokens');
 console.log('Android app public client verified.');
 // HSL Suite apps (PLAN.md 1b, 1c, 1f): every app whose origin is set has its client, roles, mapper and derived secret.
 const {createHmac}=await import('node:crypto');const {existsSync,readFileSync}=await import('node:fs');const {fileURLToPath}=await import('node:url');
 const registry=JSON.parse(readFileSync(['/tools/suite-apps.json',fileURLToPath(new URL('../suite-apps.json',import.meta.url))].find(file=>existsSync(file)),'utf8'));
 const suiteRealm=await api('');
 const policy={rememberMe:true,ssoSessionIdleTimeout:345600,ssoSessionMaxLifespan:345600,ssoSessionIdleTimeoutRememberMe:2592000,ssoSessionMaxLifespanRememberMe:2592000,clientSessionIdleTimeout:0,clientSessionMaxLifespan:0};
 for(const [key,value] of Object.entries(policy))if(suiteRealm[key]!==value)throw new Error('Session policy not applied: '+key);
 if(suiteRealm.attributes?.['hsl.sessionPolicy']!=='1')throw new Error('Session policy marker missing');
 const [web]=await api('/clients?clientId=hackspacelabs-web');const webMappers=await api('/clients/'+web.id+'/protocol-mappers/models');
 let checked=0;
 for(const app of registry){
  const origin=(process.env[app.originEnv]||'').replace(/\/+$/,'');
  const [client]=await api('/clients?clientId='+app.id);
  if(!origin){console.log(app.originEnv+' not set in this run; '+app.id+' not checked.');continue}
  if(!client)throw new Error(app.id+' client is missing');
  const c=await api('/clients/'+client.id);
  if(c.publicClient||!c.standardFlowEnabled||c.directAccessGrantsEnabled||c.implicitFlowEnabled||c.serviceAccountsEnabled||c.fullScopeAllowed||JSON.stringify(c.redirectUris)!==JSON.stringify([origin+app.callbackPath])||c.attributes?.['pkce.code.challenge.method']!=='S256'||c.attributes?.['post.logout.redirect.uris']!==origin+'/signed-out')throw new Error(app.id+' client is misconfigured');
  if((await api('/clients/'+client.id+'/client-secret')).value!==createHmac('sha256',process.env.OIDC_CLIENT_SECRET).update(app.id+'-v1').digest('hex'))throw new Error(app.id+' client secret is not the derived value');
  const roles=(await api('/clients/'+client.id+'/roles')).map(role=>role.name);
  if(Object.keys(app.roles).some(name=>!roles.includes(name)))throw new Error(app.id+' roles are missing');
  const mappers=(await api('/clients/'+client.id+'/protocol-mappers/models')).filter(m=>m.config?.['claim.name']==='hsl_roles');
  if(mappers.length!==1||mappers[0].name!=='HSL app roles'||mappers[0].config['usermodel.clientRoleMapping.clientId']!==app.id||mappers[0].config.multivalued!=='true'||mappers[0].config['id.token.claim']!=='true')throw new Error(app.id+' hsl_roles mapper is missing or wrong');
  const scopes=(await api('/clients/'+client.id+'/default-client-scopes')).map(scope=>scope.name);
  if(['basic','profile','email'].some(name=>!scopes.includes(name)))throw new Error(app.id+' default scopes are missing');
  if(!webMappers.some(m=>m.config?.['claim.name']==='hsl_apps.'+app.id))throw new Error('Portal client has no hsl_apps mapper for '+app.id);
  const scoped=(await api('/clients/'+web.id+'/scope-mappings/clients/'+client.id)).map(role=>role.name);
  if(Object.keys(app.roles).some(name=>!scoped.includes(name)))throw new Error('Portal client is not scoped to '+app.id+' roles');
  if(suiteRealm.attributes?.['hsl.firstGrant.'+app.id]!=='1')throw new Error(app.id+' first-rollout grant did not run');
  if(!(await api('/users/'+admin.id+'/role-mappings/clients/'+client.id+'/composite')).some(role=>role.name==='admin'))throw new Error('Seeded portal admin did not get the '+app.id+' admin role');
  checked++;
 }
 console.log('Suite app clients verified: '+checked+' (client, roles, hsl_roles mapper, derived secret, portal mapping, first-rollout grant) and the 96-hour / 30-day session policy.');
}

// Exercise the actual realm-scoped service account and the routes used by the portal.
if(process.argv[2]==='verify'){
 const {createHmac}=await import('node:crypto');
 const secret=createHmac('sha256',process.env.OIDC_CLIENT_SECRET).update('hackspacelabs-management-v1').digest('hex');
 const serviceResponse=await fetch(base+'/realms/hackspacelabs/protocol/openid-connect/token',{method:'POST',body:new URLSearchParams({grant_type:'client_credentials',client_id:'hackspacelabs-management',client_secret:secret})});
 if(!serviceResponse.ok)throw new Error('Portal management service account cannot authenticate');
 const serviceToken=(await serviceResponse.json()).access_token;
 async function managed(route,method='GET',body){const r=await fetch(base+'/admin/realms/hackspacelabs'+route,{method,headers:{Authorization:'Bearer '+serviceToken,'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});if(!r.ok)throw new Error('Management integration failed '+method+' '+route+' '+r.status);const raw=await r.text();return raw?JSON.parse(raw):null}
 await managed('/users','POST',{username:'portal-integration-user',enabled:true,credentials:[{type:'password',value:'test-password-in-disposable-ci',temporary:true}],requiredActions:['UPDATE_PASSWORD']});
 const [user]=await managed('/users?username=portal-integration-user&exact=true');
 await managed('/groups','POST',{name:'Portal integration group'});
 const [group]=await managed('/groups?search=Portal%20integration%20group');
 await managed('/users/'+user.id+'/groups/'+group.id,'PUT');
 const [portalClient]=await managed('/clients?clientId=hackspacelabs-web');
 const customer=await managed('/clients/'+portalClient.id+'/roles/customer');
 await managed('/groups/'+group.id+'/role-mappings/clients/'+portalClient.id,'POST',[customer]);
 if(!(await managed('/users/'+user.id+'/role-mappings/clients/'+portalClient.id+'/composite')).some(r=>r.name==='customer'))throw new Error('Group roles did not propagate');
 await managed('/users/'+user.id+'/reset-password','PUT',{type:'password',value:'replacement-disposable-password',temporary:true});
 await managed('/clients','POST',{clientId:'portal-integration-app',protocol:'openid-connect',publicClient:false,standardFlowEnabled:true,redirectUris:['https://app.example/callback'],attributes:{'pkce.code.challenge.method':'S256'}});
 const [client]=await managed('/clients?clientId=portal-integration-app');
 if(!(await managed('/clients/'+client.id+'/client-secret')).value)throw new Error('Client secret missing');
 await managed('','PUT',{passwordPolicy:''});
 if((await managed('')).passwordPolicy)throw new Error('Password policy could not be cleared');
 await managed('/clients/'+client.id,'DELETE');await managed('/users/'+user.id,'DELETE');await managed('/groups/'+group.id,'DELETE');
 console.log('Real management service account: users, passwords, groups, inherited roles, OIDC clients, secrets and settings verified.');
}
