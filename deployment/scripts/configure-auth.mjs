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
  return response.status===204?undefined:response.json();
}
const clients=await api('/clients?clientId=hackspacelabs-web');
if(clients.length!==1)throw new Error('Expected one HackSpaceLabs website client');
const client=clients[0];
await api('/clients/'+encodeURIComponent(client.id),{method:'PUT',body:JSON.stringify({rootUrl:app,baseUrl:app+'/',redirectUris:[app+'/api/auth/callback'],webOrigins:[app],attributes:{...client.attributes,'post.logout.redirect.uris':app+'/login'}})});
const realm=await api('');
await api('',{method:'PUT',body:JSON.stringify({attributes:{...realm.attributes,frontendUrl:auth}})});
const updated=await api('/clients/'+encodeURIComponent(client.id));
if(updated.redirectUris?.[0]!==app+'/api/auth/callback'||updated.webOrigins?.[0]!==app)throw new Error('Keycloak client URL verification failed');
console.log('Updated existing Keycloak client URLs. Users, passwords, and roles were preserved.');
