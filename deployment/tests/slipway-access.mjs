// CI only: check the Keycloak configuration Slipway relies on, against the real Keycloak of a disposable stack.
// Runs in the configure-auth container (bootstrap admin and Slipway client secret in its environment).
import assert from 'node:assert/strict';
const base='http://keycloak:8080';
async function token(realm,form){
  const response=await fetch(base+'/realms/'+realm+'/protocol/openid-connect/token',{method:'POST',body:new URLSearchParams(form),signal:AbortSignal.timeout(10000)});
  assert.equal(response.status,200,'token request for '+(form.client_id||'?')+' failed');
  return (await response.json()).access_token;
}
async function get(path,bearer){
  const response=await fetch(base+'/admin/realms/hackspacelabs'+path,{headers:{Authorization:'Bearer '+bearer},signal:AbortSignal.timeout(10000)});
  assert.equal(response.status,200,'GET '+path.split('?')[0]+' returned '+response.status);
  return response.json();
}
const admin=await token('master',{grant_type:'password',client_id:'admin-cli',username:process.env.ADMIN_USERNAME,password:process.env.ADMIN_PASSWORD});
const [web]=await get('/clients?clientId=hackspacelabs-web',admin);
const [user]=await get('/users?username=admin&exact=true',admin);
assert.ok(web&&user,'website client and seeded admin exist');

// What the gateway receives (ID token) and forwards to Slipway (access token) for the seeded administrator.
const example=kind=>get(`/clients/${web.id}/evaluate-scopes/generate-example-${kind}?scope=openid&userId=${user.id}`,admin);
const access=await example('access-token');
assert.ok([].concat(access.aud).includes('slipway'),'access token audience includes slipway');
assert.equal(access.azp,'hackspacelabs-web');
assert.equal(access.typ,'Bearer');
assert.equal(access.sub,user.id,'access token carries sub');
assert.ok(access.slipway_roles?.includes('admin'),'access token carries slipway_roles');
const id=await example('id-token');
assert.ok(id.hsl_roles?.includes('admin'),'ID token carries hsl_roles');
assert.ok(id.slipway_roles?.includes('admin'),'ID token carries slipway_roles');
assert.ok(![].concat(id.aud).includes('slipway'),'ID token is not addressed to Slipway');

// Slipway's service account: client credentials work, the lookups Slipway makes are allowed, writes are not.
const service=await token('hackspacelabs',{grant_type:'client_credentials',client_id:'slipway',client_secret:process.env.SLIPWAY_OIDC_CLIENT_SECRET});
const [slipway]=await get('/clients?clientId=slipway',service);
assert.equal((await get('/users/'+user.id,service)).enabled,true);
const roles=await get(`/users/${user.id}/role-mappings/clients/${slipway.id}/composite`,service);
assert.ok(roles.some(r=>r.name==='admin'),'service account sees effective Slipway roles');
const write=await fetch(base+'/admin/realms/hackspacelabs/users/'+user.id,{method:'PUT',headers:{Authorization:'Bearer '+service,'Content-Type':'application/json'},body:JSON.stringify({enabled:false})});
assert.equal(write.status,403,'Slipway service account is read-only');
console.log('Keycloak issues the tokens Slipway expects, and Slipway\'s service account is read-only.');
