// Disposable CI realm only (PLAN.md 1h). Signs a test user in to the suite apps' clients through the real Keycloak
// login form and checks what the apps rely on: hsl_roles in the ID token, refresh_expires_in from the session policy,
// roles through nested groups plus individual grants with removals showing on refresh (D17, appendix B row 19), and
// the portal's hsl_apps claim. Runs in the configure-auth container (bootstrap admin and OIDC_CLIENT_SECRET in its
// environment); everything it creates is removed again. Never prints secrets or tokens.
// KEYCLOAK_URL and SUITE_APPS_FILE are only for running it against a disposable Keycloak outside the compose network.
// APP_ENV_FILE (optional): an app .env written by scripts/app-env.mjs; its client id and secret are used for the first
// sign-in, which shows the settings it wrote work.
import assert from 'node:assert/strict';
import {createHash,createHmac,randomBytes} from 'node:crypto';
import {existsSync,readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
const base=process.env.KEYCLOAK_URL||'http://keycloak:8080';const realmPath='/realms/hackspacelabs';
const registryFile=[process.env.SUITE_APPS_FILE,'/tools/suite-apps.json',fileURLToPath(new URL('../suite-apps.json',import.meta.url))].find(file=>file&&existsSync(file));
const apps=JSON.parse(readFileSync(registryFile,'utf8'));
const secretOf=id=>createHmac('sha256',process.env.OIDC_CLIENT_SECRET).update(id+'-v1').digest('hex');
const adminToken=await (await fetch(base+'/realms/master/protocol/openid-connect/token',{method:'POST',body:new URLSearchParams({grant_type:'password',client_id:'admin-cli',username:process.env.ADMIN_USERNAME,password:process.env.ADMIN_PASSWORD})})).json();
async function api(route,method='GET',body){
  const response=await fetch(base+'/admin'+realmPath+route,{method,headers:{Authorization:'Bearer '+adminToken.access_token,'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});
  if(!response.ok)throw new Error('Admin API '+method+' '+route.split('?')[0]+' returned '+response.status);
  const text=await response.text();return text?JSON.parse(text):null;
}
const claims=jwt=>JSON.parse(Buffer.from(jwt.split('.')[1],'base64url').toString('utf8'));
const local=url=>{const u=new URL(url);const b=new URL(base);u.protocol=b.protocol;u.host=b.host;return u.href};
// Authorization code + PKCE through the login form, as a browser would. Keycloak's pages name its public hostname;
// requests go to KEYCLOAK_URL instead, which a fixed KC_HOSTNAME allows (appendix B rows 9 and 17).
async function signIn(clientId,secret,redirect,username,password,{remember=false}={}){
  const jar=new Map();const cookies=()=>[...jar].map(([k,v])=>k+'='+v).join('; ');
  const keep=response=>{for(const line of response.headers.getSetCookie()){const [pair]=line.split(';');const at=pair.indexOf('=');jar.set(pair.slice(0,at),pair.slice(at+1))}return response};
  const verifier=randomBytes(48).toString('base64url');const state=randomBytes(16).toString('hex');
  const query=new URLSearchParams({client_id:clientId,redirect_uri:redirect,response_type:'code',scope:'openid profile email',state,nonce:randomBytes(16).toString('hex'),code_challenge:createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256'});
  const page=keep(await fetch(base+realmPath+'/protocol/openid-connect/auth?'+query,{redirect:'manual'}));
  assert.equal(page.status,200,clientId+': login page');const html=await page.text();
  const action=/<form[^>]+action="([^"]+)"/.exec(html)?.[1]?.replaceAll('&amp;','&');assert.ok(action,clientId+': login form');
  const form=new URLSearchParams({username,password,credentialId:''});if(remember)form.set('rememberMe','on');
  const posted=keep(await fetch(local(action),{method:'POST',body:form,headers:{Cookie:cookies()},redirect:'manual'}));
  assert.equal(posted.status,302,clientId+': sign-in redirect');const back=new URL(posted.headers.get('location'));
  assert.equal(back.origin+back.pathname,redirect,clientId+': returns to its one callback');assert.equal(back.searchParams.get('state'),state);
  const response=await fetch(base+realmPath+'/protocol/openid-connect/token',{method:'POST',body:new URLSearchParams({grant_type:'authorization_code',code:back.searchParams.get('code'),redirect_uri:redirect,client_id:clientId,client_secret:secret,code_verifier:verifier})});
  assert.equal(response.status,200,clientId+': code exchange with the derived secret');return response.json();
}
async function refresh(clientId,tokens){
  const response=await fetch(base+realmPath+'/protocol/openid-connect/token',{method:'POST',body:new URLSearchParams({grant_type:'refresh_token',refresh_token:tokens.refresh_token,client_id:clientId,client_secret:secretOf(clientId)})});
  assert.equal(response.status,200,clientId+': refresh');return response.json();
}
const rolesIn=tokens=>{const c=claims(tokens.id_token);return c.hsl_roles===undefined?null:[...c.hsl_roles].sort()};
const clientOf=async id=>{const [client]=await api('/clients?clientId='+id);assert.ok(client,id+' client exists');return client};
const app=id=>{const entry=apps.find(a=>a.id===id);assert.ok(entry,id+' in registry');return entry};
const switchyard=await clientOf('switchyard'),tideline=await clientOf('tideline');
const redirectOf=async (id,client)=>{const full=await api('/clients/'+client.id);return full.redirectUris[0]};
const [syRedirect,tlRedirect]=[await redirectOf('switchyard',switchyard),await redirectOf('tideline',tideline)];
assert.equal(new URL(syRedirect).pathname,app('switchyard').callbackPath);
const role=async (client,name)=>api('/clients/'+client.id+'/roles/'+name);
const username='ci-suite-'+randomBytes(4).toString('hex');const password=randomBytes(24).toString('base64url');
await api('/users','POST',{username,enabled:true,firstName:'Suite',lastName:'Test',email:username+'@example.invalid',emailVerified:false,credentials:[{type:'password',value:password,temporary:false}]});
const [user]=await api('/users?username='+username+'&exact=true');const created=[];
try{
  // 1. One app client, one direct role: hsl_roles and the 96-hour / 30-day session lengths.
  await api('/users/'+user.id+'/role-mappings/clients/'+tideline.id,'POST',[await role(tideline,'viewer')]);
  let first={id:'tideline',secret:secretOf('tideline')};
  if(process.env.APP_ENV_FILE){
    const env=Object.fromEntries(readFileSync(process.env.APP_ENV_FILE,'utf8').split('\n').filter(line=>line.includes('=')).map(line=>[line.slice(0,line.indexOf('=')),line.slice(line.indexOf('=')+1)]));
    assert.equal(env.HSL_OIDC_CLIENT_ID,'tideline','APP_ENV_FILE is a Tideline .env');assert.equal(env.HSL_OIDC_ISSUER,claims((await signIn('tideline',secretOf('tideline'),tlRedirect,username,password)).id_token).iss);
    first={id:env.HSL_OIDC_CLIENT_ID,secret:env.HSL_OIDC_CLIENT_SECRET};console.log('Using the client id and secret app-env.mjs wrote.');
  }
  const plain=await signIn(first.id,first.secret,tlRedirect,username,password);
  assert.deepEqual(rolesIn(plain),['viewer']);assert.equal(plain.refresh_expires_in,345600,'96 hours without Remember me');
  const idToken=claims(plain.id_token);assert.equal(idToken.aud,'tideline');assert.ok(idToken.sid&&idToken.sub===user.id);
  const remembered=await signIn('tideline',secretOf('tideline'),tlRedirect,username,password,{remember:true});
  assert.equal(remembered.refresh_expires_in,2592000,'30 days with Remember me');
  console.log('Signed in to tideline: hsl_roles ["viewer"], refresh_expires_in 345600 (2592000 with Remember me).');
  // 2. A user with no role for an app gets no hsl_roles claim at all (appendix B row 4).
  assert.equal(rolesIn(await signIn('switchyard',secretOf('switchyard'),syRedirect,username,password)),null);
  await api('/users/'+user.id+'/role-mappings/clients/'+tideline.id,'DELETE',[await role(tideline,'viewer')]);
  // 3. D17: Staff > Infrastructure > On-call, roles on each level, the user only in On-call.
  const group=async (name,parent)=>{await api(parent?'/groups/'+parent.id+'/children':'/groups','POST',{name});const list=parent?await api('/groups/'+parent.id+'/children?max=100'):await api('/groups?search='+encodeURIComponent(name)+'&exact=true');const found=list.find(g=>g.name===name);created.push(found);return found};
  const staff=await group('ci-Staff-'+username),infra=await group('Infrastructure',staff),oncall=await group('On-call',infra);
  await api('/groups/'+staff.id+'/role-mappings/clients/'+tideline.id,'POST',[await role(tideline,'viewer')]);
  await api('/groups/'+infra.id+'/role-mappings/clients/'+switchyard.id,'POST',[await role(switchyard,'editor')]);
  await api('/groups/'+oncall.id+'/role-mappings/clients/'+tideline.id,'POST',[await role(tideline,'editor')]);
  await api('/users/'+user.id+'/groups/'+oncall.id,'PUT');
  let sy=await signIn('switchyard',secretOf('switchyard'),syRedirect,username,password);let tl=await signIn('tideline',secretOf('tideline'),tlRedirect,username,password);
  assert.deepEqual(rolesIn(sy),['editor'],'role from the parent group');assert.deepEqual(rolesIn(tl),['editor','viewer'],'roles from the group and the top group');
  await api('/users/'+user.id+'/role-mappings/clients/'+switchyard.id,'POST',[await role(switchyard,'admin')]);
  sy=await refresh('switchyard',sy);assert.deepEqual(rolesIn(sy),['admin','editor'],'an individual grant adds on refresh');
  await api('/users/'+user.id+'/groups/'+oncall.id,'DELETE');
  sy=await refresh('switchyard',sy);tl=await refresh('tideline',tl);
  assert.deepEqual(rolesIn(sy),['admin'],'leaving the group shows on refresh');assert.equal(rolesIn(tl),null,'no Tideline role left: no claim');
  console.log('Nested groups: On-call member got switchyard ["editor"] and tideline ["editor","viewer"]; an individual grant added admin; leaving the group left switchyard ["admin"] and no tideline claim.');
  // 4. The portal sees which apps someone may use, even with no portal role (PLAN.md 1f).
  const [web]=await api('/clients?clientId=hackspacelabs-web');const webClient=await api('/clients/'+web.id);
  const portal=await signIn('hackspacelabs-web',process.env.OIDC_CLIENT_SECRET,webClient.redirectUris[0],username,password);
  const portalClaims=claims(portal.id_token);
  assert.deepEqual(portalClaims.hsl_apps,{switchyard:['admin']});assert.equal(portalClaims.hsl_roles,undefined);
  console.log('Portal ID token carries hsl_apps {"switchyard":["admin"]} for a person with no portal role.');
}finally{
  for(const g of created.slice(0,1))await api('/groups/'+g.id,'DELETE').catch(()=>{});
  await api('/users/'+user.id,'DELETE').catch(()=>{});
}
console.log('Suite sign-in, session lengths, roles and nested groups verified against the real Keycloak.');
