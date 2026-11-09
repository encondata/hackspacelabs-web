import express from 'express';
import {createHmac} from 'node:crypto';
import {equalSecret} from './security.mjs';
export const managementSecret=secret=>createHmac('sha256',secret).update('hackspacelabs-management-v1').digest('hex');
export function createManagement(config,{base='http://keycloak:8080',fetcher=fetch}={}){
 let token,expiry=0;
 return async function api(route,method='GET',body){
  if(!token||Date.now()>=expiry){
   const response=await fetcher(base+'/realms/hackspacelabs/protocol/openid-connect/token',{method:'POST',body:new URLSearchParams({grant_type:'client_credentials',client_id:'hackspacelabs-management',client_secret:managementSecret(config.clientSecret)}),signal:AbortSignal.timeout(10000)});
   if(!response.ok)throw new Error('Management authentication unavailable');
   const data=await response.json();token=data.access_token;expiry=Date.now()+Math.max(0,data.expires_in-20)*1000;
  }
  const response=await fetcher(base+'/admin/realms/hackspacelabs'+route,{method,headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body),signal:AbortSignal.timeout(10000)});
  if(response.status===401){token=null;expiry=0}
  if(!response.ok){const error=new Error('Identity service request failed');error.status=[400,404,409].includes(response.status)?response.status:503;throw error}
  const text=await response.text();return text?JSON.parse(text):null;
 };
}
const fail=message=>{const error=new Error(message);error.status=400;throw error};
const text=(v,name,required=false)=>{if(typeof v!=='string'||v.length>4096||(required&&!v.trim()))fail('Invalid '+name);return v.trim()};
const segment=v=>{if(typeof v!=='string'||!v||/[\s/\\?#%]/.test(v)||v==='.'||v==='..')fail('Invalid identifier');return encodeURIComponent(v)};
const names=v=>{if(!Array.isArray(v)||v.length>100||v.some(x=>typeof x!=='string'||!x||x.length>255))fail('Invalid list');return [...new Set(v)]};
const bool=v=>{if(typeof v!=='boolean')fail('Expected true or false');return v};
const userView=u=>({id:u.id,username:u.username,firstName:u.firstName||'',lastName:u.lastName||'',email:u.email||'',enabled:u.enabled,requiredActions:u.requiredActions||[]});
const protectedClients=new Set(['hackspacelabs-web','hackspacelabs-management','account','account-console','admin-cli','broker','realm-management','security-admin-console']);
export const settingFields=['displayName','passwordPolicy','registrationAllowed','rememberMe','bruteForceProtected','accessTokenLifespan','ssoSessionIdleTimeout','ssoSessionMaxLifespan'];
export function managementRouter({api,userFor,config,log=console}){
 const router=express.Router();
 let portalClientId;
 async function portalClient(){if(!portalClientId){const clients=await api('/clients?clientId=hackspacelabs-web');if(clients.length!==1)throw new Error('Portal client unavailable');portalClientId=segment(clients[0].id)}return portalClientId}
 async function rolePath(){return '/role-mappings/clients/'+await portalClient()}

 router.use(async(req,res,next)=>{
  const user=await userFor(req,res);if(!user)return res.status(401).json({error:'Please sign in again.'});
  if(!user.roles.includes('admin'))return res.status(403).json({error:'Administrator access required.'});
  if(!['GET','HEAD'].includes(req.method)&&(req.get('origin')!==config.origin||!equalSecret(req.get('x-csrf-token'),req.session.csrf)))return res.status(403).json({error:'Invalid request. Reload and try again.'});
  // Check live effective roles, including groups, so a demoted admin cannot keep managing users.
  const record=await api('/users/'+segment(user.id));
  const roles=await api('/users/'+segment(user.id)+await rolePath()+'/composite');
  if(!record.enabled||!roles.some(r=>r.name==='admin'))return res.status(403).json({error:'Administrator access has been removed.'});
  req.actor=user;next();
 });
 async function page(route,query){const first=Math.max(0,Number(query.first)||0);return api(route+(route.includes('?')?'&':'?')+'first='+first+'&max=50')}
 function removeOwnAdminRisk(req,wanted){return !wanted.some(r=>r.name==='admin')}
 async function roleObjects(list){return Promise.all(names(list).map(name=>portalClient().then(id=>api('/clients/'+id+'/roles/'+segment(name)))))}
 async function editableClient(id){const client=await api('/clients/'+segment(id));if(protectedClients.has(client.clientId))fail('This internal client is managed by the installer.');return client}
 router.use('/users/:id',async(req,res,next)=>{if(req.method!=='GET'){const target=await api('/users/'+segment(req.params.id));if(target.serviceAccountClientId)return res.status(400).json({error:'Service accounts are managed through their connected app.'})}next()});
 const audit=(req,action)=>log.info?.('Identity administration',{actor:req.actor.id,action,target:req.params.id||req.params.name||'realm'});
 router.get('/users',async(req,res)=>{const search=typeof req.query.search==='string'?req.query.search.slice(0,200):'';res.json((await page('/users?search='+encodeURIComponent(search),req.query)).filter(u=>!u.serviceAccountClientId).map(userView))});
 router.post('/users',async(req,res)=>{const username=text(req.body.username,'username',true);const password=req.body.password;if(typeof password!=='string'||!password||password.length>4096)fail('Enter a password.');await api('/users','POST',{username,enabled:true,credentials:[{type:'password',value:password,temporary:true}],requiredActions:['UPDATE_PASSWORD']});audit(req,'create user');res.status(201).json({ok:true})});
 router.get('/users/:id',async(req,res)=>{const p='/users/'+segment(req.params.id);const [user,groups,roles,sessions]=await Promise.all([api(p),api(p+'/groups?max=100'),api(p+await rolePath()),api(p+'/sessions')]);res.json({...userView(user),groups,roles,sessions})});
 router.put('/users/:id',async(req,res)=>{const data={firstName:text(req.body.firstName,'first name'),lastName:text(req.body.lastName,'last name'),email:text(req.body.email,'email'),enabled:bool(req.body.enabled)};if(req.params.id===req.actor.id&&!data.enabled)fail('You cannot disable your own account.');await api('/users/'+segment(req.params.id),'PUT',data);if(!data.enabled)await api('/users/'+segment(req.params.id)+'/logout','POST');audit(req,'update user');res.json({ok:true})});
 router.post('/users/:id/password',async(req,res)=>{const password=req.body.password;if(typeof password!=='string'||!password||password.length>4096)fail('Enter a password.');await api('/users/'+segment(req.params.id)+'/reset-password','PUT',{type:'password',value:password,temporary:true});await api('/users/'+segment(req.params.id)+'/logout','POST');audit(req,'reset password');res.json({ok:true})});
 router.post('/users/:id/logout',async(req,res)=>{await api('/users/'+segment(req.params.id)+'/logout','POST');audit(req,'revoke user sessions');res.json({ok:true})});
 for(const kind of ['users','groups']){
  router.put('/'+kind+'/:id/roles',async(req,res)=>{
   const path='/'+kind+'/'+segment(req.params.id)+await rolePath();const wanted=await roleObjects(req.body.roles);const current=await api(path);
   if(kind==='groups'&&removeOwnAdminRisk(req,wanted)){const ownGroups=await api('/users/'+segment(req.actor.id)+'/groups?max=1000');if(ownGroups.some(g=>g.id===req.params.id))fail('Use another administrator to remove admin access from your own group.');}
   if(kind==='users'&&req.params.id===req.actor.id&&!wanted.some(r=>r.name==='admin'))fail('You cannot remove your own direct admin role.');
   const add=wanted.filter(r=>!current.some(c=>c.id===r.id));const remove=current.filter(r=>!wanted.some(c=>c.id===r.id));
   if(add.length)await api(path,'POST',add);if(remove.length)await api(path,'DELETE',remove);audit(req,'update '+kind+' roles');res.json({ok:true});
  });
 }
 router.put('/users/:id/groups/:group',async(req,res)=>{await api('/users/'+segment(req.params.id)+'/groups/'+segment(req.params.group),'PUT');audit(req,'join group');res.json({ok:true})});
 router.delete('/users/:id/groups/:group',async(req,res)=>{if(req.params.id===req.actor.id)fail('Use another administrator to change your own group membership.');await api('/users/'+segment(req.params.id)+'/groups/'+segment(req.params.group),'DELETE');audit(req,'leave group');res.json({ok:true})});
 router.get('/groups',async(req,res)=>res.json(await page('/groups?search='+encodeURIComponent(String(req.query.search||'')),req.query)));
 router.post('/groups',async(req,res)=>{await api('/groups','POST',{name:text(req.body.name,'group name',true)});audit(req,'create group');res.status(201).json({ok:true})});
 router.get('/groups/:id',async(req,res)=>{const p='/groups/'+segment(req.params.id);const [group,members,roles]=await Promise.all([api(p),page(p+'/members',req.query),api(p+await rolePath())]);res.json({...group,members:members.map(userView),roles})});
 router.put('/groups/:id',async(req,res)=>{await api('/groups/'+segment(req.params.id),'PUT',{name:text(req.body.name,'group name',true)});audit(req,'rename group');res.json({ok:true})});
 router.get('/roles',async(_req,res)=>res.json(await api('/clients/'+await portalClient()+'/roles')));
 router.post('/roles',async(req,res)=>{await api('/clients/'+await portalClient()+'/roles','POST',{name:text(req.body.name,'role name',true),description:text(req.body.description||'','description')});audit(req,'create role');res.status(201).json({ok:true})});
 router.get('/clients',async(req,res)=>res.json((await page('/clients',req.query)).map(c=>({id:c.id,clientId:c.clientId,name:c.name,enabled:c.enabled,internal:protectedClients.has(c.clientId)}))));
 router.get('/clients/:id',async(req,res)=>{const c=await api('/clients/'+segment(req.params.id));const {secret,registrationAccessToken,...safe}=c;res.json({...safe,internal:protectedClients.has(c.clientId)})});
 function clientData(body){
  const uris=names(body.redirectUris||[]);const origins=names(body.webOrigins||[]);
  for(const uri of [...uris,...origins]){let url;try{url=new URL(uri)}catch{fail('Use complete callback and origin URLs.')}if(!['http:','https:'].includes(url.protocol)||url.username||url.password||url.hash||uri.includes('*'))fail('Use exact HTTP or HTTPS URLs without wildcards.');if(origins.includes(uri)&&url.origin!==uri)fail('Web origins must contain only scheme, hostname, and port.');}
  const clientId=text(body.clientId,'client ID',true);if(protectedClients.has(clientId))fail('This client ID is reserved.');
  return {clientId,name:text(body.name||'','name'),protocol:'openid-connect',enabled:bool(body.enabled),publicClient:bool(body.publicClient),standardFlowEnabled:true,implicitFlowEnabled:false,directAccessGrantsEnabled:false,serviceAccountsEnabled:false,redirectUris:uris,webOrigins:origins,attributes:{'pkce.code.challenge.method':'S256'}};
 }
 router.post('/clients',async(req,res)=>{await api('/clients','POST',clientData(req.body));audit(req,'create client');res.status(201).json({ok:true})});
 router.put('/clients/:id',async(req,res)=>{const old=await editableClient(req.params.id);const data=clientData(req.body);await api('/clients/'+segment(req.params.id),'PUT',{...data,attributes:{...old.attributes,...data.attributes}});audit(req,'update client');res.json({ok:true})});
 router.post('/clients/:id/secret',async(req,res)=>{const client=await editableClient(req.params.id);if(client.publicClient)fail('Public clients do not have secrets.');const secret=await api('/clients/'+segment(req.params.id)+'/client-secret',req.body.rotate===true?'POST':'GET');audit(req,req.body.rotate?'rotate client secret':'reveal client secret');res.json({value:secret.value})});
 router.get('/settings',async(_req,res)=>{const realm=await api('');res.json({...Object.fromEntries(settingFields.map(k=>[k,realm[k]??(k==='passwordPolicy'?'':'')])),issuer:config.issuer,discovery:config.issuer+'/.well-known/openid-configuration'})});
 router.put('/settings',async(req,res)=>{const data={};for(const key of settingFields){if(!(key in req.body))continue;const value=req.body[key];if(['displayName','passwordPolicy'].includes(key))data[key]=text(value,key);else if(key.endsWith('Lifespan')||key.endsWith('Timeout')){if(!Number.isSafeInteger(value)||value<1||value>31536000)fail('Session and token durations must be positive seconds.');data[key]=value}else data[key]=bool(value)}await api('','PUT',data);audit(req,'update authentication settings');res.json({ok:true})});
 router.use((error,_req,res,_next)=>{const status=error.status||503;res.status(status).json({error:status===400?(error.message==='Identity service request failed'?'The identity service rejected these values. Check the fields and password policy.':error.message):status===409?'That name or identifier already exists.':status===404?'This record no longer exists.':'Identity management is unavailable. Try again after the identity service is ready.'})});
 return router;
}
