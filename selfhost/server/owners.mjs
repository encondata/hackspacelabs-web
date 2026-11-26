import express from 'express';
import {rateLimit} from 'express-rate-limit';
import {equalSecret} from './security.mjs';
import {appClientSecret} from './suite-apps.mjs';

// Owner check for personal API tokens (PLAN.md D18, item 1i), generalised from PR #1's slipway-owners.mjs.
//
// Slipway and Harbor Master accept personal API tokens without any Keycloak session. For a token whose owner signs in
// through HackSpaceLabs they ask here, at most every few minutes, whether that person is still enabled and which of
// the app's roles they hold (effective roles, so groups count). Apps have no Keycloak admin access of their own: reading
// another user's roles through the admin API would also expose every client's secret. The gateway already holds the
// realm management service account, so it answers this one narrow question and nothing more.
//
//   GET /internal/apps/<app id>/owners/<Keycloak user id>
//   Authorization: Bearer <that app's client secret, the HSL_OIDC_CLIENT_SECRET app-env.mjs wrote>
//   200 {"enabled": true, "roles": ["editor"]}    roles: the app's roles held, highest first; [] means no access
//   200 {"enabled": false, "roles": []}           also for an unknown or deleted account and for service accounts
//   400 for a malformed user id; 503 when Keycloak cannot answer (callers then keep their last answer, the outage rule)
//
// Callers must reach the gateway directly (for example http://<server>:8088), never through the public proxy:
// requests carrying forwarding headers are refused. Wrong secrets, unknown apps and proxied requests all get the
// same plain 404, so the route is not advertised.
const SUBJECT=/^[A-Za-z0-9-]{1,64}$/;
const FORWARDED=['x-forwarded-for','forwarded','x-real-ip','x-forwarded-host'];
export function ownersRouter({api,clientSecret,suiteApps,log=console}){
 const router=express.Router();const clientIds={};
 router.use(rateLimit({windowMs:60*1000,limit:600,standardHeaders:'draft-8',legacyHeaders:false,message:{error:'Too many requests.'}}));
 async function clientUuid(id){if(!clientIds[id]){const clients=await api('/clients?clientId='+encodeURIComponent(id));if(clients.length!==1)return null;clientIds[id]=encodeURIComponent(clients[0].id)}return clientIds[id]}
 router.get('/:app/owners/:sub',async(req,res)=>{
  const app=suiteApps.find(entry=>entry.id===req.params.app);const auth=req.get('authorization')||'';
  if(!app||FORWARDED.some(name=>req.get(name)!==undefined)||!auth.startsWith('Bearer ')||!equalSecret(auth.slice(7),appClientSecret(clientSecret,app.id)))return res.status(404).send('Page not found');
  res.set('Cache-Control','no-store');
  if(!SUBJECT.test(req.params.sub))return res.status(400).json({error:'Invalid user id'});
  const path='/users/'+encodeURIComponent(req.params.sub);
  try{
   let user;try{user=await api(path)}catch(error){if(error.status===404)return res.json({enabled:false,roles:[]});throw error}
   if(!user||user.serviceAccountClientId)return res.json({enabled:false,roles:[]});
   const id=await clientUuid(app.id);
   const held=id?(await api(path+'/role-mappings/clients/'+id+'/composite')).map(role=>role.name):[];
   res.json({enabled:user.enabled===true,roles:Object.keys(app.roles).filter(name=>held.includes(name))});
  }catch(error){
   log.error('Owner check failed',{app:app.id,kind:error?.name||'Error'});
   res.status(503).json({error:'Identity service unavailable'});
  }
 });
 router.use((_req,res)=>res.status(404).send('Page not found'));
 return router;
}
