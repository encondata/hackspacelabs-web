import express from 'express';
import {equalSecret} from './security.mjs';

// Internal endpoint for Slipway: is the owner of a Slipway API token still allowed in, and with which roles?
//
// Slipway has no Keycloak admin access of its own: reading another user's client roles through the admin API needs
// view-clients, which would also expose every client's secret. The gateway already holds the realm management
// service account, so it answers this one narrow question. Callers must present SLIPWAY_INTERNAL_SECRET; requests that
// arrived through the public reverse proxy (X-Forwarded-For / Forwarded) are refused outright. Unknown or refused
// requests get a plain 404, so the route is not advertised.
const SLIPWAY_ROLES=new Set(['admin','maintainer','developer','viewer']);
const SUBJECT=/^[A-Za-z0-9-]{1,64}$/;
export function slipwayOwnersRouter({api,secret,log=console}){
 const router=express.Router();
 let clientId;
 async function slipwayClient(){
  if(!clientId){const clients=await api('/clients?clientId=slipway');if(clients.length!==1)throw new Error('Slipway client unavailable');clientId=encodeURIComponent(clients[0].id)}
  return clientId;
 }
 router.get('/:sub',async(req,res)=>{
  const auth=req.get('authorization')||'';
  if(req.get('x-forwarded-for')||req.get('forwarded')||!auth.startsWith('Bearer ')||!equalSecret(auth.slice(7),secret))return res.status(404).send('Page not found');
  if(!SUBJECT.test(req.params.sub))return res.status(400).json({error:'Invalid subject'});
  res.set('cache-control','no-store');
  const path='/users/'+encodeURIComponent(req.params.sub);
  try{
   let user;
   try{user=await api(path)}catch(error){if(error.status===404)return res.json({exists:false});throw error}
   if(!user||user.serviceAccountClientId)return res.json({exists:false});
   // Effective roles, so roles granted through groups or composite roles count too.
   const roles=await api(path+'/role-mappings/clients/'+await slipwayClient()+'/composite');
   res.json({exists:true,enabled:user.enabled===true,username:user.username||null,email:user.email||null,firstName:user.firstName||'',lastName:user.lastName||'',roles:[...new Set(roles.map(r=>r.name).filter(n=>SLIPWAY_ROLES.has(n)))].sort()});
  }catch(error){
   log.error('Slipway owner lookup failed',{kind:error?.name||'Error'});
   res.status(503).json({error:'Identity service unavailable'});
  }
 });
 return router;
}
