import express from 'express';
import {equalSecret} from './security.mjs';

// Reverse proxy for the Slipway deployment API: /api/slipway/<path> -> <SLIPWAY_URL>/api/v1/<path>.
//
// Signed-in portal users: the gateway checks the session (refreshing it as usual), requires a Slipway role, and
// enforces Origin + CSRF on writes exactly like /api/me. It then sends the user's Keycloak access token, which
// Slipway verifies itself; Slipway never relies on the gateway's word about who is calling.
//
// Scripts and CI: requests that carry "Authorization: Bearer slipway_pat_..." are forwarded with that header only.
// They use no cookie or session (so no CSRF exposure), and Slipway checks the token owner's status in Keycloak.
// Any other Authorization header is refused: Keycloak tokens are only ever attached by the gateway.
const METHODS=new Set(['GET','HEAD','POST','PUT','PATCH','DELETE']);
const API_TOKEN=/^Bearer slipway_pat_[A-Za-z0-9_-]{20,100}$/;
const REQUEST_HEADERS=['accept','content-type'];
const RESPONSE_HEADERS=['content-type','retry-after'];
export function slipwayRouter({target,userFor,accessToken,config,log=console,fetchImpl=fetch,timeoutMs=120000,bodyLimit='1mb'}){
 const router=express.Router();
 router.use(express.raw({type:()=>true,limit:bodyLimit}));
 router.use(async(req,res)=>{
  if(!METHODS.has(req.method))return res.status(405).json({error:'Method not allowed'});
  let authorization=req.get('authorization');
  if(authorization!==undefined){
   if(!API_TOKEN.test(authorization))return res.status(401).json({error:'Use a Slipway API token, or sign in to the portal.'});
  }else{
   const user=await userFor(req,res);
   if(!user){
    // GitHub sends the browser back here after linking; a lapsed session should land on the sign-in page.
    if(req.method==='GET'&&req.accepts(['json','html'])==='html')return res.redirect(303,'/login?returnTo=%2Fportal');
    return res.status(401).json({error:'Please sign in again.'});
   }
   if(!user.apps?.slipway?.length)return res.status(403).json({error:'Your account has no Slipway role. Ask an administrator for access.'});
   if(req.method!=='GET'&&req.method!=='HEAD'&&(req.get('origin')!==config.origin||!equalSecret(req.get('x-csrf-token'),req.session.csrf)))return res.status(403).json({error:'Reload the page and try again.'});
   const token=accessToken(req);
   if(!token)return res.status(401).json({error:'Please sign in again.'});
   authorization='Bearer '+token;
  }
  const upstream=new URL('/api/v1'+req.url,target);
  if(upstream.origin!==target||!(upstream.pathname+'/').startsWith('/api/v1/'))return res.sendStatus(400);
  const headers={authorization,'x-forwarded-for':req.ip||'','x-forwarded-proto':req.protocol};
  for(const name of REQUEST_HEADERS){const value=req.get(name);if(value)headers[name]=value}
  const body=req.method==='GET'||req.method==='HEAD'||!Buffer.isBuffer(req.body)||!req.body.length?undefined:req.body;
  let response;
  try{response=await fetchImpl(upstream,{method:req.method,headers,body,redirect:'manual',signal:AbortSignal.timeout(timeoutMs)})}
  catch(error){
   const timedOut=error?.name==='TimeoutError';log.error('Slipway request failed',{path:upstream.pathname,kind:error?.name||'Error'});
   return res.status(timedOut?504:502).json({error:timedOut?'Slipway took too long to respond.':'Slipway is unavailable. Please try again.'});
  }
  res.status(response.status);
  for(const name of RESPONSE_HEADERS){const value=response.headers.get(name);if(value)res.set(name,value)}
  // Only same-origin relative redirects (Slipway sends the browser back to a portal page after GitHub linking).
  const location=response.headers.get('location');
  if(location&&location.startsWith('/')&&!location.startsWith('//')&&!location.includes('\\'))res.set('location',location);
  res.set('cache-control','no-store');
  const contents=req.method==='HEAD'?null:Buffer.from(await response.arrayBuffer());
  return contents&&contents.length?res.send(contents):res.end();
 });
 return router;
}
