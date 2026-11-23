import express from 'express';
import {profileRouter} from './profile.mjs';
import {managementRouter} from './management.mjs';
import session from 'express-session';
import helmet from 'helmet';
import {rateLimit} from 'express-rate-limit';
import {randomBytes} from 'node:crypto';
import path from 'node:path';
import {identityFromClaims,canAccess,safeDestination,equalSecret,tokenCipher,landing,PAGES} from './security.mjs';
import {refused} from './oidc.mjs';
import {loadSuiteApps} from './suite-apps.mjs';
// Sessions made before sessions followed Keycloak have no sessionExpiresAt; they keep the old 8-hour limit until
// their next recheck (at most refreshMs later) gives them one.
const LEGACY_SESSION_MS=8*60*60*1000;const FLOW_MS=10*60*1000;
const save=s=>new Promise((resolve,reject)=>s.save(error=>error?reject(error):resolve()));
const regenerate=s=>new Promise((resolve,reject)=>s.regenerate(error=>error?reject(error):resolve()));
const destroy=s=>new Promise((resolve,reject)=>s.destroy(error=>error?reject(error):resolve()));
export function createApp({config,store,oidc,publicDir,healthy=async()=>true,management,profiles,log=console}){
 const app=express();const cipher=tokenCipher(config.encryptionKey);const refreshes=new Map();const suiteApps=config.suiteApps||loadSuiteApps();
 const secureCookies=config.secureCookies??config.production;
 const cookieName=secureCookies?'__Host-hsl.sid':(config.production?'hsl.lan.sid':'hsl.test.sid');
 app.disable('x-powered-by');app.set('trust proxy',config.production?1:false);
 app.use(helmet({crossOriginOpenerPolicy:false,originAgentCluster:false,contentSecurityPolicy:{directives:{defaultSrc:["'self'"],scriptSrc:["'self'"],styleSrc:["'self'","'unsafe-inline'"],imgSrc:["'self'",'data:'],connectSrc:["'self'"],objectSrc:["'none'"],baseUri:["'self'"],frameAncestors:["'none'"],formAction:["'self'"],upgradeInsecureRequests:null}},strictTransportSecurity:secureCookies?{maxAge:31536000}:false,referrerPolicy:{policy:'no-referrer'}}));
 app.use((req,res,next)=>{
  // Reject ambiguous paths before authorization or static-file routing.
  const raw=req.originalUrl.split('?')[0];let decoded;try{decoded=decodeURIComponent(raw)}catch{return res.sendStatus(400)}
  if(decoded!==raw||raw.includes('\\')||raw.includes('//')||raw.includes('/.')||/[\x00-\x20\x7f]/.test(raw))return res.sendStatus(400);
  if(req.path==='/healthz')return next();
  const protectedRequest=req.path.startsWith('/api/')||PAGES.includes(req.path);
  if(config.production&&protectedRequest&&((secureCookies&&!req.secure)||req.get('host')!==new URL(config.origin).host))return res.status(400).send('Invalid request origin');
  if(req.path.startsWith('/api/')||PAGES.includes(req.path)||req.path==='/login')res.set('Cache-Control','no-store');
  next();
 });
 app.get('/healthz',async(_req,res)=>{try{await healthy();res.json({status:'ok'})}catch{res.status(503).json({status:'unavailable'})}});
 app.use('/assets',express.static(path.join(publicDir,'assets'),{immutable:true,maxAge:'1y',fallthrough:false}));
 app.use(express.json({limit:'8kb'}));app.use(express.urlencoded({extended:false,limit:'8kb'}));
 // Not rolling: a signed-in session's cookie expires with the Keycloak session (sessionExpiresAt), which userFor
 // re-applies on every request. Before sign-in the cookie only has to outlive the sign-in flow.
 app.use(session({name:cookieName,secret:config.sessionSecret,store,resave:false,saveUninitialized:false,rolling:false,cookie:{httpOnly:true,secure:secureCookies,sameSite:'lax',path:'/',maxAge:FLOW_MS}}));
 const authLimit=rateLimit({windowMs:15*60*1000,limit:60,standardHeaders:'draft-8',legacyHeaders:false,message:{error:'Too many authentication attempts. Please try again later.'}});
 app.use('/api/auth/login',authLimit);app.use('/api/auth/callback',authLimit);
 function clearCookie(res){res.clearCookie(cookieName,{httpOnly:true,secure:secureCookies,sameSite:'lax',path:'/'})}
 async function expire(req,res){await regenerate(req.session);clearCookie(res)}
 function keepUntil(req,expiresAt){req.session.sessionExpiresAt=expiresAt;req.session.cookie.expires=new Date(expiresAt)}
 async function userFor(req,res){
  if(!req.session.identity)return null;
  const now=Date.now();const ends=req.session.sessionExpiresAt??(req.session.createdAt||0)+LEGACY_SESSION_MS;
  if(now>=ends){await expire(req,res);return null}
  if(now-req.session.checkedAt>=config.refreshMs){
   let refresh=refreshes.get(req.sessionID);
   if(!refresh){let old;try{old=cipher.open(req.session.tokens)}catch{await expire(req,res);return null}refresh=oidc.refresh(old.refreshToken);refreshes.set(req.sessionID,refresh);refresh.finally(()=>refreshes.delete(req.sessionID)).catch(()=>{})}
   let fresh=null;
   // Only a definite refusal (signed out, disabled, bad token) ends the session. An outage keeps it, and the check
   // waits a full interval before trying again (PLAN.md 5.7).
   try{fresh=await refresh}catch(error){if(refused(error)){await expire(req,res);return null}req.session.checkedAt=now;log.warn?.('Identity recheck deferred',{kind:error?.name||'Error',code:error?.code||error?.error||null})}
   if(fresh){
    let identity;try{identity=identityFromClaims(fresh.claims,suiteApps)}catch{await expire(req,res);return null}
    if(identity.id!==req.session.identity.id){await expire(req,res);return null}
    req.session.identity=identity;req.session.tokens=cipher.seal({refreshToken:fresh.refreshToken,idToken:fresh.idToken});req.session.checkedAt=now;req.session.tokenExpiry=fresh.expiresAt;req.session.sessionExpiresAt=fresh.sessionExpiresAt;
   }
  }
  keepUntil(req,req.session.sessionExpiresAt??ends);
  return req.session.identity;
 }
 // Configured suite apps (origin set) this person may use; administrators see all of them.
 function appsFor(user){const configured=suiteApps.filter(app=>app.url);return (user.roles.includes('admin')?configured:configured.filter(app=>user.apps?.includes(app.id))).map(({id,name,description,url})=>({id,name,description,url}))}
 app.get('/api/auth/login',async(req,res)=>{
  const user=await userFor(req,res);const requested=safeDestination(req.query.returnTo);
  if(user){const target=requested||landing(user);return canAccess(user,target)?res.redirect(303,target):res.redirect(303,'/forbidden')}
  const flow=await oidc.begin();await regenerate(req.session);req.session.flow={...flow,url:undefined,returnTo:requested,startedAt:Date.now()};await save(req.session);res.redirect(303,flow.url);
 });
 app.get('/api/auth/callback',async(req,res)=>{
  const flow=req.session.flow;
  if(!flow||Date.now()-flow.startedAt>10*60*1000){return res.redirect(303,'/login?error=expired')}
  delete req.session.flow;await save(req.session); // consume once, including failures
  try{
   const tokens=await oidc.exchange(new URL(req.originalUrl,config.origin),flow);const identity=identityFromClaims(tokens.claims,suiteApps);
   await regenerate(req.session);const now=Date.now();req.session.identity=identity;req.session.tokens=cipher.seal({refreshToken:tokens.refreshToken,idToken:tokens.idToken});req.session.createdAt=now;req.session.checkedAt=now;req.session.tokenExpiry=tokens.expiresAt;keepUntil(req,tokens.sessionExpiresAt);req.session.csrf=randomBytes(32).toString('base64url');await save(req.session);
   const target=flow.returnTo||landing(identity);res.redirect(303,canAccess(identity,target)?target:'/forbidden');
  }catch{await expire(req,res);res.redirect(303,'/login?error=signin')}
 });
 app.get('/api/auth/session',async(req,res)=>{
  const user=await userFor(req,res);if(!user)return res.status(401).json({authenticated:false});
  const profile=profiles?await profiles.get(user.id):{};
  res.json({authenticated:true,user:{...user,apps:user.apps||[],name:profile.preferredName||user.name,avatarVersion:profile.avatarVersion||null},apps:appsFor(user),csrfToken:req.session.csrf,sampleData:true});
 });
 app.post('/api/auth/logout',async(req,res)=>{
  if(req.get('origin')!==config.origin||!equalSecret(req.get('x-csrf-token')||req.body?.csrf,req.session.csrf))return res.status(403).json({error:'Invalid logout request'});
  let idToken;try{idToken=cipher.open(req.session.tokens).idToken}catch{}
  await destroy(req.session);clearCookie(res);res.json({redirect:await oidc.logout(idToken)});
 });
 app.get('/api/auth/account',async(req,res)=>{const user=await userFor(req,res);if(!user)return res.redirect(303,'/login');res.redirect(303,'/me')});
 if(profiles)app.use('/api/me',profileRouter({profiles,management,userFor,config}));
 if(management)app.use('/api/admin',managementRouter({api:management,userFor,config,log}));
 app.use('/api',(_req,res)=>res.status(404).json({error:'No live environment or ticket API is configured. These features use sample data.'}));
 app.get(PAGES,async(req,res)=>{
  const user=await userFor(req,res);if(!user)return res.redirect(303,'/login?returnTo='+encodeURIComponent(req.path));
  if(!canAccess(user,req.path))return res.status(403).sendFile(path.join(publicDir,'index.html'));
  res.sendFile(path.join(publicDir,'index.html'));
 });
 app.get(['/','/login','/forbidden'],(_req,res)=>res.sendFile(path.join(publicDir,'index.html')));
 app.get('/favicon.ico',(_req,res)=>res.redirect(302,'/hackspacelabs-logo.png'));
 app.get('/hackspacelabs-logo.png',(_req,res)=>res.sendFile(path.join(publicDir,'hackspacelabs-logo.png')));
 app.use((_req,res)=>res.status(404).send('Page not found'));
 app.use((error,req,res,_next)=>{log.error('Request failed',{path:req.path,kind:error?.name||'Error'});if(!res.headersSent)res.status(503).json({error:'Service temporarily unavailable. Please try again.'})});
 return app;
}
