import express from 'express';
import {managementRouter} from './management.mjs';
import session from 'express-session';
import helmet from 'helmet';
import {rateLimit} from 'express-rate-limit';
import {randomBytes} from 'node:crypto';
import path from 'node:path';
import {identityFromClaims,canAccess,safeDestination,equalSecret,tokenCipher} from './security.mjs';
const save=s=>new Promise((resolve,reject)=>s.save(error=>error?reject(error):resolve()));
const regenerate=s=>new Promise((resolve,reject)=>s.regenerate(error=>error?reject(error):resolve()));
const destroy=s=>new Promise((resolve,reject)=>s.destroy(error=>error?reject(error):resolve()));
export function createApp({config,store,oidc,publicDir,healthy=async()=>true,management,log=console}){
 const app=express();const cipher=tokenCipher(config.encryptionKey);const refreshes=new Map();
 const secureCookies=config.secureCookies??config.production;
 const cookieName=secureCookies?'__Host-hsl.sid':(config.production?'hsl.lan.sid':'hsl.test.sid');
 app.disable('x-powered-by');app.set('trust proxy',config.production?1:false);
 app.use(helmet({crossOriginOpenerPolicy:false,originAgentCluster:false,contentSecurityPolicy:{directives:{defaultSrc:["'self'"],scriptSrc:["'self'"],styleSrc:["'self'","'unsafe-inline'"],imgSrc:["'self'",'data:'],connectSrc:["'self'"],objectSrc:["'none'"],baseUri:["'self'"],frameAncestors:["'none'"],formAction:["'self'"],upgradeInsecureRequests:null}},strictTransportSecurity:secureCookies?{maxAge:31536000}:false,referrerPolicy:{policy:'no-referrer'}}));
 app.use((req,res,next)=>{
  // Reject ambiguous paths before authorization or static-file routing.
  const raw=req.originalUrl.split('?')[0];let decoded;try{decoded=decodeURIComponent(raw)}catch{return res.sendStatus(400)}
  if(decoded!==raw||raw.includes('\\')||raw.includes('//')||raw.includes('/.')||/[\x00-\x20\x7f]/.test(raw))return res.sendStatus(400);
  if(req.path==='/healthz')return next();
  const protectedRequest=req.path.startsWith('/api/')||req.path==='/admin'||(req.path==='/portal'||req.path==='/me');
  if(config.production&&protectedRequest&&((secureCookies&&!req.secure)||req.get('host')!==new URL(config.origin).host))return res.status(400).send('Invalid request origin');
  if(req.path.startsWith('/api/')||(req.path==='/portal'||req.path==='/me')||req.path==='/admin'||req.path==='/login')res.set('Cache-Control','no-store');
  next();
 });
 app.get('/healthz',async(_req,res)=>{try{await healthy();res.json({status:'ok'})}catch{res.status(503).json({status:'unavailable'})}});
 app.use('/assets',express.static(path.join(publicDir,'assets'),{immutable:true,maxAge:'1y',fallthrough:false}));
 app.use(express.json({limit:'8kb'}));app.use(express.urlencoded({extended:false,limit:'8kb'}));
 app.use(session({name:cookieName,secret:config.sessionSecret,store,resave:false,saveUninitialized:false,rolling:true,cookie:{httpOnly:true,secure:secureCookies,sameSite:'lax',path:'/',maxAge:config.idleMs}}));
 const authLimit=rateLimit({windowMs:15*60*1000,limit:60,standardHeaders:'draft-8',legacyHeaders:false,message:{error:'Too many authentication attempts. Please try again later.'}});
 app.use('/api/auth/login',authLimit);app.use('/api/auth/callback',authLimit);
 function clearCookie(res){res.clearCookie(cookieName,{httpOnly:true,secure:secureCookies,sameSite:'lax',path:'/'})}
 async function expire(req,res){await regenerate(req.session);clearCookie(res)}
 async function userFor(req,res){
  if(!req.session.identity)return null;
  const now=Date.now();if(now-req.session.createdAt>config.absoluteMs||now-req.session.lastSeen>config.idleMs){await expire(req,res);return null}
  if(now-req.session.checkedAt>=config.refreshMs||now>=req.session.tokenExpiry){
   try{
    let refresh=refreshes.get(req.sessionID);
    if(!refresh){const old=cipher.open(req.session.tokens);refresh=oidc.refresh(old.refreshToken);refreshes.set(req.sessionID,refresh);refresh.finally(()=>refreshes.delete(req.sessionID)).catch(()=>{})}
    const fresh=await refresh;const identity=identityFromClaims(fresh.claims);
    if(identity.id!==req.session.identity.id)throw new Error('Identity changed');
    req.session.identity=identity;req.session.tokens=cipher.seal({refreshToken:fresh.refreshToken,idToken:fresh.idToken});req.session.checkedAt=now;req.session.tokenExpiry=fresh.expiresAt;
   }catch{await expire(req,res);return null}
  }
  req.session.lastSeen=now;return req.session.identity;
 }
 app.get('/api/auth/login',async(req,res)=>{
  const user=await userFor(req,res);const requested=safeDestination(req.query.returnTo);
  if(user){const target=requested|| (user.roles.includes('admin')?'/admin':'/portal');return canAccess(user,target)?res.redirect(303,target):res.redirect(303,'/forbidden')}
  const flow=await oidc.begin();await regenerate(req.session);req.session.flow={...flow,url:undefined,returnTo:requested,startedAt:Date.now()};await save(req.session);res.redirect(303,flow.url);
 });
 app.get('/api/auth/callback',async(req,res)=>{
  const flow=req.session.flow;
  if(!flow||Date.now()-flow.startedAt>10*60*1000){return res.redirect(303,'/login?error=expired')}
  delete req.session.flow;await save(req.session); // consume once, including failures
  try{
   const tokens=await oidc.exchange(new URL(req.originalUrl,config.origin),flow);const identity=identityFromClaims(tokens.claims);
   await regenerate(req.session);const now=Date.now();req.session.identity=identity;req.session.tokens=cipher.seal({refreshToken:tokens.refreshToken,idToken:tokens.idToken});req.session.createdAt=now;req.session.lastSeen=now;req.session.checkedAt=now;req.session.tokenExpiry=tokens.expiresAt;req.session.csrf=randomBytes(32).toString('base64url');await save(req.session);
   const target=flow.returnTo||(identity.roles.includes('admin')?'/admin':'/portal');res.redirect(303,canAccess(identity,target)?target:'/forbidden');
  }catch{await expire(req,res);res.redirect(303,'/login?error=signin')}
 });
 app.get('/api/auth/session',async(req,res)=>{
  const user=await userFor(req,res);if(!user)return res.status(401).json({authenticated:false});
  res.json({authenticated:true,user,csrfToken:req.session.csrf,sampleData:true});
 });
 app.post('/api/auth/logout',async(req,res)=>{
  if(req.get('origin')!==config.origin||!equalSecret(req.get('x-csrf-token')||req.body?.csrf,req.session.csrf))return res.status(403).json({error:'Invalid logout request'});
  let idToken;try{idToken=cipher.open(req.session.tokens).idToken}catch{}
  await destroy(req.session);clearCookie(res);res.json({redirect:await oidc.logout(idToken)});
 });
 app.get('/api/auth/account',async(req,res)=>{const user=await userFor(req,res);if(!user)return res.redirect(303,'/login');res.redirect(303,'/me')});
 if(management)app.use('/api/admin',managementRouter({api:management,userFor,config,log}));
 app.use('/api',(_req,res)=>res.status(404).json({error:'No live environment or ticket API is configured. These features use sample data.'}));
 app.get(['/admin','/portal','/me'],async(req,res)=>{
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
