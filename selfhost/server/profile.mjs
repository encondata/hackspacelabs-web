import express from 'express';
import {randomUUID} from 'node:crypto';
import sharp from 'sharp';
import {equalSecret} from './security.mjs';
export async function normalizeAvatar(bytes){
 if(!Buffer.isBuffer(bytes)||!bytes.length||bytes.length>5*1024*1024)throw new Error('Choose a JPEG, PNG, or WebP image under 5 MB.');
 const raster=bytes.subarray(0,3).equals(Buffer.from([255,216,255]))||bytes.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10]))||(bytes.toString('ascii',0,4)==='RIFF'&&bytes.toString('ascii',8,12)==='WEBP');
 if(!raster)throw new Error('Unsupported image format');
 const image=sharp(bytes,{limitInputPixels:25_000_000,failOn:'warning'});
 const metadata=await image.metadata();
 if(!['jpeg','png','webp'].includes(metadata.format)||(metadata.pages||1)>1)throw new Error('Choose a still JPEG, PNG, or WebP image.');
 return image.rotate().resize(256,256,{fit:'cover'}).webp({quality:85}).toBuffer();
}
export function profileRouter({profiles,management,userFor,config}){
 const router=express.Router();
 router.use(async(req,res,next)=>{
  const user=await userFor(req,res);if(!user)return res.status(401).json({error:'Please sign in again.'});
  if(req.method!=='GET'&&(req.get('origin')!==config.origin||!equalSecret(req.get('x-csrf-token'),req.session.csrf)))return res.status(403).json({error:'Reload the page and try again.'});
  req.accountUser=user;next();
 });
 router.get('/',async(req,res)=>{
  const user=req.accountUser;const profile=await profiles.get(user.id);
  let account=null,sessions=null,credentials=null;
  if(management){const results=await Promise.allSettled([management('/users/'+encodeURIComponent(user.id)),management('/users/'+encodeURIComponent(user.id)+'/sessions'),management('/users/'+encodeURIComponent(user.id)+'/credentials')]);[account,sessions,credentials]=results.map(result=>result.status==='fulfilled'?result.value:null)}
  res.json({profile:{...profile,name:profile.preferredName||user.name,email:account?.email??user.email,username:account?.username||'',memberSince:account?.createdTimestamp||null},roles:user.roles,security:credentials?{passwordUpdated:credentials.find(c=>c.type==='password')?.createdDate||null,twoFactorEnabled:credentials.some(c=>['otp','webauthn','webauthn-passwordless'].includes(c.type))}:null,sessions:sessions?.map(s=>({id:s.id,ipAddress:s.ipAddress,start:s.start,lastAccess:s.lastAccess,apps:Object.values(s.clients||{})}))??null,currentSignIn:{startedAt:req.session.createdAt,expiresAt:req.session.createdAt+config.absoluteMs}});
 });
 router.put('/',async(req,res)=>{
  const allowed={preferredName:120,jobTitle:160,phone:80,location:240};const details={};
  for(const [key,max] of Object.entries(allowed)){const value=req.body?.[key]??'';if(typeof value!=='string'||value.length>max)return res.status(400).json({error:'Check your profile fields and try again.'});details[key]=value.trim()}
  await profiles.update(req.accountUser.id,details);res.json({ok:true});
 });
 router.get('/avatar',async(req,res)=>{const bytes=await profiles.avatar(req.accountUser.id);if(!bytes)return res.sendStatus(404);res.type('image/webp').send(bytes)});
 router.put('/avatar',express.raw({type:['image/jpeg','image/png','image/webp','application/octet-stream'],limit:'5mb'}),async(req,res)=>{
  let bytes;try{bytes=await normalizeAvatar(req.body)}catch{return res.status(400).json({error:'Choose a valid, still JPEG, PNG, or WebP image under 5 MB and 25 megapixels.'})}
  const version=randomUUID();await profiles.putAvatar(req.accountUser.id,bytes,version);res.json({avatarVersion:version});
 });
 router.delete('/avatar',async(req,res)=>{await profiles.putAvatar(req.accountUser.id,null,null);res.json({ok:true})});
 router.use((error,_req,res,_next)=>res.status(error.type==='entity.too.large'?413:503).json({error:error.type==='entity.too.large'?'Choose an image under 5 MB.':'Your profile could not be loaded or saved. Please try again.'}));
 return router;
}
