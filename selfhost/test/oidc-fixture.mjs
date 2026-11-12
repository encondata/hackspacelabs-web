// Protocol fixture only. Never used in the production server or Docker image.
import express from 'express';
import {generateKeyPair,exportJWK,SignJWT} from 'jose';
import {randomBytes,createHash} from 'node:crypto';
export async function startIssuer(){
 const keys=await generateKeyPair('RS256');const wrongKeys=await generateKeyPair('RS256');const jwk=await exportJWK(keys.publicKey);jwk.kid='test-key';jwk.alg='RS256';
 const state={roles:['customer'],slipwayRoles:[],verified:true,subject:'sample-user',fault:null,revoked:false,accessToken:null};const codes=new Map();const refreshes=new Map();
 const app=express();app.use(express.urlencoded({extended:false}));
 const server=app.listen(0,'127.0.0.1');await new Promise(r=>server.once('listening',r));const issuer=`http://127.0.0.1:${server.address().port}`;
 app.get('/.well-known/openid-configuration',(_q,r)=>r.json({issuer,authorization_endpoint:issuer+'/authorize',token_endpoint:issuer+'/token',jwks_uri:issuer+'/jwks',end_session_endpoint:issuer+'/logout',response_types_supported:['code'],grant_types_supported:['authorization_code','refresh_token'],subject_types_supported:['public'],id_token_signing_alg_values_supported:['RS256'],token_endpoint_auth_methods_supported:['client_secret_post','client_secret_basic'],code_challenge_methods_supported:['S256']}));
 app.get('/jwks',(_q,r)=>r.json({keys:[jwk]}));
 app.get('/authorize',(q,r)=>{if(q.query.code_challenge_method!=='S256'||q.query.response_type!=='code')return r.sendStatus(400);const code=randomBytes(16).toString('hex');codes.set(code,{...q.query});const target=new URL(q.query.redirect_uri);target.searchParams.set('code',code);target.searchParams.set('state',q.query.state);r.redirect(target.href)});
 app.post('/token',async(q,r)=>{
  let flow;const grant=q.body.grant_type;
  if(grant==='authorization_code'){flow=codes.get(q.body.code);codes.delete(q.body.code);if(!flow||q.body.redirect_uri!==flow.redirect_uri||createHash('sha256').update(q.body.code_verifier||'').digest('base64url')!==flow.code_challenge)return r.status(400).json({error:'invalid_grant'})}
  else if(grant==='refresh_token'){flow=refreshes.get(q.body.refresh_token);if(!flow||state.revoked)return r.status(400).json({error:'invalid_grant'})}
  else return r.status(400).json({error:'unsupported_grant_type'});
  const token=await new SignJWT({sub:state.subject,email:'sample@example.com',name:'Sample Customer',email_verified:state.verified,hsl_roles:state.roles,slipway_roles:state.slipwayRoles,nonce:state.fault==='nonce'?'bad-nonce':flow.nonce}).setProtectedHeader({alg:'RS256',kid:'test-key'}).setIssuer(state.fault==='issuer'?'https://wrong.example':issuer).setAudience(state.fault==='audience'?'wrong-client':flow.client_id).setIssuedAt().setExpirationTime('5m').sign(state.fault==='signature'?wrongKeys.privateKey:keys.privateKey);
  const refresh=randomBytes(24).toString('hex');refreshes.set(refresh,flow);state.accessToken=randomBytes(24).toString('hex');r.json({access_token:state.accessToken,refresh_token:refresh,token_type:'Bearer',expires_in:300,id_token:token});
 });
 return {issuer,state,close:()=>new Promise(r=>server.close(r))};
}
