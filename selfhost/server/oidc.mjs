import * as oidc from 'openid-client';
export const SESSION_FALLBACK_MS=96*60*60*1000;
// A definite refusal ends a session; anything else (network, timeout, 5xx, keys unavailable) keeps it (PLAN.md 5.7).
export function refused(error){
 if(error?.error==='invalid_grant')return true;
 if(error?.code==='OAUTH_JWT_CLAIM_COMPARISON_FAILED')return true;
 return error?.code==='OAUTH_INVALID_RESPONSE'&&/signature verification failed/i.test(error.cause?.message||'');
}
export async function createOidc(settings){
 const config=await oidc.discovery(new URL(settings.issuer),settings.clientId,settings.clientSecret,undefined,{execute:[...((!settings.production||settings.allowInsecureOidc)?[oidc.allowInsecureRequests]:[]),oidc.enableNonRepudiationChecks],timeout:10});
 if(config.serverMetadata().issuer!==settings.issuer)throw new Error('OIDC issuer mismatch');
 if(!config.serverMetadata().code_challenge_methods_supported?.includes('S256'))throw new Error('OIDC server must support PKCE S256');
 const callback=settings.origin+'/api/auth/callback';
 // expiresAt is the access token's expiry; sessionExpiresAt is the Keycloak session's (96 hours when not given).
 function pack(tokens){const claims=tokens.claims();if(!claims||!tokens.refresh_token)throw new Error('OIDC identity and refresh token required');const now=Date.now();const lifetime=Number(tokens.refresh_expires_in);return {claims,refreshToken:tokens.refresh_token,idToken:tokens.id_token,expiresAt:now+Number(tokens.expires_in||60)*1000,sessionExpiresAt:now+(Number.isFinite(lifetime)&&lifetime>0?lifetime*1000:SESSION_FALLBACK_MS)}}
 return {
  async begin(){const verifier=oidc.randomPKCECodeVerifier();const state=oidc.randomState();const nonce=oidc.randomNonce();const challenge=await oidc.calculatePKCECodeChallenge(verifier);const url=oidc.buildAuthorizationUrl(config,{redirect_uri:callback,scope:'openid profile email',code_challenge:challenge,code_challenge_method:'S256',state,nonce});return {url:url.href,verifier,state,nonce}},
  async exchange(url,flow){return pack(await oidc.authorizationCodeGrant(config,url,{pkceCodeVerifier:flow.verifier,expectedState:flow.state,expectedNonce:flow.nonce,idTokenExpected:true}))},
  async refresh(token){const result=await oidc.refreshTokenGrant(config,token);if(!result.refresh_token)result.refresh_token=token;return pack(result)},
  logout(idToken){return oidc.buildEndSessionUrl(config,{client_id:settings.clientId,post_logout_redirect_uri:settings.origin+'/login',...(idToken?{id_token_hint:idToken}:{})}).href},
  account:settings.issuer+'/account/'
 };
}
