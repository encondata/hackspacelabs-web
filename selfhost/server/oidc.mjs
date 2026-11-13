import * as oidc from 'openid-client';
export async function createOidc(settings){
 const config=await oidc.discovery(new URL(settings.issuer),settings.clientId,settings.clientSecret,undefined,{execute:[...((!settings.production||settings.allowInsecureOidc)?[oidc.allowInsecureRequests]:[]),oidc.enableNonRepudiationChecks],timeout:10});
 if(config.serverMetadata().issuer!==settings.issuer)throw new Error('OIDC issuer mismatch');
 if(!config.serverMetadata().code_challenge_methods_supported?.includes('S256'))throw new Error('OIDC server must support PKCE S256');
 const callback=settings.origin+'/api/auth/callback';
 function pack(tokens){const claims=tokens.claims();if(!claims||!tokens.refresh_token)throw new Error('OIDC identity and refresh token required');return {claims,accessToken:tokens.access_token,refreshToken:tokens.refresh_token,idToken:tokens.id_token,expiresAt:Date.now()+Number(tokens.expires_in||60)*1000}}
 return {
  async begin(){const verifier=oidc.randomPKCECodeVerifier();const state=oidc.randomState();const nonce=oidc.randomNonce();const challenge=await oidc.calculatePKCECodeChallenge(verifier);const url=oidc.buildAuthorizationUrl(config,{redirect_uri:callback,scope:'openid profile email',code_challenge:challenge,code_challenge_method:'S256',state,nonce});return {url:url.href,verifier,state,nonce}},
  async exchange(url,flow){return pack(await oidc.authorizationCodeGrant(config,url,{pkceCodeVerifier:flow.verifier,expectedState:flow.state,expectedNonce:flow.nonce,idTokenExpected:true}))},
  async refresh(token){const result=await oidc.refreshTokenGrant(config,token);if(!result.refresh_token)result.refresh_token=token;return pack(result)},
  logout(idToken){return oidc.buildEndSessionUrl(config,{client_id:settings.clientId,post_logout_redirect_uri:settings.origin+'/login',...(idToken?{id_token_hint:idToken}:{})}).href},
  account:settings.issuer+'/account/'
 };
}
