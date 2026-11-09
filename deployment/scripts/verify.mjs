const app=process.env.APP_ORIGIN||'https://hackspacelabs.com';
const issuer=process.env.OIDC_ISSUER||'https://auth.hackspacelabs.com/realms/hackspacelabs';
const response=await fetch(issuer+'/.well-known/openid-configuration');if(!response.ok)throw new Error('OIDC discovery unavailable');
const metadata=await response.json();if(metadata.issuer!==issuer||!metadata.code_challenge_methods_supported?.includes('S256'))throw new Error('Unexpected issuer or missing PKCE support');
for(const route of ['/admin','/portal']){const r=await fetch(app+route,{redirect:'manual'});if(r.status!==303||!r.headers.get('location')?.startsWith('/login?'))throw new Error(route+' is not protected')}
const session=await fetch(app+'/api/auth/session');if(session.status!==401)throw new Error('Anonymous session was not rejected');
console.log('Discovery, PKCE support, anonymous route protection, and session endpoint passed. Complete the browser sign-in checklist in README.md.');
