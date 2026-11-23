import {createCipheriv,createDecipheriv,randomBytes,timingSafeEqual} from 'node:crypto';
import {loadSuiteApps,bareOrigin} from './suite-apps.mjs';
// Pages served by the gateway after a server-side role check. /apps is the suite launcher (PLAN.md 1f).
export const PAGES=['/admin','/portal','/me','/apps'];
export function safeDestination(value){return PAGES.includes(value)?value:null}
// Portal roles come from hsl_roles; the suite apps a person may use from hsl_apps.<app id> (that app's client roles).
// Staff who hold only app roles may still enter the portal, for the launcher and their account page.
export function identityFromClaims(claims,suiteApps=[]){
 if(!claims||typeof claims.sub!=='string'||!claims.sub)throw new Error('Authenticated identity required');
 const roles=Array.isArray(claims.hsl_roles)?claims.hsl_roles.filter(r=>r==='admin'||r==='customer'):[];
 const granted=claims.hsl_apps&&typeof claims.hsl_apps==='object'&&!Array.isArray(claims.hsl_apps)?claims.hsl_apps:{};
 const apps=suiteApps.filter(app=>Array.isArray(granted[app.id])&&granted[app.id].some(r=>typeof r==='string'&&Object.hasOwn(app.roles,r))).map(app=>app.id);
 if(!roles.length&&!apps.length)throw new Error('No application role');
 return {id:claims.sub,email:typeof claims.email==='string'?claims.email:'',name:typeof claims.name==='string'&&claims.name.trim()?claims.name:typeof claims.preferred_username==='string'?claims.preferred_username:'HackSpaceLabs user',roles:[...new Set(roles)],apps};
}
export function canAccess(user,pathname){
 const admin=!!user?.roles?.includes('admin'),customer=!!user?.roles?.includes('customer'),staff=(user?.apps?.length||0)>0;
 return pathname==='/admin'?admin:pathname==='/portal'?admin||customer:pathname==='/me'?admin||customer||staff:pathname==='/apps'?admin||staff:false;
}
// Where a sign-in lands when no page was requested.
export function landing(user){return user.roles.includes('admin')?'/admin':user.apps?.length?'/apps':'/portal'}
export function equalSecret(a,b){if(typeof a!=='string'||typeof b!=='string')return false;const x=Buffer.from(a);const y=Buffer.from(b);return x.length===y.length&&timingSafeEqual(x,y)}
export function tokenCipher(key){
 const secret=Buffer.from(key,'base64');if(secret.length!==32)throw new Error('TOKEN_ENCRYPTION_KEY must be 32 random bytes encoded as base64');
 return {seal(value){const iv=randomBytes(12);const cipher=createCipheriv('aes-256-gcm',secret,iv);const ciphertext=Buffer.concat([cipher.update(JSON.stringify(value),'utf8'),cipher.final()]);return [iv,cipher.getAuthTag(),ciphertext].map(x=>x.toString('base64url')).join('.')},open(value){const [iv,tag,data]=value.split('.').map(x=>Buffer.from(x,'base64url'));const decipher=createDecipheriv('aes-256-gcm',secret,iv);decipher.setAuthTag(tag);return JSON.parse(Buffer.concat([decipher.update(data),decipher.final()]).toString('utf8'))}};
}
export function privateIPv4(host){
 const parts=host.split('.');
 if(parts.length!==4||parts.some(p=>!/^\d{1,3}$/.test(p)||Number(p)>255))return false;
 const [a,b]=parts.map(Number);
 return a===10||a===192&&b===168||a===172&&b>=16&&b<=31;
}
export function readConfig(env=process.env){
 const production=env.NODE_ENV==='production';
 if(!production&&env.AUTH_LOCAL_TEST!=='1')throw new Error('Use NODE_ENV=production, or explicitly enable AUTH_LOCAL_TEST=1 for loopback-only testing');
 const lan=env.AUTH_MODE==='lan';
 const origin=new URL(env.APP_ORIGIN||'');const issuer=new URL(env.OIDC_ISSUER||'');
 for(const u of [origin,issuer]){if(u.username||u.password||u.search||u.hash)throw new Error('Invalid origin or issuer URL');if(production&&u.protocol!=='https:'&&!(lan&&u.protocol==='http:'&&privateIPv4(u.hostname)))throw new Error('Production requires HTTPS, or explicit LAN mode with private IPv4 endpoints');if(!production&&(u.protocol!=='http:'||!['localhost','127.0.0.1'].includes(u.hostname)))throw new Error('Local tests require loopback HTTP URLs')}
 if(lan&&(origin.protocol!=='http:'||issuer.protocol!=='http:'||!privateIPv4(origin.hostname)||issuer.hostname!==origin.hostname))throw new Error('LAN mode requires the same private IPv4 address for web and auth');
 if(origin.pathname!=='/')throw new Error('APP_ORIGIN must contain only scheme and host');
 if(!env.SESSION_SECRET||env.SESSION_SECRET.length<48)throw new Error('SESSION_SECRET must contain at least 48 characters');
 if(!env.OIDC_CLIENT_SECRET||env.OIDC_CLIENT_SECRET.length<32)throw new Error('OIDC_CLIENT_SECRET must contain at least 32 characters');
 if(!env.DATABASE_URL)throw new Error('DATABASE_URL is required');
 tokenCipher(env.TOKEN_ENCRYPTION_KEY||'');
 // Suite apps whose origin is set appear in the launcher; the others are still recognised in tokens.
 const suiteApps=loadSuiteApps().map(app=>({...app,url:bareOrigin(env[app.originEnv],app.originEnv)}));
 // Sessions end when the Keycloak session does (refresh_expires_in); refreshMs is the recheck interval (D5).
 return {production,secureCookies:production&&!lan,allowInsecureOidc:lan,origin:origin.origin,issuer:issuer.href.replace(/\/$/,''),clientId:env.OIDC_CLIENT_ID||'hackspacelabs-web',clientSecret:env.OIDC_CLIENT_SECRET,sessionSecret:env.SESSION_SECRET,encryptionKey:env.TOKEN_ENCRYPTION_KEY,databaseUrl:env.DATABASE_URL,port:Number(env.PORT||3000),host:production?'0.0.0.0':'127.0.0.1',refreshMs:60*1000,suiteApps};
}
