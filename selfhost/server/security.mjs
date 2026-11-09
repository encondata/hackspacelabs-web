import {createCipheriv,createDecipheriv,randomBytes,timingSafeEqual} from 'node:crypto';
export function safeDestination(value){return value==='/admin'||value==='/portal'?value:null}
export function identityFromClaims(claims){
 if(!claims||typeof claims.sub!=='string'||!claims.sub)throw new Error('Authenticated identity required');
 const roles=Array.isArray(claims.hsl_roles)?claims.hsl_roles.filter(r=>r==='admin'||r==='customer'):[];
 if(!roles.length)throw new Error('No application role');
 return {id:claims.sub,email:typeof claims.email==='string'?claims.email:'',name:typeof claims.name==='string'&&claims.name.trim()?claims.name:typeof claims.preferred_username==='string'?claims.preferred_username:'HackSpaceLabs user',roles:[...new Set(roles)]};
}
export function canAccess(user,pathname){return pathname==='/admin'?user?.roles?.includes('admin'):pathname==='/portal'?user?.roles?.some(r=>r==='admin'||r==='customer'):false}
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
 return {production,secureCookies:production&&!lan,allowInsecureOidc:lan,origin:origin.origin,issuer:issuer.href.replace(/\/$/,''),clientId:env.OIDC_CLIENT_ID||'hackspacelabs-web',clientSecret:env.OIDC_CLIENT_SECRET,sessionSecret:env.SESSION_SECRET,encryptionKey:env.TOKEN_ENCRYPTION_KEY,databaseUrl:env.DATABASE_URL,port:Number(env.PORT||3000),host:production?'0.0.0.0':'127.0.0.1',idleMs:30*60*1000,absoluteMs:8*60*60*1000,refreshMs:60*1000};
}
