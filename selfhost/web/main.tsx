// The HSL Suite kit (ui/): fonts, tokens, frame, sign-in card, and the widgets and theme (suite.js applies
// the stored light/dark choice as it loads). The site's own CSS comes after it.
import '../../ui/fonts.css';
import '../../ui/tokens.css';
import '../../ui/shell.css';
import '../../ui/auth.css';
import '../../ui/suite.js';
import '../../app/globals.css';
import MePage from './me';
import IdentityAdmin from './identity-admin';
import AppsPage from './apps';
import './suite.css';
import React,{useEffect,useState} from 'react';
import {createRoot} from 'react-dom/client';
import Home from '../../app/page';
import Dashboard,{type SuiteApp} from '../../app/portal/dashboard';
import {markUrl} from '../../app/portal/suite-widgets';
type User={id:string;email:string;name:string;roles:string[];apps?:string[];avatarVersion?:string|null};
type Session={authenticated:boolean;user?:User;apps?:SuiteApp[];csrfToken?:string};
const pages=['/admin','/portal','/me','/apps'];
// The sign-in, checking, unavailable and no-access pages: the kit's sign-in card.
function AuthCard({title,children}:{title:string;children:React.ReactNode}){return <div className="hsl-auth"><main className="hsl-auth-card"><a className="hsl-auth-brand" href="/" aria-label="HackSpaceLabs home"><img className="hsl-mark" src={markUrl} width={44} height={41} alt=""/><span className="hsl-wordmark">HackSpaceLabs</span></a><h1 className="hsl-auth-title">{title}</h1>{children}</main></div>}
function Login(){const params=new URLSearchParams(location.search);const target=params.get('returnTo');const error=params.get('error');return <AuthCard title="Sign in to HackSpaceLabs"><p className="hsl-auth-text">One account for HackSpaceLabs and connected apps.</p>{error&&<p role="alert" className="hsl-auth-alert">{error==='expired'?'Your sign-in request expired. Please start again.':'We couldn’t complete sign-in. Check that your account has portal access, then try again.'}</p>}<a className="hsl-auth-button is-primary" href={'/api/auth/login'+(target&&pages.includes(target)?'?returnTo='+encodeURIComponent(target):'')}>Continue to sign in</a><p className="hsl-auth-note">You’ll continue to your configured HackSpaceLabs identity service. Contact your administrator if you need a password reset or an account.</p><a className="hsl-auth-link" href="/">Back to home</a></AuthCard>}
function App(){const pathname=location.pathname;const [session,setSession]=useState<Session|null>(null);const [error,setError]=useState('');
 useEffect(()=>{if(![...pages,'/forbidden'].includes(pathname))return;let live=true;async function check(){try{const response=await fetch('/api/auth/session',{cache:'no-store',credentials:'same-origin'});if(response.status===401){location.replace('/login?returnTo='+encodeURIComponent(pages.includes(pathname)?pathname:'/portal'));return}if(!response.ok)throw new Error();const next=await response.json();if(live){setSession(next);setError('')}}catch{if(live){setSession(null);setError('Account service unavailable. Please reload to try again.')}}}void check();const interval=setInterval(check,60000);return()=>{live=false;clearInterval(interval)}},[pathname]);
 if(pathname==='/')return <Home/>;if(pathname==='/login')return <Login/>;
 if(error)return <AuthCard title="Unable to connect"><p role="alert" className="hsl-auth-alert">{error}</p><a className="hsl-auth-button is-primary" href={pathname}>Try again</a></AuthCard>;
 if(!session?.user)return <AuthCard title="Checking your account…"><p role="status" className="hsl-auth-text">Please wait.</p></AuthCard>;
 const isAdmin=session.user.roles.includes('admin');const isCustomer=session.user.roles.includes('customer');const apps=session.apps||[];
 // People who only hold app roles see the launcher and their account, not the sample workspace.
 const workspace=isAdmin||isCustomer;
 const logout=async()=>{try{const response=await fetch('/api/auth/logout',{method:'POST',credentials:'same-origin',headers:{'x-csrf-token':session.csrfToken||''}});if(!response.ok)throw new Error();const data=await response.json();location.assign(data.redirect)}catch{setError('Sign-out could not be completed. Please reload and try again.')}};
 if(pathname==='/forbidden'||(pathname==='/admin'&&!isAdmin)||(pathname==='/portal'&&!workspace)||(pathname==='/apps'&&!isAdmin&&!session.user.apps?.length))return <AuthCard title="Access isn’t available"><p className="hsl-auth-text">This account does not have permission to open that area.</p>{session.user.apps?.length?<a className="hsl-auth-button is-primary" href="/apps">Open your apps</a>:workspace?<a className="hsl-auth-button is-primary" href="/portal">Open customer portal</a>:null}<button type="button" className="hsl-auth-link" onClick={logout}>Sign out</button></AuthCard>;
 return <Dashboard apps={apps} workspace={workspace} appsContent={pathname==='/apps'?<AppsPage apps={apps} isAdmin={isAdmin}/>:undefined} admin={pathname==='/admin'||((pathname==='/me'||pathname==='/apps')&&isAdmin)} initialSection={new URLSearchParams(location.search).get('section')||undefined} accountContent={pathname==='/me'?<MePage user={session.user} onSignOut={logout} csrfToken={session.csrfToken||''} onChanged={async()=>{const response=await fetch('/api/auth/session',{cache:'no-store'});if(!response.ok)throw new Error('Please reload to refresh your account.');setSession(await response.json())}}/>:undefined} identity={{name:session.user.name,detail:(isAdmin?'Administrator':isCustomer?'Customer':'Member')+' · HackSpaceLabs',isAdmin,avatarVersion:session.user.avatarVersion}} onSignOut={logout} renderAdministration={(section,onNotice)=><IdentityAdmin key={section} section={section} csrfToken={session.csrfToken||''} onNotice={onNotice}/>}/>;
}
createRoot(document.getElementById('root')!).render(<App/>);
