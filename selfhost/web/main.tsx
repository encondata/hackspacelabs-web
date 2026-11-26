import MePage from './me';
import IdentityAdmin from './identity-admin';
import AppsPage from './apps';
import './suite.css';
import React,{useEffect,useState} from 'react';
import {createRoot} from 'react-dom/client';
import Home from '../../app/page';
import Dashboard,{type SuiteApp} from '../../app/portal/dashboard';
import '../../app/globals.css';
import './production.css';
type User={id:string;email:string;name:string;roles:string[];apps?:string[];avatarVersion?:string|null};
type Session={authenticated:boolean;user?:User;apps?:SuiteApp[];csrfToken?:string};
const pages=['/admin','/portal','/me','/apps'];
function AccountFrame({children}:{children:React.ReactNode}){return <div className="account-page"><header className="header wrap"><a className="brand" href="/" aria-label="HackSpaceLabs home"><img src="/hackspacelabs-logo.png" alt="HackSpaceLabs"/></a><a className="home-link" href="/">← Back to home</a></header><main className="account-main wrap"><aside className="account-intro"><p className="eyebrow"><span className="dot"/>HACKSPACELABS ACCOUNT</p><h1>Your world.<br/><em>Connected.</em></h1><p>One account for HackSpaceLabs and connected apps.</p></aside><section className="account-card">{children}</section></main></div>}
function Login(){const params=new URLSearchParams(location.search);const target=params.get('returnTo');const error=params.get('error');return <AccountFrame><p className="eyebrow">WELCOME BACK</p><h2>Log in to HackSpaceLabs.</h2><p className="account-description">Continue to your HackSpaceLabs account to sign in securely.</p>{error&&<p role="alert" className="form-message">{error==='expired'?'Your sign-in request expired. Please start again.':'We couldn’t complete sign-in. Check that your account has portal access, then try again.'}</p>}<a className="button account-submit" href={'/api/auth/login'+(target&&pages.includes(target)?'?returnTo='+encodeURIComponent(target):'')}>Continue to sign in <span aria-hidden="true">↗</span></a><p className="form-fineprint">You’ll continue to your configured HackSpaceLabs identity service. Contact your administrator if you need a password reset.</p><div className="account-card-bottom"><span>Need an account? Ask your HackSpaceLabs administrator.</span></div></AccountFrame>}
function App(){const pathname=location.pathname;const [session,setSession]=useState<Session|null>(null);const [error,setError]=useState('');
 useEffect(()=>{if(![...pages,'/forbidden'].includes(pathname))return;let live=true;async function check(){try{const response=await fetch('/api/auth/session',{cache:'no-store',credentials:'same-origin'});if(response.status===401){location.replace('/login?returnTo='+encodeURIComponent(pages.includes(pathname)?pathname:'/portal'));return}if(!response.ok)throw new Error();const next=await response.json();if(live){setSession(next);setError('')}}catch{if(live){setSession(null);setError('Account service unavailable. Please reload to try again.')}}}void check();const interval=setInterval(check,60000);return()=>{live=false;clearInterval(interval)}},[pathname]);
 if(pathname==='/')return <Home/>;if(pathname==='/login')return <Login/>;
 if(error)return <AccountFrame><h2>Unable to connect.</h2><p role="alert">{error}</p><a className="button" href={pathname}>Try again</a></AccountFrame>;
 if(!session?.user)return <AccountFrame><h2>Checking your account…</h2><p role="status">Please wait.</p></AccountFrame>;
 const isAdmin=session.user.roles.includes('admin');const isCustomer=session.user.roles.includes('customer');const apps=session.apps||[];
 // People who only hold app roles see the launcher and their account, not the sample workspace.
 const workspace=isAdmin||isCustomer;
 const logout=async()=>{try{const response=await fetch('/api/auth/logout',{method:'POST',credentials:'same-origin',headers:{'x-csrf-token':session.csrfToken||''}});if(!response.ok)throw new Error();const data=await response.json();location.assign(data.redirect)}catch{setError('Sign-out could not be completed. Please reload and try again.')}};
 if(pathname==='/forbidden'||(pathname==='/admin'&&!isAdmin)||(pathname==='/portal'&&!workspace)||(pathname==='/apps'&&!isAdmin&&!session.user.apps?.length))return <AccountFrame><h2>Access isn’t available.</h2><p>This account does not have permission to open that area.</p>{session.user.apps?.length?<a className="button" href="/apps">Open your apps</a>:workspace?<a className="button" href="/portal">Open customer portal</a>:null}<button className="auth-link" onClick={logout}>Sign out</button></AccountFrame>;
 return <Dashboard apps={apps} workspace={workspace} appsContent={pathname==='/apps'?<AppsPage apps={apps} isAdmin={isAdmin}/>:undefined} admin={pathname==='/admin'||((pathname==='/me'||pathname==='/apps')&&isAdmin)} initialSection={new URLSearchParams(location.search).get('section')||undefined} accountContent={pathname==='/me'?<MePage user={session.user} onSignOut={logout} csrfToken={session.csrfToken||''} onChanged={async()=>{const response=await fetch('/api/auth/session',{cache:'no-store'});if(!response.ok)throw new Error('Please reload to refresh your account.');setSession(await response.json())}}/>:undefined} identity={{name:session.user.name,isAdmin,avatarVersion:session.user.avatarVersion}} onSignOut={logout} renderAdministration={(section,onNotice)=><IdentityAdmin key={section} section={section} csrfToken={session.csrfToken||''} onNotice={onNotice}/>}/>;
}
createRoot(document.getElementById('root')!).render(<App/>);
