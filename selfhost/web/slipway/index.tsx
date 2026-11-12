import {useCallback,useEffect,useMemo,useRef,useState} from 'react';
import {Ship} from 'lucide-react';
import {ApiError,createApi,type SlipwayUser,type SystemInfo} from './api';
import {Alert,Empty,Heading,Loading,SlipwayProvider,type Route,type Section} from './ui';
import Overview from './overview';
import Repositories from './repositories';
import Hosts from './hosts';
import Instances from './instances';
import Deployments from './deployments';
import Settings from './settings';
import './slipway.css';

// Portal sections owned by Slipway ("slipway:<section>"), in sidebar order.
export const SLIPWAY_SECTIONS:{id:string;section:Section;label:string}[]=[
 {id:'slipway:overview',section:'overview',label:'Overview'},
 {id:'slipway:instances',section:'instances',label:'Instances'},
 {id:'slipway:deployments',section:'deployments',label:'Deployments'},
 {id:'slipway:repositories',section:'repositories',label:'Repositories'},
 {id:'slipway:hosts',section:'hosts',label:'Hosts'},
 {id:'slipway:settings',section:'settings',label:'Settings'},
];
export const isSlipwaySection=(id:string)=>SLIPWAY_SECTIONS.some(s=>s.id===id);
export const slipwayLabel=(id:string)=>SLIPWAY_SECTIONS.find(s=>s.id===id)?.label||'Slipway';
const toSection=(id:string):Section=>SLIPWAY_SECTIONS.find(s=>s.id===id)?.section||'overview';

function routeFromUrl(section:Section):Route{
 const params=new URLSearchParams(location.search);
 const id=params.get('id')||undefined;const mode=params.get('mode');
 return {section,id:id&&/^[0-9a-f-]{36}$/i.test(id)?id:undefined,mode:mode==='new'||mode==='edit'?mode:undefined};
}

export default function SlipwayApp({section:sectionId,csrfToken,onNotice,onSection}:{section:string;csrfToken:string;onNotice:(text:string)=>void;onSection:(section:string)=>void}){
 const api=useMemo(()=>createApi(csrfToken),[csrfToken]);
 const [me,setMe]=useState<SlipwayUser|null>(null);const [info,setInfo]=useState<SystemInfo|null>(null);
 const [failure,setFailure]=useState<{status:number;message:string}|null>(null);
 const section=toSection(sectionId);
 const [route,setRoute]=useState<Route>(()=>routeFromUrl(section));
 const pending=useRef<Route|null>(null);

 const load=useCallback(async()=>{
  try{const [user,system]=await Promise.all([api<SlipwayUser>('auth/me'),api<SystemInfo>('system/info')]);setMe(user);setInfo(system);setFailure(null)}
  catch(e){setFailure({status:e instanceof ApiError?e.status:0,message:(e as Error).message})}
 },[api]);
 useEffect(()=>{void load()},[load]);
 const reloadMe=useCallback(async()=>{setMe(await api<SlipwayUser>('auth/me'))},[api]);

 // The portal sidebar changes the section. An in-app navigation to another section (go) carries its detail
 // (id, mode, preset) along; a plain sidebar click opens the section's list. The first run keeps the route
 // read from the address bar, so deep links to a host or deployment work.
 const first=useRef(true);
 useEffect(()=>{
  if(first.current){first.current=false;return}
  const next=pending.current?.section===section?pending.current:{section};
  pending.current=null;
  setRoute(next);
 },[section]);

 const go=useCallback((next:Route)=>{
  window.scrollTo({top:0});
  if(next.section!==section){pending.current=next;onSection(SLIPWAY_SECTIONS.find(s=>s.section===next.section)!.id)}
  else setRoute(next);
 },[section,onSection]);

 // Keep the address bar shareable: ?section=slipway:<section>&id=<uuid>&mode=<new|edit>.
 useEffect(()=>{
  const params=new URLSearchParams(location.search);
  params.set('section','slipway:'+route.section);
  for(const key of ['id','mode','tab'])params.delete(key);
  if(route.id)params.set('id',route.id);if(route.mode)params.set('mode',route.mode);
  const next=location.pathname+'?'+params.toString();
  if(next!==location.pathname+location.search)history.replaceState(null,'',next);
 },[route]);

 if(failure)return <><Heading eyebrow="SLIPWAY" title={failure.status===403?'Slipway isn’t available to you.':'Slipway is unavailable.'}/>
  {failure.status===403?<Empty icon={<Ship size={26}/>} title="No Slipway role">Ask a HackSpaceLabs administrator to give your account a Slipway role in Identity & access.</Empty>:<><Alert>{failure.message}</Alert><button className="sw-secondary" onClick={()=>void load()}>Try again</button></>}</>;
 if(!me||!info)return <Loading what="Slipway"/>;
 const view=route.section;
 // The portal clears its notice when the section changes, so deliver notices after any navigation in progress.
 const notify=(text:string)=>{setTimeout(()=>onNotice(text),0)};
 return <SlipwayProvider value={{api,me,info,notify,go,reloadMe}}>
  <div className="sw" key={view+(route.id||'')+(route.mode||'')}>
   {view==='overview'&&<Overview/>}
   {view==='instances'&&<Instances id={route.id} mode={route.mode} preset={route.preset}/>}
   {view==='deployments'&&<Deployments id={route.id} preset={route.preset}/>}
   {view==='repositories'&&<Repositories/>}
   {view==='hosts'&&<Hosts id={route.id} mode={route.mode}/>}
   {view==='settings'&&<Settings/>}
  </div>
 </SlipwayProvider>;
}
