import {createContext,useCallback,useContext,useEffect,useRef,useState,type ReactNode} from 'react';
import {Check,Copy,LoaderCircle,TriangleAlert} from 'lucide-react';
import {hasPermission,type Api,type SlipwayUser,type SystemInfo} from './api';

export type Section='overview'|'instances'|'deployments'|'repositories'|'hosts'|'settings';
export type Route={section:Section;id?:string;mode?:'new'|'edit';preset?:Record<string,string>};

type Ctx={api:Api;me:SlipwayUser;info:SystemInfo;notify:(text:string)=>void;go:(route:Route)=>void;reloadMe:()=>Promise<void>};
const SlipwayContext=createContext<Ctx|null>(null);
export const SlipwayProvider=SlipwayContext.Provider;
export function useSlipway(){
 const ctx=useContext(SlipwayContext);if(!ctx)throw new Error('Slipway context missing');
 return {...ctx,can:(permission:string)=>hasPermission(ctx.me,permission)};
}

/** Load data, with a reload function. Ignores results from stale requests. */
export function useLoad<T>(load:()=>Promise<T>,deps:unknown[]){
 const [state,setState]=useState<{data?:T;error?:string;loading:boolean}>({loading:true});
 const generation=useRef(0);
 const reload=useCallback(async()=>{
  const mine=++generation.current;setState(s=>({...s,loading:true,error:undefined}));
  try{const data=await load();if(mine===generation.current)setState({data,loading:false})}
  catch(e){if(mine===generation.current)setState(s=>({...s,error:(e as Error).message,loading:false}))}
 // eslint-disable-next-line react-hooks/exhaustive-deps
 },deps);
 useEffect(()=>{void reload()},[reload]);
 return {...state,reload};
}

/** Run a mutation with a busy flag; reports errors and success through the caller. */
export function useAction(){
 const [busy,setBusy]=useState(false);const [error,setError]=useState('');
 const run=useCallback(async(action:()=>Promise<unknown>,onDone?:()=>void)=>{
  setBusy(true);setError('');
  try{await action();onDone?.()}catch(e){setError((e as Error).message)}finally{setBusy(false)}
 },[]);
 return {busy,error,setError,run};
}

const tone:Record<string,string>={running:'good',healthy:'good',succeeded:'good',deploying:'blue',queued:'blue',warning:'warn',stopped:'neutral',created:'neutral',unknown:'neutral',cancelled:'neutral',failed:'bad',error:'bad',unreachable:'bad'};
const label:Record<string,string>={created:'Not deployed',unknown:'Not checked',running:'Running',healthy:'Healthy',deploying:'Deploying',queued:'Queued',warning:'Warning',stopped:'Stopped',cancelled:'Cancelled',failed:'Failed',error:'Error',unreachable:'Unreachable',succeeded:'Succeeded'};
export function Status({value,kind}:{value:string;kind?:'deployment'}){
 const text=kind==='deployment'&&value==='running'?'In progress':label[value]||value;
 const cls=kind==='deployment'&&value==='running'?'blue':tone[value]||'neutral';
 return <span className={'p-badge sw-badge '+cls}>{text}</span>;
}

export function Heading({eyebrow='SLIPWAY · LIVE',title,sub,actions,back}:{eyebrow?:string;title:ReactNode;sub?:ReactNode;actions?:ReactNode;back?:ReactNode}){
 return <div className="p-heading sw-heading"><div>{back}<p className="eyebrow">{eyebrow}</p><h1>{title}</h1>{sub&&<p>{sub}</p>}</div>{actions&&<div className="sw-actions">{actions}</div>}</div>;
}

export function Panel({title,sub,actions,children,foot,className=''}:{title?:ReactNode;sub?:ReactNode;actions?:ReactNode;children:ReactNode;foot?:ReactNode;className?:string}){
 return <section className={'p-panel sw-panel '+className}>{(title||actions)&&<div className="p-panel-head"><div>{title&&<h2>{title}</h2>}{sub&&<p>{sub}</p>}</div>{actions&&<div className="sw-actions">{actions}</div>}</div>}{children}{foot&&<div className="p-panel-foot">{foot}</div>}</section>;
}

export function Empty({icon,title,children}:{icon?:ReactNode;title:string;children?:ReactNode}){
 return <div className="p-empty sw-empty">{icon}<h3>{title}</h3>{children&&<div className="sw-empty-body">{children}</div>}</div>;
}

export function Alert({children,tone='error'}:{children:ReactNode;tone?:'error'|'warning'|'info'|'success'}){
 if(!children)return null;
 return <div className={'sw-alert '+tone} role={tone==='error'?'alert':'status'}>{tone!=='info'&&tone!=='success'&&<TriangleAlert size={16}/>}<div>{children}</div></div>;
}

export function Loading({what}:{what:string}){
 return <p className="sw-loading" role="status"><LoaderCircle size={16} className="sw-spin"/>Loading {what}…</p>;
}

export function Facts({items}:{items:[ReactNode,ReactNode][]}){
 return <dl className="sw-facts">{items.map(([k,v],i)=><div key={i}><dt>{k}</dt><dd>{v??'—'}</dd></div>)}</dl>;
}

export function CopyButton({text,label='Copy'}:{text:string;label?:string}){
 const [done,setDone]=useState(false);
 async function copy(){
  try{await navigator.clipboard.writeText(text)}catch{
   const area=document.createElement('textarea');area.value=text;area.setAttribute('readonly','');area.style.position='fixed';area.style.opacity='0';
   document.body.appendChild(area);area.select();try{document.execCommand('copy')}finally{area.remove()}
  }
  setDone(true);setTimeout(()=>setDone(false),1600);
 }
 return <button type="button" className="sw-secondary sw-small" onClick={()=>void copy()}>{done?<Check size={14}/>:<Copy size={14}/>}{done?'Copied':label}</button>;
}

export function Code({children,id}:{children:string;id?:string}){
 return <pre className="sw-code" id={id}>{children}</pre>;
}

export function Meter({label,percent}:{label:string;percent?:number}){
 const value=typeof percent==='number'?Math.max(0,Math.min(100,percent)):null;
 return <div className="sw-meter"><div className="sw-meter-head"><span>{label}</span><strong>{value===null?'—':`${value.toFixed(0)}%`}</strong></div><div className="sw-meter-track"><span className={value!==null&&value>=85?'high':value!==null&&value>=65?'mid':''} style={{width:`${value??0}%`}}/></div></div>;
}

export const shortSha=(sha:string|null|undefined)=>sha?sha.slice(0,7):'—';

export function LinkButton({children,onClick,title}:{children:ReactNode;onClick:()=>void;title?:string}){
 return <button type="button" className="sw-link" onClick={onClick} title={title}>{children}</button>;
}
