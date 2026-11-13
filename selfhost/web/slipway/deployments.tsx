import {useEffect,useRef,useState} from 'react';
import {ArrowLeft,Rocket} from 'lucide-react';
import {dateTime,duration,q,timeAgo,type Deployment,type DeploymentDetail,type Instance} from './api';
import {Alert,Empty,Facts,Heading,LinkButton,Loading,Panel,Status,shortSha,useAction,useLoad,useSlipway} from './ui';

const ACTIVE=new Set(['queued','running']);

export default function Deployments({id,preset}:{id?:string;preset?:Record<string,string>}){
 return id?<DeploymentView id={id}/>:<DeploymentList instanceId={preset?.instance_id}/>;
}

function DeploymentList({instanceId}:{instanceId?:string}){
 const {api,go,can}=useSlipway();
 const [status,setStatus]=useState('');const [instance,setInstance]=useState(instanceId||'');
 const instances=useLoad(()=>can('instances:read')?api<Instance[]>('instances'):Promise.resolve([]),[api]);
 const {data,error,loading,reload}=useLoad(()=>api<Deployment[]>('deployments'+q({status,instance_id:instance,limit:100})),[api,status,instance]);
 const active=!!data?.some(d=>ACTIVE.has(d.status));
 useEffect(()=>{if(!active)return;const t=setInterval(()=>void reload(),5000);return()=>clearInterval(t)},[active,reload]);
 return <>
  <Heading title="Deployments." sub="Every build Slipway has run, newest first."/>
  <Alert>{error}</Alert>
  <Panel>
   <div className="p-toolbar"><select aria-label="Deployment status" value={status} onChange={e=>setStatus(e.target.value)}><option value="">All statuses</option><option value="queued">Queued</option><option value="running">In progress</option><option value="succeeded">Succeeded</option><option value="failed">Failed</option><option value="cancelled">Cancelled</option></select>{instances.data&&instances.data.length>0&&<select aria-label="Instance" value={instance} onChange={e=>setInstance(e.target.value)}><option value="">All instances</option>{instances.data.map(i=><option key={i.id} value={i.id}>{i.name}</option>)}</select>}<span className="p-result-count">{data?`${data.length} deployments${data.length===100?' (latest 100)':''}`:''}</span></div>
   {loading&&!data?<Loading what="deployments"/>:data&&data.length?<div className="p-table-wrap"><table><thead><tr><th>Instance</th><th>Commit</th><th>Status</th><th>By</th><th>Started</th><th>Duration</th></tr></thead><tbody>{data.map(d=><tr key={d.id} className="sw-click" onClick={()=>go({section:'deployments',id:d.id})}>
    <td><strong><LinkButton onClick={()=>go({section:'deployments',id:d.id})}>{d.instance_name}</LinkButton></strong><small className="sw-sub">{d.branch}</small></td>
    <td><span className="sw-mono">{shortSha(d.commit_sha)}</span><small className="sw-sub sw-ellipsis">{d.commit_message||'—'}</small></td>
    <td><Status value={d.status} kind="deployment"/></td><td>{d.triggered_by||'—'}</td><td>{timeAgo(d.started_at||d.created_at)}</td><td>{duration(d.started_at,d.finished_at)}</td>
   </tr>)}</tbody></table></div>:<Empty icon={<Rocket size={24}/>} title={status||instance?'No matching deployments':'No deployments yet'}>{status||instance?'Try another filter.':'Deploy an instance to see its build here.'}</Empty>}
  </Panel>
 </>;
}

function DeploymentView({id}:{id:string}){
 const {api,go,can,notify}=useSlipway();
 const [dep,setDep]=useState<DeploymentDetail|null>(null);const [error,setError]=useState('');
 const offset=useRef(0);const logRef=useRef<HTMLPreElement>(null);const follow=useRef(true);
 const action=useAction();
 useEffect(()=>{
  let live=true;let timer:ReturnType<typeof setTimeout>|undefined;offset.current=0;setDep(null);setError('');
  async function poll(){
   try{
    const from=offset.current;
    const next=await api<DeploymentDetail>(`deployments/${id}`+q({log_offset:from}));
    if(!live)return;
    setDep(current=>({...next,log:(from===0?'':current?.log||'')+next.log}));
    offset.current=next.log_offset;
    if(ACTIVE.has(next.status))timer=setTimeout(poll,1500);
   }catch(e){if(live){setError((e as Error).message);timer=setTimeout(poll,5000)}}
  }
  void poll();
  return()=>{live=false;if(timer)clearTimeout(timer)};
 },[api,id]);
 useEffect(()=>{const el=logRef.current;if(el&&follow.current)el.scrollTop=el.scrollHeight},[dep?.log]);
 if(!dep)return error?<><Heading title="Deployment not found." back={<LinkButton onClick={()=>go({section:'deployments'})}><ArrowLeft size={13}/>Deployments</LinkButton>}/><Alert>{error}</Alert></>:<Loading what="deployment"/>;
 const redeploy=()=>void action.run(async()=>{const d=await api<Deployment>(`instances/${dep.instance_id}/deploy`,{method:'POST'});notify(`Redeploying ${dep.instance_name}.`);go({section:'deployments',id:d.id})});
 const active=ACTIVE.has(dep.status);
 return <>
  <Heading back={<LinkButton onClick={()=>go({section:'deployments'})}><ArrowLeft size={13}/>Deployments</LinkButton>} title={<>{dep.instance_name} <Status value={dep.status} kind="deployment"/></>} sub={<><span className="sw-mono">{dep.branch} · {shortSha(dep.commit_sha)}</span>{dep.commit_message?` — ${dep.commit_message}`:''}</>}
   actions={<><button className="sw-secondary" onClick={()=>go({section:'instances',id:dep.instance_id})}>Open instance</button>{can('deployments:create')&&!active&&<button className="button p-primary" disabled={action.busy} onClick={redeploy}><Rocket size={16}/>Deploy again</button>}</>}/>
  <Alert>{action.error}</Alert>
  {dep.error&&<Alert><strong>Deployment failed:</strong> {dep.error}</Alert>}
  {error&&<Alert tone="warning">{error} Retrying…</Alert>}
  <Panel title="Details"><div className="sw-panel-body"><Facts items={[['Triggered by',dep.triggered_by||'—'],['Commit author',dep.commit_author||'—'],['Queued',dateTime(dep.created_at)],['Started',dateTime(dep.started_at)],['Finished',active?'Still running':dateTime(dep.finished_at)],['Duration',duration(dep.started_at,dep.finished_at)]]}/></div></Panel>
  <Panel title="Build log" sub={active?'Updating live':'Complete'} className="sw-log-panel">
   <pre ref={logRef} className="sw-log" onScroll={e=>{const el=e.currentTarget;follow.current=el.scrollHeight-el.scrollTop-el.clientHeight<40}} aria-live={active?'polite':undefined}>{dep.log||(active?'Waiting for the build to start…':'No output was recorded.')}</pre>
  </Panel>
 </>;
}
