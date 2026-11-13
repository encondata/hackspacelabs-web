import {ArrowUpRight,Boxes,Check,ChevronRight,GitBranch,Rocket,Server} from 'lucide-react';
import {timeAgo,type Deployment,type Host,type Instance,type Repo} from './api';
import {Alert,Empty,Heading,Loading,Panel,Status,shortSha,useLoad,useSlipway} from './ui';

type Data={hosts:Host[];instances:Instance[];deployments:Deployment[];repos:Repo[]};

export default function Overview(){
 const {api,me,info,go,can}=useSlipway();
 const read={hosts:can('hosts:read'),instances:can('instances:read'),deployments:can('deployments:read'),repos:can('repos:read')};
 const {data,error,loading}=useLoad<Data>(async()=>{
  const [hosts,instances,deployments,repos]=await Promise.all([
   read.hosts?api<Host[]>('hosts'):[],read.instances?api<Instance[]>('instances'):[],
   read.deployments?api<Deployment[]>('deployments?limit=100'):[],read.repos?api<Repo[]>('repositories'):[],
  ]);
  return {hosts,instances,deployments,repos};
 },[api]);
 const hour=new Date().getHours();
 const greeting=hour<12?'Good morning':hour<18?'Good afternoon':'Good evening';
 const firstName=me.full_name.split(' ')[0]||me.display_name;
 if(!read.hosts&&!read.instances&&!read.deployments&&!read.repos)return <><Heading title={`${greeting}, ${firstName}.`}/><Empty title="Nothing to show yet">Your Slipway role does not include read access. Ask a HackSpaceLabs administrator to adjust it.</Empty></>;
 if(loading&&!data)return <><Heading title={`${greeting}, ${firstName}.`}/><Loading what="your deployments"/></>;
 if(!data)return <><Heading title={`${greeting}, ${firstName}.`}/><Alert>{error}</Alert></>;
 const {hosts,instances,deployments,repos}=data;
 const today=new Date();today.setHours(0,0,0,0);
 const todays=deployments.filter(d=>Date.parse(d.created_at)>=today.getTime());
 const steps:[string,boolean,()=>void][]=[];
 if(info.github_enabled)steps.push(['Connect your GitHub account',!!me.github_login,()=>go({section:'settings'})]);
 if(read.repos)steps.push(['Sync repositories',repos.length>0,()=>go({section:'repositories'})]);
 if(read.hosts)steps.push(['Add a Docker host',hosts.length>0,()=>go({section:'hosts'})],['Verify the host’s SSH key',hosts.some(h=>!!h.host_key_fingerprint),()=>go({section:'hosts'})]);
 if(read.instances&&can('instances:write'))steps.push(['Create your first instance',instances.length>0,()=>go({section:'instances',mode:'new'})]);
 const remaining=steps.filter(s=>!s[1]).length;
 const stats=[
  read.instances&&{label:'Running instances',value:instances.filter(i=>i.status==='running').length,sub:`of ${instances.length} configured`,color:'green'},
  read.hosts&&{label:'Healthy hosts',value:hosts.filter(h=>h.status==='healthy').length,sub:`${hosts.filter(h=>['warning','unreachable','error'].includes(h.status)).length} need attention`,color:''},
  read.deployments&&{label:'Deploys today',value:todays.length,sub:`${todays.filter(d=>d.status==='failed').length} failed`,color:todays.some(d=>d.status==='failed')?'amber':''},
  read.repos&&{label:'Deployable repositories',value:repos.filter(r=>r.deployable).length,sub:`of ${repos.length} synced`,color:''},
 ].filter(Boolean) as {label:string;value:number;sub:string;color:string}[];
 return <>
  <Heading title={`${greeting}, ${firstName}.`} sub="Your GitHub repositories, deployed to your own Docker hosts." actions={can('instances:write')&&read.instances?<button className="button p-primary" onClick={()=>go({section:'instances',mode:'new'})}><Rocket size={16}/>New instance</button>:undefined}/>
  {error&&<Alert>{error}</Alert>}
  <div className="p-stats sw-stats">{stats.map(s=><div className="p-stat" key={s.label}><span>{s.label}</span><strong className={s.color}>{String(s.value).padStart(2,'0')}</strong><small>{s.sub}</small></div>)}</div>
  {remaining>0&&<Panel className="sw-setup" title="Get set up" sub={`${steps.length-remaining} of ${steps.length} done`}>
   <ol className="sw-steps">{steps.map(([text,done,open])=><li key={text} className={done?'done':''}><span className="sw-step-mark">{done?<Check size={14}/>:null}</span><button type="button" onClick={open} disabled={done}>{text}{!done&&<ChevronRight size={14}/>}</button></li>)}</ol>
  </Panel>}
  <div className="p-overview-grid">
   {read.deployments&&<Panel title="Recent deployments" sub="The latest builds across every instance" actions={<button className="p-text-link" onClick={()=>go({section:'deployments'})}>All deployments <ArrowUpRight size={14}/></button>}>
    {deployments.length?<div className="sw-rows">{deployments.slice(0,6).map(d=><button key={d.id} className="sw-row" onClick={()=>go({section:'deployments',id:d.id})}><span className="p-icon"><Rocket size={17} strokeWidth={1.6}/></span><div><strong>{d.instance_name}</strong><small>{d.branch} · {shortSha(d.commit_sha)} · {d.commit_message||'No commit message'}</small></div><span className="sw-row-meta">{timeAgo(d.created_at)}</span><Status value={d.status} kind="deployment"/></button>)}</div>:<Empty icon={<Rocket size={24}/>} title="No deployments yet">Deploy an instance to see its build here.</Empty>}
   </Panel>}
   {read.hosts&&<Panel title="Hosts" sub="Docker hosts Slipway deploys to" actions={<button className="p-text-link" onClick={()=>go({section:'hosts'})}>All hosts <ArrowUpRight size={14}/></button>}>
    {hosts.length?<div className="sw-rows">{hosts.slice(0,6).map(h=><button key={h.id} className="sw-row" onClick={()=>go({section:'hosts',id:h.id})}><span className="p-icon automation"><Server size={17} strokeWidth={1.6}/></span><div><strong>{h.name}</strong><small>{h.username}@{h.hostname}{h.environment?` · ${h.environment}`:''}</small></div><Status value={h.status}/></button>)}</div>:<Empty icon={<Server size={24}/>} title="No hosts yet">Add a server with Docker that Slipway can reach over SSH.</Empty>}
   </Panel>}
  </div>
  {read.instances&&<Panel title="Instances" sub="What is deployed where" actions={<button className="p-text-link" onClick={()=>go({section:'instances'})}>All instances <ArrowUpRight size={14}/></button>}>
   {instances.length?<div className="sw-rows">{instances.slice(0,8).map(i=><button key={i.id} className="sw-row" onClick={()=>go({section:'instances',id:i.id})}><span className="p-icon software"><Boxes size={17} strokeWidth={1.6}/></span><div><strong>{i.name}</strong><small><GitBranch size={11}/> {i.repository} · {i.branch} → {i.host}</small></div><span className="sw-row-meta">{i.last_deployed_at?`Deployed ${timeAgo(i.last_deployed_at)}`:'Never deployed'}</span><Status value={i.status}/></button>)}</div>:<Empty icon={<Boxes size={24}/>} title="No instances yet">An instance is a repository branch deployed to a host.</Empty>}
  </Panel>}
 </>;
}
