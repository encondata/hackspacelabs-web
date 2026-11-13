import {useEffect,useMemo,useState,type FormEvent} from 'react';
import {ArrowLeft,Boxes,Pencil,Play,Plus,RotateCw,Rocket,Search,Square,Terminal,Trash2,X} from 'lucide-react';
import {q,timeAgo,type ActionResult,type Deployment,type Host,type Instance,type PortMapping,type Repo,type VolumeMapping} from './api';
import {Alert,Code,Empty,Facts,Heading,LinkButton,Loading,Panel,Status,shortSha,useAction,useLoad,useSlipway} from './ui';

export default function Instances({id,mode,preset}:{id?:string;mode?:'new'|'edit';preset?:Record<string,string>}){
 if(mode==='new')return <InstanceForm preset={preset}/>;
 if(id&&mode==='edit')return <InstanceForm id={id}/>;
 if(id)return <InstanceDetail id={id}/>;
 return <InstanceList/>;
}

function InstanceList(){
 const {api,go,can}=useSlipway();
 const {data,error,loading}=useLoad(()=>api<Instance[]>('instances'),[api]);
 const [search,setSearch]=useState('');const [status,setStatus]=useState('all');
 const rows=(data||[]).filter(i=>(status==='all'||i.status===status)&&[i.name,i.repository,i.host,i.branch].some(s=>s.toLowerCase().includes(search.toLowerCase())));
 return <>
  <Heading title="Instances." sub="Each instance is one repository branch, built and run on one host." actions={can('instances:write')&&<button className="button p-primary" onClick={()=>go({section:'instances',mode:'new'})}><Plus size={16}/>New instance</button>}/>
  <Alert>{error}</Alert>
  <Panel>
   <div className="p-toolbar"><label className="p-search"><Search size={17}/><input aria-label="Search instances" placeholder="Search instances, repositories or hosts…" value={search} onChange={e=>setSearch(e.target.value)}/></label><select aria-label="Instance status" value={status} onChange={e=>setStatus(e.target.value)}><option value="all">All statuses</option>{['running','deploying','stopped','failed','created'].map(s=><option key={s} value={s}>{s==='created'?'Not deployed':s[0].toUpperCase()+s.slice(1)}</option>)}</select><span className="p-result-count">{data?`${rows.length} instances`:''}</span></div>
   {loading&&!data?<Loading what="instances"/>:rows.length?<div className="p-table-wrap"><table><thead><tr><th>Instance</th><th>Repository</th><th>Host</th><th>Status</th><th>Commit</th><th>Last deploy</th></tr></thead><tbody>{rows.map(i=><tr key={i.id} className="sw-click" onClick={()=>go({section:'instances',id:i.id})}>
    <td><div className="p-table-system"><span className="p-icon software"><Boxes size={17} strokeWidth={1.6}/></span><div><strong><LinkButton onClick={()=>go({section:'instances',id:i.id})}>{i.name}</LinkButton></strong><small>{i.build_source==='compose'?'Compose':'Dockerfile'}{i.ports.length?` · ports ${i.ports.map(p=>p.host).join(', ')}`:''}</small></div></div></td>
    <td>{i.repository}<small className="sw-sub">{i.branch}</small></td><td>{i.host}</td><td><Status value={i.status}/></td><td className="sw-mono">{shortSha(i.current_commit_sha)}</td><td>{timeAgo(i.last_deployed_at)}</td>
   </tr>)}</tbody></table></div>:<Empty icon={<Boxes size={24}/>} title={data?.length?'No matching instances':'No instances yet'}>{data?.length?'Try another search or status.':can('instances:write')?'Create one from a deployable repository.':'Nothing has been set up yet.'}</Empty>}
  </Panel>
 </>;
}

type Form={name:string;repository_id:string;branch:string;host_id:string;build_source:'dockerfile'|'compose';dockerfile_path:string;build_context:string;compose_file:string;ports:{host:string;container:string;protocol:'tcp'|'udp'}[];volumes:VolumeMapping[];env:string;deploy:boolean;clear_env:boolean};

function parseEnv(text:string):{env:Record<string,string>;error?:string}{
 const env:Record<string,string>={};
 for(const [n,raw] of text.split('\n').entries()){
  const line=raw.trim();if(!line||line.startsWith('#'))continue;
  const at=line.indexOf('=');if(at<1)return {env,error:`Line ${n+1}: use KEY=value.`};
  env[line.slice(0,at).trim()]=raw.slice(raw.indexOf('=')+1);
 }
 return {env};
}
const envText=(env:Record<string,string>)=>Object.entries(env).map(([k,v])=>`${k}=${v}`).join('\n');

function InstanceForm({id,preset}:{id?:string;preset?:Record<string,string>}){
 const {api,go,can,notify}=useSlipway();
 const refs=useLoad(async()=>{
  const [repos,hosts,instance]=await Promise.all([api<Repo[]>('repositories?deployable=true'),api<Host[]>('hosts'),id?api<Instance>('instances/'+id):Promise.resolve(null)]);
  let env:Record<string,string>|null=null;let envError='';
  if(instance&&instance.env_keys.length&&!instance.env_unreadable){try{env=await api<Record<string,string>>(`instances/${id}/env`)}catch(e){envError=(e as Error).message}}
  return {repos,hosts,instance,env,envError};
 },[api,id]);
 const [form,setForm]=useState<Form|null>(null);
 const [branches,setBranches]=useState<string[]>([]);const [branchError,setBranchError]=useState('');
 const action=useAction();
 const data=refs.data;const instance=data?.instance;
 useEffect(()=>{
  if(!data||form)return;
  const repo=data.repos.find(r=>r.id===(instance?.repository_id||preset?.repository_id))||(instance?undefined:data.repos[0]);
  const detected=repo?.detected_config||{};
  setForm(instance?{name:instance.name,repository_id:instance.repository_id,branch:instance.branch,host_id:instance.host_id,build_source:instance.build_source,dockerfile_path:instance.dockerfile_path,build_context:instance.build_context,compose_file:instance.compose_file,ports:instance.ports.map(p=>({host:String(p.host),container:String(p.container),protocol:p.protocol||'tcp'})),volumes:instance.volumes,env:data.env?envText(data.env):'',deploy:false,clear_env:false}
   :{name:repo?.name||'',repository_id:repo?.id||'',branch:repo&&repo.default_branch_usable?repo.default_branch:'',host_id:data.hosts.find(h=>h.status==='healthy')?.id||data.hosts[0]?.id||'',build_source:detected.dockerfile||!detected.compose_file?'dockerfile':'compose',dockerfile_path:'Dockerfile',build_context:'.',compose_file:detected.compose_file||'docker-compose.yml',ports:[],volumes:[],env:'',deploy:can('deployments:create'),clear_env:false});
 },[data,form,instance,preset,can]);
 const repoId=form?.repository_id;
 useEffect(()=>{
  if(!repoId)return;let live=true;setBranchError('');
  api<string[]>(`repositories/${repoId}/branches`).then(b=>{if(live)setBranches(b)}).catch(e=>{if(live){setBranches([]);setBranchError((e as Error).message)}});
  return()=>{live=false};
 },[api,repoId]);
 const locked=!!instance&&(instance.status!=='created'||!!instance.last_deployed_at);
 const repo=useMemo(()=>data?.repos.find(r=>r.id===form?.repository_id),[data,form?.repository_id]);
 if(refs.loading&&!data)return <Loading what="instance settings"/>;
 if(!data||!form)return <Alert>{refs.error}</Alert>;
 const set=<K extends keyof Form>(key:K,value:Form[K])=>setForm({...form,[key]:value});
 function chooseRepo(repoId:string){
  const r=data!.repos.find(x=>x.id===repoId);const d=r?.detected_config||{};
  setForm({...form!,repository_id:repoId,name:form!.name||r?.name||'',branch:r&&r.default_branch_usable?r.default_branch:'',build_source:d.dockerfile||!d.compose_file?'dockerfile':'compose',compose_file:d.compose_file||form!.compose_file});
 }
 function submit(e:FormEvent){
  e.preventDefault();
  const parsed=parseEnv(form!.env);if(parsed.error){action.setError(parsed.error);return}
  const ports:PortMapping[]=form!.ports.filter(p=>p.host||p.container).map(p=>({host:Number(p.host),container:Number(p.container),protocol:p.protocol}));
  const volumes=form!.volumes.filter(v=>v.source||v.target);
  const body:Record<string,unknown>={name:form!.name.trim(),branch:form!.branch,ports,volumes};
  if(!locked)Object.assign(body,{host_id:form!.host_id,build_source:form!.build_source,dockerfile_path:form!.dockerfile_path,build_context:form!.build_context,compose_file:form!.compose_file});
  const envChanged=!instance||form!.env!==(data!.env?envText(data!.env):'');
  if(envChanged)body.env=parsed.env;
  if(instance&&form!.clear_env)body.clear_env=true;
  if(!instance)Object.assign(body,{repository_id:form!.repository_id,deploy:form!.deploy});
  void action.run(async()=>{
   const saved=await api<Instance>(instance?'instances/'+instance.id:'instances',{method:instance?'PATCH':'POST',body});
   notify(instance?`Saved ${saved.name}.`:form!.deploy?`Created ${saved.name} and started its first deployment.`:`Created ${saved.name}.`);
   go({section:'instances',id:saved.id});
  });
 }
 const back=<LinkButton onClick={()=>go(instance?{section:'instances',id:instance.id}:{section:'instances'})}><ArrowLeft size={13}/>{instance?instance.name:'Instances'}</LinkButton>;
 if(!instance&&(!data.repos.length||!data.hosts.length))return <><Heading back={back} title="New instance."/><Empty icon={<Boxes size={24}/>} title={!data.repos.length?'No deployable repositories':'No hosts yet'}>{!data.repos.length?<>Sync repositories with a Dockerfile or Compose file first. <LinkButton onClick={()=>go({section:'repositories'})}>Open repositories</LinkButton></>:<>Add a Docker host first. <LinkButton onClick={()=>go({section:'hosts',mode:'new'})}>Add a host</LinkButton></>}</Empty></>;
 return <>
  <Heading back={back} title={instance?`Edit ${instance.name}.`:'New instance.'} sub={instance?`${instance.repository} on ${instance.host}`:'Pick a repository branch and the host to run it on.'}/>
  <Alert>{action.error||refs.error}</Alert>
  <form className="sw-form" onSubmit={submit}><fieldset disabled={action.busy}>
   <Panel title="Source and placement">
    <div className="sw-panel-body">
     <div className="sw-grid-2">
      <label>Name<input required maxLength={100} value={form.name} onChange={e=>set('name',e.target.value)}/></label>
      <label>Repository{instance?<input readOnly value={instance.repository}/>:<select required value={form.repository_id} onChange={e=>chooseRepo(e.target.value)}>{data.repos.map(r=><option key={r.id} value={r.id}>{r.full_name}</option>)}</select>}</label>
      <label>Branch{branches.length?<select required value={form.branch} onChange={e=>set('branch',e.target.value)}>{!branches.includes(form.branch)&&<option value={form.branch}>{form.branch||'Choose a branch'}</option>}{branches.map(b=><option key={b} value={b}>{b}</option>)}</select>:<input required value={form.branch} onChange={e=>set('branch',e.target.value)} pattern="[A-Za-z0-9._/\-]+" placeholder={repo?.default_branch||'main'}/>}{branchError&&<small className="sw-warn-text">Couldn’t list branches: {branchError}</small>}</label>
      <label>Host<select required disabled={locked} value={form.host_id} onChange={e=>set('host_id',e.target.value)}>{data.hosts.map(h=><option key={h.id} value={h.id}>{h.name} ({h.hostname}){h.host_key_fingerprint?'':' — not verified'}</option>)}</select></label>
     </div>
     {locked&&<p className="sw-hint">The host and build settings are fixed once an instance has been deployed. To move it, delete it and create it again.</p>}
    </div>
   </Panel>
   <Panel title="Build">
    <div className="sw-panel-body">
     <div className="sw-segmented" role="radiogroup" aria-label="Build source">{(['dockerfile','compose'] as const).map(s=><button type="button" key={s} role="radio" aria-checked={form.build_source===s} disabled={locked} className={form.build_source===s?'active':''} onClick={()=>set('build_source',s)}>{s==='dockerfile'?'Dockerfile':'Docker Compose'}</button>)}</div>
     {form.build_source==='dockerfile'?<div className="sw-grid-2"><label>Dockerfile path<input required disabled={locked} value={form.dockerfile_path} onChange={e=>set('dockerfile_path',e.target.value)}/></label><label>Build context<input required disabled={locked} value={form.build_context} onChange={e=>set('build_context',e.target.value)}/></label></div>
      :<label>Compose file<input required disabled={locked} value={form.compose_file} onChange={e=>set('compose_file',e.target.value)}/><small className="sw-warn-text">A Compose instance runs whatever its branch’s Compose file defines, as root on the host.</small></label>}
     {repo&&<p className="sw-hint">Detected in {repo.full_name}: {[repo.detected_config.dockerfile&&'Dockerfile',repo.detected_config.compose_file].filter(Boolean).join(' and ')||'nothing deployable'}.</p>}
    </div>
   </Panel>
   <Panel title="Ports and volumes" sub={form.build_source==='compose'?'Compose files usually declare these themselves.':'Published from the container to the host.'}>
    <div className="sw-panel-body">
     <h3 className="sw-h3">Ports</h3>
     {form.ports.map((p,i)=><div className="sw-pair-row" key={i}><input aria-label="Host port" type="number" min={1} max={65535} required placeholder="Host" value={p.host} onChange={e=>set('ports',form.ports.map((x,j)=>j===i?{...x,host:e.target.value}:x))}/><span>→</span><input aria-label="Container port" type="number" min={1} max={65535} required placeholder="Container" value={p.container} onChange={e=>set('ports',form.ports.map((x,j)=>j===i?{...x,container:e.target.value}:x))}/><select aria-label="Protocol" value={p.protocol} onChange={e=>set('ports',form.ports.map((x,j)=>j===i?{...x,protocol:e.target.value as 'tcp'|'udp'}:x))}><option value="tcp">TCP</option><option value="udp">UDP</option></select><button type="button" className="p-icon-button" aria-label="Remove port" onClick={()=>set('ports',form.ports.filter((_,j)=>j!==i))}><X size={16}/></button></div>)}
     <button type="button" className="sw-secondary sw-small" onClick={()=>set('ports',[...form.ports,{host:'',container:'',protocol:'tcp'}])}><Plus size={13}/>Add port</button>
     <h3 className="sw-h3">Volumes</h3>
     {form.volumes.map((v,i)=><div className="sw-pair-row" key={i}><input aria-label="Host path or volume name" required placeholder="/srv/app/data or volume-name" value={v.source} onChange={e=>set('volumes',form.volumes.map((x,j)=>j===i?{...x,source:e.target.value}:x))}/><span>→</span><input aria-label="Container path" required placeholder="/data" value={v.target} onChange={e=>set('volumes',form.volumes.map((x,j)=>j===i?{...x,target:e.target.value}:x))}/><button type="button" className="p-icon-button" aria-label="Remove volume" onClick={()=>set('volumes',form.volumes.filter((_,j)=>j!==i))}><X size={16}/></button></div>)}
     <button type="button" className="sw-secondary sw-small" onClick={()=>set('volumes',[...form.volumes,{source:'',target:''}])}><Plus size={13}/>Add volume</button>
    </div>
   </Panel>
   <Panel title="Environment variables" sub="Stored encrypted and written to the host as an .env file on deploy.">
    <div className="sw-panel-body">
     {instance?.env_unreadable?<Alert tone="warning">The stored variables can’t be decrypted with the current encryption key, so deploys are refused. Re-enter them below, or clear them.<label className="sw-check"><input type="checkbox" checked={form.clear_env} onChange={e=>set('clear_env',e.target.checked)}/>Clear the stored variables</label></Alert>:data.envError?<Alert tone="warning">{data.envError}</Alert>:null}
     <label>One per line, KEY=value<textarea rows={6} className="sw-mono" value={form.env} onChange={e=>set('env',e.target.value)} placeholder={'DATABASE_URL=postgres://…\nLOG_LEVEL=info'} spellCheck={false}/></label>
    </div>
   </Panel>
   <div className="sw-form-actions">{!instance&&can('deployments:create')&&<label className="sw-check"><input type="checkbox" checked={form.deploy} onChange={e=>set('deploy',e.target.checked)}/>Deploy right away</label>}<button type="button" className="sw-secondary" onClick={()=>go(instance?{section:'instances',id:instance.id}:{section:'instances'})}>Cancel</button><button className="button p-primary" type="submit">{action.busy?'Saving…':instance?'Save instance':'Create instance'}</button></div>
  </fieldset></form>
 </>;
}

type Container={Names:string;Image:string;State:string;Status:string;Ports:string;RunningFor:string};

function InstanceDetail({id}:{id:string}){
 const {api,go,can,notify}=useSlipway();
 const {data:instance,error,loading,reload}=useLoad(()=>api<Instance>('instances/'+id),[api,id]);
 const deployments=useLoad(()=>can('deployments:read')?api<Deployment[]>(`instances/${id}/deployments${q({limit:10})}`):Promise.resolve([]),[api,id]);
 const containers=useLoad(()=>instance&&instance.status!=='created'?api<Container[]>(`instances/${id}/containers`):Promise.resolve([] as Container[]),[api,id,instance?.status]);
 const [logs,setLogs]=useState<string|null>(null);
 const action=useAction();
 useEffect(()=>{
  if(instance?.status!=='deploying')return;
  const t=setInterval(()=>{void reload();void deployments.reload()},4000);return()=>clearInterval(t);
 // eslint-disable-next-line react-hooks/exhaustive-deps
 },[instance?.status]);
 if(loading&&!instance)return <Loading what="instance"/>;
 if(!instance)return <><Heading title="Instance not found." back={<LinkButton onClick={()=>go({section:'instances'})}><ArrowLeft size={13}/>Instances</LinkButton>}/><Alert>{error}</Alert></>;
 const busy=action.busy||instance.status==='deploying';
 const deploy=()=>void action.run(async()=>{const d=await api<Deployment>(`instances/${id}/deploy`,{method:'POST'});notify(`Deployment of ${instance.name} started.`);go({section:'deployments',id:d.id})});
 const operate=(verb:'start'|'stop'|'restart')=>void action.run(async()=>{const r=await api<ActionResult>(`instances/${id}/actions/${verb}`,{method:'POST'});notify(`${verb[0].toUpperCase()+verb.slice(1)} sent to ${instance.name}.`);if(r.output)setLogs(r.output);await reload();await containers.reload()});
 const remove=()=>{
  if(!window.confirm(`Delete ${instance.name}? Its containers and files are removed from ${instance.host}.`))return;
  void action.run(async()=>{const r=await api<{ok?:boolean;warning?:string}|undefined>(`instances/${id}`,{method:'DELETE'});notify(r?.warning?`${instance.name} deleted. ${r.warning}`:`${instance.name} deleted.`);go({section:'instances'})});
 };
 const loadLogs=()=>void action.run(async()=>{const r=await api<ActionResult>(`instances/${id}/logs${q({tail:300})}`);setLogs(r.output||'(no output)')});
 return <>
  <Heading back={<LinkButton onClick={()=>go({section:'instances'})}><ArrowLeft size={13}/>Instances</LinkButton>} title={<>{instance.name} <Status value={instance.status}/></>} sub={<>{instance.repository} · <span className="sw-mono">{instance.branch}</span> → <LinkButton onClick={()=>go({section:'hosts',id:instance.host_id})}>{instance.host}</LinkButton></>}
   actions={<>{can('deployments:create')&&<button className="button p-primary" disabled={busy||instance.env_unreadable} onClick={deploy} title={instance.env_unreadable?'Re-enter or clear the environment variables first':undefined}><Rocket size={16}/>{instance.status==='deploying'?'Deploying…':'Deploy'}</button>}
    {can('instances:operate')&&instance.status!=='created'&&<>{instance.status==='stopped'?<button className="sw-secondary" disabled={busy} onClick={()=>operate('start')}><Play size={14}/>Start</button>:<button className="sw-secondary" disabled={busy} onClick={()=>operate('stop')}><Square size={14}/>Stop</button>}<button className="sw-secondary" disabled={busy} onClick={()=>operate('restart')}><RotateCw size={14}/>Restart</button></>}
    {can('instances:write')&&<><button className="sw-secondary" disabled={action.busy} onClick={()=>go({section:'instances',id,mode:'edit'})}><Pencil size={14}/>Edit</button><button className="sw-secondary sw-danger" disabled={busy} onClick={remove}><Trash2 size={14}/>Delete</button></>}</>}/>
  <Alert>{action.error}</Alert>
  {instance.env_unreadable&&<Alert tone="warning">This instance’s environment variables can’t be decrypted, so deploys are refused until they are re-entered or cleared. {can('instances:write')&&<LinkButton onClick={()=>go({section:'instances',id,mode:'edit'})}>Edit variables</LinkButton>}</Alert>}
  <div className="sw-grid-2 sw-gap">
   <Panel title="Configuration"><div className="sw-panel-body"><Facts items={[
    ['Build',instance.build_source==='compose'?<>Compose · <span className="sw-mono">{instance.compose_file}</span></>:<>Dockerfile · <span className="sw-mono">{instance.dockerfile_path}</span> in <span className="sw-mono">{instance.build_context}</span></>],
    ['Current commit',<span className="sw-mono">{shortSha(instance.current_commit_sha)}</span>],
    ['Last deployed',instance.last_deployed_at?timeAgo(instance.last_deployed_at):'Never'],
    ['Ports',instance.ports.length?instance.ports.map(p=>`${p.host}→${p.container}/${p.protocol||'tcp'}`).join(', '):'None'],
    ['Volumes',instance.volumes.length?<span className="sw-mono">{instance.volumes.map(v=>`${v.source}:${v.target}`).join(', ')}</span>:'None'],
    ['Environment',instance.env_keys.length?<span className="sw-mono">{instance.env_keys.join(', ')}</span>:'None'],
    ['Slug',<span className="sw-mono">{instance.slug}</span>],
   ]}/></div></Panel>
   <Panel title="Containers" sub={instance.status==='created'?'Not deployed yet':'Live from the host'} actions={instance.status!=='created'&&<button className="sw-secondary sw-small" disabled={containers.loading} onClick={()=>void containers.reload()}><RotateCw size={13}/>Refresh</button>}>
    {containers.error?<div className="sw-panel-body"><Alert tone="warning">{containers.error}</Alert></div>:containers.loading&&!containers.data?<Loading what="containers"/>:containers.data&&containers.data.length?<div className="p-table-wrap"><table><thead><tr><th>Container</th><th>State</th><th>Ports</th></tr></thead><tbody>{containers.data.map(c=><tr key={c.Names}><td><strong className="sw-mono">{c.Names}</strong><small className="sw-sub">{c.Image}</small></td><td><Status value={c.State==='running'?'running':c.State==='exited'?'stopped':c.State}/><small className="sw-sub">{c.Status}</small></td><td className="sw-mono sw-wrap">{c.Ports||'—'}</td></tr>)}</tbody></table></div>:<Empty title={instance.status==='created'?'Deploy to start containers':'No containers running'}/>}
   </Panel>
  </div>
  {can('logs:read')&&instance.status!=='created'&&<Panel title="Application logs" sub="The last 300 lines from the running containers" actions={<button className="sw-secondary sw-small" disabled={action.busy} onClick={loadLogs}><Terminal size={13}/>{logs===null?'Load logs':'Reload'}</button>}>{logs!==null&&<div className="sw-panel-body"><Code>{logs}</Code></div>}</Panel>}
  {can('deployments:read')&&<Panel title="Deployments" actions={<button className="p-text-link" onClick={()=>go({section:'deployments',preset:{instance_id:id}})}>All for this instance</button>}>{deployments.data&&deployments.data.length?<div className="sw-rows">{deployments.data.map(d=><button key={d.id} className="sw-row" onClick={()=>go({section:'deployments',id:d.id})}><span className="p-icon"><Rocket size={17} strokeWidth={1.6}/></span><div><strong>{d.commit_message||'Deployment'}</strong><small>{d.branch} · {shortSha(d.commit_sha)}{d.triggered_by?` · by ${d.triggered_by}`:''}</small></div><span className="sw-row-meta">{timeAgo(d.created_at)}</span><Status value={d.status} kind="deployment"/></button>)}</div>:deployments.loading?<Loading what="deployments"/>:<Empty title="No deployments yet"/>}</Panel>}
 </>;
}
