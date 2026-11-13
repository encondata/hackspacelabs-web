import {useState,type FormEvent} from 'react';
import {Activity,ArrowLeft,Boxes,Fingerprint,KeyRound,Pencil,Plus,Server,Trash2} from 'lucide-react';
import {dateTime,shellQuote,timeAgo,type Host,type Instance} from './api';
import {Alert,Code,CopyButton,Empty,Facts,Heading,LinkButton,Loading,Meter,Panel,Status,useAction,useLoad,useSlipway} from './ui';

export default function Hosts({id,mode}:{id?:string;mode?:'new'|'edit'}){
 if(mode==='new')return <HostForm/>;
 if(id&&mode==='edit')return <HostForm id={id}/>;
 if(id)return <HostDetail id={id}/>;
 return <HostList/>;
}

function HostList(){
 const {api,go,can}=useSlipway();
 const {data,error,loading}=useLoad(()=>api<Host[]>('hosts'),[api]);
 return <>
  <Heading title="Hosts." sub="Servers with Docker that Slipway deploys to over SSH." actions={can('hosts:write')&&<button className="button p-primary" onClick={()=>go({section:'hosts',mode:'new'})}><Plus size={16}/>Add host</button>}/>
  <Alert>{error}</Alert>
  <Panel>{loading&&!data?<Loading what="hosts"/>:data&&data.length?<div className="p-table-wrap"><table><thead><tr><th>Host</th><th>Environment</th><th>Status</th><th>Docker</th><th>Containers</th><th>Last checked</th></tr></thead><tbody>{data.map(h=><tr key={h.id} className="sw-click" onClick={()=>go({section:'hosts',id:h.id})}>
   <td><div className="p-table-system"><span className="p-icon automation"><Server size={17} strokeWidth={1.6}/></span><div><strong><LinkButton onClick={()=>go({section:'hosts',id:h.id})}>{h.name}</LinkButton></strong><small className="sw-mono">{h.username}@{h.hostname}{h.port!==22?`:${h.port}`:''}</small></div></div></td>
   <td>{h.environment||'—'}</td><td><Status value={h.status}/>{!h.host_key_fingerprint&&<small className="sw-warn-text"> Not verified</small>}</td>
   <td className="sw-mono">{h.docker_version||'—'}</td><td>{h.metrics?.containers_running??'—'}</td><td>{timeAgo(h.last_checked_at)}</td>
  </tr>)}</tbody></table></div>:<Empty icon={<Server size={24}/>} title="No hosts yet">{can('hosts:write')?'Add a server that has Docker installed and that Slipway can reach over SSH.':'Ask someone with host access to add a server.'}</Empty>}</Panel>
 </>;
}

type HostFormData={name:string;hostname:string;port:string;username:string;environment:string;description:string;deploy_root:string;auth_method:'generate'|'key'|'password';private_key:string;key_passphrase:string;password:string};

function HostForm({id}:{id?:string}){
 const {api,info,go,notify}=useSlipway();
 const existing=useLoad(()=>id?api<Host>('hosts/'+id):Promise.resolve(null),[api,id]);
 const [form,setForm]=useState<HostFormData|null>(null);
 const action=useAction();
 const host=existing.data;
 const value:HostFormData=form??{name:host?.name??'',hostname:host?.hostname??'',port:String(host?.port??22),username:host?.username??'deploy',environment:host?.environment??'',description:host?.description??'',deploy_root:host?.deploy_root??'',auth_method:id?(host?.auth_method??'key'):'generate',private_key:'',key_passphrase:'',password:''};
 const set=(key:keyof HostFormData,v:string)=>setForm({...value,[key]:v});
 if(id&&existing.loading&&!host)return <Loading what="host"/>;
 function submit(e:FormEvent){
  e.preventDefault();
  const body:Record<string,unknown>={name:value.name.trim(),hostname:value.hostname.trim(),port:Number(value.port)||22,username:value.username.trim(),environment:value.environment.trim(),description:value.description.trim()};
  if(value.deploy_root.trim())body.deploy_root=value.deploy_root.trim();
  const changingAuth=!id||value.auth_method!==host?.auth_method||value.private_key||value.password;
  if(changingAuth){
   body.auth_method=value.auth_method;
   if(value.auth_method==='key'){body.private_key=value.private_key;if(value.key_passphrase)body.key_passphrase=value.key_passphrase}
   if(value.auth_method==='password')body.password=value.password;
  }
  void action.run(async()=>{
   const saved=await api<Host>(id?'hosts/'+id:'hosts',{method:id?'PATCH':'POST',body});
   notify(id?`Saved ${saved.name}.`:`Added ${saved.name}. Finish setting it up below.`);
   go({section:'hosts',id:saved.id});
  });
 }
 const back=<LinkButton onClick={()=>go(id?{section:'hosts',id}:{section:'hosts'})}><ArrowLeft size={13}/>{id?host?.name:'Hosts'}</LinkButton>;
 return <>
  <Heading back={back} title={id?`Edit ${host?.name??'host'}.`:'Add a host.'} sub="Slipway connects over SSH, pins the server’s host key on first contact, and runs Docker there."/>
  <Alert>{action.error||existing.error}</Alert>
  <Panel><form className="sw-form" onSubmit={submit}><fieldset disabled={action.busy}>
   <div className="sw-grid-2">
    <label>Name<input required value={value.name} onChange={e=>set('name',e.target.value)} pattern="[A-Za-z0-9][A-Za-z0-9 ._\-]{0,63}" placeholder="prod-01"/><small>Letters, numbers, spaces, dots, dashes and underscores.</small></label>
    <label>Environment<input value={value.environment} onChange={e=>set('environment',e.target.value)} maxLength={32} placeholder="production"/></label>
    <label>Hostname or IP address<input required value={value.hostname} onChange={e=>set('hostname',e.target.value)} placeholder="10.0.1.12"/></label>
    <label>SSH port<input required type="number" min={1} max={65535} value={value.port} onChange={e=>set('port',e.target.value)}/></label>
    <label>SSH user<input required value={value.username} onChange={e=>set('username',e.target.value)} pattern="[a-z_][a-z0-9_.\-]*" maxLength={64}/><small>Needs to be in the docker group.</small></label>
    <label>Deploy directory<input value={value.deploy_root} onChange={e=>set('deploy_root',e.target.value)} placeholder={info.default_deploy_root}/><small>Where releases are unpacked. Defaults to {info.default_deploy_root}.</small></label>
   </div>
   <label>Description<input value={value.description} onChange={e=>set('description',e.target.value)} maxLength={255}/></label>
   <fieldset className="sw-choice"><legend>Sign-in</legend>
    {!id&&<label className="sw-radio"><input type="radio" name="auth" checked={value.auth_method==='generate'} onChange={()=>set('auth_method','generate')}/><span><strong>Generate a key for me</strong><small>Recommended. Slipway creates a key pair; you add its public key to the server.</small></span></label>}
    <label className="sw-radio"><input type="radio" name="auth" checked={value.auth_method==='key'} onChange={()=>set('auth_method','key')}/><span><strong>Use my private key</strong><small>Paste an OpenSSH private key. It is stored encrypted.</small></span></label>
    <label className="sw-radio"><input type="radio" name="auth" checked={value.auth_method==='password'} onChange={()=>set('auth_method','password')}/><span><strong>Password</strong><small>Stored encrypted. Keys are safer.</small></span></label>
   </fieldset>
   {value.auth_method==='key'&&<><label>Private key<textarea rows={5} className="sw-mono" required={!id||host?.auth_method!=='key'} value={value.private_key} onChange={e=>set('private_key',e.target.value)} placeholder={id&&host?.auth_method==='key'?'Leave blank to keep the current key':'-----BEGIN OPENSSH PRIVATE KEY-----'}/></label><label>Key passphrase (if any)<input type="password" autoComplete="off" value={value.key_passphrase} onChange={e=>set('key_passphrase',e.target.value)}/></label></>}
   {value.auth_method==='password'&&<label>Password<input type="password" autoComplete="new-password" required={!id||host?.auth_method!=='password'} value={value.password} onChange={e=>set('password',e.target.value)} placeholder={id&&host?.auth_method==='password'?'Leave blank to keep the current password':''}/></label>}
   {id&&<p className="sw-hint">Changing the address clears the pinned host key; verify the connection again afterwards.</p>}
   <div className="sw-form-actions"><button type="button" className="sw-secondary" onClick={()=>go(id?{section:'hosts',id}:{section:'hosts'})}>Cancel</button><button className="button p-primary" type="submit">{action.busy?'Saving…':id?'Save host':'Add host'}</button></div>
  </fieldset></form></Panel>
 </>;
}

function HostDetail({id}:{id:string}){
 const {api,info,go,can,notify}=useSlipway();
 const {data:host,error,loading,reload}=useLoad(()=>api<Host>('hosts/'+id),[api,id]);
 const instances=useLoad(()=>can('instances:read')?api<Instance[]>('instances?host_id='+encodeURIComponent(id)):Promise.resolve([]),[api,id]);
 const action=useAction();
 if(loading&&!host)return <Loading what="host"/>;
 if(!host)return <><Heading title="Host not found." back={<LinkButton onClick={()=>go({section:'hosts'})}><ArrowLeft size={13}/>Hosts</LinkButton>}/><Alert>{error}</Alert></>;
 const pinned=!!host.host_key_fingerprint;const write=can('hosts:write');
 const check=()=>void action.run(async()=>{const h=await api<Host>(`hosts/${id}/check`,{method:'POST'});notify(h.status==='healthy'?`${h.name} is healthy.`:`${h.name}: ${h.last_error||h.status}`);await reload()});
 const resetKey=(message:string)=>{if(window.confirm(message))void action.run(async()=>{await api(`hosts/${id}/reset-host-key`,{method:'POST'});notify('Pinned host key cleared. Verify the connection again.');await reload()})};
 const remove=()=>{if(window.confirm(`Remove ${host.name} from Slipway? Nothing on the host is changed.`))void action.run(async()=>{await api('hosts/'+id,{method:'DELETE'});notify(`${host.name} removed.`);go({section:'hosts'})})};
 const install=host.public_key?`mkdir -p ~/.ssh && chmod 700 ~/.ssh && printf '%s\\n' ${shellQuote(host.public_key)} >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys\nsudo mkdir -p ${shellQuote(host.deploy_root)} && sudo chown ${shellQuote(host.username)} ${shellQuote(host.deploy_root)} && sudo usermod -aG docker ${shellQuote(host.username)}`:'';
 const m=host.metrics||{};
 return <>
  <Heading back={<LinkButton onClick={()=>go({section:'hosts'})}><ArrowLeft size={13}/>Hosts</LinkButton>} title={<>{host.name} <Status value={host.status}/></>} sub={<span className="sw-mono">{host.username}@{host.hostname}{host.port!==22?`:${host.port}`:''}{host.environment?` · ${host.environment}`:''}</span>}
   actions={<>{(pinned||write)&&<button className="button p-primary" disabled={action.busy} onClick={check}><Activity size={16}/>{action.busy?'Checking…':pinned?'Run health check':'Verify connection'}</button>}{write&&<button className="sw-secondary" onClick={()=>go({section:'hosts',id,mode:'edit'})}><Pencil size={14}/>Edit</button>}{write&&<button className="sw-secondary sw-danger" disabled={action.busy} onClick={remove}><Trash2 size={14}/>Remove</button>}</>}/>
  <Alert>{action.error}</Alert>
  {host.status==='error'?<Alert><strong>Host key mismatch.</strong> {host.last_error} {write&&<button className="sw-secondary sw-small sw-danger" onClick={()=>resetKey('Only do this if you know the server was rebuilt. Reset the pinned key?')}>Reset pinned key</button>}</Alert>
   :host.last_error?<Alert tone="warning"><strong>{host.status==='unreachable'?'Cannot reach host':'Docker problem'}:</strong> <span className="sw-mono">{host.last_error}</span></Alert>:null}
  {!pinned&&host.public_key&&<Panel className="sw-setup" title={`Finish setting up ${host.name}`} sub="Authorize Slipway’s key on the server, then verify the connection.">
   <div className="sw-panel-body sw-stack">
    <p><strong>1.</strong> On the server, as <code>{host.username}</code>, run:</p>
    <Code>{install}</Code><div><CopyButton text={install} label="Copy commands"/> <CopyButton text={host.public_key} label="Copy public key only"/></div>
    <p><strong>2.</strong> Click <em>Verify connection</em>. Slipway records the server’s host key fingerprint and refuses to connect if it ever changes.</p>
   </div>
  </Panel>}
  <div className="sw-grid-2 sw-gap">
   <Panel title="Health" sub={<>Last checked {timeAgo(host.last_checked_at)}{info.host_poll_interval?` · checked automatically every ${Math.max(1,Math.round(info.host_poll_interval/60))} min`:''}</>}>
    <div className="sw-panel-body">{m.cpu_percent!==undefined&&<div className="sw-grid-2 sw-meters"><Meter label={`CPU load (${m.cpus??'?'} cores)`} percent={m.cpu_percent}/><Meter label={`Memory (${m.mem_total_mb?(m.mem_total_mb/1024).toFixed(1):'?'} GB)`} percent={m.mem_percent}/></div>}
     <Facts items={[['Docker',<span className="sw-mono">{host.docker_version||'—'}</span>],['Operating system',host.os_info||'—'],['Running containers',m.containers_running??'—'],['Deploy directory',<span className="sw-mono">{host.deploy_root}</span>]]}/></div>
   </Panel>
   <Panel title="SSH" sub={host.auth_method==='key'?'Key-based sign-in':'Password sign-in'}>
    <div className="sw-panel-body"><Facts items={[[<><Fingerprint size={13}/> Host key</>,pinned?<span className="sw-mono sw-break">{host.host_key_fingerprint}</span>:<span className="sw-muted">Not verified yet</span>],[<><KeyRound size={13}/> Slipway’s key</>,host.public_key?<CopyButton text={host.public_key} label="Copy public key"/>:'—'],['Added',dateTime(host.created_at)],...(host.description?[['Description',host.description] as [string,string]]:[])]}/>
     {pinned&&write&&host.status!=='error'&&<button className="sw-secondary sw-small sw-danger" onClick={()=>resetKey('Forget the pinned host key? The next check will trust whatever key the server presents.')}>Reset pinned key</button>}</div>
   </Panel>
  </div>
  {can('instances:read')&&<Panel title="Instances on this host">{instances.data&&instances.data.length?<div className="sw-rows">{instances.data.map(i=><button key={i.id} className="sw-row" onClick={()=>go({section:'instances',id:i.id})}><span className="p-icon software"><Boxes size={17} strokeWidth={1.6}/></span><div><strong>{i.name}</strong><small>{i.repository} · {i.branch}</small></div><span className="sw-row-meta">{i.last_deployed_at?`Deployed ${timeAgo(i.last_deployed_at)}`:'Never deployed'}</span><Status value={i.status}/></button>)}</div>:instances.loading?<Loading what="instances"/>:<Empty title="Nothing deployed here yet"/>}</Panel>}
 </>;
}
