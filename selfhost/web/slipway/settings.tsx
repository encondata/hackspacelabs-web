import {useEffect,useState,type FormEvent} from 'react';
import {KeyRound,Link2,Plus,ScrollText,Search,ShieldCheck,Trash2,Unlink,Users} from 'lucide-react';
import {dateTime,q,timeAgo,type ApiToken,type AuditEvent,type SlipwayUser} from './api';
import {Alert,Code,CopyButton,Empty,Facts,Heading,Loading,Panel,useAction,useLoad,useSlipway} from './ui';

type Tab='account'|'tokens'|'people'|'audit';

const GITHUB_ERRORS:Record<string,string>={
 cancelled:'GitHub authorization was cancelled.',
 failed:'GitHub could not be reached. Please try again.',
 state:'That GitHub sign-in link expired or was started by another account. Start again from here.',
 already_linked:'That GitHub account is already connected to another HackSpaceLabs user.',
};

export default function Settings(){
 const {can}=useSlipway();
 const params=new URLSearchParams(location.search);
 const [tab,setTab]=useState<Tab>(()=>{const t=params.get('tab');return t==='tokens'||t==='people'||t==='audit'?t:'account'});
 const tabs:[Tab,string,typeof Users][]=[['account','Account & GitHub',ShieldCheck],['tokens','API tokens',KeyRound],...(can('users:read')?[['people','People',Users] as [Tab,string,typeof Users]]:[]),...(can('audit:read')?[['audit','Audit log',ScrollText] as [Tab,string,typeof Users]]:[])];
 return <>
  <Heading title="Settings." sub="Your Slipway access, GitHub connection and API tokens."/>
  <div className="sw-tabs" role="tablist">{tabs.map(([id,label,Icon])=><button key={id} role="tab" aria-selected={tab===id} className={tab===id?'active':''} onClick={()=>setTab(id)}><Icon size={15}/>{label}</button>)}</div>
  {tab==='account'&&<Account/>}{tab==='tokens'&&<Tokens/>}{tab==='people'&&<People/>}{tab==='audit'&&<Audit/>}
 </>;
}

function Account(){
 const {api,me,info,notify,reloadMe}=useSlipway();
 const action=useAction();
 const [result,setResult]=useState<{tone:'success'|'error';text:string}|null>(null);
 useEffect(()=>{
  const params=new URLSearchParams(location.search);const linked=params.get('github');const failed=params.get('github_error');
  if(!linked&&!failed)return;
  setResult(linked==='linked'?{tone:'success',text:'GitHub connected. Slipway can now sync your repositories and deploy with your access.'}:{tone:'error',text:GITHUB_ERRORS[failed||'']||'GitHub could not be connected.'});
  params.delete('github');params.delete('github_error');
  history.replaceState(null,'',location.pathname+(params.toString()?'?'+params:''));
  if(linked)void reloadMe();
 },[reloadMe]);
 const connect=()=>void action.run(async()=>{const r=await api<{authorize_url:string}>('auth/github/link',{method:'POST'});location.assign(r.authorize_url)});
 const disconnect=()=>{if(window.confirm(`Disconnect @${me.github_login}? Slipway will no longer sync or deploy with your GitHub access.`))void action.run(async()=>{await api('auth/me/github',{method:'DELETE'});await reloadMe();notify('GitHub disconnected.')})};
 return <div className="sw-grid-2 sw-gap">
  <Panel title="Your access" sub="Roles are assigned by HackSpaceLabs administrators in Identity & access.">
   <div className="sw-panel-body"><Facts items={[['Name',me.display_name],['Username',me.username||'—'],['Email',me.email||'—'],['Slipway roles',me.roles.length?me.roles.map(r=><span key={r} className="p-badge blue sw-role">{r}</span>):'None']]}/>
    <details className="sw-details"><summary>What you can do ({me.permissions.length} permissions)</summary><p className="sw-mono sw-perms">{me.permissions.includes('*')?'Everything (*)':me.permissions.join(', ')||'Nothing yet'}</p></details></div>
  </Panel>
  <Panel title="GitHub" sub="Connect GitHub so Slipway can sync your repositories and deploy with your access.">
   <div className="sw-panel-body">
    {result&&<Alert tone={result.tone}>{result.text}</Alert>}<Alert>{action.error}</Alert>
    {!info.github_enabled?<p className="sw-hint">GitHub isn’t configured for this Slipway. An administrator needs to set up a GitHub OAuth app (see the deployment guide).{info.github_service_token?' Deploys use the shared service token meanwhile.':''}</p>
     :me.github_login?<><p className="sw-github"><Link2 size={16}/>Connected as <strong>@{me.github_login}</strong></p><button className="sw-secondary sw-danger" disabled={action.busy} onClick={disconnect}><Unlink size={14}/>Disconnect GitHub</button></>
     :<><p className="sw-hint">You’ll be sent to GitHub to approve access, then brought back here. GitHub is only used for repository access, not for signing in.</p><button className="button p-primary" disabled={action.busy} onClick={connect}><Link2 size={16}/>{action.busy?'Opening GitHub…':'Connect GitHub'}</button></>}
   </div>
  </Panel>
 </div>;
}

function Tokens(){
 const {api,notify}=useSlipway();
 const {data,error,loading,reload}=useLoad(()=>api<ApiToken[]>('tokens'),[api]);
 const [created,setCreated]=useState<string|null>(null);
 const action=useAction();
 function create(e:FormEvent<HTMLFormElement>){
  e.preventDefault();const form=e.currentTarget;const fields=new FormData(form);const days=String(fields.get('expires'));
  void action.run(async()=>{const r=await api<ApiToken&{token:string}>('tokens',{method:'POST',body:{name:String(fields.get('name')).trim(),expires_in_days:days?Number(days):null}});setCreated(r.token);form.reset();await reload()});
 }
 const revoke=(t:ApiToken)=>{if(window.confirm(`Revoke “${t.name}”? Anything using it stops working immediately.`))void action.run(async()=>{await api('tokens/'+t.id,{method:'DELETE'});notify(`Revoked ${t.name}.`);await reload()})};
 const example=`curl -H "Authorization: Bearer ${created||'$SLIPWAY_TOKEN'}" ${location.origin}/api/slipway/instances`;
 return <>
  <Panel title="Create an API token" sub="For scripts and CI. A token acts as you, with your current Slipway roles, and stops working if your account is disabled.">
   <form className="sw-form sw-panel-body" onSubmit={create}><fieldset disabled={action.busy}><div className="sw-inline-form"><label>Name<input name="name" required maxLength={100} placeholder="ci-deploys"/></label><label>Expires<select name="expires" defaultValue="90"><option value="30">In 30 days</option><option value="90">In 90 days</option><option value="365">In a year</option><option value="">Never</option></select></label><button className="button p-primary" type="submit"><Plus size={15}/>Create token</button></div></fieldset>
    <Alert>{action.error}</Alert>
    {created&&<Alert tone="success"><strong>Copy this token now — it won’t be shown again.</strong><div className="sw-token"><Code>{created}</Code><CopyButton text={created}/></div></Alert>}
    <p className="sw-hint">Use it against the portal:</p><Code>{example}</Code>
   </form>
  </Panel>
  <Panel title="Your tokens">{loading&&!data?<Loading what="tokens"/>:error?<div className="sw-panel-body"><Alert>{error}</Alert></div>:data&&data.length?<div className="p-table-wrap"><table><thead><tr><th>Name</th><th>Token</th><th>Created</th><th>Last used</th><th>Expires</th><th/></tr></thead><tbody>{data.map(t=><tr key={t.id}><td><strong>{t.name}</strong></td><td className="sw-mono">{t.prefix}…</td><td>{timeAgo(t.created_at)}</td><td>{timeAgo(t.last_used_at)}</td><td>{t.expires_at?dateTime(t.expires_at):'Never'}</td><td className="sw-cell-actions"><button className="sw-secondary sw-small sw-danger" disabled={action.busy} onClick={()=>revoke(t)}><Trash2 size={13}/>Revoke</button></td></tr>)}</tbody></table></div>:<Empty icon={<KeyRound size={24}/>} title="No API tokens"/>}</Panel>
 </>;
}

function People(){
 const {api,me,can,notify}=useSlipway();
 const {data,error,loading,reload}=useLoad(()=>api<SlipwayUser[]>('users'),[api]);
 const [search,setSearch]=useState('');const [open,setOpen]=useState<string|null>(null);
 const action=useAction();
 const write=can('users:write');
 const tokens=useLoad(()=>open&&write?api<ApiToken[]>(`users/${open}/tokens`):Promise.resolve([] as ApiToken[]),[api,open,write]);
 const rows=(data||[]).filter(u=>[u.display_name,u.username||'',u.email||'',u.github_login||''].some(s=>s.toLowerCase().includes(search.toLowerCase())));
 const unlink=(u:SlipwayUser)=>{if(window.confirm(`Remove @${u.github_login} from ${u.display_name}? They can connect GitHub again themselves.`))void action.run(async()=>{await api(`users/${u.id}/github`,{method:'DELETE'});notify(`Removed ${u.display_name}’s GitHub link.`);await reload()})};
 const revoke=(u:SlipwayUser,t:ApiToken)=>{if(window.confirm(`Revoke ${u.display_name}’s token “${t.name}”?`))void action.run(async()=>{await api(`users/${u.id}/tokens/${t.id}`,{method:'DELETE'});notify(`Revoked ${t.name}.`);await tokens.reload()})};
 return <Panel title="People" sub="Everyone who has used Slipway. Accounts and roles are managed in HackSpaceLabs Identity & access.">
  <div className="p-toolbar"><label className="p-search"><Search size={17}/><input aria-label="Search people" placeholder="Search people…" value={search} onChange={e=>setSearch(e.target.value)}/></label><span className="p-result-count">{data?`${rows.length} people`:''}</span></div>
  <Alert>{action.error||error}</Alert>
  {loading&&!data?<Loading what="people"/>:rows.length?<div className="p-table-wrap"><table><thead><tr><th>Person</th><th>Roles</th><th>GitHub</th><th>Last active</th><th/></tr></thead><tbody>{rows.flatMap(u=>[<tr key={u.id}>
   <td><strong>{u.display_name}{u.id===me.id?' (you)':''}</strong><small className="sw-sub">{u.username||u.email||'—'}{!u.is_active?' · disabled':''}</small></td>
   <td>{u.roles.length?u.roles.map(r=><span key={r} className="p-badge blue sw-role">{r}</span>):<span className="sw-muted">No access</span>}</td>
   <td>{u.github_login?`@${u.github_login}`:'—'}</td><td>{timeAgo(u.last_login_at)}</td>
   <td className="sw-cell-actions">{write&&u.github_login&&<button className="sw-secondary sw-small" disabled={action.busy} onClick={()=>unlink(u)}><Unlink size={13}/>Unlink GitHub</button>}{write&&<button className="sw-secondary sw-small" onClick={()=>setOpen(open===u.id?null:u.id)} aria-expanded={open===u.id}><KeyRound size={13}/>Tokens</button>}</td>
  </tr>,...(open===u.id?[<tr key={u.id+'-tokens'} className="sw-subrow"><td colSpan={5}>{tokens.loading?<Loading what="tokens"/>:tokens.error?<Alert>{tokens.error}</Alert>:tokens.data&&tokens.data.length?<ul className="sw-token-list">{tokens.data.map(t=><li key={t.id}><span><strong>{t.name}</strong> <span className="sw-mono">{t.prefix}…</span> · last used {timeAgo(t.last_used_at)}</span><button className="sw-secondary sw-small sw-danger" disabled={action.busy} onClick={()=>revoke(u,t)}>Revoke</button></li>)}</ul>:<p className="sw-muted">No API tokens.</p>}</td></tr>]:[])])}</tbody></table></div>:<Empty icon={<Users size={24}/>} title="No matching people"/>}
 </Panel>;
}

function Audit(){
 const {api}=useSlipway();
 const [action,setAction]=useState('');const [query,setQuery]=useState('');const [page,setPage]=useState(0);
 useEffect(()=>{const t=setTimeout(()=>{setQuery(action.trim());setPage(0)},300);return()=>clearTimeout(t)},[action]);
 const size=50;
 const {data,error,loading}=useLoad(()=>api<AuditEvent[]>('audit'+q({limit:size,offset:page*size,action:query})),[api,query,page]);
 return <Panel title="Audit log" sub="Who did what in Slipway.">
  <div className="p-toolbar"><label className="p-search"><Search size={17}/><input aria-label="Filter by action" placeholder="Filter by action, e.g. instance. or host.create" value={action} onChange={e=>setAction(e.target.value)} maxLength={64}/></label></div>
  <Alert>{error}</Alert>
  {loading&&!data?<Loading what="audit events"/>:data&&data.length?<div className="p-table-wrap"><table><thead><tr><th>When</th><th>Who</th><th>Action</th><th>What</th><th>From</th></tr></thead><tbody>{data.map(e=><tr key={e.id}><td title={dateTime(e.created_at)}>{timeAgo(e.created_at)}</td><td>{e.actor||'System'}</td><td className="sw-mono">{e.action}</td><td className="sw-wrap">{e.summary}</td><td className="sw-mono">{e.ip||'—'}</td></tr>)}</tbody></table></div>:<Empty icon={<ScrollText size={24}/>} title="No matching events"/>}
  <div className="ia-pagination sw-pagination"><button disabled={loading||page===0} onClick={()=>setPage(p=>p-1)}>Newer</button><span>Page {page+1}</span><button disabled={loading||!data||data.length<size} onClick={()=>setPage(p=>p+1)}>Older</button></div>
 </Panel>;
}
