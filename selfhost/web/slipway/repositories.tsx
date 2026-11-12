import {useEffect,useState} from 'react';
import {ExternalLink,GitBranch,RefreshCw,Rocket,Search} from 'lucide-react';
import {q,timeAgo,type Repo} from './api';
import {Alert,Empty,Heading,LinkButton,Loading,Panel,useAction,useLoad,useSlipway} from './ui';

type SyncOut={created:number;updated:number;total:number};

function buildKind(r:Repo){
 const c=r.detected_config||{};
 if(c.dockerfile&&c.compose_file)return 'Dockerfile · Compose';
 if(c.dockerfile)return 'Dockerfile';
 if(c.compose_file)return 'Compose';
 return 'Not deployable';
}

export default function Repositories(){
 const {api,me,info,go,can,notify}=useSlipway();
 const [search,setSearch]=useState('');const [query,setQuery]=useState('');const [deployable,setDeployable]=useState('all');
 useEffect(()=>{const t=setTimeout(()=>setQuery(search.trim()),250);return()=>clearTimeout(t)},[search]);
 const {data,error,loading,reload}=useLoad(()=>api<Repo[]>('repositories'+q({q:query,deployable:deployable==='yes'?true:undefined})),[api,query,deployable]);
 const sync=useAction();
 const canCreate=can('instances:write');
 return <>
  <Heading title="Repositories." sub="GitHub repositories Slipway knows about, with the build setup it detected." actions={can('repos:sync')&&<button className="button p-primary" disabled={sync.busy} onClick={()=>void sync.run(async()=>{const r=await api<SyncOut>('repositories/sync',{method:'POST'});notify(`Synced ${r.total} repositories from GitHub: ${r.created} new, ${r.updated} updated.`);await reload()})}><RefreshCw size={16} className={sync.busy?'sw-spin':''}/>{sync.busy?'Syncing…':'Sync from GitHub'}</button>}/>
  {info.github_enabled&&!me.github_login&&can('repos:sync')&&<Alert tone="warning">Syncing uses your own GitHub access. <LinkButton onClick={()=>go({section:'settings'})}>Connect GitHub</LinkButton> first.</Alert>}
  <Alert>{sync.error||error}</Alert>
  <Panel>
   <div className="p-toolbar"><label className="p-search"><Search size={17}/><input aria-label="Search repositories" placeholder="Search repositories…" value={search} onChange={e=>setSearch(e.target.value)}/></label><select aria-label="Filter repositories" value={deployable} onChange={e=>setDeployable(e.target.value)}><option value="all">All repositories</option><option value="yes">Deployable only</option></select><span className="p-result-count">{data?`${data.length} repositories`:''}</span></div>
   {loading&&!data?<Loading what="repositories"/>:data&&data.length?<div className="p-table-wrap"><table><thead><tr><th>Repository</th><th>Build</th><th>Default branch</th><th>Visibility</th><th>Last push</th><th/></tr></thead><tbody>{data.map(r=><tr key={r.id}>
    <td><div className="p-table-system"><span className="p-icon"><GitBranch size={17} strokeWidth={1.6}/></span><div><strong><a className="sw-ext" href={r.html_url} target="_blank" rel="noreferrer noopener">{r.full_name}<ExternalLink size={11}/></a></strong><small>{r.description||(r.language?r.language:'No description')}{r.archived?' · Archived':''}</small></div></div></td>
    <td>{r.deployable?<span className="p-badge good">{buildKind(r)}</span>:<span className="p-badge neutral">{buildKind(r)}</span>}</td>
    <td className="sw-mono">{r.default_branch}{!r.default_branch_usable&&<small className="sw-warn-text"> (name too long to use)</small>}</td>
    <td>{r.visibility}</td><td>{timeAgo(r.pushed_at)}</td>
    <td className="sw-cell-actions">{canCreate&&r.deployable&&!r.archived&&<button className="sw-secondary sw-small" onClick={()=>go({section:'instances',mode:'new',preset:{repository_id:r.id}})}><Rocket size={13}/>Deploy</button>}</td>
   </tr>)}</tbody></table></div>:<Empty icon={<GitBranch size={24}/>} title={query||deployable==='yes'?'No matching repositories':'No repositories yet'}>{query||deployable==='yes'?'Try another search or filter.':can('repos:sync')?'Sync from GitHub to bring in the repositories you can access.':'Someone with sync access needs to bring in repositories from GitHub.'}</Empty>}
   {data&&data.length>0&&<div className="p-panel-foot">Build setup is detected from each repository’s default branch.</div>}
  </Panel>
 </>;
}
