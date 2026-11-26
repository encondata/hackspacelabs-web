import {useEffect,useState} from 'react';
// Access to the suite apps (PLAN.md 1g, D17): app roles granted to people and to nested groups, effective access with
// where it comes from, and per app who can use it. Used by identity-admin.tsx.
type RecordData=Record<string,any>;
type Api=(path:string,method?:string,body?:unknown)=>Promise<any>;
type Run=(action:()=>Promise<void>,message:string)=>Promise<void>;
export type TreeNode={id:string;name:string;path:string;subGroups:TreeNode[]};
const pretty=(path:string)=>path.replace(/^\//,'').split('/').join(' / ');
export function flattenTree(tree:TreeNode[],depth=0):(TreeNode&{depth:number})[]{return tree.flatMap(node=>[{...node,depth},...flattenTree(node.subGroups||[],depth+1)])}
function matches(node:TreeNode,term:string):boolean{return node.path.toLowerCase().includes(term)||(node.subGroups||[]).some(child=>matches(child,term))}
export function GroupTree({tree,search,selectedId,busy,onOpen}:{tree:TreeNode[];search:string;selectedId?:string;busy:boolean;onOpen:(id:string)=>void}){
 const term=search.trim().toLowerCase();const shown=tree.filter(node=>!term||matches(node,term));
 if(!shown.length)return null;
 return <ul className="ia-tree">{shown.map(node=><li key={node.id}><button disabled={busy} className={'ia-record '+(selectedId===node.id?'active':'')} aria-current={selectedId===node.id?'true':undefined} onClick={()=>onOpen(node.id)}><span><strong>{node.name}</strong><small>{node.subGroups?.length?node.subGroups.length+' subgroup'+(node.subGroups.length===1?'':'s'):'No subgroups'}</small></span><span className="ia-state">›</span></button><GroupTree tree={node.subGroups||[]} search={search} selectedId={selectedId} busy={busy} onOpen={onOpen}/></li>)}</ul>;
}
function source(s:RecordData,selfId?:string){return s.type==='direct'?'granted directly':s.type==='group'?(s.id===selfId?'from this group':'from group '+pretty(s.path)):'through a composite role'}
// One row per app: the role the app uses (the highest), then every role held and where it comes from.
export function AccessTable({access,selfId,empty}:{access:RecordData[];selfId?:string;empty:string}){
 const held=(access||[]).filter(a=>a.role);
 if(!held.length)return <p className="ia-hint">{empty}</p>;
 return <div className="ia-table-wrap"><table className="ia-access"><thead><tr><th scope="col">App</th><th scope="col">Role used</th><th scope="col">Where it comes from</th></tr></thead><tbody>{held.map(a=><tr key={a.app}><td>{a.name}</td><td>{a.role}</td><td>{a.roles.map((r:RecordData)=><small key={r.name}>{r.name}: {r.sources.map((s:RecordData)=>source(s,selfId)).join('; ')}</small>)}</td></tr>)}</tbody></table></div>;
}
// Direct app roles of a person or a group, one form per installed app.
export function AppRoles({kind,record,apps,api,run,onSaved}:{kind:'users'|'groups';record:RecordData;apps:RecordData[];api:Api;run:Run;onSaved:()=>Promise<void>}){
 const [draft,setDraft]=useState<Record<string,string[]>>({});
 useEffect(()=>{setDraft(Object.fromEntries(apps.map(app=>[app.id,(record.appRoles?.[app.id]||[]).map((r:RecordData)=>r.name)])))},[record,apps]);
 const installed=apps.filter(app=>app.installed);
 return <div className="ia-block"><h3>App roles</h3><p className="ia-hint">{kind==='groups'?'Members of this group, and of every group inside it, get these roles.':'Roles granted to this person directly, on top of what their groups give.'} No role means no access to that app. Each app uses the highest role it finds.</p>
 {installed.length?installed.map(app=><form className="ia-app-roles" key={app.id} onSubmit={e=>{e.preventDefault();void run(async()=>{await api(kind+'/'+record.id+'/app-roles/'+app.id,'PUT',{roles:draft[app.id]||[]});await onSaved()},app.name+' roles saved.')}}><h4>{app.name}</h4>{app.roles.map((role:RecordData)=><label className="ia-check" key={role.name}><input type="checkbox" checked={(draft[app.id]||[]).includes(role.name)} onChange={e=>setDraft(current=>({...current,[app.id]:e.target.checked?[...(current[app.id]||[]),role.name]:(current[app.id]||[]).filter(n=>n!==role.name)}))}/>{role.name}<span className="ia-role-note">{String(role.description||'').replace(new RegExp('^'+app.name+': '),'')}</span></label>)}<button className="ia-secondary">Save {app.name} roles</button></form>)
 :<p className="ia-hint">No suite app is set up yet. Set the apps’ origins in deployment/.env and rerun the installer.</p>}</div>;
}
// Where a group sits in the tree: move it, add a subgroup inside it, or delete it with everything below it.
export function GroupPlacement({group,tree,api,run,onChanged,onDeleted}:{group:RecordData;tree:TreeNode[];api:Api;run:Run;onChanged:()=>Promise<void>;onDeleted:()=>void}){
 const targets=flattenTree(tree).filter(node=>node.id!==group.id&&!node.path.startsWith(group.path+'/'));
 const parentPath=group.path.split('/').slice(0,-1).join('/');
 async function remove(){
  const impact=await api('groups/'+group.id+'/impact');
  const lines=[`Delete the group ${pretty(group.path)}${impact.subGroups?` and the ${impact.subGroups} group${impact.subGroups===1?'':'s'} inside it`:''}?`,impact.people?`${impact.people} ${impact.people===1?'person loses':'people lose'} the access ${impact.subGroups?'these groups give':'this group gives'}.`:'Nobody is a member, so nobody loses access.','This cannot be undone.'];
  if(!window.confirm(lines.join('\n\n')))return;
  await run(async()=>{await api('groups/'+group.id,'DELETE');onDeleted()},'Group deleted.');
 }
 return <div className="ia-block"><h3>Place in the tree</h3><p className="ia-hint">{parentPath?'Inside '+pretty(parentPath)+'. Members also get every role of the groups above it.':'A top-level group.'}</p>
 <form className="ia-inline" onSubmit={e=>{e.preventDefault();const parent=String(new FormData(e.currentTarget).get('parent')||'');void run(async()=>{await api('groups/'+group.id+'/parent','PUT',{parent:parent==='top'?null:parent});await onChanged()},'Group moved.')}}><select name="parent" aria-label="Move this group to" required defaultValue=""><option value="" disabled>Move to…</option>{parentPath&&<option value="top">Top level</option>}{targets.map(node=><option key={node.id} value={node.id}>{pretty(node.path)}</option>)}</select><button className="ia-secondary">Move</button></form>
 <form className="ia-inline" onSubmit={e=>{e.preventDefault();const form=e.currentTarget;const name=String(new FormData(form).get('name')||'').trim();if(name)void run(async()=>{await api('groups','POST',{name,parent:group.id});form.reset();await onChanged()},'Subgroup created.')}}><input name="name" aria-label="New subgroup name" placeholder="New subgroup name" required/><button className="ia-secondary">Create subgroup</button></form>
 {group.subGroups?.length>0&&<p className="ia-hint">Inside it: {group.subGroups.map((g:RecordData)=>g.name).join(', ')}.</p>}
 <button type="button" className="ia-secondary" onClick={()=>void remove().catch(()=>{})}>Delete group</button></div>;
}
// Members of a group: remove them here, or find a person and add them.
export function GroupMembers({group,api,run,onChanged}:{group:RecordData;api:Api;run:Run;onChanged:()=>Promise<void>}){
 const [term,setTerm]=useState('');const [found,setFound]=useState<RecordData[]>([]);
 useEffect(()=>{if(!term.trim()){setFound([]);return}let live=true;const timer=setTimeout(()=>{api('users?first=0&search='+encodeURIComponent(term.trim())).then(list=>{if(live)setFound(list)}).catch(()=>{})},250);return()=>{live=false;clearTimeout(timer)}},[term]);
 const members:RecordData[]=group.members||[];
 return <div className="ia-block"><h3>Members</h3>{members.length?members.map(u=><div className="ia-inline" key={u.id}><span>{u.username}</span><button className="ia-secondary" onClick={()=>void run(async()=>{await api('users/'+u.id+'/groups/'+group.id,'DELETE');await onChanged()},'Member removed.')}>Remove</button></div>):<p>No members yet.</p>}<p className="ia-hint">Showing up to 50 direct members. People in groups inside this one are listed on those groups.</p>
 <label>Add a person<input type="search" value={term} placeholder="Search by username" onChange={e=>setTerm(e.target.value)}/></label>
 {found.filter(u=>!members.some(m=>m.id===u.id)).slice(0,8).map(u=><div className="ia-inline" key={u.id}><span>{u.username}</span><button className="ia-secondary" onClick={()=>void run(async()=>{await api('users/'+u.id+'/groups/'+group.id,'PUT');setTerm('');await onChanged()},'Member added.')}>Add</button></div>)}</div>;
}
// Per app, who can use it and why: "who can change proxy hosts?"
export function AppAccessView({apps,api}:{apps:RecordData[];api:Api}){
 const installed=apps.filter(app=>app.installed);const [app,setApp]=useState(installed[0]?.id||'');const [data,setData]=useState<RecordData|null>(null);const [error,setError]=useState('');
 useEffect(()=>{if(!app)return;let live=true;setData(null);setError('');api('apps/'+app+'/access').then(result=>{if(live)setData(result)}).catch(e=>{if(live)setError(e.message)});return()=>{live=false}},[app]);
 if(!installed.length)return <section className="p-panel ia-detail"><h2>No apps set up</h2><p className="ia-hint">Set the suite apps’ origins in deployment/.env and rerun the installer.</p></section>;
 const entry=apps.find(a=>a.id===app);
 return <section className="p-panel ia-detail"><label>App<select value={app} onChange={e=>setApp(e.target.value)}>{installed.map(a=><option key={a.id} value={a.id}>{a.name}</option>)}</select></label>
 <p className="ia-hint">{entry?.roles.map((r:RecordData)=>r.name+': '+String(r.description||'').replace(new RegExp('^'+entry.name+': '),'')).join(' · ')}</p>
 {error&&<div className="ia-error" role="alert">{error}</div>}
 {!data?<p role="status" className="ia-loading">Loading access…</p>:data.people.length?<div className="ia-table-wrap"><table className="ia-access"><thead><tr><th scope="col">Person</th><th scope="col">Role used</th><th scope="col">Where it comes from</th></tr></thead><tbody>{data.people.map((p:RecordData)=><tr key={p.id}><td>{p.username}{p.enabled?'':' (disabled)'}</td><td>{p.role}</td><td>{p.roles.map((r:RecordData)=><small key={r.name}>{r.name}: {r.sources.map((s:RecordData)=>source(s)).join('; ')}</small>)}</td></tr>)}</tbody></table></div>:<p className="ia-hint">Nobody has access to {entry?.name} yet.</p>}</section>;
}
