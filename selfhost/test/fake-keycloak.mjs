// In-memory stand-in for the parts of the Keycloak admin API the portal uses for users, groups and client roles.
// Test fixture only. Behaviour follows Keycloak 26 as checked on a real instance: groups carry parentId and path,
// members are direct members only, a group's members also get its ancestors' roles, deleting a group deletes its
// subgroups, and POST /groups or /groups/{id}/children with an existing id moves that group.
export function fakeKeycloak(){
 let next=1;const id=prefix=>prefix+'-'+(next++);
 const clients=new Map(),users=new Map(),groups=new Map();const calls=[];
 const notFound=()=>{const error=new Error('Identity service request failed');error.status=404;throw error};
 function addClient(clientId,roleNames=[]){const c={id:id('c'),clientId,roles:roleNames.map(name=>({id:id('r'),name,description:clientId+': '+name}))};clients.set(c.id,c);return c}
 function addUser(username,extra={}){const u={id:extra.id||id('u'),username,enabled:true,groups:new Set(),roles:new Map(),...extra};users.set(u.id,u);return u}
 function addGroup(name,parent=null){const g={id:id('g'),name,parentId:parent?.id||null,roles:new Map()};groups.set(g.id,g);return g}
 const path=g=>(g.parentId?path(groups.get(g.parentId)):'')+'/'+g.name;
 const children=g=>[...groups.values()].filter(x=>x.parentId===g.id);
 const view=g=>({id:g.id,name:g.name,path:path(g),parentId:g.parentId||undefined,subGroupCount:children(g).length,subGroups:[]});
 const ancestors=g=>g.parentId?[g,...ancestors(groups.get(g.parentId))]:[g];
 const grants=(holder,c)=>[...(holder.roles.get(c.id)||new Set())].map(rid=>c.roles.find(r=>r.id===rid));
 function grant(holder,c,list,remove=false){const set=holder.roles.get(c.id)||new Set();for(const r of list)remove?set.delete(r.id):set.add(r.id);holder.roles.set(c.id,set)}
 const effective=(u,c)=>{const all=new Map(grants(u,c).map(r=>[r.id,r]));for(const g of u.groups)for(const a of ancestors(groups.get(g)))for(const r of grants(a,c))all.set(r.id,r);return [...all.values()]};
 const userView=u=>({id:u.id,username:u.username,enabled:u.enabled,email:u.email,serviceAccountClientId:u.serviceAccountClientId});
 async function api(route,method='GET',body){
  calls.push({route,method,body});
  const [pathname,query='']=route.split('?');const q=new URLSearchParams(query);const parts=pathname.split('/').filter(Boolean).map(decodeURIComponent);
  const client=cid=>clients.get(cid)||notFound();
  if(parts[0]==='clients'&&parts.length===1)return [...clients.values()].filter(c=>!q.has('clientId')||c.clientId===q.get('clientId')).map(c=>({id:c.id,clientId:c.clientId,enabled:true}));
  if(parts[0]==='clients'&&parts.length===2){const c=client(parts[1]);return {id:c.id,clientId:c.clientId,enabled:true,publicClient:false,secret:'hidden',attributes:{}}}
  if(parts[0]==='clients'&&parts[2]==='roles'){const c=client(parts[1]);if(parts.length===3)return c.roles;const role=c.roles.find(r=>r.name===parts[3])||notFound();
   if(parts[4]==='users')return [...users.values()].filter(u=>grants(u,c).includes(role)).map(userView);
   if(parts[4]==='groups')return [...groups.values()].filter(g=>grants(g,c).includes(role)).map(view);
   return role}
  if(parts[0]==='users'&&parts.length===1)return [...users.values()].filter(u=>u.username.includes(q.get('search')||'')).map(userView);
  if(parts[0]==='users'){
   const u=users.get(parts[1])||notFound();
   if(parts.length===2)return userView(u);
   if(parts[2]==='sessions')return [];
   if(parts[2]==='groups'&&parts.length===3)return [...u.groups].map(g=>view(groups.get(g)));
   if(parts[2]==='groups'){const g=groups.get(parts[3])||notFound();method==='PUT'?u.groups.add(g.id):u.groups.delete(g.id);return null}
   if(parts[2]==='role-mappings'){const c=client(parts[4]);if(method==='GET')return parts[5]==='composite'?effective(u,c):grants(u,c);grant(u,c,body,method==='DELETE');return null}
  }
  if(parts[0]==='groups'){
   if(parts.length===1&&method==='GET')return [...groups.values()].filter(g=>!g.parentId).map(view);
   if(parts.length===1&&method==='POST'){if(body.id){groups.get(body.id).parentId=null;return null}addGroup(body.name);return null}
   const g=groups.get(parts[1])||notFound();
   if(parts.length===2&&method==='GET')return view(g);
   if(parts.length===2&&method==='DELETE'){const drop=x=>{for(const c of children(x))drop(c);groups.delete(x.id);for(const u of users.values())u.groups.delete(x.id)};drop(g);return null}
   if(parts[2]==='children'&&method==='GET')return children(g).map(view);
   if(parts[2]==='children'&&method==='POST'){if(body.id){groups.get(body.id).parentId=g.id;return null}addGroup(body.name,g);return null}
   if(parts[2]==='members')return [...users.values()].filter(u=>u.groups.has(g.id)).map(userView);
   if(parts[2]==='role-mappings'){const c=client(parts[4]);if(method==='GET')return grants(g,c);grant(g,c,body,method==='DELETE');return null}
  }
  return null;
 }
 return {api,calls,addClient,addUser,addGroup,grant,users,groups,path};
}
