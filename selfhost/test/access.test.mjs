import {test,before,after} from 'node:test';
import assert from 'node:assert/strict';
import session from 'express-session';
import request from 'supertest';
import {randomBytes} from 'node:crypto';
import {createApp} from '../server/app.mjs';
import {createOidc} from '../server/oidc.mjs';
import {startIssuer} from './oidc-fixture.mjs';
import {fakeKeycloak} from './fake-keycloak.mjs';
let issuer,config,oidc;
before(async()=>{issuer=await startIssuer();config={production:false,origin:'http://127.0.0.1:3000',issuer:issuer.issuer,clientId:'hackspacelabs-web',clientSecret:randomBytes(32).toString('hex'),sessionSecret:randomBytes(48).toString('hex'),encryptionKey:randomBytes(32).toString('base64'),refreshMs:60000};oidc=await createOidc(config)});
after(()=>issuer.close());
// A realm like the one in PLAN.md appendix B row 19: Staff > Infrastructure > On-call.
async function fixture({role='admin',installed=['slipway','switchyard','harbormaster','tideline']}={}){
 const kc=fakeKeycloak();const web=kc.addClient('hackspacelabs-web',['admin','customer']);
 const roleSets={slipway:['admin','maintainer','developer','viewer'],switchyard:['admin','editor','viewer'],harbormaster:['admin','member'],tideline:['admin','editor','viewer']};
 const apps=Object.fromEntries(installed.map(id=>[id,kc.addClient(id,roleSets[id])]));
 const actor=kc.addUser('portal-admin',{id:'sample-user'});kc.grant(actor,web,[web.roles[0]]);
 const staff=kc.addGroup('Staff'),infra=kc.addGroup('Infrastructure',staff),oncall=kc.addGroup('On-call',infra);
 const pick=(app,name)=>apps[app].roles.filter(r=>r.name===name);
 if(apps.tideline){kc.grant(staff,apps.tideline,pick('tideline','viewer'));kc.grant(oncall,apps.tideline,pick('tideline','editor'))}
 if(apps.switchyard)kc.grant(infra,apps.switchyard,pick('switchyard','editor'));
 const ada=kc.addUser('ada');ada.groups.add(oncall.id);const bob=kc.addUser('bob');bob.groups.add(infra.id);
 const infos=[];
 issuer.state.roles=[role];issuer.state.apps=undefined;
 const app=createApp({config,store:new session.MemoryStore(),oidc,management:kc.api,publicDir:'.',log:{error(){},warn(){},info:(...args)=>infos.push(args)}});const agent=request.agent(app);
 const start=await agent.get('/api/auth/login');const redirect=await fetch(start.headers.location,{redirect:'manual'});const url=new URL(redirect.headers.get('location'));await agent.get(url.pathname+url.search);const result=await agent.get('/api/auth/session');
 const mutate=(method,path,body)=>agent[method]('/api/admin'+path).set('Origin',config.origin).set('x-csrf-token',result.body.csrfToken).send(body);
 return {kc,agent,mutate,apps,web,actor,staff,infra,oncall,ada,bob,pick,infos};
}
test('the app list and role editor follow the registry, in registry order',async()=>{
 const f=await fixture({installed:['switchyard','tideline']});
 const apps=(await f.agent.get('/api/admin/apps')).body;
 assert.deepEqual(apps.map(a=>[a.id,a.installed,a.roles.map(r=>r.name)]),[['slipway',false,['admin','maintainer','developer','viewer']],['switchyard',true,['admin','editor','viewer']],['harbormaster',false,['admin','member']],['tideline',true,['admin','editor','viewer']]]);
 assert.deepEqual((await f.agent.get('/api/admin/apps/switchyard/roles')).body.map(r=>r.name),['admin','editor','viewer']);
 assert.deepEqual((await f.agent.get('/api/admin/apps/slipway/roles')).body,[]);
 assert.equal((await f.mutate('put','/users/'+f.ada.id+'/app-roles/switchyard',{roles:['viewer']})).status,200);
 assert.equal((await f.mutate('put','/users/'+f.ada.id+'/app-roles/switchyard',{roles:['admin']})).status,200);
 const writes=f.kc.calls.filter(c=>c.route.startsWith('/users/'+f.ada.id+'/role-mappings/clients/')&&c.method!=='GET').map(c=>[c.method,c.body.map(r=>r.name)]);
 assert.deepEqual(writes,[['POST',['viewer']],['POST',['admin']],['DELETE',['viewer']]]);
 assert.equal((await f.mutate('put','/groups/'+f.staff.id+'/app-roles/tideline',{roles:['admin','viewer']})).status,200);
 assert.deepEqual((await f.agent.get('/api/admin/groups/'+f.staff.id)).body.appRoles.tideline.map(r=>r.name),['admin','viewer']);
 assert.ok(f.infos.some(([,entry])=>entry.action==='update switchyard roles for user'&&entry.target===f.ada.id));
});
test('app role changes refuse unknown roles and apps, apps not set up, missing CSRF and non-admins',async()=>{
 const f=await fixture({installed:['switchyard']});const before=f.kc.calls.length;
 assert.equal((await f.mutate('put','/users/'+f.ada.id+'/app-roles/switchyard',{roles:['root']})).status,400);
 assert.equal((await f.mutate('put','/users/'+f.ada.id+'/app-roles/other',{roles:['admin']})).status,400);
 assert.equal((await f.mutate('put','/users/'+f.ada.id+'/app-roles/tideline',{roles:['admin']})).status,404);
 assert.equal((await f.agent.put('/api/admin/users/'+f.ada.id+'/app-roles/switchyard').send({roles:['admin']})).status,403);
 assert.ok(!f.kc.calls.slice(before).some(c=>c.method!=='GET'));
 const customer=await fixture({role:'customer'});assert.equal((await customer.mutate('put','/users/'+customer.ada.id+'/app-roles/switchyard',{roles:['admin']})).status,403);
});
test('a person\'s effective access names the role each app uses and where every grant comes from',async()=>{
 const f=await fixture();f.kc.grant(f.ada,f.apps.switchyard,f.pick('switchyard','admin'));
 const ada=(await f.agent.get('/api/admin/users/'+f.ada.id)).body;
 const byApp=Object.fromEntries(ada.access.map(a=>[a.app,a]));
 assert.equal(byApp.switchyard.role,'admin');
 assert.deepEqual(byApp.switchyard.roles,[{name:'admin',sources:[{type:'direct'}]},{name:'editor',sources:[{type:'group',id:f.infra.id,path:'/Staff/Infrastructure'}]}]);
 assert.equal(byApp.tideline.role,'editor');
 assert.deepEqual(byApp.tideline.roles,[{name:'editor',sources:[{type:'group',id:f.oncall.id,path:'/Staff/Infrastructure/On-call'}]},{name:'viewer',sources:[{type:'group',id:f.staff.id,path:'/Staff'}]}]);
 assert.deepEqual([byApp.slipway.role,byApp.slipway.roles,byApp.harbormaster.role],[null,[],null]);
 assert.deepEqual(ada.appRoles.switchyard.map(r=>r.name),['admin']);
 const group=(await f.agent.get('/api/admin/groups/'+f.oncall.id)).body;
 assert.equal(group.path,'/Staff/Infrastructure/On-call');
 assert.deepEqual(group.gives.filter(a=>a.role).map(a=>[a.app,a.roles.map(r=>r.name+' from '+r.sources.map(s=>s.path).join(' and '))]),[['switchyard',['editor from /Staff/Infrastructure']],['tideline',['editor from /Staff/Infrastructure/On-call','viewer from /Staff']]]);
 assert.deepEqual((await f.agent.get('/api/admin/groups/'+f.staff.id)).body.subGroups.map(g=>g.path),['/Staff/Infrastructure']);
});
test('per app, who has access and why, including members of subgroups',async()=>{
 const f=await fixture();f.kc.grant(f.bob,f.apps.switchyard,f.pick('switchyard','viewer'));
 const result=(await f.agent.get('/api/admin/apps/switchyard/access')).body;
 assert.deepEqual(result.people.map(p=>[p.username,p.role,p.roles.map(r=>r.name+':'+r.sources.map(s=>s.type==='direct'?'direct':s.path).join('+'))]),[['ada','editor',['editor:/Staff/Infrastructure']],['bob','editor',['editor:/Staff/Infrastructure','viewer:direct']]]);
 assert.deepEqual((await f.agent.get('/api/admin/apps/tideline/access')).body.people.map(p=>[p.username,p.role]),[['ada','editor'],['bob','viewer']]);
 assert.equal((await f.agent.get('/api/admin/apps/nope/access')).status,400);
});
test('groups nest: create inside another, show the tree, move, and refuse moves into themselves',async()=>{
 const f=await fixture();
 assert.equal((await f.mutate('post','/groups',{name:'Night',parent:f.oncall.id})).status,201);
 assert.equal((await f.mutate('post','/groups',{name:'Contractors'})).status,201);
 const tree=(await f.agent.get('/api/admin/groups/tree')).body;
 const flat=list=>list.flatMap(g=>[g.path,...flat(g.subGroups)]);
 assert.deepEqual(flat(tree),['/Staff','/Staff/Infrastructure','/Staff/Infrastructure/On-call','/Staff/Infrastructure/On-call/Night','/Contractors']);
 const contractors=[...f.kc.groups.values()].find(g=>g.name==='Contractors');
 assert.equal((await f.mutate('put','/groups/'+f.oncall.id+'/parent',{parent:contractors.id})).status,200);
 assert.equal(f.kc.path(f.oncall),'/Contractors/On-call');
 assert.equal((await f.mutate('put','/groups/'+f.oncall.id+'/parent',{parent:null})).status,200);assert.equal(f.kc.path(f.oncall),'/On-call');
 for(const parent of [f.staff.id,f.infra.id])assert.equal((await f.mutate('put','/groups/'+f.staff.id+'/parent',{parent})).status,400,'into itself or below');
 assert.equal(f.kc.path(f.staff),'/Staff');
 assert.ok(f.infos.some(([,entry])=>entry.action==='move group'));
});
test('deleting a group reports how many people lose access, and an admin cannot delete or move their own group',async()=>{
 const f=await fixture();
 assert.deepEqual((await f.agent.get('/api/admin/groups/'+f.staff.id+'/impact')).body,{path:'/Staff',subGroups:2,people:2});
 f.actor.groups.add(f.oncall.id);
 assert.match((await f.mutate('delete','/groups/'+f.staff.id)).body.error,/another administrator/);
 assert.match((await f.mutate('put','/groups/'+f.infra.id+'/parent',{parent:null})).body.error,/another administrator/);
 f.actor.groups.delete(f.oncall.id);
 assert.equal((await f.mutate('delete','/groups/'+f.infra.id)).status,200);
 assert.deepEqual([...f.kc.groups.values()].map(g=>g.name),['Staff'],'subgroups go with it');
 assert.ok(f.infos.some(([,entry])=>entry.action==='delete group'));
 assert.ok(!JSON.stringify(f.infos).includes(config.clientSecret));
});
test('group members are added and removed from the group page',async()=>{
 const f=await fixture();
 assert.equal((await f.mutate('put','/users/'+f.bob.id+'/groups/'+f.staff.id)).status,200);
 assert.deepEqual((await f.agent.get('/api/admin/groups/'+f.staff.id)).body.members.map(m=>m.username),['bob']);
 assert.equal((await f.mutate('delete','/users/'+f.bob.id+'/groups/'+f.staff.id)).status,200);
 assert.deepEqual((await f.agent.get('/api/admin/groups/'+f.staff.id)).body.members,[]);
});
test('suite app clients are read-only under Connected apps and their ids are reserved',async()=>{
 const f=await fixture();const before=f.kc.calls.length;
 for(const id of ['slipway','switchyard','harbormaster','tideline']){
  const client=[...(await f.agent.get('/api/admin/clients')).body].find(c=>c.clientId===id);
  assert.equal(client.internal,true,id);
  assert.equal((await f.mutate('put','/clients/'+client.id,{clientId:id,enabled:true,publicClient:false,redirectUris:['https://x.example/cb'],webOrigins:[]})).status,400);
  assert.equal((await f.mutate('post','/clients/'+client.id+'/secret',{rotate:true})).status,400);
  assert.equal((await f.mutate('post','/clients',{clientId:id,enabled:true,publicClient:false,redirectUris:['https://x.example/cb'],webOrigins:[]})).status,400);
 }
 assert.ok(!f.kc.calls.slice(before).some(c=>c.method!=='GET'));
});
test('the Authentication page can set the two remember-me durations',async()=>{
 const f=await fixture();
 assert.equal((await f.mutate('put','/settings',{ssoSessionIdleTimeoutRememberMe:2592000,ssoSessionMaxLifespanRememberMe:2592000})).status,200);
 assert.deepEqual(f.kc.calls.find(c=>c.route===''&&c.method==='PUT').body,{ssoSessionIdleTimeoutRememberMe:2592000,ssoSessionMaxLifespanRememberMe:2592000});
 for(const value of [0,-1,'30',31536001])assert.equal((await f.mutate('put','/settings',{ssoSessionMaxLifespanRememberMe:value})).status,400,String(value));
});
