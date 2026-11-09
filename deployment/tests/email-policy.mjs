// Isolated CI realm only. Seed the old email gate, then verify migration removes it.
const base='http://keycloak:8080';
const response=await fetch(base+'/realms/master/protocol/openid-connect/token',{method:'POST',body:new URLSearchParams({grant_type:'password',client_id:'admin-cli',username:process.env.ADMIN_USERNAME,password:process.env.ADMIN_PASSWORD})});
if(!response.ok)throw new Error('Test administrator login failed');
const token=(await response.json()).access_token;
async function api(route,options={}){
 const result=await fetch(base+'/admin/realms/hackspacelabs'+route,{...options,headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'}});
 if(!result.ok)throw new Error('Test API returned '+result.status+' for '+route);
 return result.status===204?undefined:result.json();
}
const [admin]=await api('/users?username=admin&exact=true');
if(!admin)throw new Error('Seed administrator is missing');
const profile=await api('/users/profile');
if(process.argv[2]==='seed'){
 await api('',{method:'PUT',body:JSON.stringify({verifyEmail:true,resetPasswordAllowed:true})});
 await api('/users/'+admin.id,{method:'PUT',body:JSON.stringify({requiredActions:['UPDATE_PASSWORD','VERIFY_EMAIL','UPDATE_PROFILE']})});
 for(const attribute of profile.attributes||[])if(['email','firstName','lastName'].includes(attribute.name))attribute.required={roles:['user','admin']};
 await api('/users/profile',{method:'PUT',body:JSON.stringify(profile)});
 console.log('Seeded legacy email/profile gate in disposable CI realm.');
}else{
 const realm=await api('');
 if(realm.verifyEmail||realm.resetPasswordAllowed)throw new Error('Email dependency remains');
 if(JSON.stringify(admin.requiredActions)!==JSON.stringify(['UPDATE_PASSWORD']))throw new Error('Password-change-only requirement was not preserved');
 if(admin.email)throw new Error('Test admin unexpectedly has email');
 for(const attribute of profile.attributes||[])if(['email','firstName','lastName'].includes(attribute.name)&&attribute.required)throw new Error('Profile field remains mandatory: '+attribute.name);
 for(const action of await api('/authentication/required-actions'))if(['VERIFY_EMAIL','UPDATE_PROFILE','VERIFY_PROFILE'].includes(action.alias)&&(action.enabled||action.defaultAction))throw new Error('Unrequested action remains enabled');
 console.log('Existing email/profile gates removed; admin still requires password change, without an email address.');
}
