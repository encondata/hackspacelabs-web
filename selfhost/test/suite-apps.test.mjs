import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHmac} from 'node:crypto';
import {loadSuiteApps,validateSuiteApps,bareOrigin,appClientSecret,highestRole} from '../server/suite-apps.mjs';
test('the registry lists the four suite apps with the contract of PLAN.md 5.2',()=>{
 const apps=loadSuiteApps();
 assert.deepEqual(apps.map(a=>[a.id,a.originEnv,a.publicUrlEnv,a.callbackPath,Object.keys(a.roles)]),[
  ['slipway','SLIPWAY_ORIGIN','SLIPWAY_BASE_URL','/auth/hsl/callback',['admin','maintainer','developer','viewer']],
  ['switchyard','SWITCHYARD_ORIGIN','CPM_PUBLIC_URL','/api/auth/oidc/callback',['admin','editor','viewer']],
  ['harbormaster','HARBORMASTER_ORIGIN','PUBLIC_URL','/api/auth/hsl/callback',['admin','member']],
  ['tideline','TIDELINE_ORIGIN','TIDELINE_PUBLIC_URL','/api/auth/oidc/callback',['admin','editor','viewer']]]);
 for(const app of apps)for(const text of Object.values(app.roles))assert.ok(text.length<=80,'role descriptions stay short: '+text);
});
test('registry validation refuses entries that would break the settings format',()=>{
 const good={id:'x-app',name:'X',description:'An app',originEnv:'X_ORIGIN',publicUrlEnv:'X_URL',callbackPath:'/cb',roles:{admin:'X: all'}};
 assert.equal(validateSuiteApps([good]).length,1);
 for(const bad of [{name:'A|B'},{name:'A,B'},{id:'Bad'},{callbackPath:'https://evil.example/cb'},{roles:{}},{originEnv:'lower'}])assert.throws(()=>validateSuiteApps([{...good,...bad}]),JSON.stringify(bad));
 assert.throws(()=>validateSuiteApps([good,good]),/duplicate/);
});
test('origins must be bare, and secrets are derived per client',()=>{
 assert.equal(bareOrigin('https://slipway.example.com/','SLIPWAY_ORIGIN'),'https://slipway.example.com');
 assert.equal(bareOrigin('http://10.0.0.5:8080','SWITCHYARD_ORIGIN'),'http://10.0.0.5:8080');
 assert.equal(bareOrigin('  ','X'),null);
 for(const bad of ['https://a.example/path','ftp://a.example','not a url','https://a.example?x=1'])assert.throws(()=>bareOrigin(bad,'X'),bad);
 assert.equal(appClientSecret('k'.repeat(48),'tideline'),createHmac('sha256','k'.repeat(48)).update('tideline-v1').digest('hex'));
 const [slipway]=loadSuiteApps();assert.equal(highestRole(slipway,['viewer','developer']),'developer');assert.equal(highestRole(slipway,['other']),null);
});
