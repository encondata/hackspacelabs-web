import {test} from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdtempSync,writeFileSync,readFileSync,statSync,rmSync,readdirSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHmac,randomBytes} from 'node:crypto';
const script=fileURLToPath(new URL('../../deployment/scripts/app-env.mjs',import.meta.url));
const secret=randomBytes(48).toString('hex');
function setup(t,deployment,app=''){
 const dir=mkdtempSync(path.join(tmpdir(),'hsl-app-env-'));t.after(()=>rmSync(dir,{recursive:true,force:true}));
 writeFileSync(path.join(dir,'deployment.env'),'OIDC_CLIENT_SECRET='+secret+'\nAPP_ORIGIN=https://hackspacelabs.example\nAUTH_ORIGIN=https://auth.hackspacelabs.example\nUNTRUSTED=$(touch '+path.join(dir,'marker')+')\n'+deployment);
 writeFileSync(path.join(dir,'app.env'),app,{mode:0o644});
 const run=(...args)=>spawnSync(process.execPath,[script,...args],{env:{...process.env,DEPLOYMENT_ENV_FILE:path.join(dir,'deployment.env')},encoding:'utf8'});
 return {dir,run,target:path.join(dir,'app.env')};
}
const values=text=>Object.fromEntries(text.split('\n').filter(Boolean).map(line=>[line.slice(0,line.indexOf('=')),line.slice(line.indexOf('=')+1)]));
test('Switchyard gets its sign-in settings and own address, mode 600, without printing the secret',t=>{
 const {dir,run,target}=setup(t,'SWITCHYARD_ORIGIN=http://192.168.1.10:8080/\nTIDELINE_ORIGIN=https://tideline.example\nSLIPWAY_ORIGIN=\n','CPM_SECRET_KEY=keep-me\nHSL_OIDC_CLIENT_ID=old\n');
 const result=run('switchyard',target);assert.equal(result.status,0,result.stderr);
 const written=values(readFileSync(target,'utf8'));
 assert.deepEqual(written,{CPM_SECRET_KEY:'keep-me',HSL_OIDC_CLIENT_ID:'switchyard',HSL_OIDC_ISSUER:'https://auth.hackspacelabs.example/realms/hackspacelabs',HSL_OIDC_CLIENT_SECRET:createHmac('sha256',secret).update('switchyard-v1').digest('hex'),HSL_PORTAL_URL:'https://hackspacelabs.example',HSL_SUITE_APPS:'portal|HackSpaceLabs|https://hackspacelabs.example/apps,switchyard|Switchyard|http://192.168.1.10:8080,tideline|Tideline|https://tideline.example',CPM_PUBLIC_URL:'http://192.168.1.10:8080'});
 assert.equal(statSync(target).mode&0o777,0o600);
 assert.ok(!result.stdout.includes(written.HSL_OIDC_CLIENT_SECRET)&&!result.stderr.includes(written.HSL_OIDC_CLIENT_SECRET));
 assert.doesNotMatch(result.stdout,/CPM_SECRET_KEY/);
 assert.ok(!readdirSync(dir).includes('marker'),'deployment/.env is read as data');
 assert.equal(run('switchyard',target).status,0);assert.deepEqual(values(readFileSync(target,'utf8')),written,'a rerun changes nothing');
});
test('Switchyard without CPM_SECRET_KEY is told so; Tideline gets TIDELINE_PUBLIC_URL',t=>{
 const {run,target}=setup(t,'SWITCHYARD_ORIGIN=http://192.168.1.10:8080\nTIDELINE_ORIGIN=https://tideline.example\n');
 const result=run('switchyard',target);assert.equal(result.status,0);assert.match(result.stdout,/no CPM_SECRET_KEY/);
 assert.equal(run('tideline',target).status,0);assert.equal(values(readFileSync(target,'utf8')).TIDELINE_PUBLIC_URL,'https://tideline.example');
});
test('Slipway and Harbor Master keep their own address and stop when it differs from the registry origin',t=>{
 const {run,target}=setup(t,'SLIPWAY_ORIGIN=https://slipway.example\nHARBORMASTER_ORIGIN=https://harbormaster.example\n','SLIPWAY_BASE_URL=https://old.example\n');
 const refused=run('slipway',target);assert.equal(refused.status,1);assert.match(refused.stderr,/SLIPWAY_BASE_URL is "https:\/\/old.example".*Nothing was written/);
 assert.equal(readFileSync(target,'utf8'),'SLIPWAY_BASE_URL=https://old.example\n');
 assert.match(run('harbormaster',target).stderr,/PUBLIC_URL is not set/);
 writeFileSync(target,'SLIPWAY_BASE_URL="https://slipway.example/"\nPUBLIC_URL=https://harbormaster.example\n');
 assert.equal(run('slipway',target).status,0);assert.equal(run('harbormaster',target).status,0);
 const written=values(readFileSync(target,'utf8'));
 assert.equal(written.SLIPWAY_BASE_URL,'"https://slipway.example/"');assert.equal(written.HSL_PORTAL_INTERNAL_URL,'');assert.equal(written.HSL_OIDC_CLIENT_ID,'harbormaster');assert.equal(written.PUBLIC_URL,'https://harbormaster.example');
});
test('unknown apps, unset origins and malformed origins are refused',t=>{
 const {run,target}=setup(t,'TIDELINE_ORIGIN=https://tideline.example/path\n');
 assert.match(run('other',target).stderr,/Unknown app/);
 assert.match(run('switchyard',target).stderr,/Set SWITCHYARD_ORIGIN/);
 assert.match(run('tideline',target).stderr,/must be an origin/);
 assert.equal(run().status,1);
});
test('Slipway and Harbor Master get the gateway address for the owner check; Switchyard does not',t=>{
 const {run,target}=setup(t,'SLIPWAY_ORIGIN=https://slipway.example\nSWITCHYARD_ORIGIN=http://192.168.1.10:8080\nPORTAL_INTERNAL_URL=http://192.168.1.10:8088/\n','SLIPWAY_BASE_URL=https://slipway.example\n');
 const told=run('slipway',target);assert.equal(told.status,0,told.stderr);assert.doesNotMatch(told.stdout,/No PORTAL_INTERNAL_URL/);
 assert.equal(values(readFileSync(target,'utf8')).HSL_PORTAL_INTERNAL_URL,'http://192.168.1.10:8088');
 assert.equal(run('switchyard',target).status,0);
 const lan=setup(t,'AUTH_MODE=lan\nSLIPWAY_ORIGIN=https://slipway.example\n','SLIPWAY_BASE_URL=https://slipway.example\n');
 assert.equal(lan.run('slipway',lan.target).status,0);assert.equal(values(readFileSync(lan.target,'utf8')).HSL_PORTAL_INTERNAL_URL,'https://hackspacelabs.example');
 const none=setup(t,'SLIPWAY_ORIGIN=https://slipway.example\n','SLIPWAY_BASE_URL=https://slipway.example\n');
 assert.match(none.run('slipway',none.target).stdout,/No PORTAL_INTERNAL_URL/);
 assert.match(setup(t,'PORTAL_INTERNAL_URL=http://x/path\nSLIPWAY_ORIGIN=https://slipway.example\n','SLIPWAY_BASE_URL=https://slipway.example\n').run('slipway',target).stderr,/must be an origin/);
});
