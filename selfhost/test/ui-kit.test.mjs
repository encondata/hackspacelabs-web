// The HSL Suite kit (ui/): rules every app relies on, and the sync script's copy and drift check.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,readdirSync,writeFileSync,mkdtempSync,rmSync,appendFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const ui=fileURLToPath(new URL('../../ui/',import.meta.url));
const sync=fileURLToPath(new URL('../../scripts/sync-hsl-ui.sh',import.meta.url));
const read=name=>readFileSync(path.join(ui,name),'utf8');
// The code without its comments, which are allowed to mention what the code must not do.
const code=name=>read(name).replace(/\/\*[\s\S]*?\*\//g,'').replace(/^\s*\/\/.*$/gm,'');
const css=readdirSync(ui).filter(f=>f.endsWith('.css')&&!f.startsWith('demo'));

test('light is the default: no stylesheet follows the operating system',()=>{
 for(const f of css)assert.doesNotMatch(code(f),/prefers-color-scheme/,f);
 assert.doesNotMatch(code('suite.js'),/prefers-color-scheme|matchMedia/);
 assert.match(read('tokens.css'),/:root\[data-theme='dark'\]/);
});

test('suite.js works under style-src self: no inline styles, style tags or shadow DOM',()=>{
 const js=code('suite.js');
 for(const bad of [/\.style\b/,/setAttribute\(\s*['"]style/,/<style/,/attachShadow/,/innerHTML/,/insertAdjacentHTML/])assert.doesNotMatch(js,bad);
});

test('the frame classes are all prefixed, and VERSION matches suite.js',()=>{
 for(const f of ['shell.css','auth.css']){
  const classes=[...code(f).matchAll(/\.([a-zA-Z][\w-]*)/g)].map(m=>m[1]).filter(c=>!/^(woff2?|svg|css)$/.test(c));
  for(const c of classes)assert.match(c,/^(hsl-|is-)/,f+': .'+c);
 }
 const version=read('VERSION').trim();
 assert.match(version,/^\d+\.\d+\.\d+$/);
 assert.match(read('suite.js'),new RegExp(`version: '${version.replaceAll('.','\\.')}'`));
});

test('every token the dark theme sets also has a light value',()=>{
 const tokens=code('tokens.css');
 const [light,dark]=tokens.split(":root[data-theme='dark']");
 const names=block=>new Set([...block.matchAll(/(--[\w-]+)\s*:/g)].map(m=>m[1]));
 const lightNames=names(light);
 for(const n of names(dark))assert.ok(lightNames.has(n),n+' has no light value');
});

test('sync copies the kit without the demo, and --check catches edits',t=>{
 const dir=mkdtempSync(path.join(tmpdir(),'hsl-ui-sync-'));t.after(()=>rmSync(dir,{recursive:true,force:true}));
 const dest=path.join(dir,'web/src/hsl-ui');
 const run=(...args)=>spawnSync('bash',[sync,...args],{env:{...process.env,HSL_UI_SOURCE:ui},encoding:'utf8'});
 const synced=run('ui-v0.0.0',dest);
 assert.equal(synced.status,0,synced.stderr);
 const files=readdirSync(dest);
 assert.ok(files.includes('tokens.css')&&files.includes('suite.js')&&files.includes('HSL-UI.sum')&&files.includes('fonts'));
 assert.ok(!files.some(f=>f.startsWith('demo')),'demo files copied');
 assert.equal(run('--check',dest).status,0);
 appendFileSync(path.join(dest,'tokens.css'),'\n/* local edit */\n');
 const drift=run('--check',dest);
 assert.equal(drift.status,1);assert.match(drift.stderr,/differs/);
 assert.equal(run('ui-v0.0.0',dest).status,0,'a fresh sync repairs it');
 writeFileSync(path.join(dest,'extra.css'),'');
 assert.equal(run('--check',dest).status,1,'an added file is drift too');
 assert.equal(spawnSync('bash',[sync,'v1',dest],{encoding:'utf8'}).status,2,'bad tag refused');
});

test('kit classes on a <button> set their own hover colours, so an app button:hover cannot show through',()=>{
 const rules=[...code('shell.css').matchAll(/([^{}]+)\{([^}]*)\}/g),...code('auth.css').matchAll(/([^{}]+)\{([^}]*)\}/g)];
 const hover=sel=>rules.filter(([,s])=>s.split(',').map(x=>x.trim()).includes(sel)).map(([,,body])=>body).join(';');
 for(const sel of ['.hsl-auth-link:hover','.hsl-auth-button:hover','.hsl-userbtn:hover','.hsl-iconbtn:hover','.hsl-menu-item:hover']){
  const body=hover(sel);
  for(const prop of ['background','border-color','color'])assert.match(body,new RegExp(`(^|[;\\s])${prop}\\s*:`),sel+' sets no '+prop);
 }
 const nav=hover('.hsl-nav-item:hover');
 for(const prop of ['background','color'])assert.match(nav,new RegExp(`(^|[;\\s])${prop}\\s*:`),'.hsl-nav-item:hover sets no '+prop);
});

test('the user menu takes avatar-url and compact-below, and the touch icon is a 180 px PNG',()=>{
 const js=code('suite.js');
 assert.match(js,/'avatar-url'/);assert.match(js,/'compact-below'/);
 assert.match(js,/safeUrl\(this\.getAttribute\('avatar-url'\)\)/,'the photo address goes through safeUrl');
 assert.match(code('shell.css'),/hsl-user-menu\[data-hsl-compact\] \.hsl-userbtn-name/);
 const png=readFileSync(path.join(ui,'apple-touch-icon.png'));
 assert.equal(png.subarray(1,4).toString(),'PNG');
 assert.equal(png.readUInt32BE(16),180);assert.equal(png.readUInt32BE(20),180);
});
