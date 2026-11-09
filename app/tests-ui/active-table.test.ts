import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
const base='e87c521e3f26927d65e5b2963a10f1bb899b3991';
const read=(p:string)=>readFileSync(new URL('../src/'+p,import.meta.url),'utf8');
const old=(p:string)=>execFileSync('git',['show',`${base}:app/src/${p}`],{encoding:'utf8'});
test('only active-card list body changes; shell, counts, footer, all other cards and rate order stay byte-identical',()=>{
 const isolate=(s:string)=>s.replace(/<div className="active-top-list(?: ac-table)?">[\s\S]*?(?=\{running&&<footer)/,'LIST');
 assert.equal(isolate(read('pages/Dashboard.tsx')),isolate(old('pages/Dashboard.tsx')));
 assert.match(read('pages/Dashboard.tsx'),/topConnections\(running\?items:\[\],c.connectionSpeeds\)/);
});
test('CSS is append-only and scoped to ac classes; production sorting, labels and data paths stay untouched',()=>{
 const css=read('k3.css');assert.ok(css.startsWith(old('k3.css')));
 for(const line of css.slice(old('k3.css').length).split('\n').filter(l=>l.includes('{')))assert.ok(line.startsWith('.ac-')||line.startsWith('.active-connections-card .ac-'),line);
 for(const p of ['client/presentation.ts','components/labels.tsx','client/useClient.ts','charts/SpeedChart.tsx','charts/speedColumns.ts','components/SideStatus.tsx','ui.css','r11.css'])assert.equal(read(p),old(p),p);
});
