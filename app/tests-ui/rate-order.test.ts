import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
const baseline='4cd649d54e188bcbd4b47ded8de02672a26e51a4';
const read=(p:string)=>readFileSync(new URL('../src/'+p,import.meta.url),'utf8');
const old=(p:string)=>execFileSync('git',['show',`${baseline}:app/src/${p}`],{encoding:'utf8'});
test('dashboard rate cards only transpose complete up/down DOM blocks; rates, peaks, colors and cumulative sections stay exact',()=>{
 const p='pages/Dashboard.tsx',lines=old(p).split('\n'),i=lines.findIndex(l=>l.includes('className="rate-m hr down"'));
 assert.ok(i>=0);assert.ok(lines[i+1].includes('className="rate-m hr up"'));[lines[i],lines[i+1]]=[lines[i+1],lines[i]];
 assert.equal(read(p),lines.join('\n'));
});
test('sidebar and speed tooltip only transpose complete spans, including arrow, color and bound value',()=>{
 for(const [p,a,b] of [
  ['components/SideStatus.tsx',`<span className="down">↓ {running?showRate(s?.traffic.down_rate):'—'}</span>`,`<span className="up">↑ {running?showRate(s?.traffic.up_rate):'—'}</span>`],
  ['charts/SpeedChart.tsx','<span className="down">↓ {rate(column.down)}</span>','<span className="up">↑ {rate(column.up)}</span>']
 ]) {assert.ok(old(p).includes(a+b));assert.equal(read(p),old(p).replace(a+b,b+a));}
});
test('cumulative traffic/connection fields, chart grouping, sampling, formatters and styles remain byte-for-byte unchanged',()=>{
 for(const p of ['charts/WeekBars.tsx','charts/TrafficDistribution.tsx','charts/Donut.tsx','components/FlowDetail.tsx','pages/Connections.tsx','pages/Logs.tsx','components/SubscriptionCard.tsx','charts/speedColumns.ts','charts/scale.ts','client/useClient.ts','client/display.ts','lib/format.ts','ui.css','k3.css','finish.css','r9.css'])assert.equal(read(p),old(p),p);
});
