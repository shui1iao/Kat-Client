import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {mergeConnectionLogs} from '../src/client/logDetails.ts';
import type {ConnLogEntry} from '../src/client/types.ts';
const idle:ConnLogEntry={seq:2,time:'2026-11-06T00:00:00Z',network:'udp',source:'',target:'',rule:'',chain:[],flow_id:'1',outcome:'idle',code:'udp_no_datagrams',ended:true,up:0,down:0};
test('empty UDP association remains a visible neutral terminal record',()=>{
 const r=mergeConnectionLogs([], [idle]);assert.equal(r.length,1);assert.equal(r[0].outcome,'idle');assert.equal(r[0].target,'');assert.equal(r[0].up,0);
});
test('terminal neutral status is not overwritten with success while merging',()=>{
 const old={...idle,seq:1,outcome:'ok' as const,ended:false};const r=mergeConnectionLogs([old],[idle]);assert.equal(r.length,1);assert.equal(r[0].outcome,'idle');assert.equal(r[0].code,'udp_no_datagrams');assert.equal(r[0].ended,true);
});
test('runtime reachability gates polling without requiring running forwarding',()=>{
 const hook=fs.readFileSync('src/client/useClient.ts','utf8'),logs=fs.readFileSync('src/pages/Logs.tsx','utf8');
 assert.match(hook,/coreReachable.current=false;setStatus\(null\)/);assert.match(hook,/coreReachable.current=true;\s*setStatus\(s\)/);
 assert.match(hook,/if\(automatic&&!coreReachable.current\)return/);assert.match(hook,/if\(automatic&&!coreReachable.current\)\{skippedUnavailable=true;return;\}/);
 assert.match(hook,/!mounted.current\|\|!coreReachable.current\|\|appRestartingRef/);
 assert.equal((logs.match(/const readable=c.hasHost&&c.status!==null/g)||[]).length,2);
 assert.equal((logs.match(/\[readable,paused\]/g)||[]).length,2);
 assert.match(logs,/idle:'未传输'/);assert.match(logs,/e.outcome==='idle'\?'muted'/);
 const detail=fs.readFileSync('src/components/FlowDetail.tsx','utf8');assert.match(detail,/e.outcome!=='ok'&&e.outcome!=='idle'/);
});
