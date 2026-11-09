import test from 'node:test';import assert from 'node:assert/strict';
import {spacedTimeTicks} from '../src/charts/ticks.ts';
test('review time axis retains endpoints and drops ticks below 64 px',()=>{
 for(const n of [2,3,4,6,10,30,1800])for(const w of [128,240,420,650,1000]){const ticks=spacedTimeTicks(n,w);assert.equal(ticks[0],0);assert.equal(ticks.at(-1),n-1);assert.equal(new Set(ticks).size,ticks.length);for(let j=1;j<ticks.length;j++)assert.ok((ticks[j]-ticks[j-1])*w/(n-1)>=64);}
 assert.ok(spacedTimeTicks(30,240).length<6);assert.deepEqual(spacedTimeTicks(0,300),[]);assert.deepEqual(spacedTimeTicks(1,300),[0]);
});

test('user Top5 omits rate text without touching ordering or counters',async()=>{
 const {readFileSync}=await import('node:fs');const s=readFileSync('src/pages/Dashboard.tsx','utf8');assert.match(s,/topConnections\(running\?items:\[\],c.connectionSpeeds\)/);assert.doesNotMatch(s,/showRate\(c.connectionSpeeds\[x.id\]\)/);assert.match(s,/本次启动共/);assert.match(s,/TCP.*UDP/);
});
