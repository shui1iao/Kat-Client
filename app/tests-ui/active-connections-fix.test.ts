import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { topConnections } from '../src/client/presentation.ts';
import type { ConnectionInfo } from '../src/client/types.ts';

test('active connections retain zero/unknown rates and rank rate, traffic, newest start before Top5', () => {
  const conn = (id:number, up=0, down=0, start='2026-11-01T00:00:00Z'):ConnectionInfo => ({id,up,down,start,network:'tcp',inbound:'test',source:'test',target:'test',rule:'',chain:[],duration_ms:0});
  const idle = Array.from({length:8}, (_,i) => conn(i,0,i));
  assert.deepEqual(topConnections(idle,Object.fromEntries(idle.map(x=>[x.id,0]))).map(x=>x.id),[7,6,5,4,3]);
  assert.equal(topConnections(idle,{}).length,5);
  assert.deepEqual(topConnections([],{}),[]);
  const items = [conn(1,1,0),conn(2,900,100),conn(3,40,60),conn(4,70,30,'2026-11-01T00:01:00Z'),conn(5,90,10),conn(6,100,0),conn(7,0,100)];
  const before = [...items];
  assert.deepEqual(topConnections(items,{1:200,2:100,3:100,4:100,5:100,6:null,7:0}).map(x=>x.id),[1,2,4,3,5]);
  assert.deepEqual(items,before);
  const page=readFileSync('src/pages/Dashboard.tsx','utf8');
  assert.match(page,/topConnections\(running\?items:\[\],c.connectionSpeeds\)/);
  assert.match(page,/\(!running\|\|!items.length\)&&<div className="empty">暂无活跃连接/);
});
