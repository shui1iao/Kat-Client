import test from 'node:test';
import assert from 'node:assert/strict';
import {smartHeaderMember} from '../src/client/groupSelection.ts';
import {policyMemberProbe} from '../src/client/policyProbe.ts';
import {smartProbe,weightedProbe} from '../src/client/groupDisplay.ts';
import {latencyTone} from '../src/lib/format.ts';
import {displaySorted} from '../src/client/settings.ts';

test('Smart normal probe is independent of never/insufficient/learned state and decision cost',()=>{
 for(const phase of ['never','confirming','learned'])for(const score of [null,126,9000]){
  const status:any={nodes:[],groups:[{name:'S',current:'JP',selection_mode:'site',most_used_member:'HK',candidate:phase==='confirming'?'JP':undefined,members:[{name:'HK',probe_ms:40,weight:1.5,decision_score_ms:score,score_parts:{real_ms:700},sample_count:phase==='never'?0:phase==='confirming'?1:50},{name:'JP',probe_ms:200,decision_score_ms:1}]}]};
  const name=smartHeaderMember(status.groups[0]);assert.equal(name,'HK');
  const p=policyMemberProbe(status,'S',name!);
  assert.equal(smartProbe(p?.probe_ms,p?.probe_error,1.5),'40 ms × 1.5');assert.equal(latencyTone(p?.probe_ms??null),'ok');
  const order=displaySorted(['JP','HK'],'latency',x=>x,n=>{const p=policyMemberProbe(status,'S',n);return p?.probe_ms==null?null:p.probe_ms*(n==='HK'?1.5:1)});
  assert.deepEqual(order,['HK','JP']);
  status.groups[0].members[0].probe_error='PROBE_FAILED';assert.equal(smartProbe(policyMemberProbe(status,'S','HK')?.probe_ms,'PROBE_FAILED',1.5),'失败');
  status.groups[0].members[0].probe_ms=null;delete status.groups[0].members[0].probe_error;assert.equal(smartProbe(policyMemberProbe(status,'S','HK')?.probe_ms,undefined,1.5),'—');
 }
});
test('Smart ordinary probe follows current nested leaf and latest timestamp, not old group score',()=>{
 const status:any={nodes:[{name:'HK',probe_ms:40,probe_at:'2026-11-02T04:00:00Z'}],groups:[{name:'S',current:'N',members:[{name:'N',probe_ms:999,decision_score_ms:126}]},{name:'N',current:'HK',members:[{name:'HK',probe_ms:90,probe_at:'2026-11-02T03:00:00Z'}]}]};
 assert.equal(policyMemberProbe(status,'S','N')?.probe_ms,40);
 status.groups[1].current='missing';assert.equal(policyMemberProbe(status,'S','N'),undefined);
});

test('unlearned Smart header falls back to measured current, not the fastest or score',()=>{
 const group:any={name:'S',type:'smart',current:'JP',selection_mode:'site',most_used_member:'',members:[{name:'HK',probe_ms:40,weight:1.5,decision_score_ms:126},{name:'JP',probe_ms:600,weight:2,decision_score_ms:null}]};
 const status:any={nodes:[],groups:[group]};
 const display=()=>{const name=smartHeaderMember(group),m=group.members.find((m:any)=>m.name===name),p=name?policyMemberProbe(status,'S',name):undefined;return {name,text:smartProbe(p?.probe_ms,p?.probe_error,m?.weight??1),tone:latencyTone(p?.probe_ms??null)}};
 assert.deepEqual(display(),{name:'JP',text:'600 ms × 2',tone:'mid'});
 group.most_used_member='HK';assert.deepEqual(display(),{name:'HK',text:'40 ms × 1.5',tone:'ok'});
 group.most_used_member='';group.members[1].probe_ms=null;assert.deepEqual(display(),{name:'JP',text:'—',tone:'off'});
 group.current=null;assert.deepEqual(display(),{name:null,text:'—',tone:'off'});
});

test('Smart latency puts ms before the actual multiplier without changing other groups',()=>{
 assert.equal(smartProbe(40,undefined,.5),'40 ms × 0.5');
 assert.equal(smartProbe(40,undefined,1),'40 ms');
 assert.equal(smartProbe(40,undefined,.001),'40 ms × 0.001');
 assert.equal(smartProbe(40,'PROBE_FAILED',.5),'失败');
 assert.equal(smartProbe(undefined,undefined,.5),'—');
 assert.equal(weightedProbe(40,undefined,.5),'40 × 0.5 ms');
});
