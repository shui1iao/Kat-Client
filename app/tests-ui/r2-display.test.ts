import test from 'node:test';
import assert from 'node:assert/strict';
import {weekDateLabel,showWeekLabel} from '../src/charts/scale.ts';
test('weekly date labels are compact and dense labels skip alternates but keep endpoints',()=>{
 assert.equal(weekDateLabel('10-25'),'10/25');assert.equal(weekDateLabel('01-02'),'1/2');assert.equal(weekDateLabel('2026-11-01'),'11/1');assert.equal(weekDateLabel('今天'),'今天');
 assert.deepEqual(Array.from({length:7},(_,i)=>showWeekLabel(i,7,40)),Array(7).fill(true));
 assert.deepEqual(Array.from({length:7},(_,i)=>i).filter(i=>showWeekLabel(i,7,28)),[0,2,4,6]);
 assert.deepEqual(Array.from({length:6},(_,i)=>i).filter(i=>showWeekLabel(i,6,28)),[0,2,4,5]);
 assert.equal(showWeekLabel(0,1,10),true);
});
