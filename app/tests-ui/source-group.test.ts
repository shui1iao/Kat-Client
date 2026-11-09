import test from 'node:test';
import assert from 'node:assert/strict';
import {groupFormValue} from '../src/client/entityValidation.ts';
import {dynamic,validateGraph,putEntity,removeEntity,references,SOURCE_GROUP_ERROR} from '../src/client/operations.ts';
import {groupFormSources,selectGroupSource,groupPreviewParams,previewGroupSource} from '../src/client/groupSource.ts';
import type {DocumentSource,Group} from '../src/client/types.ts';
const base=():DocumentSource=>({schema_version:1,client:{mode:'rule'},kernel:{outbounds:[{name:'HK',type:'socks5',server:'127.0.0.1',port:1},{name:'US',type:'socks5',server:'127.0.0.1',port:2}],groups:[{name:'Source',type:'select',members:['HK','US']},{name:'Consumer',type:'url-test',include_group:'Source',members:['US'],fixed:'HK',priority:{HK:0.5}}]}});
test('include_group is typed, retained and makes empty-manual groups dynamic',()=>{
 const g=groupFormValue({name:'G',type:'select',include_group:'Source'});assert.equal(g.include_group,'Source');assert.ok(dynamic(g));
 for(const v of [1,null,[],{}])assert.throws(()=>groupFormValue({...g,include_group:v}));
 const d=base();d.kernel.groups![1].members=[];validateGraph(d);
});
test('only explicit source selection replaces legacy global/provider scopes and preserves manual preferences',()=>{
 const old:Group={name:'G',type:'url-test',members:['US'],filter:'(?i)HK',use:['P'],include_all:true,include_all_proxies:true,include_all_providers:true,fixed:'US',selected:'US',priority:{US:0.5}};
 assert.deepEqual(groupFormSources(old,old),old);
 const next=selectGroupSource(old,'Source');
 assert.equal(next.include_group,'Source');for(const k of ['use','include_all','include_all_proxies','include_all_providers'])assert.equal(next[k],undefined);
 for(const k of ['members','fixed','selected','priority'])assert.deepEqual(next[k],old[k]);
 assert.deepEqual(groupFormSources(next,old),next);
 const toggled=groupFormSources(selectGroupSource(next,''),old,true);assert.equal(toggled.include_all,true);
 const cleared=groupFormSources(selectGroupSource(next,''),next);assert.equal(cleared.include_group,undefined);assert.equal(cleared.include_all,true);assert.deepEqual(cleared.members,['US']);
 const blank=groupFormSources(selectGroupSource({...next,filter:''},''),next);assert.equal(blank.include_all,undefined);assert.deepEqual(blank.members,['US']);
 const provider={name:'PGroup',type:'select',use:['P'],filter:'HK',include_all_providers:true};
 assert.deepEqual(groupFormSources({...provider,filter:'US'},provider),{...provider,filter:'US'});
 const advanced={...old,include_group:'Source'};assert.deepEqual(groupFormValue(advanced),advanced);assert.deepEqual(groupFormSources(advanced,advanced),advanced);
});
test('preview scopes and existing-consumer identity exactly follow IPC contract',()=>{
 assert.deepEqual(groupPreviewParams({name:'New',type:'select',include_group:'Source'},null),{include_group:'Source',filter:'',exclude_filter:''});
 assert.deepEqual(groupPreviewParams({name:'Renamed',type:'select',include_group:'Source',exclude_filter:'US'},'Old'),{include_group:'Source',group_name:'Old',filter:'',exclude_filter:'US'});
 assert.deepEqual(groupPreviewParams({name:'G',type:'select',exclude_filter:'US'},'G'),{filter:'',exclude_filter:''});
 assert.deepEqual(groupPreviewParams({name:'G',type:'select',filter:'(?i)HK',exclude_filter:'US'},'G'),{filter:'(?i)HK',exclude_filter:'US'});
});
test('regex and source errors use corresponding fields and only Go decides regex validity',async()=>{
 const g:Group={name:'G',type:'select',include_group:'Source',filter:'(?i)HK',exclude_filter:'['};const regex='正则表达式无效（使用 RE2 语法）';
 const calls:Record<string,unknown>[]=[];
 const r=await previewGroupSource(async p=>{calls.push(p);return p.exclude_filter?{names:[],error:regex}:{names:['HK']};},g,'G');
 assert.deepEqual(r,{names:[],errors:{'排除（正则）':regex}});assert.equal(calls.length,2);
 assert.deepEqual(await previewGroupSource(async()=>({names:[],error:regex}),g,null),{names:[],errors:{'包含（正则）':regex}});
 assert.deepEqual(await previewGroupSource(async()=>({names:[],error:SOURCE_GROUP_ERROR}),g,null),{names:[],errors:{'来源策略组':SOURCE_GROUP_ERROR}});
 assert.deepEqual(await previewGroupSource(async()=>({names:['HK','US']}),{...g,filter:'',exclude_filter:''},null),{names:['HK','US'],errors:{}});
});
test('validateGraph rejects missing/non-group/self references, relay and mixed members/via cycles',()=>{
 for(const source of ['missing','HK','Consumer']){const d=base();d.kernel.groups![1].include_group=source;assert.throws(()=>validateGraph(d),/来源策略组无效/);}
 const direct=base();direct.kernel.groups![0].type='relay';assert.throws(()=>validateGraph(direct),/来源策略组无效/);
 const target=base();target.kernel.groups![1].type='relay';assert.throws(()=>validateGraph(target),/来源策略组无效/);
 const nested=base();nested.kernel.groups!.push({name:'Relay',type:'relay',members:['HK']});nested.kernel.groups![0].members=['Relay'];assert.throws(()=>validateGraph(nested),/来源策略组无效/);
 const member=base();member.kernel.groups![0].members=['Consumer'];assert.throws(()=>validateGraph(member),/来源策略组无效/);
 const via=base();via.kernel.outbounds![0].via='Consumer';assert.throws(()=>validateGraph(via),/来源策略组无效/);
 const sources=base();sources.kernel.groups![0].include_group='Consumer';assert.throws(()=>validateGraph(sources),/来源策略组无效/);
});
test('rename rewrites source references atomically through putEntity; deletion explicitly refuses',()=>{
 const d=base();assert.ok(references(d,'Source').some(p=>p.endsWith('.include_group')));
 const before=structuredClone(d);assert.throws(()=>removeEntity(d,'groups','Source'),/include_group/);assert.deepEqual(d,before);
 putEntity(d,'groups','Source',{...d.kernel.groups![0],name:'Renamed'});assert.equal(d.kernel.groups![1].include_group,'Renamed');validateGraph(d);
 assert.deepEqual(d.kernel.groups![1].members,['US']);assert.equal(d.kernel.groups![1].fixed,'HK');assert.deepEqual(d.kernel.groups![1].priority,{HK:0.5});
 const duplicate=structuredClone(d);assert.throws(()=>putEntity(d,'groups','Renamed',{...d.kernel.groups![0],name:'Consumer'}),/名称重复/);assert.deepEqual(d,duplicate);
});
