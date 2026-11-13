import { readDocument } from './document';
import type { DocumentFormat, DocumentSource, SubscriptionPreview, SubscriptionStatus } from './types';
import type { DocumentSession } from './session';
export function importKind(text:string, format:DocumentFormat='yaml'):'native'|'clash'|'nodes' {
 try {const d=readDocument(text,format);if(d?.schema_version===1&&d.client&&d.kernel)return 'native';if(d&&typeof d==='object'&&['proxies','proxy-groups','rule-providers','rules'].some(k=>Object.hasOwn(d,k)))return 'clash';}catch { /* core returns the authoritative safe error */ }
 return 'nodes';
}
export function assertSubscriptionWritable(doc:DocumentSession) {
 if(doc.saved===null)throw new Error('配置未连接');
 if(doc.dirty||doc.draftFilename)throw new Error('请先保存或取消原文草稿；导入不会覆盖草稿');
 if(doc.saving||doc.installing||doc.uncertain)throw new Error('请等待当前保存或安装完成');
}
export async function acceptSubscription(doc:DocumentSession,p:SubscriptionPreview,revision:number) {
 assertSubscriptionWritable(doc);
 if(doc.revision!==revision)throw new Error('配置或草稿已变化，请重新预览');
 if(!p.token||!p.text||!p.format||p.issues.length)throw new Error('没有可接纳的完整候选');
 await doc.save(p.text,p.format);
}
export function dueSubscriptions(source:DocumentSource|null,now:number,attempts:Map<string,number>,statuses:Record<string,SubscriptionStatus>={},busy:Set<string>=new Set()) {
 return (source?.subscriptions??[]).filter(s=>{
  const finished=attempts.get(s.id),state=statuses[s.id];
  const deadline=state?.next_due??(finished===undefined?s.updated+s.interval:finished+Math.min(s.interval,1800));
  return s.url&&s.auto_update!==false&&!busy.has('subscription:'+s.id)&&now>=deadline;
 });
}
export function subscriptionSummary(p:SubscriptionPreview) {
 const n=p.counts;return `${n.nodes??0} 节点 · ${n.groups??0} 策略组 · ${n.rules??0} 规则 + ${n.match??0} MATCH · ${n.rule_sets??0} 规则集`;
}

export function intervalLabel(seconds:number){const minutes=seconds/60;return '每 '+(minutes>=1440&&minutes%1440===0?minutes/1440+' 天':minutes>=60&&minutes%60===0?minutes/60+' 小时':minutes+' 分钟');}

export interface SubscriptionTransport{preview(params:Record<string,unknown>):Promise<SubscriptionPreview>;cancel(token:string):Promise<unknown>}
// Network work never owns DocumentSession.saving. One optimistic remerge
// handles intervening accepted edits; a second conflict remains explicit.
export async function backgroundSubscription(doc:DocumentSession,api:SubscriptionTransport,params:Record<string,unknown>,approved?:{preview:SubscriptionPreview;revision:number}){
 if(doc.saved===null||doc.installing||doc.uncertain)throw new Error('请先连接并完成当前安装或配置核对');
 for(let attempt=0;attempt<2;attempt++){
  while(doc.saving)await new Promise(r=>setTimeout(r,20));
  const revision=doc.revision;let p:SubscriptionPreview|undefined;
  try{
   p=approved&&approved.revision===revision?approved.preview:await api.preview(params);
   if(doc.revision!==revision){if(attempt===0)continue;throw new Error('配置再次变化，请重新更新订阅；原配置已保留');}
   if(p.kind==='native')throw {code:'subscription_native_config'};
   if(p.kind&&p.kind!=='full')throw {code:'subscription_format_unsupported'};
   if(p.issues.length)throw new Error(p.issues[0]);
   if(p.needs_confirmation&&!(approved?.preview===p&&approved.revision===revision)){const review={preview:p,revision};p=undefined;return {confirmation:review};}
   if(!p.token||!p.text||!p.format)throw new Error('没有可接纳的完整候选');
   if(doc.installing||doc.uncertain)throw new Error('请等待安装或配置核对完成后重新更新');
   await doc.save(p.text,p.format,true);return {done:true};
  }catch(e){if(attempt===0&&['subscription_stale','candidate_expired'].includes((e as any)?.code)){approved=undefined;continue;}throw e;}
  finally{if(p?.token)await api.cancel(p.token).catch(()=>{});}
 }
 throw new Error('配置变化，请重新更新订阅；原配置已保留');
}

export function routeLabel(route?:string){return route==='kernel_rules'?'经 Kat 内核下载':route==='windows_static_http'?'经第三方系统代理下载':route==='direct'?'直连下载':'尚无成功路线';}
export function subscriptionUsage(s:{userinfo?:{upload:number;download:number;total?:number;expire?:number}},now=Date.now()/1000){
 const u=s.userinfo;if(!u)return null;const used=u.upload+u.download,total=u.total&&u.total>0?u.total:undefined,percent=total?used/total*100:undefined;
 const days=u.expire?Math.ceil((u.expire-now)/86400):undefined;
 return {used,total,percent,days,expired:u.expire!==undefined&&u.expire<=now,tone:percent===undefined||percent<70?'normal':percent<=90?'warn':'bad'};
}
export function subscriptionGroup(source:DocumentSource|null,name?:string){return name?source?.subscriptions?.find(s=>s.active!==false&&s.snapshot.groups?.some((g:{name:string})=>g.name===name)):undefined;}

const stableSubscriptionValue=(v:any):any=>Array.isArray(v)?v.map(stableSubscriptionValue):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,stableSubscriptionValue(v[k])])):v;
const stableSubscriptionKey=(v:unknown)=>JSON.stringify(stableSubscriptionValue(v));
export function sameSubscriptionObject(a:unknown,b:unknown):boolean {
 return stableSubscriptionKey(a)===stableSubscriptionKey(b);
}
const subscriptionRuleIndex=new WeakMap<object,{overlayRef:unknown;overlayLen:number;snapshotRef:unknown;snapshotLen:number;patches:Map<string,{patch:number;originalKey:string}>;remotes:Map<string,number>}>();
function getSubscriptionRuleIndex(s:any){
 const overlayRef=s.overlay?.rules,overlayLen=Array.isArray(overlayRef)?overlayRef.length:0;
 const snapshotRef=s.snapshot?.rules,snapshotLen=Array.isArray(snapshotRef)?snapshotRef.length:0;
 let cached=subscriptionRuleIndex.get(s);
 if(cached&&cached.overlayRef===overlayRef&&cached.overlayLen===overlayLen&&cached.snapshotRef===snapshotRef&&cached.snapshotLen===snapshotLen)return cached;
 const patches=new Map<string,{patch:number;originalKey:string}>(),remotes=new Map<string,number>();
 if(Array.isArray(overlayRef))overlayRef.forEach((p:any,i:number)=>{
  const valKey=stableSubscriptionKey(p?.value),origKey=stableSubscriptionKey(p?.original);
  if(!patches.has(valKey))patches.set(valKey,{patch:i,originalKey:origKey});
  if(!patches.has(origKey))patches.set(origKey,{patch:i,originalKey:origKey});
 });
 if(Array.isArray(snapshotRef))snapshotRef.forEach((r:unknown,i:number)=>{
  const k=stableSubscriptionKey(r);if(!remotes.has(k))remotes.set(k,i);
 });
 cached={overlayRef,overlayLen,snapshotRef,snapshotLen,patches,remotes};
 subscriptionRuleIndex.set(s,cached);
 return cached;
}
export function subscriptionRule(source:DocumentSource|null,rule:unknown){
 const subs=source?.subscriptions;if(!subs?.length)return undefined;
 const ruleKey=stableSubscriptionKey(rule);
 for(const s of subs){
  if(s.active===false)continue;
  const idx=getSubscriptionRuleIndex(s);
  const hit=idx.patches.get(ruleKey);
  const patch=hit?hit.patch:-1;
  const originalKey=hit?hit.originalKey:ruleKey;
  const remote=idx.remotes.get(originalKey)??-1;
  if(patch>=0||remote>=0)return {owner:s,patch,remote};
 }
 return undefined;
}

export function subscriptionFieldErrors(p:{mode:'remote'|'local';text:string;name:string;interval:string}){
 const errors:Record<string,string>={};if(p.mode==='remote'){try{const u=new URL(p.text.trim());if(u.protocol!=='https:'||!u.hostname||u.username||u.password||u.hash)throw Error();}catch{errors.url='请输入不含账号密码或片段的 HTTPS 订阅链接';}}
 else if(!p.text.trim())errors.text='请选择文件或粘贴完整 Clash 配置';
 if(new TextEncoder().encode(p.name).length>128||/[\r\n\0]/.test(p.name))errors.name='名称须在 128 字节以内且不能换行';
 if(!['0','follow'].includes(p.interval)&&(!Number.isInteger(Number(p.interval))||Number(p.interval)<60||Number(p.interval)>2592000))errors.interval='自动更新间隔须为 1 分钟至 30 天';
 return errors;
}
