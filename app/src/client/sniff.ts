import {durationMS} from './settings';
import type {SniffSettings} from './types';

export type SniffField='tcp_ports'|'udp_ports'|'timeout';
export type SkipDomainMode='default'|'custom';

export const DEFAULT_SKIP_DOMAINS=['+.push.apple.com','Mijia Cloud','+.io.mi.com','+.cloudflare-ech.com'] as const;

const utf8Encoder=new TextEncoder();

function hasLoneSurrogate(s:string):boolean {
 for(let i=0;i<s.length;i++){
  const c=s.charCodeAt(i);
  if(c>=0xd800&&c<=0xdbff){
   const next=s.charCodeAt(++i);
   if(!(next>=0xdc00&&next<=0xdfff))return true;
  }else if(c>=0xdc00&&c<=0xdfff){
   return true;
  }
 }
 return false;
}

// Matches route.ParsePorts: 1..65535, ascending ranges, comma/slash lists, <=64 entries/1024 bytes.
export function sniffPortsError(value:string):string {
 if(value===''||value==='none')return '';
 const entries=value.replaceAll('/',',').split(',');
 const valid=value.length<=1024&&entries.length<=64&&entries.every(s=>{
  const m=/^(\d{1,5})(?:-(\d{1,5}))?$/.exec(s);if(!m)return false;
  const lo=Number(m[1]),hi=Number(m[2]??m[1]);return lo>=1&&hi>=lo&&hi<=65535;
 });
 return valid?'':'请输入 1–65535 端口、升序范围或 none';
}

export function sniffTimeoutInput(value?:string):string {
 if(value===undefined)return '';const ms=value==='0'?0:durationMS(value);return ms===0?'':String(ms);
}

export function sniffInputError(field:SniffField,value:string):string {
 if(field!=='timeout')return sniffPortsError(value);
 return value===''||Number.isFinite(Number(value))&&Number(value)>=1&&Number(value)<=2000?'':'等待首包须为 1–2000 毫秒';
}

export function skipDomainMode(rawSkip:unknown):SkipDomainMode {
 return rawSkip===undefined||rawSkip===null?'default':'custom';
}

export function parseSkipDomainInput(raw:string,mode:SkipDomainMode='custom'):string[]|undefined {
 if(mode==='default')return undefined;
 return raw.split(',').map(s=>s.trim()).filter(Boolean);
}

export function sameSkipDomain(a:string[]|undefined,b:string[]|undefined):boolean {
 if(a===undefined||b===undefined)return a===b;
 return a.length===b.length&&a.every((v,i)=>v===b[i]);
}

export function skipDomainKey(items:string[]|undefined):string {
 return items===undefined?'default':'custom:'+JSON.stringify(items);
}

// Aligned with Go kernel.ValidateSkipDomains: <=128 entries, valid UTF-8,
// no C0/C1 control chars (unicode.IsControl), 1..253 UTF-8 bytes after trim,
// and non-empty/non-whitespace suffix body after stripping +./*./. and trailing dots.
export function skipDomainError(items:string[]|undefined|null):string {
 if(items===undefined||items===null)return '';
 if(!Array.isArray(items))return '跳过列表格式无效';
 if(items.length>128)return '跳过列表最多 128 项';
 for(const raw of items){
  if(typeof raw!=='string'||hasLoneSurrogate(raw))return '每项须为有效 UTF-8 文本';
  if(/[\u0000-\u001f\u007f-\u009f]/.test(raw))return '每项须为 1–253 字节且不含控制字符';
  const s=raw.trim();
  const byteLen=utf8Encoder.encode(s).length;
  if(byteLen<1||byteLen>253)return '每项须为 1–253 字节且不含控制字符';
  const suffixRest=s.startsWith('+.')||s.startsWith('*.')?s.slice(2):s.startsWith('.')?s.slice(1):null;
  if(suffixRest!==null&&suffixRest.replace(/\.+$/,'').trim().length===0)return '后缀规则不能为空';
 }
 return '';
}

export function shouldBlurOnSkipKeyDown(event:{key:string;isComposing?:boolean;keyCode?:number}):boolean {
 return event.key==='Enter'&&!event.isComposing&&event.keyCode!==229;
}

export function canClearDnsCache(running:boolean,busy:{has(key:string):boolean}):boolean {
 return running&&!busy.has('dns-clear');
}

export function patchSniff(cur:SniffSettings|undefined,patch:Partial<SniffSettings>):SniffSettings {
 const safeCur=cur&&typeof cur==='object'&&!Array.isArray(cur)
  ?{...cur,...(cur.skip_domain===undefined||cur.skip_domain===null?{skip_domain:undefined}:{skip_domain:Array.isArray(cur.skip_domain)?cur.skip_domain.filter((v):v is string=>typeof v==='string'):[]})}
  :undefined;
 const next:SniffSettings={enabled:true,override_destination:true,...safeCur,...patch};
 if(next.skip_domain!==undefined){
  if((next.skip_domain as unknown)===null){
   delete next.skip_domain;
  }else{
   next.skip_domain=Array.isArray(next.skip_domain)?next.skip_domain.filter((v):v is string=>typeof v==='string'):[];
  }
 }
 for(const k of ['tcp_ports','udp_ports','timeout','skip_domain'] as const)if(next[k]===undefined)delete next[k];
 return next;
}

export interface SkipDomainControllerState {
 mode:SkipDomainMode;
 value:string;
 error:string;
}

/** Stateful interaction controller used by SkipDomainInput and behavior tests:
 *  single-commit on blur, mode persistence, error clearing on edit, and serialized async saves. */
export function createSkipDomainController(
 initialRawSkip:string[]|undefined|null,
 save:(patch:Partial<SniffSettings>)=>Promise<boolean>,
 onChange?:(state:SkipDomainControllerState)=>void,
) {
 const normalizeAccepted=(raw:string[]|undefined|null):string[]|undefined=>
  raw===undefined||raw===null?undefined:Array.isArray(raw)?raw.filter((v):v is string=>typeof v==='string'):[];
 let accepted=normalizeAccepted(initialRawSkip);
 let lastExternal=accepted===undefined?undefined:[...accepted];
 let state:SkipDomainControllerState={
  mode:skipDomainMode(accepted),
  value:accepted?accepted.join(', '):'',
  error:'',
 };
 let opSeq=0;
 let pendingKey:string|null=null;
 let queue:Promise<void>=Promise.resolve();

 const emit=(patch:Partial<SkipDomainControllerState>)=>{
  state={...state,...patch};
  onChange?.(state);
 };

 const enqueueSave=(seq:number,nextSkip:string[]|undefined,onAccepted?:()=>void,onRejected?:()=>void):Promise<void>=>{
  const targetKey=skipDomainKey(nextSkip);
  pendingKey=targetKey;
  queue=queue.then(async()=>{
   try{
    if(seq!==opSeq)return;
    if(sameSkipDomain(accepted,nextSkip)){
     onAccepted?.();
     return;
    }
    const ok=await save({skip_domain:nextSkip});
    if(ok){
     accepted=nextSkip===undefined?undefined:[...nextSkip];
     lastExternal=accepted===undefined?undefined:[...accepted];
    }
    if(seq!==opSeq)return;
    if(ok){
     onAccepted?.();
    }else{
     onRejected?.();
    }
   }finally{
    if(seq===opSeq&&pendingKey===targetKey)pendingKey=null;
   }
  });
  return queue;
 };

 return {
  getState:()=>state,
  getAccepted:()=>accepted,
  syncExternal(rawSkip:string[]|undefined|null){
   const nextExternal=normalizeAccepted(rawSkip);
   if(sameSkipDomain(lastExternal,nextExternal))return;
   lastExternal=nextExternal===undefined?undefined:[...nextExternal];
   if(sameSkipDomain(accepted,nextExternal))return;
   opSeq++;
   pendingKey=null;
   accepted=nextExternal===undefined?undefined:[...nextExternal];
   emit({
    mode:skipDomainMode(accepted),
    value:accepted?accepted.join(', '):'',
    error:'',
   });
  },
  editInput(nextValue:string){
   emit({value:nextValue,error:''});
  },
  changeMode(nextMode:SkipDomainMode,disabled=false):Promise<void>{
   if(disabled||nextMode===state.mode)return queue;
   const seq=++opSeq;
   if(nextMode==='default'){
    emit({mode:'default',value:'',error:''});
    return enqueueSave(
     seq,
     undefined,
     ()=>emit({mode:'default',value:'',error:''}),
     ()=>emit({mode:skipDomainMode(accepted),value:accepted?accepted.join(', '):''}),
    );
   }
   emit({mode:'custom',value:'',error:''});
   return enqueueSave(
    seq,
    [],
    ()=>emit({mode:'custom',value:'',error:''}),
    ()=>emit({mode:skipDomainMode(accepted),value:accepted?accepted.join(', '):''}),
   );
  },
  commitBlur(disabled=false):Promise<void>{
   if(disabled||state.mode!=='custom')return queue;
   const nextSkip=parseSkipDomainInput(state.value,'custom')??[];
   const err=skipDomainError(nextSkip);
   if(err){
    emit({error:err});
    return queue;
   }
   const normalizedText=nextSkip.join(', ');
   if(state.error)emit({error:''});
   if(sameSkipDomain(accepted,nextSkip)){
    if(state.value!==normalizedText)emit({value:normalizedText});
    return queue;
   }
   if(pendingKey===skipDomainKey(nextSkip))return queue;
   const seq=++opSeq;
   return enqueueSave(seq,nextSkip,()=>emit({value:normalizedText,error:''}));
  },
  keyDown(event:{key:string;isComposing?:boolean;keyCode?:number;preventDefault:()=>void;blur:()=>void}){
   if(shouldBlurOnSkipKeyDown(event)){
    event.preventDefault();
    event.blur();
   }
  },
 };
}
