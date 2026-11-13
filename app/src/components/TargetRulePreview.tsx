import {useEffect,useRef,useState} from 'react';
import {Modal,LocalError} from './Editors';
import {Icon} from './Icon';
import {core,errorText} from '../client/ipc';
import type {Client} from '../client/useClient';

type TargetPreview={
 target:{input:string;host:string;kind:'domain'|'ip';addresses:string[]};
 matched:{source:'rule'|'final';index:number|null;type:string;payload:string;policy:string};
 chain:string[];resolved:boolean;scope:'target-only';
};

// Target-address projection only. The kernel owns ordering, rule-set evaluation,
// address resolution and FINAL. This view never implements its own matcher.
export function TargetRulePreview({c,close}:{c:Client;close:()=>void}){
 const [target,setTarget]=useState(''),[busy,setBusy]=useState(false),[result,setResult]=useState<TargetPreview|null>(null),[error,setError]=useState('');
 const request=useRef(0);
 useEffect(()=>()=>{request.current++},[]);
 async function preview(){
  const input=target.trim();if(!input||busy||!c.hasHost)return;
  const id=++request.current;setBusy(true);setError('');setResult(null);
  try{const reply=await core<TargetPreview>('routing.previewTarget',{target:input});if(request.current===id)setResult(reply);}
  catch(e){if(request.current===id)setError(errorText(e));}
  finally{if(request.current===id)setBusy(false);}
 }
 const final=result?.matched.source==='final';
 return <Modal readOnly className="target-rule-preview" title="规则判定" closeLabel="关闭" close={close}>
  <div className="target-preview-body">
   <div className="target-preview-input">
    <label htmlFor="target-preview-address">域名或 IP</label>
    <div className="target-preview-input-row">
     <input id="target-preview-address" className="inp" placeholder="example.com / 1.1.1.1" autoComplete="off" spellCheck={false} value={target} disabled={busy} onChange={e=>{setTarget(e.target.value);setResult(null);setError('');}} onKeyDown={e=>{if(e.key==='Enter'&&!e.nativeEvent.isComposing){e.preventDefault();void preview();}}}/>
     <button className="btn primary" type="button" disabled={busy||!target.trim()||!c.hasHost} onClick={()=>void preview()}>{busy?'判定中…':'判定'}</button>
    </div>
    <p className="target-preview-help">也可粘贴网址。仅匹配域名和目标 IP，进程等条件不参与；不访问目标，必要时仅查询 DNS。</p>
   </div>
   <LocalError text={error}/>
   {result?<section className="target-preview-result" role="status" aria-live="polite">
    <div className="target-preview-result-head"><Icon name="rules" size={16}/><span>{final?'未命中规则，使用 FINAL':`命中第 ${result.matched.index} 条规则`}</span></div>
    <div className="target-preview-policy">{c.label(result.matched.policy)}</div>
    <dl className="target-preview-details">
     <dt>目标</dt><dd className="target-preview-mono">{result.target.host}</dd>
     <dt>匹配</dt><dd><span>{result.matched.type}</span>{result.matched.payload&&<code>{result.matched.payload}</code>}</dd>
     {result.chain.length>0&&<><dt>策略链</dt><dd>{result.chain.map(c.label).join(' → ')}</dd></>}
     {result.resolved&&result.target.addresses.length>0&&<><dt>DNS 结果</dt><dd className="target-preview-mono">{result.target.addresses.join(' · ')}</dd></>}
    </dl>
   </section>:!error&&<div className="target-preview-empty">输入目标，查看首条命中规则及对应策略。</div>}
  </div>
 </Modal>;
}
