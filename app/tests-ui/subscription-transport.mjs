// Current one-step full-subscription fixture. Synthetic IPC only.
export function installSubscriptionTransport() {
 const s=window.__TEST,native=window.__TAURI_INTERNALS__.invoke;
 s.subscriptionRequests=[];s.pending=null;
 window.__TAURI_INTERNALS__.invoke=async(cmd,args={})=>{
  const p=args.params??{};
  if(cmd==='core_request'&&args.method==='subscription.preview'){
   s.calls.push({method:args.method});s.subscriptionRequests.push(structuredClone(p));
   if(p.text==='unsupported')return {kind:'nodes',issues:[],counts:{},needs_confirmation:false};
   const d=JSON.parse(s.text),outbounds=[{name:'Imported',type:'socks5',server:'127.0.0.1',port:19003}];
   d.kernel.outbounds.push(...outbounds);d.subscriptions=[{id:'fixture-full',name:'Complete subscription',interval:3600,updated:Math.floor(Date.now()/1000),snapshot:{outbounds,groups:[],rules:[],rule_sets:[]}}];
   s.pending={kind:'full',token:'fixture-token',id:'fixture-full',text:JSON.stringify(d),format:'json',issues:[],needs_confirmation:false,counts:{nodes:1,groups:0,rules:0,rule_sets:0,match:0}};
   return structuredClone(s.pending);
  }
  if(cmd==='core_request'&&args.method==='subscription.cancel'){s.calls.push({method:args.method});s.pending=null;return {};}
  return native(cmd,args);
 };
}
