import {handleTrayAction,selectGroupMember,traySnapshot,type TrayAPI} from './tray';
import {connectionRates,withConnectionSnapshot} from './presentation';
import { useEffect, useMemo, useRef, useState } from 'react';
import { listen } from '@tauri-apps/api/event';
import { watchNetworkEvents } from './networkEvents';
import {hydrateIcons,cachedIcon} from './iconCache';
import {originalNames} from './names';
import { acceptSubscription, backgroundSubscription, dueSubscriptions } from './subscription';
import { core, hasHost, host } from './ipc';
import { errorText, isMutationUncertain, subscriptionFailureText } from '../lib/errors';
import { updatePreferences } from './daily';
import { DocumentSession } from './session';
import type { ConnectionsReply, DesktopPreferences, DesktopSettingsReply, CoreMethod, CoreStatus, DocumentReply, DocumentSource, HostCommand, NetworkStatus, ProbeResult, SubscriptionPreview, SubscriptionStatus } from './types';
export interface Sample { at: number; down: number; up: number }
export function appendSample(old: readonly Sample[], sample: Sample, now = sample.at): Sample[] {
  const cutoff = now - 3600000, keepLast = sample.at > cutoff ? 1 : 0;
  let count = keepLast, start = old.length;
  while (start > 0 && count < 1801) {
    start--;
    if (old[start].at > cutoff) count++;
  }
  const out = new Array<Sample>(count);
  let w = 0;
  for (let i = start; i < old.length; i++) {
    if (old[i].at > cutoff) out[w++] = old[i];
  }
  if (keepLast) out[w] = sample;
  return out;
}
export const MAIN_WINDOW_HIDDEN_EVENT = 'main-window-hidden';
export function applyMainWindowHidden(hidden: unknown, root: { dataset?: DOMStringMap | Record<string, string | undefined> } | null = typeof document !== 'undefined' ? document.documentElement : null) {
  if (typeof hidden !== 'boolean' || !root?.dataset) return;
  if (hidden && root.dataset.view !== 'tray-menu') root.dataset.katWindowHidden = 'true';
  else delete root.dataset.katWindowHidden;
}
export function watchMainWindowHidden(subscribe: typeof listen = listen, root?: { dataset?: DOMStringMap | Record<string, string | undefined> } | null) {
  applyMainWindowHidden(false, root);
  let live = true, stop: (() => void) | undefined;
  void subscribe<boolean>(MAIN_WINDOW_HIDDEN_EVENT, e => { if (live) applyMainWindowHidden(e.payload, root); })
    .then(unlisten => { if (live) stop = unlisten; else unlisten(); })
    .catch(() => applyMainWindowHidden(false, root));
  return () => { live = false; stop?.(); applyMainWindowHidden(false, root); };
}
export function useMainWindowHidden() {
  useEffect(() => {
    applyMainWindowHidden(false);
    if (!hasHost()) return;
    return watchMainWindowHidden(listen);
  }, []);
}
export function useClient() {
  useMainWindowHidden();
  const [, redraw] = useState(0);
  const [status, setStatus] = useState<CoreStatus | null>(null);
  // Process reachability is separate from a healthy core's stopped engine.
  const coreReachable = useRef(false);
  const [desktop, setDesktop] = useState<DesktopSettingsReply | null>(null);
  const [network, setNetwork] = useState<NetworkStatus | null>(null);
  const [error, setErrorState] = useState('');
  const [errorQueue,setErrorQueue]=useState<string[]>([]);

  const selectionSequence=useRef(0);
  const [selections,setSelections]=useState<Record<string,{member:string;unpin:boolean;id:number}>>({});
  const [busy, setBusy] = useState<Set<string>>(new Set());
  const [connectionSpeeds,setConnectionSpeeds]=useState<Record<number,number|null>>({});
  const lastConnections=useRef<{at:number;items:CoreStatus['connections']['items']}|null>(null);
  const [samples, setSamples] = useState<Sample[]>([]);
  const [kernelRestarting,setKernelRestarting]=useState(false);
  const [appRestarting,setAppRestarting]=useState(false);
  const [quitCleanupPending,setQuitCleanupPending]=useState(false);
  const appRestartingRef=useRef(false);
  const [legacyNotices,setLegacyNotices]=useState<Record<string,string>>({});
 const [probingAll,setProbingAll]=useState(false);
 const [subscriptionResults,setSubscriptionResults]=useState<Record<string,SubscriptionStatus>>({});
 const subscriptionResultsRef=useRef(subscriptionResults);subscriptionResultsRef.current=subscriptionResults;
 const showSubscriptionFailure=(e:unknown)=>{const text=subscriptionFailureText(e);setErrorState(text);setErrorQueue(q=>[...q,text]);};
 async function refreshSubscriptionResults(){if(!coreReachable.current)return;try{const r=await core<Record<string,SubscriptionStatus>>('subscription.status');if(mounted.current){subscriptionResultsRef.current=r;setSubscriptionResults(r);}}catch{/* older host cannot provide persisted attempt details */}}
 const [subscriptionNotices,setSubscriptionNotices]=useState<Record<string,string>>({});
  const subscriptionPause=useRef(0),subscriptionAttempts=useRef(new Map<string,number>());
  const pauseSubscriptions=(paused:boolean)=>{subscriptionPause.current=Math.max(0,subscriptionPause.current+(paused?1:-1));};
  const jobs = useRef(new Set<string>());
  const mounted = useRef(true), lifetime = useRef(0);
  const session = useRef<DocumentSession | null>(null);
  if (!session.current) session.current = new DocumentSession({ validate: (text, format) => core('document.validate', { text, format }), apply: (text, format) => core<DocumentReply>('document.apply', { text, format }) }, () => { if (mounted.current) redraw(x => x + 1); });
  const doc = session.current;
  const setError=(text:string)=>{setErrorState(text);if(text&&!doc.editing)setErrorQueue(q=>[...q,errorText(text)]);};
  const reportOperationError=(e:unknown)=>{const text=errorText(e);setErrorState(text);setErrorQueue(q=>[...q,text]);};
 const dismissError=()=>{setErrorState('');setErrorQueue(q=>q.slice(1));};
  const subscriptionTail=useRef<Promise<unknown>>(Promise.resolve());
  const [subscriptionReviews,setSubscriptionReviews]=useState<Record<string,{preview:SubscriptionPreview;revision:number}>>({});
  const reviewRef=useRef(subscriptionReviews);reviewRef.current=subscriptionReviews;

  const statusRequest = useRef(0), networkRequest = useRef(0);
  const reconciliation = useRef<Promise<void> | null>(null);
  const active = (life: number) => mounted.current && lifetime.current === life;
  const observeUncertain = (e: unknown, revision = doc.revision) => { if (isMutationUncertain(e)) doc.markUncertain(revision); };
  async function refreshStatus() {
    const request=++statusRequest.current, life=lifetime.current;let s:CoreStatus;
    try {
      s=await core<CoreStatus>('status');
      if(s.runtime.state==='running'){
        if(!coreReachable.current&&active(life)&&request===statusRequest.current){coreReachable.current=true;setStatus(s);}
        try { s=withConnectionSnapshot(s,await core<ConnectionsReply>('connections.list',{closed_limit:1})); }
        catch(e) {
          if(active(life)&&request===statusRequest.current)observeUncertain(e);
          // A supplemental connection read is not the runtime/measurement
          // snapshot. Reconfirm actual status rather than clearing valid probes
          // or retaining an old Running value if the core really stopped/exited.
          s=await core<CoreStatus>('status');
        }
      }
    } catch(e) { if(active(life)&&request===statusRequest.current){observeUncertain(e);coreReachable.current=false;setStatus(null);}throw e; }
    if(!active(life)||request!==statusRequest.current)return s;
    const next={at:Date.now(),items:s.runtime.state==='running'?s.connections.items:[]};
    const nextRates=connectionRates(lastConnections.current,next);
    setConnectionSpeeds(old=>Object.keys(old).length===0&&Object.keys(nextRates).length===0?old:nextRates);lastConnections.current=next;
    coreReachable.current=true;
    setStatus(s);
    if (s.traffic?.down_rate != null && s.traffic?.up_rate != null) setSamples(old => {
      const now = Date.now();
      return appendSample(old, { at: now, down: s.traffic.down_rate!, up: s.traffic.up_rate! }, now);
    });
    return s;
  }
  async function refreshNetwork() { const request=++networkRequest.current,life=lifetime.current;try { const n=await host<NetworkStatus>('network_status');if(active(life)&&request===networkRequest.current)setNetwork(n);return n; } catch(e) { if(active(life)&&request===networkRequest.current){observeUncertain(e);setNetwork(null);}throw e; } }
  // Shared by the existing poll and reconnect. Only a stable public get may
  // release this local gate; status/diagnostics and ordinary refreshes cannot.
  async function reconcileAccepted() {
    if (!doc.uncertain) return;
    if (reconciliation.current) return reconciliation.current;
    const life=lifetime.current, version=doc.uncertainVersion;
    const pending=(async()=>{
      const reply=await core<DocumentReply>('document.get');
      if(!active(life)||!doc.uncertain||version!==doc.uncertainVersion)return;
      if(!doc.reconcileAccepted(reply))throw new Error('CORE_MUTATION_UNCERTAIN');
      // Invalidate older polling before refreshing the newly reconciled runtime.
      statusRequest.current++;networkRequest.current++;
      try { await refreshStatus(); } catch { /* ordered refresh owns failure projection */ }
      if(!active(life))return;
      try { await refreshNetwork(); } catch { /* ordered refresh owns failure projection */ }
      if(active(life)&&!doc.uncertain)setErrorState(old=>isMutationUncertain(old)?'':old);
    })();
    reconciliation.current=pending;
    try { await pending; } finally { if(reconciliation.current===pending)reconciliation.current=null; }
  }
  async function run(key: string, task: () => Promise<unknown>, onError?: (e:unknown)=>void): Promise<boolean> {
    if (!mounted.current || jobs.current.has(key) || doc.installing || appRestartingRef.current) return false;
    const life=lifetime.current,revision=doc.revision;
    jobs.current.add(key); if(active(life)){setBusy(new Set(jobs.current));setError('');}
    try { await task(); return true; }
    catch (e) { if(active(life)){observeUncertain(e,revision);if(onError)onError(e);else setError(errorText(e));} return false; }
    finally { jobs.current.delete(key);if(active(life))setBusy(new Set(jobs.current)); }
  }
  async function refreshDesktop() { const life=lifetime.current;try { const r=await host<DesktopSettingsReply>('desktop_settings_get');if(active(life))setDesktop(r);return r; } catch(e) { if(active(life)){observeUncertain(e);setDesktop(null);}throw e; } }
  const setPreferences=(patch:Partial<DesktopPreferences>)=>run('preferences',()=>updatePreferences({get:()=>host<DesktopSettingsReply>('desktop_settings_get'),set:p=>host<DesktopSettingsReply>('desktop_settings_set',{patch:p})},patch,setDesktop));
  async function connect() {
    const life=lifetime.current;
    await run('connect', async () => {
      if (!hasHost()) throw new Error('未连接 · 需要桌面宿主');
      const hello = await core<{ protocol: number }>('hello');
      if(!active(life))return;
      if (hello.protocol !== 1) throw new Error('不支持的核心协议');
      if (doc.uncertain) await reconcileAccepted();
      else if (doc.saved === null) {
        const reply=await core<DocumentReply>('document.get');
        if(!active(life))return;
        if(doc.uncertain)await reconcileAccepted();else if(doc.saved===null)doc.load(reply);
        // Load disk/remote group icons asynchronously after publishing accepted config
        // so large icon caches never block first-screen rendering or status refresh.
        void (async()=>{
          try{const cached=await core<Record<string,string>>('icon.cached');if(active(life)){hydrateIcons(cached);redraw(x=>x+1);}}catch{/* missing cache never blocks accepted configuration */}
          const seen=new Set<string>();
          for(const g of doc.source?.kernel.groups??[]){if(!active(life))break;if(!g.icon||seen.has(g.icon)||!cachedIcon(g.icon))continue;seen.add(g.icon);try{const r=await core<{data_uri:string}>('icon.get',{url:g.icon,group:g.name});if(active(life)){hydrateIcons({[g.icon]:r.data_uri});redraw(x=>x+1);}}catch{/* quiet icon task */}}
        })();
      }
      if(active(life)){
       for(const p of [...(doc.source?.kernel.providers??[])]){if(!active(life))break;await migrateOne(p.name);}
       await refreshStatus();
       await refreshSubscriptionResults();
      }
    },e=>setErrorState(errorText(e)));
  }
  useEffect(() => {
    mounted.current=true;
    if (hasHost()) {
      void refreshDesktop().catch(e=>{if(mounted.current)setErrorState(errorText(e));});
      void refreshNetwork().catch(e=>{if(mounted.current)setErrorState(errorText(e));});
      void refreshStatus().catch(()=>{/* connect() owns startup error reporting */});
    }
    void connect();
    if (!hasHost()) return () => { mounted.current=false;lifetime.current++; };
    let live = true, polling = false;
    const id = setInterval(async () => {
      if (!live || polling) return; polling = true;
      try {
        await Promise.allSettled([refreshStatus(), refreshNetwork()]);
        if(!live)return;
        // Do not await the get: normal read-only polling continues while it is in flight.
        if(live&&coreReachable.current&&doc.uncertain)void reconcileAccepted().catch(()=>{ /* keep gate and draft; next existing poll may read again */ });
      } finally { polling = false; }
    }, 2000);
    return () => { live = false;mounted.current=false;lifetime.current++;statusRequest.current++;networkRequest.current++;clearInterval(id); };
  }, []);
  useEffect(()=> {
    if (!hasHost()) return;
    return watchNetworkEvents(listen, setError, () => { void refreshNetwork().catch(()=>{});void refreshStatus().catch(()=>{}); },setKernelRestarting,setQuitCleanupPending);
  }, []);
  useEffect(()=>{
    if(!hasHost())return;let live=true;const stops:Array<()=>void>=[];
    for(const name of ['app-restarting','app-restart-failed'])void listen(name,e=>{
      if(!live)return;
      if(name==='app-restarting'&&typeof e.payload==='boolean'){appRestartingRef.current=e.payload;setAppRestarting(e.payload);}
      if(name==='app-restart-failed'){appRestartingRef.current=false;setAppRestarting(false);reportOperationError(e.payload);void refreshNetwork().catch(()=>{});void refreshStatus().catch(()=>{});}
    }).then(stop=>{if(live)stops.push(stop);else stop();}).catch(reportOperationError);
    return()=>{live=false;for(const stop of stops)stop();};
  },[]);
  async function readActualNetwork() { if(!mounted.current)return;try { await refreshNetwork(); } catch { /* refresh owns ordering and failure projection */ } }
  const edit = (fn: (d: DocumentSource) => void,onError?:(e:unknown)=>void) => run('save', async () => { try { await doc.edit(fn); } finally { await readActualNetwork(); } try { await refreshStatus(); } catch { /* refresh owns failure projection */ } },onError);
  const save = () => run('save', async () => { try { await doc.save(); } finally { await readActualNetwork(); } try { await refreshStatus(); } catch { /* refresh owns failure projection */ } });
  async function migrateOne(name:string){
    if(doc.dirty||doc.draftFilename||doc.editing||doc.saving||doc.uncertain)throw new Error('请先关闭编辑并保存或取消草稿');
    const revision=doc.revision;let p:SubscriptionPreview|undefined;
    try{p=await core<SubscriptionPreview>('subscription.migrate',{name});await acceptSubscription(doc,p,revision);setLegacyNotices(old=>{const n={...old};delete n[name];return n;});}
    catch(e){setLegacyNotices(old=>({...old,[name]:errorText(e)}));observeUncertain(e,revision);}
    finally{if(p?.token)await core('subscription.cancel',{token:p.token});}
  }
  const migrate=(name:string)=>run('migration',async()=>{await migrateOne(name);await refreshStatus();});
  const probeOutcomeError=(outcome:{error?:string}|null|undefined)=>{
    // Member failures are already shown with each node. Only an operation-level
    // failure belongs in the global error dialog.
    if(outcome?.error)throw new Error(outcome.error);
  };
  const probeAll=()=>run('probe.all',async()=>{
    setProbingAll(true);
    try{
      const admitted=await core<{id:string}>('probe.all');
      while(mounted.current){
        const s=await refreshStatus();
        if(s.runtime.state!=='running')break;
        if(s.probe_round?.id!==admitted.id){
          if(s.probe_round_result?.id===admitted.id)probeOutcomeError(s.probe_round_result);
          break;
        }
        await new Promise(resolve=>window.setTimeout(resolve,250));
      }
    }finally{if(mounted.current)setProbingAll(false);}
  },reportOperationError);
  const probeAllProgress=status?.probe_round??(probingAll?{done:0,total:status?.nodes.filter(n=>!['direct','reject'].includes(n.type)).length??0,names:status?.nodes.map(n=>n.name)??[]}:null);
  const probeGroupProgress:NonNullable<CoreStatus['probe_group_rounds']>=status?.probe_group_rounds??{};
  // Frozen Policies interface: a group operation never globally locks peers.
  const groupProbing=(name:string)=>busy.has('probe.group:'+name)||!!probeGroupProgress[name];
  const probingNames=new Set<string>(probeAllProgress?.names);for(const k of Object.keys(probeGroupProgress))for(const n of probeGroupProgress[k].names)probingNames.add(n);
  const memberProbing=(name:string)=>busy.has('probe.node:'+name)||probingNames.has(name);
  const probeLocked=status?.runtime.state!=='running'||!!probeAllProgress||doc.installing||kernelRestarting||appRestarting;
  const probe = (kind: 'node' | 'group', name: string) => run(`probe.${kind}:${name}`, async () => {
    if(kind==='group'){
      const admitted=await core<{id:string}>('probe.group',{name});
      while(mounted.current){
        const s=await refreshStatus();
        if(s.runtime.state!=='running')break;
        if(s.probe_group_rounds?.[name]?.id!==admitted.id){
          const outcome=s.probe_group_results?.[name];
          if(outcome?.id===admitted.id)probeOutcomeError(outcome);
          break;
        }
        await new Promise(resolve=>window.setTimeout(resolve,250));
      }
    }else{
      await core<ProbeResult>('probe.node',{name});
      await refreshStatus();
    }
  },reportOperationError);
  // Optional existing-layout cancel action: an old ID can never cancel a newer
  // round. Route changes alone do not cancel Host-owned measurements.
  const cancelProbeGroup=(name:string,id:string)=>run(`probe.group.cancel:${name}`,async()=>{
    await core('probe.group',{name,cancel_id:id});
    await refreshStatus();
  },reportOperationError);

  const os = (cmd: HostCommand, params: Record<string, unknown> = {}) => run('network', async () => {
    const revision=doc.revision;let failure:unknown;
    const installing=cmd==='network_service_install';
    if(installing){if(jobs.current.size>1)throw new Error('请等待当前操作完成后再安装或更新');doc.beginInstall();}
    try { await host(cmd, params); } catch(e){if(installing)doc.endInstall();observeUncertain(e,revision);failure=e;}
    // Success exits this source GUI. Keep editing locked until the native process
    // actually exits; cancellations/errors unlock without discarding any draft.
    try { await refreshNetwork(); } catch(e) { if(!failure)failure=e; }
    if(failure)throw failure;
  });
  // A download occupies only its own subscription job, not the document or
  // network controls. Core's single staged candidate is serialized separately.
  async function startSubscription(params:Record<string,unknown>,key:string,automatic=false,onFailure?:(text:string)=>boolean,confirm=false){
   if(automatic&&!coreReachable.current)return;
   let skippedUnavailable=false;
   let result:{done?:boolean;confirmation?:{preview:SubscriptionPreview;revision:number};error?:string}|undefined;
   await run('subscription:'+key,async()=>{
    const work=subscriptionTail.current.then(async()=>{
     if(automatic&&!coreReachable.current){skippedUnavailable=true;return;}
     const approved=confirm?reviewRef.current[key]:undefined;
     const r=await backgroundSubscription(doc,{preview:p=>core<SubscriptionPreview>('subscription.preview',p),cancel:token=>core('subscription.cancel',{token})},params,approved);
     result=r;
     setSubscriptionReviews(old=>{const n={...old};if(r.confirmation)n[key]=r.confirmation;else delete n[key];return n;});
     setSubscriptionNotices(old=>{const n={...old};if(r.confirmation)n[key]='订阅变化需要确认；请点击编辑查看';else delete n[key];return n;});
     if(r.done){try{await refreshStatus();await refreshNetwork();}catch{/* actual state poll recovers */}}
    });
    subscriptionTail.current=work.catch(()=>{});await work;
   },e=>{const text=subscriptionFailureText(e);result={error:text};setSubscriptionNotices(old=>({...old,[key]:text}));if(!automatic){if((e as any)?.code==='invalid_params'&&onFailure?.(text))return;showSubscriptionFailure(e);}});
   if(skippedUnavailable)return result;
   subscriptionAttempts.current.set(key,Date.now()/1000);
   await refreshSubscriptionResults();
   return result;
  }
  const clearSubscriptionReview=(key:string)=>{const r=reviewRef.current[key];if(r?.preview.token)void core('subscription.cancel',{token:r.preview.token}).catch(()=>{});const next={...reviewRef.current};delete next[key];reviewRef.current=next;setSubscriptionReviews(old=>{const n={...old};delete n[key];return n;});if(r)setSubscriptionNotices(old=>{if(!old[key]?.includes('订阅变化需要确认'))return old;const n={...old};delete n[key];return n;});};
  useEffect(()=>{
   if(!hasHost())return;
   const timer=setInterval(()=>{
    if(!mounted.current||!coreReachable.current||appRestartingRef.current||subscriptionPause.current||doc.editing||doc.saved===null||doc.installing||doc.uncertain)return;
    const now=Date.now()/1000,sub=dueSubscriptions(doc.source,now,subscriptionAttempts.current,subscriptionResultsRef.current,jobs.current)[0];if(!sub)return;
    void startSubscription({id:sub.id,download_mode:sub.download_mode??'auto',full_only:true},sub.id,true);
   },30000);return()=>clearInterval(timer);
  },[]);
  // Native remains responsible for core/OS write gating and safe network shutdown.
  const restartCore=()=>run('core',async()=>{const revision=doc.revision;try{await host('core_restart');}catch(e){observeUncertain(e,revision);throw e;}finally{await readActualNetwork();try{await refreshStatus()}catch{/* final state owns the stopped/error projection */}}},reportOperationError);
  const control = (method: CoreMethod) => run('core', async () => { const revision=doc.revision;try { await core(method); } catch(e){observeUncertain(e,revision);throw e;} finally { await readActualNetwork(); } await refreshStatus(); });
  async function updateSubscription(id:string):Promise<'confirmation'|'done'> {
   const sub=doc.source?.subscriptions?.find(s=>s.id===id);if(!sub)return 'done';
   const r=await startSubscription({id,download_mode:sub.download_mode??'auto',full_only:true},id);
   return r?.confirmation?'confirmation':'done';
  }
  async function selectSubscription(id:string,patch:Record<string,unknown>={}){
   return run('subscription:'+id,async()=>{const revision=doc.revision;let p:SubscriptionPreview|undefined;try{p=await core<SubscriptionPreview>('subscription.select',{id,...patch});await acceptSubscription(doc,p,revision);await refreshStatus();}finally{if(p?.token)await core('subscription.cancel',{token:p.token}).catch(()=>{});}},showSubscriptionFailure);
  }
  async function updateAllSubscriptions(){for(const sub of [...(doc.source?.subscriptions??[])]){if(sub.url&&!jobs.current.has('subscription:'+sub.id))await startSubscription({id:sub.id,download_mode:sub.download_mode??'auto',full_only:true},sub.id);}}
  // Optimistic per-group projection; never writes source/drafts before native
  // acceptance and never reads/reconfigures OS network for a manual selection.
  const selectMember=(group:string,member:string,unpin=false)=>{
    const id=++selectionSequence.current,key='select:'+group+':'+id;
    setSelections(old=>({...old,[group]:{member,unpin,id}}));
    return run(key,async()=>{
      await doc.select(d=>selectGroupMember(d,group,member,unpin,(status?.nodes??[]).map(n=>n.name)));
      try{await refreshStatus();}catch{/* polling owns actual stopped state */}
    },reportOperationError).finally(()=>setSelections(old=>{if(old[group]?.id!==id)return old;const next={...old};delete next[group];return next;}));
  };
  let projectedSource=doc.source,projectedStatus=status;
  if(Object.keys(selections).length){
    if(projectedSource){
      // Only selection fields are projected; accepted rules/subscription snapshots
      // and all untouched groups stay read-only and need no deep copy.
      const kernel={...projectedSource.kernel};
      if(kernel.groups){kernel.groups=[...kernel.groups];for(const [group,p]of Object.entries(selections)){const i=kernel.groups.findIndex(g=>g.name===group);if(i>=0){const g={...kernel.groups[i]};if(p.unpin)delete g.fixed;else if(g.type==='select')g.selected=p.member;else g.fixed=p.member;kernel.groups[i]=g;}}}
      projectedSource={...projectedSource,kernel};
    }
    if(projectedStatus)projectedStatus={...projectedStatus,groups:projectedStatus.groups.map(g=>{const p=selections[g.name];return p&&!p.unpin?{...g,current:p.member}:g;})};
  }
  const labels=useMemo(()=>originalNames(doc.source),[doc.source]),label=(name:string|null|undefined)=>name?labels.get(name)??name:'—';
  // Host owns its app-restarting flag. Do not echo our own accepted restart as
  // an external snapshot busy condition into its second pre-cleanup check.
  const trayProjectionBlocked=()=>kernelRestarting||doc.saving||doc.uncertain||doc.installing||jobs.current.has('save')||jobs.current.has('network')||jobs.current.has('core');
  const trayBlocked=()=>appRestartingRef.current||trayProjectionBlocked();
  // Quitting restores OS network and exits; never block quit on drafts/background jobs.
  const lifecycleBlocked=(action?:'quit'|'restart_core'|'restart_app')=>action==='quit'?false:action==='restart_app'?(appRestartingRef.current||kernelRestarting||doc.saving||doc.installing||jobs.current.has('save')):(appRestartingRef.current||kernelRestarting||doc.saving||doc.installing||jobs.current.has('save')||jobs.current.has('core'));
  const restartApp=async()=>{
    if(lifecycleBlocked('restart_app')){reportOperationError(Error('正在保存配置或执行网络操作，请稍后再试'));return false;}
    return run('app-restart',async()=>{
      // Lock locally before IPC; success is only native acceptance. Async
      // failure unlocks through app-restarting/app-restart-failed above.
      appRestartingRef.current=true;setAppRestarting(true);
      try{await host('window_action',{action:'restart-app'});}
      catch(e){appRestartingRef.current=false;setAppRestarting(false);throw e;}
    },reportOperationError);
  };
  const trayAPI=useRef<TrayAPI|null>(null);trayAPI.current={blocked:trayBlocked,lifecycleBlocked,restartCore,restartApp,quit:()=>run('window',()=>host('window_action',{action:'quit'}),reportOperationError),mode:m=>edit(d=>{d.client.mode=m},reportOperationError),select:selectMember,network:(cmd,enabled)=>os(cmd,{enabled}),show:()=>host('window_action',{action:'show'}),error:reportOperationError};
  const trayListenerReady=useRef(false);
  const lastTray=useRef<{state:string;payload:ReturnType<typeof traySnapshot>}|null>(null);
  const nextTray=traySnapshot(projectedSource,projectedStatus,network,trayProjectionBlocked(),label),trayState=JSON.stringify(nextTray);
  if(lastTray.current?.state!==trayState)lastTray.current={state:trayState,payload:nextTray};
  const trayPayload=lastTray.current.payload;
  const trayStateRef=useRef(trayPayload);trayStateRef.current=trayPayload;
  useEffect(()=>{
    if(!hasHost())return;let live=true;const stops:Array<()=>void>=[];
    const keep=(stop:()=>void)=>{if(live)stops.push(stop);else stop();};
    const actionListener=listen('tray-action',e=>{
      if(!live||!trayAPI.current)return;
      const payload=e.payload as {delivery_id?:unknown};
      void(async()=>{
        try{
          if(typeof payload?.delivery_id!=='string'||!payload.delivery_id)throw Error('托盘动作缺少有效送达标识，请重新打开菜单');
          // ACK only means this main listener now owns validation. Never replay
          // an old action after a stale/failed delivery acknowledgement.
          await host('tray_sync',{listener_ready:true,delivery_ack:payload.delivery_id});
          if(live&&trayAPI.current)await handleTrayAction(e.payload,trayAPI.current);
        }catch(error){if(live&&trayAPI.current){trayAPI.current.error(error);await trayAPI.current.show().catch(()=>{});}}
      })();
    }).then(keep);
    const errorListener=listen('tray-menu-error',e=>{if(live&&trayAPI.current)trayAPI.current.error(e.payload);}).then(keep);
    void Promise.all([actionListener,errorListener]).then(()=>{
      if(!live)return;trayListenerReady.current=true;
      void host('tray_sync',{snapshot:trayStateRef.current,listener_ready:true}).catch(reportOperationError);
    }).catch(e=>{trayListenerReady.current=false;for(const stop of stops.splice(0))stop();if(live)reportOperationError(e);});
    return()=>{live=false;trayListenerReady.current=false;for(const stop of stops.splice(0))stop();void host('tray_sync',{listener_ready:false}).catch(()=>{});};
  },[]);
  useEffect(()=>{if(hasHost())void host('tray_sync',{snapshot:trayPayload,listener_ready:trayListenerReady.current}).catch(()=>{/* native tray errors must not alter confirmed configuration */});},[trayState]);
  return { selectMember,kernelRestarting,appRestarting,quitCleanupPending,restartCore,restartApp,reportOperationError, subscriptionResults,showSubscriptionFailure,selectSubscription,updateAllSubscriptions, connectionSpeeds,label, startSubscription,subscriptionReviews,clearSubscriptionReview,errorQueue,dismissError, updateSubscription,legacyNotices, migrate, probeAll, probeAllProgress, probeGroupProgress, groupProbing, memberProbing, probeLocked, cancelProbeGroup, pauseSubscriptions, subscriptionNotices, desktop, refreshDesktop, setPreferences, doc, source: projectedSource, status:projectedStatus, network, busy, error:doc.uncertain?errorText('CORE_MUTATION_UNCERTAIN'):error, samples, hasHost: hasHost(), connected: doc.saved !== null, edit, save, run, probe, os, control, connect, setError, refreshStatus, refreshNetwork };
}
export type Client = ReturnType<typeof useClient>;
