import {pinnable,validateGraph} from './operations';
import type {DocumentSource,CoreStatus,NetworkStatus,Mode} from './types';
export function selectGroupMember(d:DocumentSource,group:string,member:string,unpin:boolean,nodes:string[]){
 const g=d.kernel.groups?.find(g=>g.name===group);if(!g)throw Error('策略组不存在');
 if(unpin){if(!pinnable(g.type))throw Error('此组不能取消固定');delete g.fixed;}else if(pinnable(g.type))g.fixed=member;else if(g.type==='select')g.selected=member;else throw Error('此组不支持手动选择');
 validateGraph(d,nodes);
}
export function traySnapshot(d:DocumentSource|null,s:CoreStatus|null,n:NetworkStatus|null,busy:boolean,label:(name:string)=>string){
 const running=s?.runtime.state==='running';return {ready:!!d&&running,busy,mode:s?.mode??d?.client.mode??'',system_proxy:!!n?.system_proxy.enabled,tun:!!(n?.tun.intent??n?.tun.enabled),proxy_ready:!!n&&(!!n.system_proxy.enabled||!!n.system_proxy.error||!!(running&&s?.local?.http.ready)),tun_ready:!!n&&(!!n.tun.intent||!!n.tun.enabled||!!n.tun.error||!!(running&&s?.local?.socks.ready&&n.service.installed)),groups:(d?.kernel.groups??[]).map(g=>{const runtime=s?.groups?.find(x=>x.name===g.name);const members=runtime?.members.length?runtime.members.map(x=>x.name):g.members??[];return {name:g.name,label:label(g.name),kind:g.type,fixed:g.fixed??null,current:runtime?.current??g.selected??null,members:members.map(name=>({name,label:label(name)}))};})};
}
export interface TrayAPI{blocked:()=>boolean;lifecycleBlocked?:(action?:'quit'|'restart_core'|'restart_app')=>boolean;restartCore?:()=>Promise<boolean>;restartApp?:()=>Promise<boolean>;quit?:()=>Promise<boolean>;mode:(mode:Mode)=>Promise<boolean>;select:(group:string,member:string,unpin:boolean)=>Promise<boolean>;network:(kind:'tun_set'|'system_proxy_set',enabled:boolean)=>Promise<boolean>;show:()=>Promise<unknown>;error:(e:unknown)=>void}
export async function handleTrayAction(payload:any,api:TrayAPI){
 if(payload?.kind==='quit'){const ok=await api.quit?.()??false;if(!ok)await api.show();return;}
 const lifecycle=['restart_core','restart_app'].includes(payload?.kind);
 if((lifecycle?api.lifecycleBlocked?.(payload?.kind)??api.blocked():api.blocked())){api.error(Error('正在保存配置或执行网络操作，请稍后重试'));await api.show();return;}
 let ok=false;
 try{switch(payload?.kind){case 'mode':if(!['rule','global','direct'].includes(payload.mode))return;ok=await api.mode(payload.mode);break;case 'system_proxy':if(typeof payload.enabled!=='boolean')return;ok=await api.network('system_proxy_set',payload.enabled);break;case 'tun':if(typeof payload.enabled!=='boolean')return;ok=await api.network('tun_set',payload.enabled);break;case 'member':if(typeof payload.group!=='string'||typeof payload.member!=='string'||typeof payload.unpin!=='boolean')return;ok=await api.select(payload.group,payload.member,payload.unpin);break;case 'restart_core':ok=await api.restartCore?.()??false;break;case 'restart_app':ok=await api.restartApp?.()??false;break;case 'quit':ok=await api.quit?.()??false;break;default:return;}}catch(e){api.error(e);}
 if(!ok)await api.show();
}
