import type {ConnLogEntry,ConnectionsReply} from './types';
const mergedFlows=new WeakMap<ConnLogEntry,Map<string,{up:number;down:number}>>();
function lanSubnetTarget(target?:string){
 if(!target)return '';
 if(target.includes('/16:'))return target;
 const m=/^(\d+)\.(\d+)\.(\d+)\.(\d+):(\d+)$/.exec(target);
 if(!m)return '';
 const a=Number(m[1]),b=Number(m[2]),port=m[5];
 if(a===10||(a===172&&b>=16&&b<=31)||(a===192&&b===168)||(a===100&&b>=64&&b<=127)||(a===169&&b===254)){
  return `${a}.${b}.0.0/16:${port}`;
 }
 return '';
}
function connBaseKey(e:ConnLogEntry){
 const host=e.dest_host||e.host||'';
 const sub=!host?lanSubnetTarget(e.target):'';
 const name=host||sub||e.target||'';
 if(!name||!e.target)return '';
 return [e.network,name,sub||e.target,e.rule,(e.chain||[]).join('>'),e.outcome].join('|');
}
function sameGroup(a:ConnLogEntry,b:ConnLogEntry){
 const ka=connBaseKey(a),kb=connBaseKey(b);
 if(!ka||ka!==kb)return false;
 return !a.process_name||!b.process_name||a.process_name===b.process_name;
}
function attachFlows(entry:ConnLogEntry,map:Map<string,{up:number;down:number}>){mergedFlows.set(entry,map);return entry;}
export function mergeConnectionLogs(old:ConnLogEntry[],incoming:ConnLogEntry[]){
 let out=[...old];
 for(const e of incoming){
  const fid=e.flow_id;
  if(e.ended&&fid&&out.some(x=>x.flow_id===fid||mergedFlows.get(x)?.has(fid))){
   out=out.map(x=>{
    const map=mergedFlows.get(x);
    if(x.flow_id!==fid&&!map?.has(fid))return x;
    const meta={
     process_name:e.process_name||x.process_name,
     process_path:e.process_path||x.process_path,
     source_addr:e.source_addr||x.source_addr,
     inbound_kind:e.inbound_kind||x.inbound_kind,
     dest_ip:e.dest_ip||x.dest_ip,
     dest_ips:e.dest_ips?.length?e.dest_ips:x.dest_ips,
     ...(x.outcome==='ok'&&e.outcome!=='ok'?{outcome:e.outcome,code:e.code,error_text:e.error_text,error_stage:e.error_stage}:{})
    };
    if(map&&map.size>1){
     const nextMap=new Map(map);
     nextMap.set(fid,{up:e.up??0,down:e.down??0});
     let up=0,down=0;for(const v of nextMap.values()){up+=v.up;down+=v.down;}
     return attachFlows({...x,...meta,up,down,end:e.end??x.end,duration_ms:(x.duration_ms??0)+(e.duration_ms??0),ended:true},nextMap);
    }
    const next:ConnLogEntry={...x,...meta,up:e.up,down:e.down,start:e.start,end:e.end,duration_ms:e.duration_ms,ended:true};
    attachFlows(next,new Map([[fid,{up:e.up??0,down:e.down??0}]]));
    return next;
   });
   continue;
  }
  const existingIdx=connBaseKey(e)?out.findIndex(x=>sameGroup(x,e)):-1;
  if(existingIdx>=0){
   const x=out[existingIdx];
   const nextMap=new Map(mergedFlows.get(x)??(x.flow_id?[[x.flow_id,{up:x.up??0,down:x.down??0}]]:[]));
   if(fid)nextMap.set(fid,{up:e.up??0,down:e.down??0});
   let up=0,down=0;for(const v of nextMap.values()){up+=v.up;down+=v.down;}
   const sub=!(x.dest_host||x.host||e.dest_host||e.host)&&x.target!==e.target?lanSubnetTarget(e.target):'';
   const target=sub||x.target;
   const ips=Array.from(new Set([...(x.dest_ips??(x.dest_ip?[x.dest_ip]:[])),...(e.dest_ips??(e.dest_ip?[e.dest_ip]:[]))])).slice(0,16);
   const merged=attachFlows({...x,target,time:e.time||x.time,flow_id:fid||x.flow_id,process_name:x.process_name||e.process_name,process_path:x.process_path||e.process_path,source_addr:x.source_addr||e.source_addr,inbound_kind:x.inbound_kind||e.inbound_kind,dest_ip:sub?sub.split(':')[0]:(x.dest_ip||e.dest_ip),dest_ips:ips.length?ips:undefined,up:x.up===undefined&&e.up===undefined?undefined:up,down:x.down===undefined&&e.down===undefined?undefined:down,end:e.end??x.end,duration_ms:(x.duration_ms??0)+(e.duration_ms??0),ended:Boolean(x.ended&&e.ended)},nextMap);
   out.splice(existingIdx,1);
   out.unshift(merged);
  }else{
   const fresh={...e};
   if(fresh.flow_id)attachFlows(fresh,new Map([[fresh.flow_id,{up:fresh.up??0,down:fresh.down??0}]]));
   out.unshift(fresh);
  }
 }
 return out.slice(0,2000);
}
export function flowLog(e:ConnLogEntry,list:ConnectionsReply|null){
 if(!e.flow_id||!list)return e;
 const map=mergedFlows.get(e);
 if(map&&map.size>1){
  let up=0,down=0;
  const all=[...list.active,...list.closed];
  for(const [fid,v] of map.entries()){
   const f=all.find(x=>x.flow_id===fid);
   up+=f?f.up:v.up;
   down+=f?f.down:v.down;
  }
  return {...e,up,down};
 }
 const f=[...list.active,...list.closed].find(x=>x.flow_id===e.flow_id);
 return f?{...e,up:f.up,down:f.down,start:f.start,end:'end' in f&&typeof f.end==='string'?f.end:undefined,duration_ms:f.duration_ms}:e;
}
export const inboundLabel=(s?:string)=>({tun:'TUN',system_proxy:'系统代理(HTTP)',socks:'SOCKS',http:'HTTP'}[s??'']??'—');
export const kernelLevelVisible=(entry:string,level:string)=>level==='all'||['debug','info','warn','error'].indexOf(entry)>=['debug','info','warn','error'].indexOf(level);
