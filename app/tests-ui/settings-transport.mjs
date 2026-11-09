// Isolated test-only fixture. No import from src or production fallback.
import { installTransport, installDailyTransport } from './daily-transport.mjs';
export { installTransport, installDailyTransport };
export function installSettingsTransport(){
 const state=window.__TEST,d=JSON.parse(state.text);
 d.kernel.outbounds.push({name:'LocalC',type:'socks5',server:'127.0.0.1',port:19003},{name:'LocalD',type:'socks5',server:'127.0.0.1',port:19004});
 d.kernel.groups[1].members=['LocalB','LocalA','LocalC','LocalD'];d.kernel.groups[1].priority={LocalA:0.8};d.kernel.groups[1].fixed='LocalB';d.kernel.groups[1].probe.url='http://127.0.0.1/background';
 d.kernel.providers.push({name:'http-fixture',type:'http',url:'http://127.0.0.1/sub',path:'/loopback/cache',via:'direct',interval:'1h',format:'auto',timeout:'90s',user_agent:'fixture-agent',exclude_type:'direct',headers:{'X-Fixture':'fixture-private-value'},advanced:{keep:true}});
 state.text=JSON.stringify(d,null,2)+'\n';state.original=state.text;state.probes={LocalA:65,LocalB:60,LocalC:null,LocalD:65};state.probeAt={LocalA:'2026-10-28T02:20:01Z',LocalB:'2026-10-28T02:21:02Z',LocalC:null,LocalD:'2026-10-28T02:22:03Z'};
 const invoke=window.__TAURI_INTERNALS__.invoke;
 window.__TAURI_INTERNALS__.invoke=async(command,args={})=>{
  const r=await invoke(command,args);
  if(command==='core_request'&&/^probe\./.test(args.method)){state.lastProbe={method:args.method,...args.params};state.probeAt[args.params.name]='2026-10-28T02:30:04Z';}
  if(command==='core_request'&&args.method==='status'){
   for(const n of r.nodes)n.probe_at=state.probeAt[n.name]??null;
   for(const g of r.groups)for(const m of g.members){m.probe_at=state.probeAt[m.name]??null;if(m.name==='LocalC')m.available=false;}
  }
  return r;
 };
}
