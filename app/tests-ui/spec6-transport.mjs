// Test-only OS/telemetry fixture. No production fallback and no native mutation.
export function installSpec6Transport() {
  const state=window.__TEST,doc=JSON.parse(state.text),now=Date.now();
  doc.kernel.providers=[];doc.kernel.dns={servers:['1.1.1.1'],cache_entries:256};
  state.text=JSON.stringify(doc,null,2)+'\n';state.now=now-3600000;state.sampleIndex=0;state.speedData=[];
  const realInterval=window.setInterval.bind(window);let poll;
  window.setInterval=(fn,ms,...args)=>ms===2000?(poll=fn,987654):realInterval(fn,ms,...args);
  state.tick=()=>poll?.();Date.now=()=>state.now;
  const invoke=window.__TAURI_INTERNALS__.invoke;
  window.__TAURI_INTERNALS__.invoke=async(command,args={})=>{
    const r=await invoke(command,args);
    if(command==='core_request'&&args.method==='status') {
      state.sampleIndex++;state.now+=2000;const i=state.sampleIndex;
      r.runtime={...r.runtime,core_version:'0.7.1',memory_bytes:117440512};
      const date=new Date();const yyyy=date.getFullYear(),mm=String(date.getMonth()+1).padStart(2,'0'),dd=String(date.getDate()).padStart(2,'0');
      r.traffic={...r.traffic,down_rate:(i%41===0?0:(18+12*Math.sin(i/13)+i%7)*1024),up_rate:(i%31===0?.2:(4+2*Math.cos(i/17))*1024),
        groups:[{name:'HK',down:102400,up:13312},{name:'JP',down:204800,up:81920},{name:'unknown',down:50,up:null}],
        rule_targets:[{name:'Final',hits:120},...Array.from({length:7},(_,j)=>({name:j===2?'Very-long-policy-name-without-truncating-its-real-tooltip':`Policy-${j+1}`,hits:35-j*4})),{name:'zero',hits:0}],
        daily:Array.from({length:7},(_,j)=>({date:j===6?`${yyyy}-${mm}-${dd}`:`2026-10-${26+j}`,down:j===3?210.4*1024**2:(j+1)*12*1024**2,up:j===3?12*1024**2:(j+1)*1024**2})),
        today_down:84*1024**2,today_up:7*1024**2,total_down:700*1024**2,total_up:35*1024**2};
      state.speedData.push({at:state.now,down:r.traffic.down_rate,up:r.traffic.up_rate});
    }
    return r;
  };
}
