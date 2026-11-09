import { errorText } from '../lib/errors';
type Stop = () => void;
export type EventListen = (name: string, handler: (event: { payload: unknown }) => void) => Promise<Stop>;
/** Only native diagnostic codes cross this display boundary, never raw reasons. */
export function recoveryMessage(payload: unknown) {
  const p=payload&&typeof payload==='object'?payload as {code?:unknown;tun?:unknown;transport?:unknown}:null;
  const raw=p?.code??payload;
  const code=typeof raw==='string'&&/^[A-Z][A-Z0-9_]{1,63}$/.test(raw)?raw:'RECOVERY_PENDING';
  return '网络操作未完成：' + errorText({code,tun:p?.tun,transport:p?.transport});
}
export const QUIT_CLEANUP_NOTICE = '正在完成网络清理…';
export function watchNetworkEvents(listen: EventListen, failed: (text: string) => void, refresh: () => void, restarting: (active:boolean)=>void = ()=>{}, quitWaiting: (active:boolean)=>void = ()=>{}) {
  let live = true;
  const stops: Stop[] = [];
  for (const name of ['network-recovery-required', 'network-changed','kernel-restarting','kernel-restart-failed','quit-cleanup-pending']) {
    void listen(name, event => {
      if (!live) return;
      if (name === 'network-recovery-required') { quitWaiting(false); failed(recoveryMessage(event.payload)); }
      if(name==='kernel-restarting'&&typeof event.payload==='boolean')restarting(event.payload);
      if(name==='kernel-restart-failed'){failed('重启内核失败：'+recoveryMessage(event.payload));}
      if(name==='quit-cleanup-pending'&&typeof event.payload==='boolean')quitWaiting(event.payload);
      refresh();
    }).then(stop => { if (live) stops.push(stop); else stop(); }).catch(() => { /* no native event bridge outside desktop */ });
  }
  return () => { live = false; for (const stop of stops) stop(); };
}
