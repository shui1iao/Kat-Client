import {durationMS} from './settings';
import type {GroupStatus} from './types';
// A site's choices are not the group-level default. Most-used is real runtime
// usage; probe labels always remain policyMemberProbe data in the view.
export function smartHeaderMember(g:GroupStatus|undefined):string|null|undefined {
 return g?.selection_mode==='site' ? g.most_used_member||g.current : g?.current;
}

export function durationNumber(v:string|number|undefined,unit:'ms'|'s'):number|''{
 if(v===undefined)return '';if(typeof v==='number')return unit==='ms'?v:v/1000;
 const ms=v==='0'?0:durationMS(v);if(!Number.isFinite(ms))return '';
 return unit==='ms'?ms:ms/1000;
}
export function selectionReason(g:GroupStatus|undefined,label:(s:string)=>string):string{
 if(!g)return '';
 if(g.selection_reason==='fixed')return `固定 ${label(g.fixed??g.current??'')}：手动偏好优先`;
 if(g.selection_reason==='fixed_fallback')return `固定 ${label(g.fixed??'')} 暂不可用，自动兜底；验证恢复后切回`;
 if(g.candidate)return `候选 ${label(g.candidate)}：确认中 ${g.confirm_progress??0}/${g.confirm_required??2}${g.remaining_dwell_ms?` · 最短保持还需 ${Math.ceil(g.remaining_dwell_ms/1000)} 秒`:''}`;
 return '';
}
