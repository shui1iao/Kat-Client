import { durationMS } from './settings';
import type { Group, GroupStatus } from './types';
// A site's choices are not the group-level default. Most-used is real runtime
// usage; probe labels always remain policyMemberProbe data in the view.
export function smartHeaderMember(runtime: GroupStatus | undefined, cfg?: Group): string | null | undefined {
  const site = cfg
    ? cfg.type === 'smart' && (runtime?.selection_mode ?? cfg.smart?.scope ?? 'site') === 'site'
    : runtime?.selection_mode === 'site';
  return site ? runtime?.most_used_member || runtime?.current : runtime?.current;
}

export function durationNumber(v:string|number|undefined,unit:'ms'|'s'):number|''{
 if(v===undefined)return '';if(typeof v==='number')return unit==='ms'?v:v/1000;
 const ms=v==='0'?0:durationMS(v);if(!Number.isFinite(ms))return '';
 return unit==='ms'?ms:ms/1000;
}

