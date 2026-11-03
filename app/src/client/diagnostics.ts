import type {NetworkDiagnosticReply} from './types';
// Display-only legacy-cache compatibility. Never rewrite history or start a probe.
export function visibleUnlockCache(reply:NetworkDiagnosticReply|null):NetworkDiagnosticReply|null {
  return reply?{...reply,items:reply.items.filter(item=>item.name!=='TikTok')}:null;
}
