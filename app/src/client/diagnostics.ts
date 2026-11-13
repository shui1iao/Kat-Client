import type {NetworkDiagnosticReply} from './types';
const REMOVED_UNLOCK=new Set(['TikTok','YouTube','YouTube Premium','Claude','Disney+']);
// Display-only legacy-cache compatibility. Never rewrite history or start a probe.
export function visibleUnlockCache(reply:NetworkDiagnosticReply|null):NetworkDiagnosticReply|null {
  return reply?{...reply,items:reply.items.filter(item=>!REMOVED_UNLOCK.has(item.name))}:null;
}
