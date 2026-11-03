import type { ProbeResult } from './types';

// Only frozen categories cross the display boundary. Never render backend
// error text, node names, addresses, URLs or credentials, even for old peers.
export function probeFailureSummary(results: ProbeResult[]): string {
  const failed = results.filter(r => r.error || r.error_code || r.probe_ms == null);
  if (!failed.length) return '';
  const counts = { dependency: 0, target: 0, canceled: 0, queue: 0, other: 0 };
  for (const r of failed) {
    switch (r.error_code) {
      case 'PROBE_DEPENDENCY_UNREADY': counts.dependency++; break;
      case 'PROBE_TARGET_TIMEOUT': counts.target++; break;
      case 'PROBE_CANCELED': counts.canceled++; break;
      case 'PROBE_QUEUE_TIMEOUT': counts.queue++; break;
      default: counts.other++;
    }
  }
  return '测速未完成 · ' + [
    counts.dependency && `依赖策略组未就绪 ${counts.dependency} 项（诊断码：PROBE_DEPENDENCY_UNREADY）`,
    counts.target && `目标探测超时 ${counts.target} 项（诊断码：PROBE_TARGET_TIMEOUT）`,
    counts.canceled && `已取消 ${counts.canceled} 项（诊断码：PROBE_CANCELED）`,
    counts.queue && `等待测速名额超时 ${counts.queue} 项（诊断码：PROBE_QUEUE_TIMEOUT）`,
    counts.other && `探测失败 ${counts.other} 项（诊断码：PROBE_FAILED）`,
  ].filter(Boolean).join('；');
}
