import type { FlowDetails, DocumentSource, SourceObject } from './types';
import { isValidIPv4, isValidIPv6, splitHostPort } from '../lib/netAddr';

export interface FlowRuleSource extends FlowDetails { host?: string; target: string; chain: string[] }

function normalizeFlowIp(raw: string): string {
  const s = raw.trim();
  if (!s) return '';
  if (isValidIPv4(s)) return s;
  if (!isValidIPv6(s)) return '';
  const unb = s.startsWith('[') && s.endsWith(']') ? s.slice(1, -1) : s;
  const pct = unb.indexOf('%');
  const clean = pct > 0 ? unb.slice(0, pct) : unb;
  return isValidIPv6(clean) ? clean : '';
}

export function flowRuleValues(x: FlowRuleSource): Record<string, string> {
  const host = x.dest_host || x.host || '';
  const target = x.dest_ip || splitHostPort(x.target).host;
  const ip = normalizeFlowIp(target);
  return {
    domain_suffix: x.domain_suffix || host,
    domain: host,
    ip_cidr: ip ? ip + (ip.includes(':') ? '/128' : '/32') : '',
    process_name: x.process_name || '',
  };
}

export function flowRuleDraft(x: FlowRuleSource, d: DocumentSource | null) {
  const values = flowRuleValues(x);
  const field = values.domain ? 'domain_suffix' : 'ip_cidr';
  const target = x.chain.find((n) => d?.kernel.groups?.some((g) => g.name === n)) || 'direct';
  const value: SourceObject = { [field]: values[field], ...(target === 'direct' ? { action: target } : { outbound: target }) };
  return { index: null, value, flow: x };
}

export function processCounts(xs: { process_name?: string }[]) {
  const m = new Map<string, number>();
  for (const x of xs) m.set(x.process_name || '', (m.get(x.process_name || '') || 0) + 1);
  return [...m].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
}
