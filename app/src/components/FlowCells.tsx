import { useMemo, type ReactNode } from 'react';
import type { Client } from '../client/useClient';
import { parseConnectionRule, ruleColor } from '../client/presentation';
import { ProcessIcon } from './EntityIcons';
import { ConnectionTarget, KTag, NetworkTag } from './labels';
import { tip } from './Tooltip';

/* Two-line flow cells shared by 连接 and 连接日志 (user decision 2026-11-27):
   the row's leading icon column shows the destination site icon (DomainIcon),
   line 1 carries the target and landing node, and line 2 carries the process
   icon + process name · network · rule alongside the policy path. */

const shortRuleType = (t: string) =>
  t.replace('DOMAIN-SUFFIX', 'SUFFIX').replace('DOMAIN-KEYWORD', 'KEYWORD').replace('PROCESS-NAME', 'PROC').replace('RULE-SET', 'SET');

export function FlowTargetCell({
  name,
  title,
  ip,
  rule,
  sniffed,
  network,
  processName,
  processPath,
}: {
  name: string;
  title?: string;
  ip?: string;
  rule: string;
  sniffed?: boolean;
  network: string;
  /** Omit inside a process group (the group header already names it). */
  processName?: string | null;
  processPath?: string;
}) {
  const parsed = parseConnectionRule(rule);
  return (
    <span className="flow-cell flow-target-cell">
      <span className="flow-l1">
        <ConnectionTarget showIcon={false} name={name} ip={ip} rule={rule} title={title} sniffed={sniffed} />
      </span>
      <span className="flow-l2">
        {processName !== undefined && (
          <span className="flow-proc" {...tip(processPath || processName || '未知', true)}>
            <ProcessIcon name={processName ?? undefined} path={processPath} size="sm" />
            <span className="ell">{processName || '未知'}</span>
          </span>
        )}
        <NetworkTag network={network} />
        <span className="flow-rule" {...tip(rule, true)}>
          {parsed ? (
            <>
              <KTag label={shortRuleType(parsed.type)} color={ruleColor(parsed.type)} />
              {parsed.payload && <span className="ell">{parsed.payload}</span>}
            </>
          ) : (
            <span className="ell">{rule || '—'}</span>
          )}
        </span>
      </span>
    </span>
  );
}

export function FlowExitCell({ chain }: { chain: string[] }) {
  const landing = chain.at(-1) ?? '—';
  const path = chain.slice(0, -1).join(' → ');
  const full = chain.join(' → ') || '—';
  return (
    <span className="flow-cell flow-exit-cell" {...tip(full, true)}>
      <span className="flow-l1 flow-landing ell">{landing}</span>
      <span className="flow-l2 ell">{path}</span>
    </span>
  );
}

export function FlowNumCell({ top, bottom, topClass = '' }: { top: ReactNode; bottom: ReactNode; topClass?: string }) {
  return (
    <span className="flow-cell flow-num-cell num">
      <span className={'flow-l1 ' + topClass}>{top}</span>
      <span className="flow-l2">{bottom}</span>
    </span>
  );
}

export function useNodeProtoMap(c: Client): Map<string, string> {
  const nodes = c.status?.nodes;
  const outbounds = c.source?.kernel.outbounds;
  return useMemo(() => {
    const m = new Map<string, string>();
    for (const n of nodes ?? []) m.set(n.name, n.type);
    for (const o of outbounds ?? []) if (!m.has(o.name)) m.set(o.name, o.type);
    return m;
  }, [nodes, outbounds]);
}
