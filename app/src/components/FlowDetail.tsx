import type { ReactNode } from 'react';
import { tip } from './Tooltip';
import { ConnectionRule } from './labels';
import { CopyButton } from './ui';
import { ProtocolTag } from './ProtocolTag';
import { inboundLabel } from '../client/logDetails';
import { clockStr, durationStr, showBytes } from '../client/display';
import type { ConnLogEntry } from '../client/types';

interface FlowDetailEntry {
  target: string;
  host?: string;
  dest_host?: string;
  dest_ip?: string;
  dest_ips?: string[];
  remote_dns?: boolean;
  sniffed?: boolean;
  inbound_kind?: string;
  inbound?: string;
  source_addr?: string;
  source?: string;
  up?: number;
  down?: number;
  start?: string;
  time?: string;
  end?: string;
  duration_ms?: number;
  process_path?: string;
  process_name?: string;
  rule: string;
  outcome?: ConnLogEntry['outcome'];
  error_text?: string;
  code?: string;
  error_stage?: string;
}

export function FlowDetail({
  e,
  rawChain,
  labelOf,
  nodeProtoMap,
  onCreateRule,
  canCreateRule = true,
  extraActions,
}: {
  e: FlowDetailEntry;
  rawChain: string[];
  labelOf: (name: string) => string;
  nodeProtoMap: Map<string, string>;
  onCreateRule?: () => void;
  canCreateRule?: boolean;
  extraActions?: ReactNode;
}) {
  const name = e.dest_host || e.host || e.target || '';
  const targetSub =
    [
      e.dest_ip || (e.remote_dns ? '远端解析' : ''),
      e.target && e.target !== name ? e.target : '',
      e.sniffed ? '嗅探 SNI' : '',
      e.dest_ips && e.dest_ips.length > 1 ? `候选 ${e.dest_ips.join(', ')}` : '',
    ]
      .filter(Boolean)
      .join(' · ') || '直接目标';

  const rawIn = e.inbound_kind ?? e.inbound;
  const rawSrc = e.source_addr ?? e.source;
  const inboundText =
    [inboundLabel(rawIn) !== '—' ? inboundLabel(rawIn) : rawIn ?? '', rawSrc]
      .filter(Boolean)
      .join(' · ') || '—';



  const hasError = (e.outcome !== undefined && e.outcome!=='ok'&&e.outcome!=='idle') || !!e.error_text || !!e.code;

  return (
    <div className="conn-inline-detail">
      <div className="cid-grid">
        <div className="cid-item">
          <span>目标与解析</span>
          <b className="mono ell" {...tip(targetSub, true)}>
            {targetSub}
          </b>
        </div>
        <div className="cid-item">
          <span>入站与来源</span>
          <b className="mono ell" {...tip(inboundText, true)}>
            {inboundText}
          </b>
        </div>
        <div className="cid-item">
          <span>流量与耗时</span>
          <b className="num">
            <em style={{ color: 'var(--up)', fontStyle: 'normal' }}>↑ {e.up == null ? '—' : showBytes(e.up)}</em>
            {' · '}
            <em style={{ color: 'var(--down)', fontStyle: 'normal' }}>↓ {e.down == null ? '—' : showBytes(e.down)}</em>
            {' · '}
            {clockStr(e.start || e.time)}
            {e.end ? ' → ' + clockStr(e.end) : ''}
            {e.duration_ms != null ? ` (${durationStr(e.duration_ms)})` : ''}
          </b>
        </div>
        <div className="cid-item cid-span">
          <span>进程路径</span>
          <b className="mono ell" {...tip(e.process_path || e.process_name || '未知', true)}>
            {e.process_path || e.process_name || '未知'}
          </b>
        </div>
        <div className="cid-item">
          <span>命中规则</span>
          <b>
            <ConnectionRule raw={e.rule} />
          </b>
        </div>
      </div>

      {hasError && (
        <div className="cid-error-bar">
          <div className="cid-error-main">
            <span className="cid-error-tag">{e.outcome === 'rejected' ? '已拒绝' : '异常原因'}</span>
            <span>{e.error_text || (e.outcome === 'rejected' ? '规则拦截连接' : '连接中断')}</span>
            {e.code && <code>{e.code}</code>}
            {e.error_stage && <code>{e.error_stage}</code>}
          </div>
          <CopyButton
            variant="link"
            text={[e.error_text, e.code, e.error_stage].filter(Boolean).join(' · ')}
            label="复制原因"
          />
        </div>
      )}

      <div className="cid-bottom">
        <div className="cid-chain">
          <span className="cid-chain-label">出口链路</span>
          {rawChain.length > 0 ? (
            rawChain.map((hop, idx) => {
              const isLast = idx === rawChain.length - 1;
              const proto = isLast ? nodeProtoMap.get(hop) : undefined;
              return (
                <span className="cid-hop" key={idx + ':' + hop}>
                  {idx > 0 && <span className="cid-arrow">→</span>}
                  <b>{labelOf(hop)}</b>
                  {proto && !['direct', 'reject'].includes(proto) && <ProtocolTag type={proto} />}
                </span>
              );
            })
          ) : (
            <span className="muted">—</span>
          )}
        </div>

        <div className="cid-actions">
          {onCreateRule && (
            <button type="button" className="btn sm primary" disabled={!canCreateRule} onClick={onCreateRule}>
              生成规则
            </button>
          )}
          <CopyButton text={name || e.target} label="复制目标" />
          {extraActions}
        </div>
      </div>
    </div>
  );
}
