import { useState } from 'react';
import { tip } from './Tooltip';
import { ConnectionRule } from './labels';
import { StableText } from './ui';
import { ProtocolTag } from './ProtocolTag';
import { inboundLabel } from '../client/logDetails';
import { clockStr, durationStr, showBytes } from '../client/display';
import type { ConnLogEntry } from '../client/types';

export function FlowDetail({
  e,
  rawChain,
  labelOf,
  nodeProtoMap,
  onCreateRule,
  canCreateRule = true,
}: {
  e: ConnLogEntry;
  rawChain: string[];
  labelOf: (name: string) => string;
  nodeProtoMap: Map<string, string>;
  onCreateRule?: () => void;
  canCreateRule?: boolean;
}) {
  const [copiedTarget, setCopiedTarget] = useState(false);
  const [copiedErr, setCopiedErr] = useState<'idle' | 'ok' | 'fail'>('idle');

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

  const inboundText =
    [inboundLabel(e.inbound_kind) !== '—' ? inboundLabel(e.inbound_kind) : '', e.source_addr]
      .filter(Boolean)
      .join(' · ') || '—';

  const copyTarget = async () => {
    if (!name) return;
    try {
      await navigator.clipboard.writeText(name);
      setCopiedTarget(true);
      window.setTimeout(() => setCopiedTarget(false), 1500);
    } catch {
      /* ignore clipboard denial */
    }
  };

  const copyError = async () => {
    try {
      await navigator.clipboard.writeText([e.error_text, e.code, e.error_stage].filter(Boolean).join(' · '));
      setCopiedErr('ok');
      window.setTimeout(() => setCopiedErr('idle'), 1500);
    } catch {
      setCopiedErr('fail');
    }
  };

  const hasError = (e.outcome !== 'ok' && e.outcome !== 'idle') || !!e.error_text || !!e.code;

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
          <button type="button" className="link-btn" onClick={() => void copyError()}>
            <StableText current={copiedErr === 'ok' ? '已复制' : copiedErr === 'fail' ? '复制失败' : '复制原因'} items={['复制原因', '复制失败', '已复制']} />
          </button>
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
          <button type="button" className="btn sm" disabled={!name} onClick={() => void copyTarget()}>
            <StableText current={copiedTarget ? '已复制' : '复制目标'} items={['复制目标', '已复制']} />
          </button>
        </div>
      </div>
    </div>
  );
}
