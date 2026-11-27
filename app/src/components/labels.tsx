import type { CSSProperties } from 'react';
import { parseConnectionRule, ruleColor } from '../client/presentation';
import { tip } from './Tooltip';
import { DomainIcon } from './EntityIcons';

export function KTag({
  label,
  color = 'var(--text-3)',
  size,
  tipText,
  className = '',
}: {
  label: string;
  color?: string;
  size?: 'xs';
  tipText?: string;
  className?: string;
}) {
  const cls = ['ktag', size ? 'ktag-' + size : '', color === 'var(--text-3)' && size === 'xs' ? 'is-neutral' : '', className]
    .filter(Boolean)
    .join(' ');
  return (
    <span className={cls} style={{ '--tag-color': color } as CSSProperties} {...tip(tipText)}>
      {label}
    </span>
  );
}

export function NetworkTag({ network, size }: { network: string; size?: 'xs' }) {
  return (
    <KTag
      size={size}
      className="network-tag"
      label={network ? network.toUpperCase() : '—'}
      color={network === 'udp' ? 'var(--accent)' : 'var(--text-3)'}
    />
  );
}

export function RuleTag({ type, size }: { type: string; size?: 'xs' }) {
  return <KTag size={size} label={type} color={ruleColor(type)} />;
}

export function ConnectionRule({ raw }: { raw: string }) {
  const p = parseConnectionRule(raw);
  return (
    <span className="conn-rule" {...tip(raw)}>
      {p ? (
        <>
          <RuleTag type={p.type} />
          {p.payload && <span className="rule-payload">{p.payload}</span>}
        </>
      ) : (
        raw || '—'
      )}
    </span>
  );
}

export function PolicyPill({
  label,
  color,
  bold = false,
  className = '',
}: {
  label: string;
  color: string;
  bold?: boolean;
  className?: string;
}) {
  return (
    <span className={'rule-policy' + (className ? ' ' + className : '')}>
      <i style={{ background: color }} />
      {bold ? <b {...tip(label, true)}>{label}</b> : <span {...tip(label, true)}>{label}</span>}
    </span>
  );
}

export function KState({ tone, label, title }: { tone: 'ok' | 'warn' | 'bad' | 'muted'; label: string; title?: string }) {
  return (
    <span className={'kstate ' + tone} {...tip(title && title !== label ? title : undefined)}>
      <i />
      {label}
    </span>
  );
}

export function ConnectionTarget({
  name,
  title,
  sniffed,
  showIcon,
  ip,
  rule,
}: {
  name: string;
  title?: string;
  sniffed?: boolean;
  showIcon?: boolean;
  ip?: string;
  rule?: string;
}) {
  return (
    <span className="conn-target">
      {showIcon && <DomainIcon domain={name} ip={ip} rule={rule} size="sm" />}
      <span className="conn-name" {...tip(title && title !== name ? title : name, !(title && title !== name))}>
        {name || '—'}
      </span>
      {sniffed && <KTag size="xs" label="嗅探" tipText="嗅探得到的域名" />}
    </span>
  );
}
