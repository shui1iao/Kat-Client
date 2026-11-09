import { Fragment, useEffect, useId, useRef, useState, type ReactNode, type KeyboardEvent } from 'react';
import { core } from '../client/ipc';
import { policyColor, ruleKindLabel } from '../client/presentation';
import type { Client } from '../client/useClient';
import { errorText } from '../lib/errors';
import { Modal, LocalError } from './Editors';
import { Icon } from './Icon';

const labels = {
  target: '目标地址', network: '传输协议', target_port: '目标端口', process_name: '进程名称',
  source_ip: '来源 IP', source_port: '来源端口', inbound_name: '入站名称',
  inbound_type: '入站类型', inbound_port: '入站端口', protocol: '嗅探协议',
} as const;
type FieldName = keyof typeof labels;
type Values = Record<FieldName, string>;
const empty: Values = { target: '', network: '', target_port: '', process_name: '', source_ip: '', source_port: '', inbound_name: '', inbound_type: '', inbound_port: '', protocol: '' };
const portFields: FieldName[] = ['target_port', 'source_port', 'inbound_port'];
const missingLabels: Record<string, string> = { ...labels, destination_ip: '目的 IP（离线不解析 DNS）', rule_set_data: '已加载的规则集资源' };
const portSources: Record<string, string> = { url_explicit: 'URL 显式', url_default: 'URL 默认', manual: '手填', unspecified: '未指定' };
const modeNames: Record<string, string> = { rule: '规则', global: '全局', direct: '直连' };
interface KnownInput {
  host?: string; ip?: string; port?: number; port_source: string; network?: string; process_name?: string;
  source_ip?: string; source_port?: number; inbound_name?: string; inbound_type?: string; inbound_port?: number; protocol?: string;
}
interface RelatedResource {
  kind: string; name: string; data_available: boolean | null; state: string; code?: string; entries?: number; warning?: string;
}
interface RuleDecision {
  status: 'matched' | 'final' | 'unknown'; rule: number; display_row: number;
  condition: string; policy: string; reason?: string; rule_set?: string; missing: string[];
  blocked_rule?: number; candidate_policy?: string; resources: RelatedResource[]; resources_more?: number;
  resource_warnings: RelatedResource[]; resource_warnings_more?: number;
}
interface ConditionalAfter extends RuleDecision {
  assumption: { rule: number; rule_set?: string; condition: string; matches: false };
}
interface RuleResult extends RuleDecision {
  target: string; known: KnownInput; admission_warnings?: string[]; conditional_after?: ConditionalAfter | null;
}
// Older/empty peers may encode lists as null. Preserve absence of a branch,
// while normalizing both result scopes before rendering or copying text.
function normalizeDecision<T extends RuleDecision>(r: T): T {
  return { ...r, missing: r.missing ?? [], resources: r.resources ?? [], resource_warnings: r.resource_warnings ?? [] };
}
function normalizeReply(reply: InspectorReply): InspectorReply {
  const result = normalizeDecision(reply.result);
  return { ...reply, result: { ...result, conditional_after: result.conditional_after ? normalizeDecision(result.conditional_after) : null } };
}
const assumptionText = (after: ConditionalAfter) => `若第 ${after.assumption.rule} 条${after.assumption.rule_set ? ' ' + after.assumption.rule_set : ''}整条规则不匹配：`;
const conditionalNote = '这是假设结果，不代表本次连接已确认走该策略。';
function conditionalText(after: ConditionalAfter, label: (name: string) => string): string {
  if (after.status === 'final') return '后续落最终路由 · ' + label(after.policy);
  if (after.status === 'matched') return `后续命中第 ${after.rule} 条 · ` + label(after.policy);
  return '后续仍需' + after.missing.map(name => missingLabels[name] ?? name).join('、') + `（第 ${after.blocked_rule ?? after.rule} 条）`;
}
interface InspectorReply { mode: string; simulation: 'rule'; ipv6_enabled: boolean; result: RuleResult }
const resourceName = (r: RelatedResource) => r.name || ({ geoip: 'GeoIP', asn: 'ASN', geosite: 'Geosite' } as Record<string, string>)[r.kind] || r.kind;
const resourceWarning = (r: RelatedResource) => r.warning === 'not_loaded' ? '尚未加载；当前按空资源快照判定'
  : r.warning === 'refresh_failed_using_loaded' ? '最近刷新失败；继续使用已加载数据'
  : '资源状态暂不可核对；仅依据本次数据快照';
function generalError(e: unknown): string {
  const code = e && typeof e === 'object' ? (e as { code?: string }).code : '';
  if (code === 'core_not_running' || code === 'not_running') return '请先启动内核，判定使用当前已生效规则';
  if (code === 'rule_test_unavailable') return '当前规则或资源无法安全判定，请检查已生效配置与资源状态';
  if (code === 'invalid_params') return '判定参数无效，请检查补充条件';
  return errorText(e);
}

export function RuleInspector({ c, close }: { c: Client; close: () => void }) {
  const [values, setValues] = useState<Values>({ ...empty });
  const [expanded, setExpanded] = useState(false), [busy, setBusy] = useState(false);
  const [fields, setFields] = useState<Partial<Record<FieldName, string>>>({}), [error, setError] = useState('');
  const [reply, setReply] = useState<InspectorReply | null>(null), [copied, setCopied] = useState('');
  const live = useRef(true), pending = useRef(false), revision = useRef(0);
  const refs = useRef<Partial<Record<FieldName, HTMLInputElement | HTMLSelectElement | null>>>({});
  const id = useId(), supplementalId = id + '-conditions';
  useEffect(() => { live.current = true; return () => { live.current = false; revision.current++; }; }, []);
  const dismiss = () => { live.current = false; revision.current++; close(); };
  function change(name: FieldName, value: string) {
    revision.current++;
    setValues(old => ({ ...old, [name]: value })); setReply(null); setFields({}); setError(''); setCopied('');
  }
  const count = (Object.keys(values) as FieldName[]).filter(k => k !== 'target' && values[k].trim()).length;
  function focusField(name: string) {
    if (!Object.hasOwn(labels, name)) return;
    if (name !== 'target') setExpanded(true);
    requestAnimationFrame(() => refs.current[name as FieldName]?.focus());
  }
  async function run() {
    if (pending.current) return;
    const invalid: Partial<Record<FieldName, string>> = {};
    const params: Record<string, unknown> = { target: values.target };
    if (!values.target.trim()) invalid.target = '请填写目标地址';
    for (const name of Object.keys(values) as FieldName[]) {
      if (name === 'target' || !values[name].trim()) continue;
      if (portFields.includes(name)) {
        if (!/^[0-9]{1,5}$/.test(values[name]) || Number(values[name]) < 1 || Number(values[name]) > 65535) invalid[name] = '端口应为 1–65535 的整数';
        else params[name] = Number(values[name]);
      } else params[name] = values[name];
    }
    setReply(null); setFields(invalid); setError(''); setCopied('');
    const first = (Object.keys(invalid) as FieldName[])[0];
    if (first) { focusField(first); return; }
    const epoch = ++revision.current;
    pending.current = true; setBusy(true);
    try {
      const next = await core<InspectorReply>('rules.test', params);
      if (live.current && revision.current === epoch) setReply(normalizeReply(next));
    } catch (e) {
      if (!live.current || revision.current !== epoch) return;
      const failure = e as { code?: string; path?: string; message?: string };
      if (failure?.code === 'invalid_params' && failure.path && Object.hasOwn(labels, failure.path)) {
        const name = failure.path as FieldName;
        // This method's field errors are fixed, non-echoing validation messages.
        setFields({ [name]: typeof failure.message === 'string' ? failure.message.slice(0, 200) : '请检查此条件' });
        focusField(name);
      } else setError(generalError(e));
    } finally {
      pending.current = false;
      if (live.current) setBusy(false);
    }
  }
  function onKeyDown(e: KeyboardEvent<HTMLDivElement>) {
    if (e.key === 'Enter' && !e.nativeEvent.isComposing && e.target instanceof HTMLInputElement) {
      e.preventDefault(); void run();
    }
  }
  const mode = reply?.mode ?? c.status?.mode ?? 'unknown';
  const r = reply?.result;
  const known = r?.known;
  const after = r?.status === 'unknown' ? r.conditional_after : null;
  const status = r?.status === 'unknown' ? '条件不足，无法唯一确定'
    : r?.status === 'final' ? '未命中前序规则' : r ? `命中第${r.rule}条规则` : '';
  const conditionType = r ? (r.condition.startsWith('and(') ? 'AND' : r.condition.startsWith('or(') ? 'OR'
    : r.condition.startsWith('not(') ? 'NOT' : r.status === 'final' ? 'MATCH'
    : ruleKindLabel(r.condition.split(':', 1)[0], r.condition.slice(r.condition.indexOf(':') + 1))) : '';
  const field = (name: FieldName, control: ReactNode) => <div className="rule-inspector-field" key={name}>
    <label htmlFor={id + '-' + name}>{labels[name]}</label>{control}
    {fields[name] && <small id={id + '-' + name + '-error'} className="field-error" role="alert">{fields[name]}</small>}
  </div>;
  function input(name: FieldName, maxLength: number, placeholder = '') {
    return <input ref={el => { refs.current[name] = el; }} id={id + '-' + name} className="inp"
      value={values[name]} onChange={e => change(name, e.target.value)} maxLength={maxLength}
      inputMode={portFields.includes(name) ? 'numeric' : undefined} placeholder={placeholder} autoComplete="off" spellCheck={false}
      aria-invalid={!!fields[name]} aria-describedby={fields[name] ? id + '-' + name + '-error' : undefined} />;
  }
  function select(name: FieldName, options: [string, string][]) {
    return <select ref={el => { refs.current[name] = el; }} id={id + '-' + name} className="inp"
      value={values[name]} onChange={e => change(name, e.target.value)} aria-invalid={!!fields[name]}
      aria-describedby={fields[name] ? id + '-' + name + '-error' : undefined}>
      <option value="">未指定</option>{options.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
    </select>;
  }
  async function copyResult() {
    if (!r) return;
    const epoch = revision.current;
    const lines = ['规则判定 · 离线按规则模拟', `当前模式：${modeNames[mode] ?? '未知'}`, `目标：${r.target}`, status,
      r.status === 'unknown' ? '策略：未确定' : `策略：${c.label(r.policy)}`,
      `规则：${r.status === 'final' ? 'MATCH · 第' + r.display_row + '行（runtime rule=0）' : '#' + r.rule + ' · ' + r.condition}`,
      `规范化目标：${r.known.host || r.known.ip || '—'}`, `目标端口：${r.known.port ?? '未指定'} · ${portSources[r.known.port_source] ?? '未指定'}`];
    for (const name of Object.keys(labels) as FieldName[]) {
      if (name !== 'target' && name !== 'target_port') {
        const value = r.known[name as keyof KnownInput];
        if (value) lines.push(labels[name] + '：' + value);
      }
    }
    if (r.missing.length) lines.push('缺少：' + r.missing.map(n => missingLabels[n] ?? n).join('、'));
    if (r.candidate_policy) lines.push('可能策略：' + c.label(r.candidate_policy));
    for (const item of r.resource_warnings) lines.push('正式判定资源 · ' + resourceName(item) + '：' + resourceWarning(item));
    if (after) {
      lines.push('条件性后续', assumptionText(after), '该假设下：' + conditionalText(after, c.label));
      lines.push(`后续规则：${after.status === 'final' ? 'MATCH · 第' + after.display_row + '行（runtime rule=0）' : '#' + after.rule + ' · ' + after.condition}`);
      if (after.candidate_policy) lines.push('该假设下仍未确定；可能策略：' + c.label(after.candidate_policy));
      for (const item of after.resource_warnings) lines.push('假设后续资源 · ' + resourceName(item) + '：' + resourceWarning(item));
      if (after.resource_warnings_more) lines.push(`另有 ${after.resource_warnings_more} 项假设后续资源提示`);
      lines.push(conditionalNote);
    }
    if (reply?.ipv6_enabled === false) lines.push('当前 IPv6 已关闭；规则模拟不等于实际准入或连接成功');
    try { await navigator.clipboard.writeText(lines.join('\n')); if (live.current && revision.current === epoch) setCopied('已复制'); }
    catch { if (live.current && revision.current === epoch) setCopied('复制失败'); }
  }
  return <Modal readOnly title="规则判定" className="rule-inspector" closeLabel="关闭" close={dismiss}>
    <div className="rule-inspector-body" onKeyDown={onKeyDown}>
      <div className="rule-inspector-scope">
        <div className="rule-inspector-meta"><span>离线 · 按规则模拟</span><span>当前模式：{modeNames[mode] ?? '未知'}</span></div>
        {(mode === 'global' || mode === 'direct') && <p className="rule-inspector-mode-note">当前为{modeNames[mode]}；下方是规则模式模拟，实际模式不按该规则决定</p>}
      </div>
      <div className="rule-inspector-target">
        <label htmlFor={id + '-target'}>目标地址</label>
        <div className="rule-inspector-input-row">{input('target', 2048, '域名、URL 或 IP')}<button type="button" className="btn primary" disabled={busy || !c.connected} onClick={() => void run()}>{busy ? '判定中…' : '判定'}</button></div>
        {fields.target && <small id={id + '-target-error'} className="field-error" role="alert">{fields.target}</small>}
        <p className="rule-inspector-help">只读取已生效规则，不连接目标地址</p>
        {(c.doc.dirty || !!c.doc.draftFilename) && <p className="rule-inspector-draft">未保存修改不参与判定</p>}
      </div>
      <div className="rule-inspector-supplement">
        <button type="button" className="link-btn rule-inspector-disclosure" aria-expanded={expanded} aria-controls={supplementalId} onClick={() => setExpanded(!expanded)}>
          <Icon name={expanded ? 'chevDown' : 'chevRight'} size={14} />补充条件<span>已填 {count} 项</span>
        </button>
        {expanded && <div id={supplementalId} className="rule-inspector-conditions">
          <p className="rule-inspector-help">仅使用手动模拟值；未指定条件保持未知。传输协议与嗅探协议分开判定。</p>
          <div className="rule-inspector-grid">
            {field('network', select('network', [['tcp', 'TCP'], ['udp', 'UDP']]))}
            {field('target_port', input('target_port', 5, '1–65535'))}
            {field('process_name', input('process_name', 255, '进程文件名，不含路径'))}
            {field('source_ip', input('source_ip', 64, 'IP 字面量，不含区域标识'))}
            {field('source_port', input('source_port', 5, '1–65535'))}
            {field('inbound_name', input('inbound_name', 64))}
            {field('inbound_type', select('inbound_type', [['shadowsocks', 'Shadowsocks'], ['anytls', 'AnyTLS'], ['trojan', 'Trojan'], ['vless', 'VLESS'], ['socks5', 'SOCKS5'], ['snell', 'Snell']]))}
            {field('inbound_port', input('inbound_port', 5, '1–65535'))}
            {field('protocol', select('protocol', [['http', 'HTTP'], ['tls', 'TLS'], ['quic', 'QUIC']]))}
          </div>
        </div>}
      </div>
      <LocalError text={error} />
      <section className="rule-inspector-result" aria-label="规则判定结果" aria-busy={busy}>
        <div className={'rule-inspector-conclusion' + (r?.status === 'unknown' ? ' is-unknown' : '') + (!r ? ' is-empty' : '')} aria-live="polite" aria-atomic="true">
          {!r ? <p className="rule-inspector-empty">{busy ? '正在读取已生效规则…' : '输入目标后查看匹配规则与策略'}</p> : <>
            <div className="rule-inspector-result-title"><Icon name={r.status === 'unknown' ? 'alert' : r.status === 'final' ? 'route' : 'check'} size={16} /><span>{status}</span></div>
            <div className="rule-inspector-policy">{r.status === 'unknown' ? '未确定' : <>{r.status === 'final' && <span>最终路由 · </span>}<i style={{ background: policyColor(r.policy, c.status, c.label) }} />{c.label(r.policy)}</>}</div>
          </>}
        </div>
        {r && <>
          {r.status === 'unknown' && <div className="rule-inspector-missing"><span>尚需条件</span><ul>{r.missing.map(name => <li key={name}><span>{missingLabels[name] ?? name}</span>{Object.hasOwn(labels, name) && <button type="button" className="link-btn" onClick={() => focusField(name)}>填写</button>}</li>)}</ul></div>}
          <dl className="rule-inspector-details">
            <dt>{r.status === 'unknown' ? '最早不确定规则' : '匹配规则'}</dt><dd>{r.status === 'final' ? `MATCH · 第${r.display_row}行` : `#${r.blocked_rule ?? r.rule}`}</dd>
            <dt>判定依据</dt><dd><span>{conditionType}</span><code>{r.condition}</code></dd>
            {r.candidate_policy && <><dt>可能策略</dt><dd>{c.label(r.candidate_policy)}（不代表已命中）</dd></>}
            {r.rule_set && <><dt>规则集</dt><dd>{r.rule_set}（不推断子项行号）</dd></>}
          </dl>
          {after && <section className="rule-inspector-conditional" aria-label="条件性后续">
            <h4>条件性后续</h4>
            <p>{assumptionText(after)}</p>
            <p className="rule-inspector-conditional-result"><span>该假设下：</span>{conditionalText(after, c.label)}</p>
            <p className="rule-inspector-conditional-rule">{after.status === 'final' ? `MATCH · 第${after.display_row}行` : `#${after.rule} · ${after.condition}`}</p>
            {after.candidate_policy && <p>该假设下仍未确定；可能策略：{c.label(after.candidate_policy)}</p>}
            {after.resources.length > 0 && <p className="rule-inspector-conditional-rule">假设后续相关资源：{after.resources.map(resourceName).join('、')}{after.resources_more ? `（另有 ${after.resources_more} 项）` : ''}</p>}
            {(after.resource_warnings.length > 0 || !!after.resource_warnings_more) && <div className="rule-inspector-warnings">
              {after.resource_warnings.map(item => <p key={item.kind + ':' + item.name}><Icon name="info" size={14} /><span>假设后续资源 · {resourceName(item)}：{resourceWarning(item)}</span></p>)}
              {!!after.resource_warnings_more && <p>另有 {after.resource_warnings_more} 项假设后续资源提示</p>}
            </div>}
            <p className="rule-inspector-conditional-note">{conditionalNote}</p>
          </section>}
          <dl className="rule-inspector-details rule-inspector-input-details">
            <dt>输入原文</dt><dd className="rule-inspector-mono">{r.target}</dd>
            <dt>规范化目标</dt><dd className="rule-inspector-mono">{known?.host || known?.ip || '—'}</dd>
            <dt>目标端口</dt><dd>{known?.port ?? '未指定'} · {portSources[known?.port_source ?? ''] ?? '未指定'}</dd>
            {(Object.keys(labels) as FieldName[]).filter(name => name !== 'target' && name !== 'target_port').map(name => {
              const value = known?.[name as keyof KnownInput];
              return value ? <Fragment key={name}><dt>{labels[name]}</dt><dd className="rule-inspector-mono">{value}</dd></Fragment> : null;
            })}
            {r.resources.length > 0 && <><dt>相关资源</dt><dd><ul className="rule-inspector-resources">{r.resources.map(item => <li key={item.kind + ':' + item.name}>{resourceName(item)} · {item.data_available === true ? '已加载' : item.data_available === false ? '未加载' : '状态不可核对'}{item.entries != null && item.data_available === true ? ` · ${item.entries} 项` : ''}</li>)}</ul>{!!r.resources_more && <span>另有 {r.resources_more} 项相关资源</span>}</dd></>}
          </dl>
          {(r.resource_warnings.length > 0 || !!r.resource_warnings_more) && <div className="rule-inspector-warnings">{r.resource_warnings.map(item => <p key={item.kind + ':' + item.name}><Icon name="info" size={14} /><span>正式判定资源 · {resourceName(item)}：{resourceWarning(item)}</span></p>)}{!!r.resource_warnings_more && <p>正式判定另有 {r.resource_warnings_more} 项相关资源提示</p>}</div>}
          {reply?.ipv6_enabled === false && <p className="rule-inspector-admission"><Icon name="info" size={14} /><span>{r.admission_warnings?.includes('ipv6_disabled') ? '该 IPv6 输入的实际准入受当前 IPv6 关闭设置限制；规则策略保持模拟结果。' : '当前 IPv6 已关闭；规则模拟不会更改此设置。'}</span></p>}
          <div className="rule-inspector-result-end"><p>按本次已加载资源判定，不代表最终出口节点或连接成功</p><button type="button" className="link-btn" onClick={() => void copyResult()}><Icon name="copy" size={12} />{copied || '复制结果'}</button></div>
        </>}
      </section>
    </div>
  </Modal>;
}
