import { useEffect, useId, useRef, useState, type KeyboardEvent, type ReactNode } from 'react';
import { core } from '../client/ipc';
import { policyColor } from '../client/presentation';
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
const missingLabels: Record<string, string> = { ...labels, destination_ip: '目的 IP（需 DNS 解析）', rule_set_data: '规则集数据' };
const modeNames: Record<string, string> = { rule: '规则', global: '全局', direct: '直连' };
interface Resource { kind: string; name: string; data_available: boolean | null; warning?: string; entries?: number }
interface RuleResult {
  status: 'matched' | 'final' | 'unknown'; rule: number; display_row: number; target: string;
  condition: string; policy: string; reason?: string; rule_set?: string; missing: string[];
  blocked_rule?: number; candidate_policy?: string; resources: Resource[]; resource_warnings: Resource[];
  resources_more?: number; resource_warnings_more?: number;
  known: { host?: string; ip?: string; port?: number; port_source?: string } & Partial<Record<Exclude<FieldName, 'target' | 'target_port'>, string | number>>;
  dns?: { status: 'not_needed' | 'resolved' | 'failed'; addresses: string[]; selected_ip?: string; message?: string; different_rules?: boolean };
  ip_results?: { ip: string; status: string; rule: number; policy: string }[];
}
interface InspectorReply {
  mode: string; simulation: string; ipv6_enabled: boolean; result: RuleResult;
  effective?: { mode: string; source: 'rules' | 'mode'; policy: string };
}
const resourceName = (r: Resource) => r.name || ({ geoip: 'GeoIP', asn: 'ASN', geosite: 'Geosite' } as Record<string, string>)[r.kind] || r.kind;
const resourceWarning = (r: Resource) => r.warning === 'not_loaded' ? '尚未加载，按当前空资源判定'
  : r.warning === 'refresh_failed_using_loaded' ? '刷新失败，使用已加载数据' : '使用本次已加载数据';
function generalError(e: unknown): string {
  const code = e && typeof e === 'object' ? (e as { code?: string }).code : '';
  if (code === 'core_not_running' || code === 'not_running') return '请先启动内核';
  if (code === 'rule_test_stale') return '生效规则或模式已变化，请重新判定';
  if (code === 'rule_test_unavailable') return '无法读取当前规则或规则集，请检查资源状态';
  if (code === 'invalid_params') return '请检查输入条件';
  return errorText(e);
}

export function RuleInspector({ c, close }: { c: Client; close: () => void }) {
  const [values, setValues] = useState<Values>({ ...empty });
  const [expanded, setExpanded] = useState(false), [busy, setBusy] = useState(false);
  const [fields, setFields] = useState<Partial<Record<FieldName, string>>>({}), [error, setError] = useState('');
  const [reply, setReply] = useState<InspectorReply | null>(null), [copied, setCopied] = useState('');
  const live = useRef(true), pending = useRef(false), revision = useRef(0);
  const refs = useRef<Partial<Record<FieldName, HTMLInputElement | HTMLSelectElement | null>>>({});
  const id = useId(), conditionsId = id + '-conditions';
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
    if (!values.target.trim()) invalid.target = '请输入域名、IP 或 URL';
    for (const name of Object.keys(values) as FieldName[]) {
      if (name === 'target' || !values[name].trim()) continue;
      if (portFields.includes(name)) {
        if (!/^[0-9]{1,5}$/.test(values[name]) || Number(values[name]) < 1 || Number(values[name]) > 65535) invalid[name] = '端口应为 1–65535';
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
      if (live.current && revision.current === epoch) setReply({ ...next, result: { ...next.result, missing: next.result.missing ?? [], resources: next.result.resources ?? [], resource_warnings: next.result.resource_warnings ?? [] } });
    } catch (e) {
      if (!live.current || revision.current !== epoch) return;
      const failure = e as { code?: string; path?: string; message?: string };
      if (failure?.code === 'invalid_params' && failure.path && Object.hasOwn(labels, failure.path)) {
        const name = failure.path as FieldName;
        setFields({ [name]: typeof failure.message === 'string' ? failure.message.slice(0, 200) : '请检查此条件' }); focusField(name);
      } else setError(generalError(e));
    } finally {
      pending.current = false;
      if (live.current) setBusy(false);
    }
  }
  function onKeyDown(e: KeyboardEvent<HTMLDivElement>) {
    if (e.key === 'Enter' && !e.nativeEvent.isComposing && e.target instanceof HTMLInputElement) { e.preventDefault(); void run(); }
  }
  const mode = reply?.mode ?? c.status?.mode ?? 'unknown', r = reply?.result;
  const status = r?.status === 'matched' ? `命中第 ${r.rule} 条规则` : r?.status === 'final' ? '未命中规则，使用 FINAL' : '需要补充条件';
  const effective = reply?.effective;
  const field = (name: FieldName, control: ReactNode) => <div className="rule-inspector-field" key={name}>
    <label htmlFor={id + '-' + name}>{labels[name]}</label>{control}
    {fields[name] && <small id={id + '-' + name + '-error'} className="field-error" role="alert">{fields[name]}</small>}
  </div>;
  function input(name: FieldName, maxLength: number, placeholder = '') {
    return <input ref={el => { refs.current[name] = el; }} id={id + '-' + name} className="inp" value={values[name]}
      onChange={e => change(name, e.target.value)} maxLength={maxLength} inputMode={portFields.includes(name) ? 'numeric' : undefined}
      placeholder={placeholder} autoComplete="off" spellCheck={false} aria-invalid={!!fields[name]} aria-describedby={fields[name] ? id + '-' + name + '-error' : undefined} />;
  }
  function select(name: FieldName, options: [string, string][]) {
    return <select ref={el => { refs.current[name] = el; }} id={id + '-' + name} className="inp" value={values[name]} onChange={e => change(name, e.target.value)}
      aria-invalid={!!fields[name]} aria-describedby={fields[name] ? id + '-' + name + '-error' : undefined}>
      <option value="">未指定</option>{options.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
    </select>;
  }
  async function copyResult() {
    if (!r) return;
    const epoch = revision.current;
    const lines = ['规则判定', `目标：${r.target}`, `模式：${modeNames[mode] ?? mode}`];
    if (effective?.source === 'mode') lines.push(`当前实际策略：${c.label(effective.policy)}`, '以下为规则模式下的匹配结果');
    lines.push(status, `策略：${r.status === 'unknown' ? '未确定' : c.label(r.policy)}`, `规则：${r.status === 'final' ? 'FINAL' : '#' + r.rule + ' · ' + r.condition}`);
    if (r.rule_set) lines.push('规则集：' + r.rule_set);
    if (r.missing.length) lines.push('缺少：' + r.missing.map(n => missingLabels[n] ?? n).join('、'));
    if (r.dns?.status === 'resolved') lines.push('DNS：' + r.dns.addresses.join('、'));
    if (r.dns?.status === 'failed') lines.push(r.dns.message ?? 'DNS 解析失败');
    lines.push('不连接目标；仅依据当前生效规则和已提供条件。');
    try { await navigator.clipboard.writeText(lines.join('\n')); if (live.current && revision.current === epoch) setCopied('已复制'); }
    catch { if (live.current && revision.current === epoch) setCopied('复制失败'); }
  }
  return <Modal readOnly title="规则判定" className="rule-inspector" closeLabel="关闭" close={dismiss}>
    <div className="rule-inspector-body" onKeyDown={onKeyDown}>
      <div className="rule-inspector-meta"><span>当前模式：{modeNames[mode] ?? '未知'}</span><span>不连接目标 · 必要时仅查询 DNS</span></div>
      <div className="rule-inspector-target">
        <label htmlFor={id + '-target'}>目标地址</label>
        <div className="rule-inspector-input-row">{input('target', 2048, '域名、IP 或 URL')}<button type="button" className="btn primary" disabled={busy || !c.connected} onClick={() => void run()}>{busy ? '判定中…' : '判定'}</button></div>
        {fields.target && <small id={id + '-target-error'} className="field-error" role="alert">{fields.target}</small>}
        {(c.doc.dirty || !!c.doc.draftFilename) && <p className="rule-inspector-help">未保存的规则修改不参与判定</p>}
      </div>
      <div className="rule-inspector-supplement">
        <button type="button" className="link-btn rule-inspector-disclosure" aria-expanded={expanded} aria-controls={conditionsId} onClick={() => setExpanded(!expanded)}>
          <Icon name={expanded ? 'chevDown' : 'chevRight'} size={14}/>补充条件{count > 0 && <span>{count} 项</span>}
        </button>
        {expanded && <div id={conditionsId} className="rule-inspector-conditions"><div className="rule-inspector-grid">
          {field('network', select('network', [['tcp', 'TCP'], ['udp', 'UDP']]))}
          {field('target_port', input('target_port', 5, '1–65535'))}
          {field('process_name', input('process_name', 255, '进程文件名'))}
          {field('source_ip', input('source_ip', 64, 'IP 地址'))}
          {field('source_port', input('source_port', 5, '1–65535'))}
          {field('inbound_name', input('inbound_name', 64))}
          {field('inbound_type', select('inbound_type', [['shadowsocks', 'Shadowsocks'], ['anytls', 'AnyTLS'], ['trojan', 'Trojan'], ['socks5', 'SOCKS5']]))}
          {field('inbound_port', input('inbound_port', 5, '1–65535'))}
          {field('protocol', select('protocol', [['http', 'HTTP'], ['tls', 'TLS'], ['quic', 'QUIC']]))}
        </div></div>}
      </div>
      <LocalError text={error}/>
      <section className="rule-inspector-result" aria-label="规则判定结果" aria-busy={busy}>
        {!r ? <p className="rule-inspector-empty">{busy ? '正在匹配生效规则…' : '输入目标，查看将命中的规则与策略'}</p> : <>
          {effective?.source === 'mode' && <div className="rule-inspector-effective"><span>当前实际策略</span><b>{c.label(effective.policy)}</b><small>{modeNames[mode]}模式不使用下方规则结果</small></div>}
          <div className={'rule-inspector-conclusion' + (r.status === 'unknown' ? ' is-unknown' : '')} aria-live="polite" aria-atomic="true">
            <div className="rule-inspector-result-title"><Icon name={r.status === 'unknown' ? 'info' : 'rules'} size={16}/><span>{effective?.source === 'mode' ? '规则模式下：' : ''}{status}</span></div>
            <div className="rule-inspector-policy">{r.status === 'unknown' ? '暂不能确定策略' : <><i style={{background:policyColor(r.policy,c.status,c.label)}}/>{c.label(r.policy)}</>}</div>
          </div>
          {r.status === 'unknown' && <div className="rule-inspector-missing"><p>{r.dns?.status === 'failed' ? 'DNS 解析失败，无法继续判断 IP 规则。' : `第 ${r.blocked_rule ?? r.rule} 条规则尚不能排除，不跳过它推断后续结果。`}</p><ul>{r.missing.map(name=><li key={name}><span>{missingLabels[name]??name}</span>{Object.hasOwn(labels,name)&&<button type="button" className="link-btn" onClick={()=>focusField(name)}>填写</button>}</li>)}</ul></div>}
          <dl className="rule-inspector-details">
            <dt>{r.status === 'unknown' ? '待判定规则' : '匹配规则'}</dt><dd>{r.status === 'final' ? 'FINAL' : <><span>第 {r.blocked_rule ?? r.rule} 条</span><code>{r.condition}</code></>}</dd>
            {r.rule_set && <><dt>规则集</dt><dd>{r.rule_set}</dd></>}
          </dl>
          <details className="rule-inspector-extra"><summary>判定详情</summary><dl className="rule-inspector-details">
            <dt>目标</dt><dd className="rule-inspector-mono">{r.known.host||r.known.ip||r.target}</dd>
            {r.known.port != null && <><dt>目标端口</dt><dd className="num">{r.known.port}</dd></>}
            <dt>DNS</dt><dd>{!r.dns||r.dns.status==='not_needed'?'无需查询':r.dns.status==='failed'?'解析失败':r.dns.addresses.join('、')}</dd>
            {r.dns?.different_rules && <><dt>多 IP 结果</dt><dd><ul>{r.ip_results?.map(x=><li key={x.ip}>{x.ip} · {x.status==='unknown'?'未确定':`${x.rule?'第 '+x.rule+' 条':'FINAL'} → ${c.label(x.policy)}`}</li>)}</ul></dd></>}
            {r.resources.length>0&&<><dt>规则资源</dt><dd>{r.resources.map(x=><div key={x.kind+':'+x.name}>{resourceName(x)} · {x.data_available===true?'已加载':x.data_available===false?'未加载':'未知'}</div>)}{r.resources_more?`另有 ${r.resources_more} 项`:null}</dd></>}
            {(Object.keys(labels) as FieldName[]).filter(n=>n!=='target'&&n!=='target_port').flatMap(n=>{const value=r.known[n as keyof RuleResult['known']];return value?[<dt key={n+'-label'}>{labels[n]}</dt>,<dd key={n}>{value}</dd>]:[];})}
          </dl></details>
          {r.resource_warnings.map(x=><p className="rule-inspector-help" key={x.kind+':'+x.name}>{resourceName(x)}：{resourceWarning(x)}</p>)}
          {reply?.ipv6_enabled===false&&r.known.ip?.includes(':')&&<p className="rule-inspector-help">当前 IPv6 已关闭，此目标的实际访问会受限</p>}
          <div className="rule-inspector-result-end"><span>按生效顺序首匹配，均不匹配则使用 FINAL</span><button type="button" className="link-btn" onClick={()=>void copyResult()}><Icon name="copy" size={12}/>{copied||'复制结果'}</button></div>
        </>}
      </section>
    </div>
  </Modal>;
}
