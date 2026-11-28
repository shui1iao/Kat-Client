import test from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeStatus,
  normalizeUpdateState,
  normalizeDiagnostics,
  normalizeKernelLogs,
  normalizeConnections,
  normalizeDNSLogs,
  normalizeDNSQuery,
  normalizeNetworkStatus,
  normalizeDesktopSettings,
} from '../src/client/normalize.ts';
import { previewGroupSource } from '../src/client/groupSource.ts';
import { diagnosticEvents, tunDiagnosticText } from '../src/client/daily.ts';
import { parseDocument } from '../src/client/document.ts';
import { errorText } from '../src/lib/errors.ts';

test('normalizeStatus guards null local listeners and filters nested null array elements', () => {
  for (const badTop of [null, undefined, 0, 'bad', [], { runtime: null }]) {
    assert.throws(() => normalizeStatus(badTop), /运行状态格式无效/);
  }
  const s = normalizeStatus({
    runtime: { state: 'running' },
    local: { http: null, socks: null },
    traffic: {
      hourly: [null, undefined, { hour: 2, up: 100, down: 200 }],
      domains: [null, { domain: 'example.com', hits: 1, up: 10, down: 20 }],
      groups: [null, { name: 'G', up: 10, down: 20 }],
      rule_targets: [null, { name: 'direct', up: 10, down: 20 }],
      rules: [null, { rule: 'MATCH', hits: 1, up: 10, down: 20 }],
    },
    groups: [null, { name: 'G', type: 'select', members: [null, { name: 'N1' }] }],
    nodes: [null, { name: 'N1', type: 'socks5' }],
    connections: { active: 1, total: 1, tcp: 1, udp: 0, items: [null, { id: 1, chain: [null, 'direct'] }] },
  });
  assert.equal(s.runtime.state, 'running');
  if (s.local) {
    assert.equal(s.local.http === undefined || typeof s.local.http.ready === 'boolean', true);
    assert.equal(s.local.socks === undefined || typeof s.local.socks.ready === 'boolean', true);
  }
  assert.equal((s.traffic.hourly ?? []).some((x) => x == null), false);
  assert.equal((s.traffic.domains ?? []).some((x) => x == null), false);
  assert.equal((s.traffic.groups ?? []).some((x) => x == null), false);
  assert.equal((s.traffic.rule_targets ?? []).some((x) => x == null), false);
  assert.equal((s.traffic.rules ?? []).some((x) => x == null), false);
  assert.equal(s.groups.some((x) => x == null), false);
  assert.equal(s.nodes.some((x) => x == null), false);
  assert.equal(s.connections.items.some((x) => x == null), false);
});

test('normalizeUpdateState guards null confirmation/rows/proposal and lowercase update error codes localize', () => {
  for (const raw of [
    null,
    undefined,
    {},
    { confirmation: null, rows: null, proposal: { kind: 'invalid', nonce: '', version: '' }, error: null },
    { confirmation: { pending: true, running: null, message: null }, rows: [null, { kind: 'client', current: null, latest: '0.2.38', offer: 'o1' }], proposal: { nonce: '1', kind: 'client', version: '0.2.38' } },
  ]) {
    const st = normalizeUpdateState(raw);
    assert.equal(typeof st.confirmation.pending, 'boolean');
    assert.equal(typeof st.confirmation.running, 'boolean');
    assert.equal(typeof st.confirmation.message, 'string');
    assert.equal(Array.isArray(st.rows), true);
    assert.equal(st.rows.some((r) => r == null), false);
  }
  const upper = errorText({ code: 'MANIFEST_SCHEMA', message: 'raw english' });
  const lower = errorText({ code: 'manifest_schema', message: 'raw english' });
  assert.equal(upper, lower);
  assert.match(lower, /更新清单格式无效/);
  assert.match(errorText('update_verify: bad sig'), /更新包签名或清单校验失败/);
});

test('normalizeDiagnostics, normalizeKernelLogs, daily helpers and network/desktop normalizers never throw on null fields', () => {
  const diag = normalizeDiagnostics({
    service: null,
    network: { system_proxy: null, tun: null, recovery_pending: true },
    host_events: [null, { seq: 1, time: null, level: null, event: 'tun_err', tun: { attempt: 1, phase: 'start', detail: { stage: 'wintun', changes: null } } }],
    core_events: null,
    errors: [null, 'host pipe error'],
    app_data_dir: null,
  });
  assert.equal(diag.host_events.length, 1);
  assert.deepEqual(diag.core_events, []);
  assert.equal(diag.errors.length, 1);
  assert.equal(typeof diag.network.system_proxy.enabled, 'boolean');
  assert.equal(typeof diag.network.tun.enabled, 'boolean');

  const evs = diagnosticEvents(
    {
      ...diag,
      host_events: [
        { seq: 1, time: null as any, level: 'error', event: 'a', tun: { attempt: 1, phase: 'start', detail: { stage: 'wintun', changes: null as any } } },
        { seq: 2, time: '2026-11-28T01:00:00Z', level: 'info', event: 'b' },
      ],
    },
    'all',
    '',
  );
  assert.equal(evs.length, 2);
  const tunText = tunDiagnosticText(evs.find((e) => e.seq === 1)!);
  assert.match(tunText, /stage=wintun/);

  const kLogs = normalizeKernelLogs({
    instance: 2,
    next_seq: 9,
    entries: [null, { seq: 5, time: null, level: null, message: null }],
  });
  assert.equal(kLogs.entries.length, 1);
  assert.equal(kLogs.entries[0].message, '');
  assert.equal(kLogs.entries[0].time, '');
  assert.equal(kLogs.entries[0].level, 'info');

  const cLogs = normalizeConnections({ connection_instance: null, active: [null], closed: null, total: null });
  assert.deepEqual(cLogs.active, []);
  assert.deepEqual(cLogs.closed, []);

  const dLogs = normalizeDNSLogs({ instance: 1, entries: [null, { seq: 1, addresses: [null, '1.1.1.1'] }], next_seq: 1 });
  assert.deepEqual(dLogs.entries[0].addresses, ['1.1.1.1']);

  const dQuery = normalizeDNSQuery({ name: null, addresses: [null, { addr: '1.1.1.1', type: null }] });
  assert.equal(dQuery.addresses.length, 1);

  const net = normalizeNetworkStatus({ system_proxy: null, tun: null, service: null });
  assert.equal(net.tun.enabled, false);
  assert.equal(net.system_proxy.enabled, false);

  const desk = normalizeDesktopSettings({ preferences: null, autostart: null });
  assert.equal(desk.preferences.close_action, 'tray');
});

test('previewGroupSource and parseDocument safely guard null replies and explicit null array fields', async () => {
  const res = await previewGroupSource(async () => null as any, { name: 'G', type: 'select', filter: 'hk' } as any, null);
  assert.deepEqual(res, { names: [], errors: {} });

  for (const invalidNullDoc of [
    { schema_version: 1, client: { mode: 'rule' }, subscriptions: null, kernel: {} },
    { schema_version: 1, client: { mode: 'rule' }, kernel: { groups: [{ name: 'G', type: 'select', members: null }] } },
    { schema_version: 1, client: { mode: 'rule' }, kernel: { dns: { servers: null } } },
    { schema_version: 1, client: { mode: 'rule' }, kernel: { routing: { rules: null } } },
  ]) {
    assert.throws(() => parseDocument(JSON.stringify(invalidNullDoc), 'json'), /格式无效/);
  }
});
