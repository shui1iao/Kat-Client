import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import {
  InvalidReplyError,
  normalizeConnLogs,
  captureCloseTargets,
  normalizeConnections,
  normalizeDNSLogs,
  normalizeDNSQuery,
  normalizeKernelLogs,
  normalizePreview,
  normalizeResources,
  normalizeStatus,
  normalizeTargetPreview,
} from "../src/client/normalize.ts";
import { byteAxis } from "../src/charts/scale.ts";
import {
  HIDDEN_POLL_MS,
  MAIN_WINDOW_SHOWN_EVENT,
  applyMainWindowHidden,
} from "../src/client/useClient.ts";
import { errorText } from "../src/lib/errors.ts";

test("normalizeStatus guards Go null slices and malformed nested arrays without crashing", () => {
  const s = normalizeStatus({
    runtime: { state: "running" },
    probe_round: { done: 1, total: 2, names: null },
    probe_group_rounds: { Main: { done: 0, total: 1, names: null } },
    groups: [{ name: "Main", members: null }, null, "bad"],
    nodes: null,
    providers: null,
    traffic: {
      daily: [{ date: "2026-11-23", domains: null }],
      hourly: null,
      domains: null,
      groups: null,
      rule_targets: null,
      rules: null,
    },
    connections: {
      active: null,
      items: [{ id: "1", chain: null }],
    },
  });
  assert.deepEqual(s.probe_round?.names, []);
  assert.deepEqual(s.probe_group_rounds?.Main?.names, []);
  assert.equal(s.groups.length, 1);
  assert.deepEqual(s.groups[0].members, []);
  assert.deepEqual(s.nodes, []);
  assert.deepEqual(s.providers, []);
  assert.deepEqual(s.traffic.daily[0].domains, []);
  assert.deepEqual(s.traffic.hourly, []);
  assert.deepEqual(s.traffic.domains, []);
  assert.deepEqual(s.traffic.groups, []);
  assert.deepEqual(s.traffic.rule_targets, []);
  assert.deepEqual(s.traffic.rules, []);
  assert.deepEqual(s.connections.items[0].chain, []);
  assert.throws(() => normalizeStatus(null), InvalidReplyError);
});

test("normalize helpers guard connections, logs, dns, resources, target preview and subscription preview", () => {
  const conn = normalizeConnections({ active: [{ id: "1", chain: null }], closed: null, total: null });
  assert.deepEqual(conn.active[0].chain, []);
  assert.deepEqual(conn.closed, []);

  assert.deepEqual(normalizeConnLogs({ instance: 1, entries: [{ chain: null }], next_seq: 1, dropped: 0 }).entries[0].chain, []);
  assert.deepEqual(normalizeDNSLogs({ instance: 1, entries: [{ addresses: null }], next_seq: 1, dropped: 0 }).entries[0].addresses, []);
  assert.deepEqual(normalizeKernelLogs({ instance: 1, entries: null, next_seq: 0, dropped: 0 }).entries, []);
  assert.deepEqual(normalizeResources({ items: null }).items, []);
  assert.deepEqual(normalizeDNSQuery({ addresses: null }).addresses, []);

  const tp = normalizeTargetPreview({ target: { addresses: null }, chain: null, matched: { rule: "FINAL" } });
  assert.deepEqual(tp.target.addresses, []);
  assert.deepEqual(tp.chain, []);

  const sp = normalizePreview({ counts: null, changes: null, issues: null });
  assert.deepEqual(sp.changes, []);
  assert.deepEqual(sp.issues, []);
});

test("byteAxis never produces fractional byte ticks like 0.5 B on empty or tiny values", () => {
  const empty = byteAxis([0, 0, 0]);
  assert.equal(empty.empty, true);
  assert.ok(empty.ticks.every((t) => Number.isInteger(t)), `expected integer byte ticks, got ${empty.ticks}`);

  const tiny = byteAxis([1, 2]);
  assert.equal(tiny.empty, false);
  assert.ok(tiny.ticks.every((t) => Number.isInteger(t)), `expected integer byte ticks, got ${tiny.ticks}`);
});

test("main window hidden state toggles dataset and uses throttled hidden poll interval", () => {
  assert.ok(HIDDEN_POLL_MS >= 5000);
  const root = { dataset: {} as Record<string, string | undefined> };
  applyMainWindowHidden(true, root);
  assert.equal(root.dataset.katWindowHidden, "true");
  applyMainWindowHidden(false, root);
  assert.equal(root.dataset.katWindowHidden, undefined);
  assert.equal(typeof MAIN_WINDOW_SHOWN_EVENT, "string");
});

test("ErrorBoundary keeps window controls and sanitizes fault summaries", () => {
  const summary = errorText(new Error("failed fetching https://example.com/sub?token=secret123\nline2")).replace(/\s+/g, " ").trim();
  assert.ok(!summary.includes("secret123"), "errorText must redact URL credentials/query");
  assert.ok(!summary.includes("\n"), "summary must stay single-line");

  const appSrc = fs.readFileSync("src/App.tsx", "utf8");
  assert.match(appSrc, /<ErrorBoundary\s+scope="page"/, "App must wrap page body in page-scoped ErrorBoundary");
  const ebSrc = fs.readFileSync("src/components/ErrorBoundary.tsx", "utf8");
  assert.match(ebSrc, /export function faultSummary/, "ErrorBoundary must export faultSummary");
  assert.match(ebSrc, /act\(['"]minimize['"]\)/, "AppFault fallback must keep minimize control");
  assert.match(ebSrc, /act\(['"]close['"]\)/, "AppFault fallback must keep close control");
});

test("CSS preserves standard backdrop-filter declarations and SideControls supports listbox keyboard nav", () => {
  const css = ["src/design/components.css", "src/design/shell.css", "src/design/pages.css"]
    .map((f) => fs.readFileSync(f, "utf8"))
    .join("\n");
  const matches = css.match(/(?<!-webkit-)backdrop-filter\s*:/g) ?? [];
  assert.ok(matches.length >= 6, `expected >= 6 standard backdrop-filter rules, found ${matches.length}`);

  const sideSrc = fs.readFileSync("src/components/SideControls.tsx", "utf8");
  assert.match(sideSrc, /ArrowDown/);
  assert.match(sideSrc, /ArrowUp/);
  assert.match(sideSrc, /Escape/);
});

test("captureCloseTargets freezes connection_instance and deduplicated member_ids, refusing legacy snapshots", () => {
  const reply = normalizeConnections({
    connection_instance: "inst-42",
    active: [
      { id: 10, member_ids: [10, 11], chain: ["Final"] },
      { id: 12, member_ids: [11, 12], chain: ["Final"] },
    ],
    closed: [],
    total: 3,
  });
  assert.equal(reply.connection_instance, "inst-42");
  const frozen = captureCloseTargets(reply, reply.active);
  assert.deepEqual(frozen, { connection_instance: "inst-42", ids: [10, 11, 12] });

  // Missing connection_instance or member_ids (e.g. legacy core or status summary) must refuse exact close.
  assert.equal(captureCloseTargets({ active: reply.active, closed: [], total: 2 }, reply.active), null);
  assert.equal(captureCloseTargets(reply, [{ member_ids: undefined }]), null);
  assert.equal(captureCloseTargets(reply, [{ member_ids: [] }]), null);

  const connSrc = fs.readFileSync("src/pages/Connections.tsx", "utf8");
  assert.match(connSrc, /connections\.close.*connection_instance:\s*target\.connection_instance/);
});
