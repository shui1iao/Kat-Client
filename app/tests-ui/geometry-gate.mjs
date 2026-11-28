import { createServer } from 'node:http';
import { access, readFile } from 'node:fs/promises';
import { extname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import assert from 'node:assert/strict';
import { installTransport, installDailyTransport } from './daily-transport.mjs';

const appRoot = resolve(import.meta.dirname, '..');

async function loadChromium() {
  const candidates = [
    process.env.PLAYWRIGHT_CORE_PATH,
    '/opt/kat-resize-review-20261113-2324/node_modules/playwright-core/index.mjs',
    '/opt/kat-windows-client-20261028/tools/node_modules/playwright-core/index.mjs',
  ].filter(Boolean);
  for (const raw of candidates) {
    const target = raw.endsWith('.mjs') ? resolve(raw) : resolve(raw, 'index.mjs');
    try {
      await access(target);
      return (await import(pathToFileURL(target).href)).chromium;
    } catch {
      /* next */
    }
  }
  return (await import('playwright-core')).chromium;
}

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://127.0.0.1');
    let p = resolve(appRoot, 'dist', '.' + decodeURIComponent(url.pathname));
    if (url.pathname === '/') p = resolve(appRoot, 'dist/index.html');
    if (!p.startsWith(resolve(appRoot, 'dist') + '/')) throw new Error('forbidden');
    const data = await readFile(p);
    const mime =
      {
        '.html': 'text/html; charset=utf-8',
        '.js': 'application/javascript; charset=utf-8',
        '.css': 'text/css; charset=utf-8',
        '.svg': 'image/svg+xml',
        '.woff2': 'font/woff2',
      }[extname(p)] ?? 'application/octet-stream';
    res.setHeader('Content-Type', mime);
    res.end(data);
  } catch {
    res.writeHead(404);
    res.end();
  }
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const base = `http://127.0.0.1:${server.address().port}`;

const chromium = await loadChromium();
const browser = await chromium.launch({
  executablePath: process.env.CHROMIUM_PATH || '/usr/bin/chromium',
  headless: true,
  args: ['--no-sandbox', '--disable-dev-shm-usage'],
});

const failures = [];
const consoleIssues = [];

try {
  // --- PART 1: Self-drawn Tray Menu (?view=tray-menu) in BOTH Dark & Light ---
  for (const trayTheme of ['dark', 'light']) {
    const tCtx = await browser.newContext({ viewport: { width: 360, height: 600 }, colorScheme: trayTheme });
    await tCtx.addInitScript((th) => {
      window.__TAURI_INTERNALS__ = {
        invoke: async (cmd) => {
          if (cmd === 'tray_menu_state') {
            return {
              revision: 'r1',
              theme: th,
              popup: { epoch: '1', layout: '1', phase: 'visible', client_width: 296, client_height: 420, max_width: 360, max_height: 560 },
              nodes: [
                {
                  id: 'mode',
                  title: '代理模式',
                  enabled: true,
                  checked: null,
                  children: [
                    { id: 'm-rule', title: '规则', enabled: true, checked: true, children: [] },
                    { id: 'm-global', title: '全局', enabled: true, checked: false, children: [] },
                    { id: 'm-direct', title: '直连', enabled: true, checked: false, children: [] },
                  ],
                },
                { id: 'k3-proxy', title: '系统代理', enabled: true, checked: true, children: [] },
                { id: 'k3-tun', title: 'TUN 模式', enabled: true, checked: false, children: [] },
                { id: '', title: '', enabled: true, checked: null, children: [] },
                {
                  id: 'groups',
                  title: '策略组',
                  enabled: true,
                  checked: null,
                  children: [
                    {
                      id: 'g-main',
                      title: '默认代理：香港 01',
                      enabled: true,
                      checked: null,
                      children: [
                        { id: 'n-hk', title: '香港 01', enabled: true, checked: true, children: [] },
                        { id: 'n-jp', title: '日本 01', enabled: true, checked: false, children: [] },
                      ],
                    },
                  ],
                },
                { id: '', title: '', enabled: true, checked: null, children: [] },
                { id: 'show', title: '显示主窗口', enabled: true, checked: null, children: [] },
                { id: 'restart', title: '重启内核', enabled: true, checked: null, children: [] },
                { id: 'restart-app', title: '重启 Kat', enabled: true, checked: null, children: [] },
                { id: 'quit', title: '退出', enabled: true, checked: null, children: [] },
              ],
            };
          }
          return null;
        },
        transformCallback: () => 1,
      };
    }, trayTheme);
    const tp = await tCtx.newPage();
    tp.on('pageerror', (e) => consoleIssues.push(`tray(${trayTheme}): ${e.message}`));
    tp.on('console', (m) => {
      if (m.type() === 'error' || m.type() === 'warning') consoleIssues.push(`tray(${trayTheme}) ${m.type()}: ${m.text()}`);
    });
    await tp.goto(`${base}/?view=tray-menu`, { waitUntil: 'networkidle' });
    await tp.waitForSelector('.tray-menu');
    const tm = await tp.evaluate(() => {
      const list = document.querySelector('.tm-list');
      const seg = document.querySelector('.tm-seg').getBoundingClientRect();
      const row = document.querySelector('.tm-row').getBoundingClientRect();
      const sw = document.querySelector('.sw').getBoundingClientRect();
      return {
        listOverflowX: list.scrollWidth - list.clientWidth,
        segWidth: Math.round(seg.width),
        rowWidth: Math.round(row.width),
        sw: `${Math.round(sw.width)}x${Math.round(sw.height)}`,
      };
    });
    if (tm.listOverflowX > 0) failures.push(`tray(${trayTheme}) .tm-list overflowX=${tm.listOverflowX}px`);
    if (tm.sw !== '32x18') failures.push(`tray(${trayTheme}) switch=${tm.sw}, expected 32x18`);
    await tp.click('button:has-text("默认代理")');
    await tp.waitForSelector('.tm-check.on svg');
    await tCtx.close();
  }

  // --- PART 2: Main Window across 3 Viewports (900x600 min, 1080x810 default 4:3, 1440x900 wide) & Dark/Light ---
  const viewports = [
    { name: 'default-1080x810', width: 1080, height: 810 },
    { name: 'min-900x600', width: 900, height: 600 },
    { name: 'narrow-880x600', width: 880, height: 600 },
    { name: 'wide-1440x900', width: 1440, height: 900 },
  ];

  for (const vp of viewports) {
    const ctx = await browser.newContext({ viewport: { width: vp.width, height: vp.height }, colorScheme: 'dark' });
    await ctx.addInitScript(installTransport, { empty: false });
    await ctx.addInitScript(installDailyTransport);
    await ctx.addInitScript(() => {
      const inv = window.__TAURI_INTERNALS__.invoke;
      const nowS = Math.floor(Date.now() / 1000);
      const now = Date.now();
      window.__TAURI_INTERNALS__.invoke = async (cmd, args = {}) => {
        if (cmd === "tray_sync" || cmd === "window_action") return null;
        if (cmd === "update_state" || cmd === "update_recover" || cmd === "update_settings" || cmd === "update_check") {
          return {
            confirmation: { pending: false, running: false, message: "" },
            auto_check: true,
            last_check: nowS - 1800,
            checking: false,
            rows: [
              { kind: "client", current: "0.2.38", latest: "0.2.38", phase: "idle", message: "", offer: null, received: 0, total: null, downloaded: false },
              { kind: "core", current: "0.8.23", latest: "0.8.23", phase: "idle", message: "", offer: null, received: 0, total: null, downloaded: false },
            ],
            proposal: null,
            notice: false,
            preparing: false,
            error: "",
          };
        }
        if (cmd === "core_request") {
          const m = args.method, prm = args.params ?? {};
          if (m === "icon.cached") return {};
          if (m === "icon.get") return { data_uri: "" };
          if (m === "subscription.status") return {};
          if (m === "logs.dns") return { instance: 1, next_seq: 3, dropped: 0, entries: [
            { seq: 1, time: new Date(now - 5000).toISOString(), name: "api.github.com", qtype: "A", addresses: ["140.82.114.6", "140.82.114.5", "140.82.114.4"], server: "1.1.1.1", cached: false, duration_ms: 14, outcome: "ok", source: "tun" },
            { seq: 2, time: new Date(now - 2000).toISOString(), name: "chatgpt.com", qtype: "A", addresses: ["104.18.37.228"], server: "system", cached: true, duration_ms: 0, outcome: "ok", source: "kernel" },
          ]};
          if (m === "dns.cache.list") return { capacity: 4096, entries: [
            { name: "api.github.com", qtype: "A", addresses: ["140.82.114.6", "140.82.114.5", "140.82.114.4"], server: "1.1.1.1", ttl_sec: 120 },
          ]};
          if (m === "dns.query") return { name: prm.name, addresses: [{ addr: "140.82.114.6", type: "A" }], server: "1.1.1.1", duration_ms: 12, cached: false };
          if (m === "resources.list") return { items: [{ kind: "geoip", name: "geoip.mmdb", updated_at: new Date(now - 86400e3).toISOString(), size_bytes: 5.2e6, entries: 252, state: "ok" }] };
          if (m === "diagnostics.network") return { at: new Date(now - 600e3).toISOString(), items: [{ name: "Google", url: "https://www.google.com", result: "ok", chain: ["Final"], http_status: 204, duration_ms: 98 }] };
          if (m === "routing.previewTarget") return { target: { input: prm.target, host: "openai.com", addresses: ["104.18.37.228"] }, matched: { source: "final", rule: "MATCH", policy: "Final" }, chain: ["Final"], resolved: true };
        }
        return inv(cmd, args);
      };
    });
    const p = await ctx.newPage();
    p.on('pageerror', (e) => consoleIssues.push(`${vp.name}: ${e.message}`));
    p.on('console', (m) => {
      if (m.type() === 'error' || m.type() === 'warning') consoleIssues.push(`${vp.name} ${m.type()}: ${m.text()}`);
    });
    await p.goto(base + '/', { waitUntil: 'networkidle' });
    await p.waitForSelector('.navcard');

    const themes = vp.name === 'default-1080x810' ? ['dark', 'light'] : ['dark'];
    for (const th of themes) {
      if (th === 'light') {
        await p.click('[data-page="settings"]');
        await p.getByRole('tab', { name: '浅色', exact: true }).click();
        await p.waitForTimeout(50);
      }

      const steps = [
        ['overview', async () => p.click('[data-page="overview"]')],
        ['overview-dest-2', async () => { const t = p.locator('.ov-dest [role="tab"]'); if ((await t.count()) > 1) await t.nth(1).click(); }],
        ['overview-usage-7d', async () => { const t = p.locator('.ov-usage [role="tab"]'); if ((await t.count()) > 1) await t.nth(1).click(); }],
        ['overview-diag-conn', async () => p.getByRole('tab', { name: '连通性' }).click()],
        ['overview-diag-exit', async () => p.getByRole('tab', { name: '出口 IP' }).click()],
        ['connections-active', async () => p.click('[data-page="connections"]')],
        ['connections-grouped', async () => p.getByRole('button', { name: '按进程' }).click()],
        ['connections-closed', async () => p.getByRole('tab', { name: /已关闭/ }).click()],
        ['dns-recent', async () => { await p.click('[data-page="dns"]'); await p.getByRole('tab', { name: '最近解析' }).click(); }],
        ['dns-cache', async () => p.getByRole('tab', { name: '解析缓存' }).click()],
        ['dns-settings', async () => p.getByRole('tab', { name: 'DNS 设置' }).click()],
        ['logs-conn', async () => { await p.click('[data-page="logs"]'); await p.getByRole('tab', { name: '连接日志' }).click(); }],
        ['logs-kernel', async () => p.getByRole('tab', { name: '内核日志' }).click()],
        ['logs-events', async () => p.getByRole('tab', { name: '事件' }).click()],
        ['policies', async () => p.click('[data-page="policies"]')],
        ['nodes', async () => p.click('[data-page="nodes"]')],
        ['rules-list', async () => { await p.click('[data-page="rules"]'); await p.getByRole('tab', { name: /^规则/ }).click(); }],
        ['rules-resources', async () => p.getByRole('tab', { name: '外部资源' }).click()],
        ['config', async () => p.click('[data-page="config"]')],
        ['settings', async () => p.click('[data-page="settings"]')],
      ];

      for (const [stepName, runStep] of steps) {
        await runStep();
        await p.waitForTimeout(35);
        const stepIssues = await p.evaluate((tag) => {
          const out = [];
          // 1. Check horizontal overflow on shells, cards and toolbars
          for (const el of document.querySelectorAll('.app, .sidebar, .main, .content, .card, .table-toolbar, .pol-topbar, .settings-topbar')) {
            const cs = getComputedStyle(el);
            if (cs.display === 'none') continue;
            if (el.scrollWidth - el.clientWidth > 1 && cs.overflowX !== 'auto' && cs.overflowX !== 'scroll') {
              out.push(`${tag}: overflowX=${el.scrollWidth - el.clientWidth}px on ${el.tagName}.${[...el.classList].join('.')}`);
            }
          }
          // 2. Check window caption buttons exact 34x28 / 6px radius
          for (const b of document.querySelectorAll('.winbtns button')) {
            const r = b.getBoundingClientRect();
            const rad = getComputedStyle(b).borderRadius;
            if (Math.round(r.width) !== 34 || Math.round(r.height) !== 28 || rad !== '6px') {
              out.push(`${tag}: winbtn=${Math.round(r.width)}x${Math.round(r.height)} radius=${rad}`);
            }
          }
          // 3. Check toolbar interactive controls share exact 30px height
          const tb = document.querySelector('.table-toolbar');
          if (tb) {
            for (const c of tb.children) {
              const cs = getComputedStyle(c);
              if (cs.display === 'none' || c.classList.contains('sp') || c.classList.contains('conn-line-break') || c.tagName === 'SPAN') continue;
              const h = Math.round(c.getBoundingClientRect().height);
              if (h !== 30) out.push(`${tag}: toolbar control ${c.tagName}.${c.className} height=${h}px != 30px`);
            }
          }
          return out;
        }, `${vp.name}/${th}/${stepName}`);
        failures.push(...stepIssues);
      }
    }

    // --- PART 3: Modals & Popovers geometry on default 1080x810 ---
    if (vp.name === 'default-1080x810') {
      // 3a. NodeEditor modal
      await p.click('[data-page="nodes"]');
      await p.getByRole('button', { name: '添加节点', exact: true }).click();
      await p.waitForSelector('[role="dialog"]');
      await p.waitForTimeout(180);
      const nodeModal = await p.evaluate(() => {
        const dlg = document.querySelector('[role="dialog"]');
        const secretH = Math.round(dlg.querySelector('.secret-input').getBoundingClientRect().height);
        const inpH = Math.round(dlg.querySelector('.editor-field input.inp').getBoundingClientRect().height);
        const toolsDisplay = getComputedStyle(dlg.querySelector('.modal-tools')).display;
        return { secretH, inpH, toolsDisplay, overflowX: dlg.scrollWidth - dlg.clientWidth };
      });
      if (nodeModal.secretH !== 34 || nodeModal.inpH !== 34) failures.push(`NodeEditor heights: secret=${nodeModal.secretH}, inp=${nodeModal.inpH}`);
      if (nodeModal.toolsDisplay !== 'flex') failures.push(`NodeEditor .modal-tools display=${nodeModal.toolsDisplay}`);
      if (nodeModal.overflowX > 1) failures.push(`NodeEditor overflowX=${nodeModal.overflowX}`);
      await p.keyboard.press('Escape');
      await p.waitForTimeout(50);

      // 3b. SubscriptionImport modal (both Segmented controls MUST match 34px!)
      await p.locator('.qi-foot .link-btn').click();
      await p.waitForSelector('[role="dialog"]');
      await p.waitForTimeout(180);
      const subModal = await p.evaluate(() => {
        const dlg = document.querySelector('[role="dialog"]');
        const segHeights = [...dlg.querySelectorAll('.seg')].map((s) => Math.round(s.getBoundingClientRect().height));
        const secretH = Math.round(dlg.querySelector('.secret-input').getBoundingClientRect().height);
        return { segHeights, secretH, overflowX: dlg.scrollWidth - dlg.clientWidth };
      });
      if (subModal.segHeights.some((h) => h !== 34)) failures.push(`SubscriptionModal .seg heights=${JSON.stringify(subModal.segHeights)} (expected all 34)`);
      if (subModal.secretH !== 34) failures.push(`SubscriptionModal secretH=${subModal.secretH}`);
      if (subModal.overflowX > 1) failures.push(`SubscriptionModal overflowX=${subModal.overflowX}`);
      await p.keyboard.press('Escape');
      await p.waitForTimeout(50);

      // 3c. PolicyEditor modal
      await p.click('[data-page="policies"]');
      await p.getByRole('button', { name: '新建策略组', exact: true }).click();
      await p.waitForSelector('[role="dialog"]');
      await p.waitForTimeout(180);
      await p.click('summary:has-text("添加手动成员")');
      const polModal = await p.evaluate(() => {
        const dlg = document.querySelector('[role="dialog"]');
        const searchH = Math.round(dlg.querySelector('.pe-details .search').getBoundingClientRect().height);
        return { searchH, overflowX: dlg.scrollWidth - dlg.clientWidth };
      });
      if (polModal.searchH !== 34) failures.push(`PolicyModal searchH=${polModal.searchH}`);
      if (polModal.overflowX > 1) failures.push(`PolicyModal overflowX=${polModal.overflowX}`);
      await p.keyboard.press('Escape');
      await p.waitForTimeout(50);

      // 3d. RuleEditor modal + RuleJudge popover + DnsQuery popover + DnsAddrPopover
      await p.click('[data-page="rules"]');
      await p.getByRole('tab', { name: /^规则/ }).click();
      await p.click('[data-action="add-rule"]');
      await p.waitForSelector('[role="dialog"]');
      await p.waitForTimeout(180);
      const ruleModal = await p.evaluate(() => {
        const dlg = document.querySelector('[role="dialog"]');
        const inpH = [...dlg.querySelectorAll('.editor-field .inp')].map((el) => Math.round(el.getBoundingClientRect().height));
        const toolsDisplay = getComputedStyle(dlg.querySelector('.modal-tools')).display;
        return { inpH, toolsDisplay, overflowX: dlg.scrollWidth - dlg.clientWidth };
      });
      if (ruleModal.inpH.some((h) => h !== 34)) failures.push(`RuleModal inp heights=${JSON.stringify(ruleModal.inpH)}`);
      if (ruleModal.toolsDisplay !== 'flex') failures.push(`RuleModal .modal-tools display=${ruleModal.toolsDisplay}`);
      if (ruleModal.overflowX > 1) failures.push(`RuleModal overflowX=${ruleModal.overflowX}`);
      await p.keyboard.press('Escape');
      await p.waitForTimeout(50);

      await p.getByRole('button', { name: '判定', exact: true }).click();
      await p.waitForSelector('.rule-judge-pop');
      const judgeH = await p.evaluate(() => [...document.querySelector('.rule-judge-form').children].map((c) => Math.round(c.getBoundingClientRect().height)));
      if (judgeH.some((h) => h !== 30)) failures.push(`RuleJudge heights=${JSON.stringify(judgeH)}`);
      await p.keyboard.press('Escape');
      await p.waitForTimeout(50);

      await p.click('[data-page="dns"]');
      await p.getByRole('tab', { name: '最近解析' }).click();
      await p.getByRole('button', { name: '解析', exact: true }).click();
      await p.waitForSelector('.dns-query-pop');
      const dnsPopH = await p.evaluate(() => [...document.querySelector('.dns-query-pop .rule-judge-form').children].map((c) => Math.round(c.getBoundingClientRect().height)));
      if (dnsPopH.some((h) => h !== 30)) failures.push(`DnsQueryPop heights=${JSON.stringify(dnsPopH)}`);
      await p.keyboard.press('Escape');
      await p.waitForTimeout(50);

      await p.click('.dns-ip-more-btn');
      await p.waitForSelector('.dns-addr-pop');
      await p.keyboard.press('Escape');
    }

    await ctx.close();
  }

  // --- PART 4: PolicyReveal zero hidden DOM, exitGhost rapid Escape, and 5000-rule / 2000-conn virtual scroll gate ---
  {
    const vCtx = await browser.newContext({ viewport: { width: 1280, height: 860 }, colorScheme: 'dark' });
    await vCtx.addInitScript(installTransport, { empty: false });
    await vCtx.addInitScript(installDailyTransport);
    await vCtx.addInitScript(() => {
      const d = JSON.parse(window.__TEST.text);
      d.kernel.routing ??= { final: 'direct', rules: [] };
      d.kernel.routing.rules = Array.from({ length: 5000 }, (_, i) => ({
        domain_suffix: `virtual-rule-${i}.example.com`,
        action: i % 2 === 0 ? 'direct' : 'route',
        ...(i % 2 === 1 ? { outbound: d.kernel.groups?.[0]?.name ?? 'direct' } : {}),
      }));
      window.__TEST.text = JSON.stringify(d);

      const bigConns = Array.from({ length: 2000 }, (_, i) => ({
        id: i + 1,
        network: i % 3 === 0 ? 'udp' : 'tcp',
        source: `127.0.0.1:${30000 + i}`,
        target: `conn-host-${i}.example.com:443`,
        process: i % 2 === 0 ? 'chrome.exe' : 'curl.exe',
        rule: 'DOMAIN-SUFFIX,example.com',
        chain: ['direct'],
        up: 1024 * (i + 1),
        down: 4096 * (i + 1),
        start: new Date(Date.now() - i * 1000).toISOString(),
      }));

      const inv = window.__TAURI_INTERNALS__.invoke;
      window.__TAURI_INTERNALS__.invoke = async (cmd, args = {}) => {
        if (cmd === 'tray_sync' || cmd === 'window_action') return null;
        if (cmd === 'update_state') {
          return { confirmation: { pending: false, running: false, message: '' }, auto_check: true, last_check: 0, checking: false, rows: [], proposal: null, notice: false, preparing: false, error: '' };
        }
        if (cmd === 'core_request') {
          const m = args.method;
          if (m === 'icon.cached') return {};
          if (m === 'icon.get') return { data_uri: '' };
          if (m === 'subscription.status') return {};
          if (m === 'connections.list') {
            return { connection_instance: 'v-inst-1', active: bigConns, closed: [], total: bigConns.length };
          }
          if (m === 'status') {
            const s = await inv(cmd, args);
            s.traffic.daily = [{ date: '2026-11-27', up: NaN, down: Infinity, direct: -500, proxy: NaN }, { date: '2026-11-28', up: 4096, down: 8192 }];
            s.connections = { active: bigConns.length, total: bigConns.length, tcp: 1334, udp: 666, items: bigConns.slice(0, 20) };
            s.rules = d.kernel.routing.rules.map((r, idx) => ({
              index: idx,
              type: 'domain_suffix',
              value: r.domain_suffix,
              action: r.action,
              outbound: r.outbound,
              hits: idx % 7,
            }));
            return s;
          }
        }
        return inv(cmd, args);
      };
    });

    const vp = await vCtx.newPage();
    vp.on('pageerror', (e) => consoleIssues.push(`virtual-gate: ${e.message}`));

    // 4a-pre. Overview WeekBars/TrafficDistribution NaN/Infinity resilience
    await vp.goto(`${base}/#overview`, { waitUntil: 'networkidle' });
    const badSvgCount = await vp.evaluate(() =>
      [...document.querySelectorAll('svg *')].filter((el) =>
        [...el.attributes].some((a) => a.value.includes('NaN') || a.value.includes('Infinity')),
      ).length,
    );
    if (badSvgCount !== 0) failures.push(`Overview SVG had ${badSvgCount} NaN/Infinity attributes`);

    // 4a. PolicyReveal collapsed child DOM count === 0
    await vp.goto(`${base}/#policies`, { waitUntil: 'networkidle' });
    await vp.waitForSelector('.pol-stream');
    const collapseBtn = vp.locator('.pol-topbar button').filter({ hasText: '全部收起' }).first();
    if (await collapseBtn.count()) {
      await collapseBtn.click();
      await vp.waitForTimeout(280);
    }
    const collapsedChildDom = await vp.evaluate(() => document.querySelectorAll('.pc-reveal:not(.open) *').length);
    if (collapsedChildDom !== 0) {
      failures.push(`PolicyReveal(open=false) mounted child DOM=${collapsedChildDom}, expected 0`);
    }

    // 4b. exitGhost rapid double-Escape (20ms interval): SelectPopover + Modal both close cleanly
    await vp.click('[data-page="rules"]');
    await vp.getByRole('tab', { name: /^规则/ }).click();
    await vp.click('[data-action="add-rule"]');
    await vp.waitForSelector('[role="dialog"]');
    const firstSelect = vp.locator('[role="dialog"] select.inp').first();
    await firstSelect.focus();
    await vp.keyboard.press('Space');
    await vp.waitForSelector('.kat-pop:not(.kat-leaving)');
    await vp.keyboard.press('Escape');
    await vp.waitForTimeout(20);
    await vp.keyboard.press('Escape');
    await vp.waitForTimeout(260);
    const activeDialogCount = await vp.evaluate(
      () => document.querySelectorAll('[role="dialog"]:not(.kat-leaving *), [role="alertdialog"]:not(.kat-leaving *)').length,
    );
    if (activeDialogCount !== 0) {
      failures.push(`exitGhost rapid 20ms double-Escape left active dialog count=${activeDialogCount}, expected 0`);
    }

    // 4c. 5,000 Rules virtual scroll & search < 150ms
    const rulesDom = await vp.evaluate(() => document.querySelectorAll('*').length);
    const ruleSearch = vp.getByLabel('搜索规则', { exact: true });
    await ruleSearch.focus();
    const rSearchMs = await vp.evaluate(async () => {
      const inp = document.querySelector('input[aria-label="搜索规则"]');
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
      const t0 = performance.now();
      setter.call(inp, 'virtual-rule-4999');
      inp.dispatchEvent(new Event('input', { bubbles: true }));
      await new Promise((r) => requestAnimationFrame(r));
      return Math.round(performance.now() - t0);
    });
    if (rulesDom >= 5000) failures.push(`5000-rules virtual scroll DOM=${rulesDom}, expected < 5000`);
    if (rSearchMs >= 150) failures.push(`5000-rules search filter=${rSearchMs}ms, expected < 150ms`);
    await ruleSearch.fill('');

    // 4d. 2,000 Connections virtual scroll & search < 150ms
    await vp.click('[data-page="connections"]');
    await vp.waitForSelector('.conn-entry');
    const connsDom = await vp.evaluate(() => document.querySelectorAll('*').length);
    const connSearch = vp.getByLabel('搜索连接', { exact: true });
    await connSearch.focus();
    const cSearchMs = await vp.evaluate(async () => {
      const inp = document.querySelector('input[aria-label="搜索连接"]');
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
      const t0 = performance.now();
      setter.call(inp, 'conn-host-1999');
      inp.dispatchEvent(new Event('input', { bubbles: true }));
      await new Promise((r) => requestAnimationFrame(r));
      return Math.round(performance.now() - t0);
    });
    if (connsDom >= 5000) failures.push(`2000-conns virtual scroll DOM=${connsDom}, expected < 5000`);
    if (cSearchMs >= 150) failures.push(`2000-conns search filter=${cSearchMs}ms, expected < 150ms`);

    console.log(`VIRTUAL_AND_GHOST_GATE_METRICS: collapsedRevealDom=${collapsedChildDom}, rapidEscActiveDialogs=${activeDialogCount}, rules5000={dom:${rulesDom},searchMs:${rSearchMs}}, conns2000={dom:${connsDom},searchMs:${cSearchMs}}`);
    await vCtx.close();
  }

} finally {
  await browser.close();
  server.close();
}

assert.deepEqual(consoleIssues, [], `Browser console errors/warnings:\n${consoleIssues.join('\n')}`);
assert.deepEqual(failures, [], `Geometry & overflow gate failures:\n${failures.join('\n')}`);
console.log('GEOMETRY_GATE_PASSED: 4 viewports × dark/light × 20 sub-views × tray-menu × all modals/popovers = 0 overflows, 0 height mismatches, 0 console issues');
