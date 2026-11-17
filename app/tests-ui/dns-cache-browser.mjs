import { createServer } from 'node:http';
import { access, readFile, mkdir, writeFile } from 'node:fs/promises';
import { resolve, extname } from 'node:path';
import { pathToFileURL } from 'node:url';
import assert from 'node:assert/strict';
import { installTransport, installDailyTransport } from './daily-transport.mjs';

async function resolvePlaywrightEntry() {
  const candidates = [
    process.env.PLAYWRIGHT_CORE_PATH,
    '/opt/kat-resize-review-20261113-2324/node_modules/playwright-core/index.mjs',
    '/opt/kat-windows-client-20261028/tools/node_modules/playwright-core/index.mjs',
    '/opt/kat-ui-emphasis-20261029/tools/node_modules/playwright-core/index.mjs',
  ].filter(Boolean);
  for (const raw of candidates) {
    const asFile = raw.endsWith('.mjs') || raw.endsWith('.js') ? resolve(raw) : resolve(raw, 'index.mjs');
    try {
      await access(asFile);
      return pathToFileURL(asFile).href;
    } catch {
      // try next candidate
    }
  }
  throw new Error('playwright-core not found; set PLAYWRIGHT_CORE_PATH to an existing playwright-core directory or index.mjs');
}

const { chromium } = await import(await resolvePlaywrightEntry());
const app = resolve(import.meta.dirname, '..');
const evidence = process.env.UI_EVIDENCE_DIR ? resolve(process.env.UI_EVIDENCE_DIR) : resolve(app, '../ui-evidence');
const executablePath = process.env.CHROMIUM_PATH || '/usr/bin/chromium';
await mkdir(evidence, { recursive: true });
for (const dir of ['tmp', 'daily/xdg', 'daily/chromium']) {
  await mkdir(resolve(app, 'tests-ui/.cache', dir), { recursive: true });
}
await mkdir('/tmp/kat-pw-tmp', { recursive: true });
process.env.TMPDIR = '/tmp/kat-pw-tmp';
process.env.TEMP = process.env.TMPDIR;
process.env.TMP = process.env.TMPDIR;
process.env.XDG_CACHE_HOME = resolve(app, 'tests-ui/.cache/daily/xdg');

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost');
    const path = resolve(app, 'dist', url.pathname === '/' ? 'index.html' : '.' + decodeURIComponent(url.pathname));
    if (!path.startsWith(resolve(app, 'dist') + '/')) throw new Error();
    const data = await readFile(path);
    res.setHeader(
      'Content-Type',
      ({ '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.woff2': 'font/woff2' })[
        extname(path)
      ] ?? 'application/octet-stream',
    );
    res.end(data);
  } catch {
    res.writeHead(404);
    res.end();
  }
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const base = 'http://127.0.0.1:' + server.address().port;
const browser = await chromium
  .launch({
    executablePath,
    headless: true,
    args: [
      '--no-sandbox',
      '--disable-dev-shm-usage',
      '--disable-background-networking',
      '--disk-cache-dir=' + resolve(app, 'tests-ui/.cache/daily/chromium'),
    ],
  })
  .catch(async (e) => {
    await new Promise((r) => server.close(r));
    throw e;
  });

const oomStart = Number((await readFile('/proc/vmstat', 'utf8')).match(/^oom_kill (\d+)/m)?.[1] ?? 0);
let resourceError = '';
const monitor = setInterval(async () => {
  const mem = Number((await readFile('/proc/meminfo', 'utf8')).match(/MemAvailable:\s+(\d+)/)?.[1] ?? 0);
  const oom = Number((await readFile('/proc/vmstat', 'utf8')).match(/^oom_kill (\d+)/m)?.[1] ?? 0);
  if (mem < 1048576 || oom > oomStart) {
    resourceError = 'Resource guard stopped owned daily browser';
    await browser.close();
  }
}, 1500);

const errors = [];
const external = [];
const checks = [];
try {
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 960 }, colorScheme: 'light' });
  await ctx.addInitScript(installTransport);
  await ctx.addInitScript(installDailyTransport);
  await ctx.addInitScript(() => {
    const doc = JSON.parse(window.__TEST.text);
    delete doc.kernel.providers;
    for (const g of doc.kernel.groups ?? []) delete g.use;
    window.__TEST.text = JSON.stringify(doc, null, 2) + '\n';

    const prev = window.__TAURI_INTERNALS__.invoke;
    window.__TAURI_INTERNALS__.invoke = async (command, args = {}) => {
      if (command === 'tray_sync') return null;
      if (command === 'update_state') {
        return {
          confirmation: { pending: false, running: false, message: '' },
          auto_check: false,
          last_check: 0,
          checking: false,
          rows: [],
          proposal: null,
          notice: false,
          preparing: false,
          error: '',
        };
      }
      if (command === 'core_request' && args.method === 'logs.dns') {
        return { instance: 1, entries: [], next_seq: 0, dropped: 0 };
      }
      if (command === 'core_request' && args.method === 'dns.cache.list') {
        window.__TEST.calls.push({ command, method: args.method });
        return { capacity: 256, entries: [] };
      }
      if (command === 'core_request' && args.method === 'dns.cache.clear') {
        window.__TEST.calls.push({ command, method: args.method });
        return { cleared: 0 };
      }
      return prev(command, args);
    };
  });
  const page = await ctx.newPage();
  page.setDefaultTimeout(5000);
  page.on('pageerror', (e) => errors.push(e.message));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(m.text());
  });
  page.on('request', (r) => {
    if (!r.url().startsWith(base + '/') && !r.url().startsWith('data:')) external.push(r.url());
  });

  await page.goto(base + '/#dns-settings');
  const input = page.getByLabel('DNS 缓存条数');
  await input.waitFor();
  assert.equal(await input.getAttribute('min'), '0');
  assert.equal(await input.getAttribute('max'), '4096');

  const initial = await page.evaluate(() => window.__TEST.text);
  await input.fill('4097');
  assert.equal(await input.evaluate((e) => e.validity.rangeOverflow), true);
  await page.locator('.dns-bare-form').getByRole('alert').filter({ hasText: 'DNS 缓存须为 0–4096' }).waitFor();
  await page.getByRole('button', { name: '保存 DNS', exact: true }).click();
  assert.equal(await page.evaluate(() => window.__TEST.text), initial);
  checks.push('custom DNS: input max4096 and rangeOverflow4097; invalid value stays visible and unsaved');

  await input.fill('4096');
  await page.getByRole('button', { name: '保存 DNS', exact: true }).click();
  await page.waitForFunction(() => JSON.parse(window.__TEST.text).kernel.dns.cache_entries === 4096);
  assert.equal(await input.inputValue(), '4096');
  assert.equal(await page.evaluate(() => JSON.parse(window.__TEST.text).kernel.dns.server), '1.1.1.1');
  checks.push('custom DNS: 4096 saves target cache field only, legacy dns.server untouched');

  await page.getByLabel('DNS 模式').selectOption('system');
  assert.equal(await input.inputValue(), '4096');
  assert.equal(await page.locator('.dns-bare-form').getByRole('alert').count(), 0);
  await page.getByRole('button', { name: '保存 DNS', exact: true }).click();
  await page.waitForFunction(() => {
    const dns = JSON.parse(window.__TEST.text).kernel.dns;
    return dns.server === 'system' && !dns.servers && dns.cache_entries === 4096;
  });
  checks.push('system DNS: accepts 4096 cache entries without obsolete zero-only error');

  await input.fill('0');
  await page.getByRole('button', { name: '保存 DNS', exact: true }).click();
  await page.waitForFunction(() => {
    const dns = JSON.parse(window.__TEST.text).kernel.dns;
    return dns.server === 'system' && !dns.servers && dns.cache_entries === 0;
  });
  checks.push('system DNS: accepts explicit 0 cache entries');

  await input.fill('512');
  await page.getByRole('button', { name: '保存 DNS', exact: true }).click();
  await page.waitForFunction(() => {
    const dns = JSON.parse(window.__TEST.text).kernel.dns;
    return dns.server === 'system' && !dns.servers && dns.cache_entries === 512;
  });
  checks.push('system DNS: accepts mid-range 512 cache entries');

  const applies = await page.evaluate(() => window.__TEST.calls.filter((c) => c.method === 'document.apply').length);
  await input.fill('-1');
  assert.equal(await input.evaluate((e) => e.validity.rangeUnderflow), true);
  await page.locator('.dns-bare-form').getByRole('alert').filter({ hasText: 'DNS 缓存须为 0–4096' }).waitFor();
  await page.getByRole('button', { name: '保存 DNS', exact: true }).click();
  assert.equal(await page.evaluate(() => window.__TEST.calls.filter((c) => c.method === 'document.apply').length), applies);
  assert.equal(await page.evaluate(() => JSON.parse(window.__TEST.text).kernel.dns.cache_entries), 512);
  checks.push('system DNS: rejects -1 with visible range error and blocks apply');

  await input.fill('4097');
  assert.equal(await input.evaluate((e) => e.validity.rangeOverflow), true);
  await page.locator('.dns-bare-form').getByRole('alert').filter({ hasText: 'DNS 缓存须为 0–4096' }).waitFor();
  await page.getByRole('button', { name: '保存 DNS', exact: true }).click();
  assert.equal(await page.evaluate(() => window.__TEST.calls.filter((c) => c.method === 'document.apply').length), applies);
  assert.equal(await page.evaluate(() => JSON.parse(window.__TEST.text).kernel.dns.cache_entries), 512);
  checks.push('system DNS: rejects 4097 with visible range error and blocks apply');

  await page.screenshot({ path: resolve(evidence, 'dns-cache-system-range-1280x960.png') });

  // Reset invalid draft on DNS form before testing SniffSettingsCard & DnsCacheView
  await page.getByRole('button', { name: '取消更改', exact: true }).click();

  // M5 & M6: Sniff skip_domain mode selector, explicit [] save, validation & a11y
  const modeSelect = page.getByLabel('跳过目标覆盖模式');
  await modeSelect.waitFor();
  assert.equal(await modeSelect.inputValue(), 'default');
  await page.locator('.sniff-card').filter({ hasText: '+.push.apple.com, Mijia Cloud, +.io.mi.com, +.cloudflare-ech.com' }).waitFor();

  await modeSelect.selectOption('custom');
  await page.waitForFunction(() => {
    const s = JSON.parse(window.__TEST.text).client.sniff;
    return s && Array.isArray(s.skip_domain) && s.skip_domain.length === 0;
  });
  const skipInput = page.getByLabel('跳过目标覆盖', { exact: true });
  await skipInput.waitFor();
  assert.equal(await skipInput.inputValue(), '');
  await page.locator('.sniff-card').filter({ hasText: '空列表，不跳过任何域名' }).waitFor();
  checks.push('sniff skip_domain: mode switch to custom persists explicit [] and renders empty-list status');

  await skipInput.fill('+...');
  await skipInput.blur();
  assert.equal(await skipInput.getAttribute('aria-invalid'), 'true');
  await page.locator('.sniff-card').getByRole('alert').filter({ hasText: '后缀规则不能为空' }).waitFor();
  await skipInput.fill('+.push.apple.com, Mijia Cloud');
  assert.equal(await skipInput.getAttribute('aria-invalid'), 'false');
  const appliesBeforeEnter = await page.evaluate(() => window.__TEST.calls.filter((c) => c.method === 'document.apply').length);
  await skipInput.press('Enter');
  await page.waitForFunction(() => {
    const s = JSON.parse(window.__TEST.text).client.sniff;
    return Array.isArray(s?.skip_domain) && s.skip_domain.length === 2 && s.skip_domain[1] === 'Mijia Cloud';
  });
  assert.equal(
    await page.evaluate(() => window.__TEST.calls.filter((c) => c.method === 'document.apply').length),
    appliesBeforeEnter + 1,
  );
  checks.push('sniff skip_domain: malformed suffix alert + aria-invalid, edit clears error, Enter commits once via blur');

  await modeSelect.selectOption('default');
  await page.waitForFunction(() => !('skip_domain' in (JSON.parse(window.__TEST.text).client.sniff ?? {})));
  checks.push('sniff skip_domain: mode switch back to default omits skip_domain field');

  // M7: DnsCacheView allows clearing even when entries list is empty while running
  await page.goto(base + '/#dns-cache');
  const clearBtn = page.getByRole('button', { name: '清除缓存', exact: true });
  await clearBtn.waitFor();
  await page.locator('.dns-empty').filter({ hasText: '当前暂无存活的 DNS 缓存条目' }).waitFor();
  assert.equal(await clearBtn.isDisabled(), false);
  await clearBtn.click();
  await page.getByRole('status').filter({ hasText: '已清除 0 条' }).waitFor();
  assert.equal(
    await page.evaluate(() => window.__TEST.calls.filter((c) => c.method === 'dns.cache.clear').length),
    1,
  );
  checks.push('dns cache tab: clear button enabled and invokes dns.cache.clear even when entries list is empty');

  assert.deepEqual(errors, []);
  assert.deepEqual(external, []);
  if (resourceError) throw Error(resourceError);
  await writeFile(
    resolve(evidence, 'dns-cache-browser-results.json'),
    JSON.stringify(
      {
        passed: true,
        scope: 'system/custom DNS cache 0..4096 acceptance and -1/4097 rejection; synthetic transport, not native peer or Windows',
        checks,
        consoleErrors: errors,
        externalRequests: external,
      },
      null,
      2,
    ),
  );
  console.log(JSON.stringify({ passed: true, checks, errors, external }, null, 2));
  await ctx.close();
} finally {
  clearInterval(monitor);
  await browser.close();
  await new Promise((r) => server.close(r));
  console.log('Owned cache test Chromium and loopback server closed');
}
