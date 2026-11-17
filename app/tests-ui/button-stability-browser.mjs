import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { access, mkdir, readFile } from 'node:fs/promises';
import { extname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
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
  throw new Error('playwright-core not found');
}

await mkdir('/tmp/kat-pw-tmp', { recursive: true });
process.env.TMPDIR = '/tmp/kat-pw-tmp';
process.env.TEMP = '/tmp/kat-pw-tmp';
process.env.TMP = '/tmp/kat-pw-tmp';

const { chromium } = await import(await resolvePlaywrightEntry());
const app = resolve(import.meta.dirname, '..');
const dist = resolve(app, 'dist');
const mime = { '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2' };

const srv = createServer(async (req, res) => {
  const u = (req.url || '/').split('?')[0];
  const p = join(dist, u === '/' ? 'index.html' : u);
  try {
    const b = await readFile(p);
    res.writeHead(200, { 'content-type': mime[extname(p)] || 'application/octet-stream' });
    res.end(b);
  } catch {
    res.writeHead(404);
    res.end();
  }
});
await new Promise((r) => srv.listen(0, '127.0.0.1', r));
const base = `http://127.0.0.1:${srv.address().port}`;

const browser = await chromium.launch({
  executablePath: process.env.CHROMIUM_PATH || '/usr/bin/chromium',
  args: ['--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage'],
});

try {
  for (const vw of [900, 965, 1000, 1080, 1280]) {
    const ctx = await browser.newContext({ viewport: { width: vw, height: 720 } });
    await ctx.addInitScript(installTransport);
    await ctx.addInitScript(installDailyTransport);
    await ctx.addInitScript(() => {
      const doc = JSON.parse(window.__TEST.text);
      delete doc.kernel.providers;
      for (const g of doc.kernel.groups ?? []) delete g.use;
      doc.client.sniff = { enabled: true, override_destination: true };
      window.__TEST.text = JSON.stringify(doc, null, 2) + '\n';
      const prev = window.__TAURI_INTERNALS__.invoke;
      window.__TAURI_INTERNALS__.invoke = async (command, args = {}) => {
        if (command === 'tray_sync') return null;
        if (command === 'update_state') {
          return { confirmation: { pending: false, running: false, message: '' }, auto_check: false, last_check: 0, checking: false, rows: [], proposal: null, notice: false, preparing: false, error: '' };
        }
        if (command === 'core_request' && args.method === 'logs.dns') {
          return {
            instance: 1,
            next_seq: 1200,
            entries: Array.from({ length: 1200 }, (_, i) => ({
              seq: i + 1,
              time: new Date().toISOString(),
              name: 'a.com',
              qtype: 'A',
              addresses: ['1.1.1.1'],
              server: 'system',
              source: 'tun',
              duration_ms: 5,
              outcome: i === 0 ? 'nxdomain' : 'ok',
              cached: i % 3 === 0,
            })),
          };
        }
        if (command === 'core_request' && args.method === 'dns.cache.list') {
          return { capacity: 256, entries: Array.from({ length: 42 }, (_, i) => ({ name: `c${i}.com`, qtype: 'A', addresses: ['1.1.1.1'], server: 'system', ttl_sec: 42 })) };
        }
        if (command === 'core_request' && args.method === 'dns.cache.clear') {
          return { cleared: 42 };
        }
        return prev(command, args);
      };
    });

    const page = await ctx.newPage();
    await page.goto(base + '/#dns');
    await page.getByRole('button', { name: '暂停', exact: true }).waitFor();
    await page.waitForTimeout(150);

    const box = async (loc) => {
      const b = await loc.boundingBox();
      return { x: Math.round(b.x * 100) / 100, y: Math.round(b.y * 100) / 100, w: Math.round(b.width * 100) / 100, h: Math.round(b.height * 100) / 100 };
    };

    const t1 = await Promise.all(['最近解析', '解析缓存', 'DNS 设置'].map((n) => box(page.getByRole('tab', { name: n }))));
    const pillBefore = await box(page.getByRole('radio', { name: '空 / 失败' }));
    const pauseBefore = await box(page.getByRole('button', { name: '暂停', exact: true }));
    await page.getByRole('radio', { name: '空 / 失败' }).click();
    const pillAfter = await box(page.getByRole('radio', { name: '空 / 失败' }));
    const pauseAfter = await box(page.getByRole('button', { name: '暂停', exact: true }));
    assert.deepEqual(pillBefore, pillAfter, `VW=${vw}: DNS filter pill shifted when count changed!`);
    assert.deepEqual(pauseBefore, pauseAfter, `VW=${vw}: DNS pause button shifted when count changed!`);

    await page.getByRole('tab', { name: '解析缓存' }).click();
    await page.getByRole('button', { name: '清除缓存', exact: true }).waitFor();
    await page.waitForFunction(() => !document.querySelector('.dns-table-card .btn.danger')?.disabled);
    const t2 = await Promise.all(['最近解析', '解析缓存', 'DNS 设置'].map((n) => box(page.getByRole('tab', { name: n }))));
    assert.deepEqual(t1, t2, `VW=${vw}: DNS tabs shifted when switching to Cache!`);
    const clearCacheBtn1 = await box(page.getByRole('button', { name: '清除缓存', exact: true }));
    await page.getByRole('button', { name: '清除缓存', exact: true }).click();
    await page.getByRole('status').filter({ hasText: /已清除 \d+ 条/ }).waitFor();
    const clearCacheBtnAfterNotice = await box(page.getByRole('button', { name: '清除缓存', exact: true }));
    assert.deepEqual(clearCacheBtn1, clearCacheBtnAfterNotice, `VW=${vw}: Clear cache button shifted when status appeared!`);

    await page.getByRole('tab', { name: 'DNS 设置' }).click();
    await page.getByLabel('跳过目标覆盖模式').waitFor();
    const t3 = await Promise.all(['最近解析', '解析缓存', 'DNS 设置'].map((n) => box(page.getByRole('tab', { name: n }))));
    assert.deepEqual(t1, t3, `VW=${vw}: DNS tabs shifted when switching to Settings!`);
    const clearCacheBtnSettings = await box(page.getByRole('button', { name: '清除缓存', exact: true }));
    assert.deepEqual(clearCacheBtn1, clearCacheBtnSettings, `VW=${vw}: Clear cache button position differs between Cache and Settings tabs!`);

    const skipModeSel = page.getByLabel('跳过目标覆盖模式');
    const skipSelBefore = await box(skipModeSel);
    await page.evaluate(() => {
      const el = document.querySelector('[aria-label="跳过目标覆盖模式"]');
      el.value = 'custom';
      el.dispatchEvent(new Event('change', { bubbles: true }));
    });
    await page.getByLabel('跳过目标覆盖', { exact: true }).waitFor();
    const skipSelAfter = await box(skipModeSel);
    assert.deepEqual(skipSelBefore, skipSelAfter, `VW=${vw}: Skip domain mode select shifted when custom input opened!`);

    await page.locator('[data-page=connections]').click();
    await page.getByRole('button', { name: '按进程' }).waitFor();
    const byProcBtn1 = await box(page.getByRole('button', { name: '按进程' }));
    const connPause1 = await box(page.getByRole('button', { name: '暂停', exact: true }));
    await page.getByRole('button', { name: '按进程' }).click();
    await page.waitForTimeout(60);
    const byProcBtn2 = await box(page.getByRole('button', { name: '按进程' }));
    const connPause2 = await box(page.getByRole('button', { name: '暂停', exact: true }));
    assert.deepEqual(byProcBtn1, byProcBtn2, `VW=${vw}: 按进程 button shifted under cursor!`);
    assert.deepEqual(connPause1, connPause2, `VW=${vw}: Connections pause button shifted on groupByProc!`);
    await page.getByRole('tab', { name: /已关闭/ }).click();
    await page.waitForTimeout(80);
    const connPause3 = await box(page.getByRole('button', { name: '暂停', exact: true }));
    assert.deepEqual(connPause1, connPause3, `VW=${vw}: Connections pause button shifted on Closed tab!`);

    await page.locator('[data-page=logs]').click();
    await page.getByRole('tab', { name: '内核日志' }).waitFor();
    const lt1 = await Promise.all(['连接日志', '内核日志', '事件'].map((n) => box(page.getByRole('tab', { name: n }))));
    const errPill1 = await box(page.getByRole('radio', { name: '失败' }));
    await page.getByRole('radio', { name: '失败' }).click();
    const errPill2 = await box(page.getByRole('radio', { name: '失败' }));
    assert.deepEqual(errPill1, errPill2, `VW=${vw}: Logs filter pill shifted when count changed!`);
    await page.getByRole('tab', { name: '内核日志' }).click();
    await page.waitForTimeout(80);
    const lt2 = await Promise.all(['连接日志', '内核日志', '事件'].map((n) => box(page.getByRole('tab', { name: n }))));
    await page.getByRole('tab', { name: '事件' }).click();
    await page.waitForTimeout(80);
    const lt3 = await Promise.all(['连接日志', '内核日志', '事件'].map((n) => box(page.getByRole('tab', { name: n }))));
    assert.deepEqual(lt1, lt2, `VW=${vw}: Logs tabs shifted on Kernel!`);
    assert.deepEqual(lt1, lt3, `VW=${vw}: Logs tabs shifted on Events!`);

    await ctx.close();
  }
  console.log(JSON.stringify({ passed: true, viewports: [900, 965, 1000, 1080, 1280], zero_shift: true }));
} finally {
  await browser.close();
  srv.close();
}
