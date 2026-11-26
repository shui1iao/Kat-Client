import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { parseDnsQueryInput } from '../src/client/dnsInput.ts';

test('parseDnsQueryInput extracts clean hostnames from domains, URLs, ports, paths and IDN', () => {
  assert.deepEqual(parseDnsQueryInput('api.github.com'), {
    ok: true,
    domain: 'api.github.com',
    fromUrl: false,
  });
  assert.deepEqual(parseDnsQueryInput('  API.GitHub.COM.  '), {
    ok: true,
    domain: 'api.github.com',
    fromUrl: false,
  });
  assert.deepEqual(parseDnsQueryInput('https://api.github.com/repos/shui1iao/Kat-Client?tab=readme#top'), {
    ok: true,
    domain: 'api.github.com',
    fromUrl: true,
  });
  assert.deepEqual(parseDnsQueryInput('http://Example.COM:8080/path?x=1'), {
    ok: true,
    domain: 'example.com',
    fromUrl: true,
  });
  assert.deepEqual(parseDnsQueryInput('//cdn.jsdelivr.net/npm/react'), {
    ok: true,
    domain: 'cdn.jsdelivr.net',
    fromUrl: true,
  });
  assert.deepEqual(parseDnsQueryInput('github.com/shui1iao/Kat-Client'), {
    ok: true,
    domain: 'github.com',
    fromUrl: true,
  });
  assert.deepEqual(parseDnsQueryInput('example.com:443/health'), {
    ok: true,
    domain: 'example.com',
    fromUrl: true,
  });
  const idn = parseDnsQueryInput('https://例子.测试/abc');
  assert.equal(idn.ok, true);
  if (idn.ok) {
    assert.equal(idn.domain, 'xn--fsqu00a.xn--0zwm56d');
    assert.equal(idn.fromUrl, true);
  }
});

test('parseDnsQueryInput rejects IPs, empty authority, unsupported schemes and malformed inputs cleanly', () => {
  for (const raw of ['', '   ', 'api github.com', 'https:///foo', '///foo', 'mailto:a@b.com', 'javascript:alert(1)', 'ftp://', '-bad.com']) {
    const res = parseDnsQueryInput(raw);
    assert.equal(res.ok, false, `expected reject for ${JSON.stringify(raw)}`);
  }
  const v4 = parseDnsQueryInput('1.1.1.1');
  assert.equal(v4.ok, false);
  if (!v4.ok) assert.match(v4.error, /IP/);

  const v4Url = parseDnsQueryInput('https://127.0.0.1:8080/test');
  assert.equal(v4Url.ok, false);
  if (!v4Url.ok) assert.match(v4Url.error, /IP/);

  const v6Url = parseDnsQueryInput('https://[2606:4700::1]/dns-query');
  assert.equal(v6Url.ok, false);
  if (!v6Url.ok) assert.match(v6Url.error, /IP/);
});

test('unified overlay glass, radius and soft fade CSS rules remain standard-property safe for LightningCSS', () => {
  const tokens = readFileSync(resolve(import.meta.dirname, '../src/design/tokens.css'), 'utf8');
  const comp = readFileSync(resolve(import.meta.dirname, '../src/design/components.css'), 'utf8');
  const pages = readFileSync(resolve(import.meta.dirname, '../src/design/pages.css'), 'utf8');

  assert.match(tokens, /--r-pop:\s*10px/);
  assert.match(tokens, /--r-modal:\s*12px/);
  assert.match(tokens, /--sep-fade:/);
  assert.match(tokens, /\[data-scroll-fade\]/);
  // Never emit manual -webkit-backdrop-filter that causes LightningCSS to drop standard backdrop-filter
  assert.equal(comp.includes('-webkit-backdrop-filter:'), false);
  assert.equal(pages.includes('-webkit-backdrop-filter:'), false);
  assert.match(pages, /\.rule-judge-pop\s*\{[^}]*border-radius:\s*var\(--r-pop\)[^}]*backdrop-filter:\s*blur\(20px\)\s*saturate\(200%\)/s);
  assert.match(pages, /\.dns-query-pop\s*\{/s);
  assert.match(pages, /\.dns-addr-pop\s*\{[^}]*border-radius:\s*var\(--r-pop\)[^}]*backdrop-filter:\s*blur\(20px\)\s*saturate\(200%\)/s);
});
