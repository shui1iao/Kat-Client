import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { isValidIPv4, isValidIPv6, splitHostPort, formatHostPort } from '../src/lib/netAddr.ts';
import { bytesStr, rateStr, clock, latencyTone, probeLabel } from '../src/lib/format.ts';
import { showBytes, showRate, showUptime, countStr, clockMsStr } from '../src/client/display.ts';
import { nodeRows } from '../src/client/nodeRows.ts';
import { byteAxis, speedAxis } from '../src/charts/scale.ts';
import { speedColumns } from '../src/charts/speedColumns.ts';

test('netAddr validates IPv4/IPv6 strictly and brackets bare IPv6 in formatHostPort & nodeRows', () => {
  assert.equal(isValidIPv4('1.1.1.1'), true);
  assert.equal(isValidIPv4('999.1.1.1'), false);
  assert.equal(isValidIPv6('2001:db8:85a3::8a2e:370:7334'), true);
  assert.equal(isValidIPv6('::1'), true);
  assert.equal(isValidIPv6('fe80::1%eth0'), true);
  assert.equal(isValidIPv6('face.de:443'), false);
  assert.equal(isValidIPv6('cafe.ba:8080'), false);
  assert.equal(isValidIPv6(':::'), false);
  assert.equal(isValidIPv6('2001::db8::1'), false);

  assert.deepEqual(splitHostPort('face.de:443'), { host: 'face.de', port: '443' });
  assert.deepEqual(splitHostPort('[2001:db8::1]:8443'), { host: '2001:db8::1', port: '8443' });
  assert.deepEqual(splitHostPort('2001:db8::1'), { host: '2001:db8::1', port: '' });

  assert.equal(formatHostPort('2001:db8:85a3::8a2e:370:7334', 65535), '[2001:db8:85a3::8a2e:370:7334]:65535');
  assert.equal(formatHostPort('[::1]', 17890), '[::1]:17890');
  assert.equal(formatHostPort('127.0.0.1', 17890), '127.0.0.1:17890');

  const rows = nodeRows({
    schema_version: 1,
    client: { mode: 'rule' },
    kernel: { outbounds: [{ name: 'v6', type: 'socks5', server: '2001:db8::1', port: 1080 }] },
  });
  assert.equal(rows[0].address, '[2001:db8::1]:1080');
});

test('format & display handle <1024 B, PB tier, NaN/Infinity/negative inputs and clockMsStr cleanly', () => {
  assert.equal(showBytes(0), '0 B');
  assert.equal(showBytes(1), '1 B');
  assert.equal(showBytes(300), '300 B');
  assert.equal(showBytes(1023), '1023 B');
  assert.equal(showBytes(1024), '1 KB');
  assert.equal(showBytes(1024 ** 5), '1.00 PB');
  assert.equal(showBytes(Number.MAX_SAFE_INTEGER), '8.00 PB');

  for (const bad of [NaN, Infinity, -Infinity, -1, -1024]) {
    assert.equal(bytesStr(bad), '0 B');
    assert.equal(rateStr(bad), '0 B/s');
    assert.equal(clock(bad), '00:00:00');
    assert.equal(showBytes(bad), '—');
    assert.equal(showRate(bad), '—');
    assert.equal(showUptime(bad), '—');
    assert.equal(countStr(bad), '—');
    assert.equal(latencyTone(bad), 'off');
    assert.equal(probeLabel(bad), '—');
  }

  assert.equal(latencyTone(80), 'ok');
  assert.equal(latencyTone(550), 'mid');
  assert.equal(latencyTone(1500), 'bad');
  assert.equal(clockMsStr(''), '—');
  assert.equal(clockMsStr(null), '—');
  assert.equal(clockMsStr('not-a-timestamp'), '—');
  const validMs = clockMsStr('2026-11-28T01:02:03.007Z');
  assert.equal(validMs.includes('NaN'), false);
  assert.match(validMs, /\d{2}:\d{2}:\d{2}\.007$/);
});

test('chart axes, speedColumns, WeekBars and TrafficDistribution sanitize NaN/Infinity/negative inputs', () => {
  const bAx = byteAxis([NaN, Infinity, -Infinity, -500]);
  assert.equal(Number.isFinite(bAx.top) && bAx.top > 0, true);
  assert.equal(bAx.ticks.every((t) => Number.isFinite(t) && t >= 0), true);

  const sAx = speedAxis([NaN, Infinity, -Infinity, -500]);
  assert.equal(Number.isFinite(sAx.top) && sAx.top > 0, true);
  assert.equal(sAx.ticks.every((t) => Number.isFinite(t) && t >= 0), true);

  const cols = speedColumns([NaN, 100, Infinity, -5], [0, NaN, 50, 10], 200);
  assert.equal(
    cols.every(
      (c) =>
        Number.isFinite(c.x0) &&
        Number.isFinite(c.x1) &&
        (c.down === null || (Number.isFinite(c.down) && c.down >= 0)) &&
        (c.up === null || (Number.isFinite(c.up) && c.up >= 0)),
    ),
    true,
  );

  const wbSrc = readFileSync(resolve(import.meta.dirname, '../src/charts/WeekBars.tsx'), 'utf8');
  const tdSrc = readFileSync(resolve(import.meta.dirname, '../src/charts/TrafficDistribution.tsx'), 'utf8');
  assert.equal(wbSrc.includes('Number.isFinite'), true);
  assert.equal(tdSrc.includes('Number.isFinite'), true);
});
