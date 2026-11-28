const IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const HEX_GROUP_RE = /^[0-9a-fA-F]{1,4}$/;
const ZONE_ID_RE = /^[A-Za-z0-9._-]+$/;

export function isValidIPv4(raw: string): boolean {
  if (!IPV4_RE.test(raw)) return false;
  return raw.split('.').every((part) => {
    if (part.length > 1 && part.startsWith('0')) return false;
    const n = Number(part);
    return Number.isInteger(n) && n >= 0 && n <= 255;
  });
}

export function isValidIPv6(raw: string): boolean {
  const startsB = raw.startsWith('[');
  const endsB = raw.endsWith(']');
  if (startsB !== endsB) return false;
  const unb = startsB ? raw.slice(1, -1) : raw;
  if (unb.includes('[') || unb.includes(']')) return false;
  const pct = unb.indexOf('%');
  let s = unb;
  if (pct >= 0) {
    if (pct === 0) return false;
    const zone = unb.slice(pct + 1);
    if (!ZONE_ID_RE.test(zone)) return false;
    s = unb.slice(0, pct);
  }
  if (!s || (s.match(/:/g)?.length ?? 0) < 2) return false;
  if (/^:(?!:)/.test(s) || /(?<!:):$/.test(s) || s.includes(':::')) return false;
  const halves = s.split('::');
  if (halves.length > 2) return false;
  const parsePart = (part: string, allowV4Tail: boolean): number => {
    if (!part) return 0;
    const segs = part.split(':');
    let units = 0;
    for (let i = 0; i < segs.length; i++) {
      const seg = segs[i];
      if (allowV4Tail && i === segs.length - 1 && seg.includes('.')) {
        if (!isValidIPv4(seg)) return -1;
        units += 2;
      } else {
        if (!HEX_GROUP_RE.test(seg)) return -1;
        units += 1;
      }
    }
    return units;
  };
  if (halves.length === 1) {
    return parsePart(halves[0], true) === 8;
  }
  const left = parsePart(halves[0], false);
  const right = parsePart(halves[1], true);
  if (left < 0 || right < 0) return false;
  return left + right < 8;
}

export function splitHostPort(raw: string): { host: string; port: string } {
  const s = raw.trim();
  if (!s) return { host: '', port: '' };
  if (s.startsWith('[')) {
    const close = s.indexOf(']');
    if (close > 1) {
      const host = s.slice(1, close);
      const rest = s.slice(close + 1);
      if (!rest) return { host, port: '' };
      if (/^:\d{1,5}$/.test(rest)) {
        const p = Number(rest.slice(1));
        if (p >= 1 && p <= 65535) return { host, port: rest.slice(1) };
      }
    }
    return { host: s, port: '' };
  }
  if (isValidIPv6(s)) return { host: s, port: '' };
  const firstColon = s.indexOf(':');
  const lastColon = s.lastIndexOf(':');
  if (firstColon > 0 && firstColon === lastColon) {
    const portPart = s.slice(firstColon + 1);
    if (/^\d{1,5}$/.test(portPart)) {
      const p = Number(portPart);
      if (p >= 1 && p <= 65535) return { host: s.slice(0, firstColon), port: portPart };
    }
  }
  return { host: s, port: '' };
}

export function formatHostPort(host: string, port: number | string): string {
  const rawHost = host.trim();
  const pStr = typeof port === 'number' ? (Number.isInteger(port) ? String(port) : '') : port.trim();
  if (!rawHost || !/^\d{1,5}$/.test(pStr)) return '';
  const pNum = Number(pStr);
  if (!Number.isInteger(pNum) || pNum < 1 || pNum > 65535) return '';
  const sp = splitHostPort(rawHost);
  const baseHost = (sp.port && sp.host ? sp.host : rawHost).replace(/^\[+|\]+$/g, '').trim();
  if (!baseHost || baseHost.includes('[') || baseHost.includes(']')) return '';
  if (baseHost.includes(':')) return `[${baseHost}]:${pNum}`;
  return `${baseHost}:${pNum}`;
}
