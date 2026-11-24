export type ParsedDnsInput =
  | { ok: true; domain: string; fromUrl: boolean }
  | { ok: false; error: string };

const IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const DNS_LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const SUPPORTED_URL_SCHEMES = new Set(['http:', 'https:', 'ws:', 'wss:', 'ftp:']);

function isIPv4(host: string): boolean {
  if (!IPV4_RE.test(host)) return false;
  return host.split('.').every((part) => {
    const n = Number(part);
    return Number.isInteger(n) && n >= 0 && n <= 255;
  });
}

function isIPv6(host: string): boolean {
  const s = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
  if (!s.includes(':')) return false;
  return /^[0-9a-fA-F:.]+$/.test(s);
}

function isValidDomain(domain: string): boolean {
  if (!domain || domain.length > 253) return false;
  if (isIPv4(domain) || isIPv6(domain)) return false;
  const labels = domain.split('.');
  if (labels.some((l) => !DNS_LABEL_RE.test(l))) return false;
  return true;
}

/**
 * Extracts a normalized DNS hostname from either a plain domain or a full/partial website URL.
 * Supports http(s)/ws(s)/ftp links, protocol-relative //host/path, host:port/path, trailing dots,
 * and IDN domains (converted to punycode via URL).
 */
export function parseDnsQueryInput(raw: string): ParsedDnsInput {
  const trimmed = raw.trim();
  if (!trimmed) {
    return { ok: false, error: '请输入域名或网站链接' };
  }
  if (/[\u0000-\u0020\u007f]/.test(trimmed)) {
    return { ok: false, error: '输入包含空白或无效控制字符' };
  }
  if (isIPv4(trimmed) || isIPv6(trimmed)) {
    return { ok: false, error: '已是 IP 地址，无需 DNS 解析' };
  }

  let candidate = trimmed;
  let hadUrlWrapper = false;

  const schemeMatch = /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\//.exec(trimmed);
  if (schemeMatch) {
    hadUrlWrapper = true;
    const afterScheme = trimmed.slice(schemeMatch[0].length);
    if (!afterScheme || afterScheme.startsWith('/')) {
      return { ok: false, error: '网站链接缺少有效主机名' };
    }
    try {
      const u = new URL(trimmed);
      if (!SUPPORTED_URL_SCHEMES.has(u.protocol)) {
        return { ok: false, error: '仅支持常见网页链接或域名' };
      }
      candidate = u.hostname;
    } catch {
      return { ok: false, error: '网站链接格式无效，请检查后重试' };
    }
  } else if (trimmed.startsWith('//')) {
    hadUrlWrapper = true;
    if (trimmed.length <= 2 || trimmed.startsWith('///')) {
      return { ok: false, error: '网站链接缺少有效主机名' };
    }
    try {
      const u = new URL('https:' + trimmed);
      candidate = u.hostname;
    } catch {
      return { ok: false, error: '网站链接格式无效，请检查后重试' };
    }
  } else if (/^[a-zA-Z][a-zA-Z0-9+.-]*:(?!\d+(?:[/?#]|$))/.test(trimmed)) {
    // Reject non-URL schemes such as mailto:user@example.com or javascript:...
    return { ok: false, error: '请输入有效的域名或网站链接' };
  } else if (/[/?#:]/.test(trimmed) || /[^\x00-\x7f]/.test(trimmed)) {
    hadUrlWrapper = /[/?#:]/.test(trimmed);
    try {
      const u = new URL('https://' + trimmed);
      candidate = u.hostname;
    } catch {
      return { ok: false, error: '请输入有效的域名或网站链接' };
    }
  }

  const normalized = candidate.replace(/\.+$/, '').toLowerCase();
  if (isIPv4(normalized) || isIPv6(normalized)) {
    return {
      ok: false,
      error: hadUrlWrapper ? '链接主机已是 IP 地址，无需 DNS 解析' : '已是 IP 地址，无需 DNS 解析',
    };
  }
  if (!isValidDomain(normalized)) {
    return { ok: false, error: '请输入有效的域名或网站链接' };
  }

  const fromUrl = hadUrlWrapper || normalized !== trimmed.replace(/\.+$/, '').toLowerCase();
  return { ok: true, domain: normalized, fromUrl };
}
