import { useEffect, useState } from 'react';
import {
  cachedIcon,
  domainIconKey,
  processIconKey,
  requestDomainIcon,
  requestProcessIcon,
  subscribeIcon,
  validCachedImage,
} from '../client/iconCache';
import { GroupIcon } from './GroupIcon';
import { Icon } from './Icon';
import { isValidIPv4, isValidIPv6, splitHostPort } from '../lib/netAddr';

function normalizeHostOrIp(raw?: string): string {
  if (!raw) return '';
  const trimmed = raw.trim().toLowerCase();
  if (!trimmed || trimmed === '—' || trimmed === '-' || trimmed === 'dns' || trimmed === 'localhost') return '';
  let s = splitHostPort(trimmed).host;
  if (s.endsWith('.')) s = s.slice(0, -1);
  return s;
}

function isIpLiteral(s: string): boolean {
  return isValidIPv4(s) || isValidIPv6(s);
}

export function DomainIcon({
  domain,
  ip,
  rule,
  size = 'md',
}: {
  domain: string;
  ip?: string;
  rule?: string;
  size?: 'sm' | 'md';
}) {
  const clean = normalizeHostOrIp(domain);
  const cleanIp = normalizeHostOrIp(ip);
  const key = domainIconKey(clean, cleanIp, rule);
  const [src, setSrc] = useState(() => (key ? cachedIcon(key) : ''));

  useEffect(() => {
    let live = true;
    if (!key) {
      setSrc('');
      return;
    }
    const cached = cachedIcon(key);
    if (cached) {
      setSrc(cached);
      return subscribeIcon(key, (uri) => {
        if (live && validCachedImage(uri)) setSrc(uri);
      });
    }
    setSrc('');
    const unsub = subscribeIcon(key, (uri) => {
      if (live && validCachedImage(uri)) setSrc(uri);
    });
    void requestDomainIcon(clean, cleanIp, rule)
      .then((uri) => {
        if (live && validCachedImage(uri)) setSrc(uri);
      })
      .catch(() => {});
    return () => {
      live = false;
      unsub();
    };
  }, [clean, cleanIp, rule, key]);

  const cls = 'ei-domain-tile' + (size === 'sm' ? ' is-sm' : '');

  if (src) {
    return (
      <span className={cls + ' has-img'} aria-hidden="true">
        <img className="ei-img" src={src} alt="" onError={() => setSrc('')} />
      </span>
    );
  }

  return (
    <span className={cls + ' is-placeholder'} aria-hidden="true">
      <Icon name={isIpLiteral(clean) ? 'target' : 'nodes'} size={size === 'sm' ? 15 : 17} stroke={1.65} />
    </span>
  );
}

export function PolicyMiniIcon({
  name,
  iconUrl,
  groupType = 'select',
  running = false,
}: {
  name: string;
  iconUrl?: string;
  groupType?: string;
  running?: boolean;
}) {
  return (
    <span className="ov-group-icon" aria-hidden="true">
      <GroupIcon value={iconUrl} type={groupType} group={name} running={running} />
    </span>
  );
}

export function ProcessIcon({
  name,
  path,
  size = 'md',
}: {
  name?: string;
  path?: string;
  size?: 'sm' | 'md';
}) {
  const key = processIconKey(path, name);
  const nameFallbackKey = path && name ? processIconKey(undefined, name) : '';
  const [procSrc, setProcSrc] = useState(() => (key ? cachedIcon(key) || (nameFallbackKey ? cachedIcon(nameFallbackKey) : '') : ''));

  useEffect(() => {
    let live = true;
    if (!key) {
      setProcSrc('');
      return;
    }
    const c = cachedIcon(key) || (nameFallbackKey ? cachedIcon(nameFallbackKey) : '');
    if (c) {
      setProcSrc(c);
      return subscribeIcon(key, (uri) => {
        if (live && validCachedImage(uri)) setProcSrc(uri);
      });
    }
    setProcSrc('');
    const unsub = subscribeIcon(key, (uri) => {
      if (live && validCachedImage(uri)) setProcSrc(uri);
    });
    void requestProcessIcon(path, name)
      .then((uri) => {
        if (live && validCachedImage(uri)) setProcSrc(uri);
      })
      .catch(() => {});
    return () => {
      live = false;
      unsub();
    };
  }, [path, name, key, nameFallbackKey]);

  const cls = 'ei-proc-box' + (size === 'sm' ? ' is-sm' : '');

  if (procSrc) {
    return (
      <span className={cls + ' has-img'} aria-hidden="true">
        <img className="ei-img" src={procSrc} alt="" onError={() => setProcSrc('')} />
      </span>
    );
  }

  return (
    <span className={cls + ' is-placeholder'} aria-hidden="true">
      <Icon name="monitor" size={size === 'sm' ? 11 : 15} stroke={1.65} />
    </span>
  );
}
