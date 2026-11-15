import { useEffect, useState } from 'react';
import { cachedIcon, requestDomainIcon, requestProcessIcon, validCachedImage } from '../client/iconCache';
import { GroupIcon } from './GroupIcon';
import { Icon } from './Icon';

function normalizeHostOrIp(raw?: string): string {
  if (!raw) return '';
  let s = raw.trim().toLowerCase();
  if (!s || s === '—' || s === '-' || s === 'dns' || s === 'localhost') return '';
  if (s.startsWith('[')) {
    const end = s.indexOf(']');
    if (end > 1) return s.slice(1, end);
  }
  const firstColon = s.indexOf(':');
  const lastColon = s.lastIndexOf(':');
  if (firstColon > 0 && firstColon === lastColon) {
    // host:port or ipv4:port
    s = s.slice(0, firstColon);
  }
  if (s.endsWith('.')) s = s.slice(0, -1);
  return s;
}

function isIpLiteral(s: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(s) || s.includes(':');
}

export function DomainIcon({ domain, size = 'md' }: { domain: string; size?: 'sm' | 'md' }) {
  const clean = normalizeHostOrIp(domain);
  const key = clean ? 'dom:' + clean : '';
  const [src, setSrc] = useState(() => (key ? cachedIcon(key) : ''));

  useEffect(() => {
    let live = true;
    if (!clean || !key) {
      setSrc('');
      return;
    }
    const cached = cachedIcon(key);
    if (cached) {
      setSrc(cached);
      return;
    }
    setSrc('');
    void requestDomainIcon(clean)
      .then((uri) => {
        if (live && validCachedImage(uri)) setSrc(uri);
      })
      .catch(() => {});
    return () => {
      live = false;
    };
  }, [clean, key]);

  const cls = 'ei-domain-tile' + (size === 'sm' ? ' is-sm' : '');

  if (src) {
    return (
      <span className={cls + ' has-img'} aria-hidden="true">
        <img className="ei-img" src={src} alt="" onError={() => setSrc('')} />
      </span>
    );
  }

  // Clean unified default icon placeholder (globe for domains, network node for unresolved raw IP)
  return (
    <span className={cls + ' is-placeholder'} aria-hidden="true">
      <Icon name={isIpLiteral(clean) ? 'target' : 'nodes'} size={size === 'sm' ? 13 : 15} stroke={1.65} />
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
  color?: string;
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
  fallbackDomain,
}: {
  name?: string;
  path?: string;
  fallbackDomain?: string;
}) {
  const pKey = path ? 'proc:' + path.trim().toLowerCase() : '';
  const dClean = normalizeHostOrIp(fallbackDomain);
  const dKey = dClean ? 'dom:' + dClean : '';

  const [procSrc, setProcSrc] = useState(() => (pKey ? cachedIcon(pKey) : ''));
  const [domSrc, setDomSrc] = useState(() => (dKey ? cachedIcon(dKey) : ''));

  useEffect(() => {
    let live = true;
    if (!path || !pKey) {
      setProcSrc('');
    } else {
      const c = cachedIcon(pKey);
      if (c) {
        setProcSrc(c);
      } else {
        setProcSrc('');
        void requestProcessIcon(path)
          .then((uri) => {
            if (live && validCachedImage(uri)) setProcSrc(uri);
          })
          .catch(() => {});
      }
    }
    return () => {
      live = false;
    };
  }, [path, pKey]);

  useEffect(() => {
    let live = true;
    if (procSrc || !dClean || !dKey) return;
    const c = cachedIcon(dKey);
    if (c) {
      setDomSrc(c);
      return;
    }
    void requestDomainIcon(dClean)
      .then((uri) => {
        if (live && validCachedImage(uri)) setDomSrc(uri);
      })
      .catch(() => {});
    return () => {
      live = false;
    };
  }, [procSrc, dClean, dKey]);

  if (procSrc) {
    return (
      <span className="ei-proc-box has-img" aria-hidden="true">
        <img className="ei-img" src={procSrc} alt="" onError={() => setProcSrc('')} />
      </span>
    );
  }

  if (domSrc) {
    return (
      <span className="ei-proc-box has-img" aria-hidden="true">
        <img className="ei-img" src={domSrc} alt="" onError={() => setDomSrc('')} />
      </span>
    );
  }

  // Always show a clean default app/terminal placeholder icon instead of returning null or random letters!
  return (
    <span className="ei-proc-box is-placeholder" aria-hidden="true">
      <Icon name="monitor" size={13} stroke={1.65} />
    </span>
  );
}
