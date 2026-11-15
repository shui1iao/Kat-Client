import { useEffect, useState, type CSSProperties } from 'react';
import { cachedIcon, requestDomainIcon, requestProcessIcon, validCachedImage } from '../client/iconCache';
import { GroupIcon } from './GroupIcon';

const MONOGRAM_PALETTE = [
  '#8866E8',
  '#3B82F6',
  '#2EAD76',
  '#EA8538',
  '#DE6890',
  '#24A3B6',
  '#6875DF',
  '#D4923A',
];

function hashPick(s: string): string {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0;
  return MONOGRAM_PALETTE[Math.abs(h) % MONOGRAM_PALETTE.length];
}

function primaryDomainLabel(domain: string): string {
  const parts = domain.toLowerCase().split('.').filter(Boolean);
  if (parts.length >= 3 && ['com', 'net', 'org', 'gov', 'edu', 'co'].includes(parts[parts.length - 2])) {
    return parts[parts.length - 3];
  }
  return parts.length >= 2 ? parts[parts.length - 2] : parts[0] || '?';
}

export function DomainIcon({ domain, size = 'md' }: { domain: string; size?: 'sm' | 'md' }) {
  const clean = domain.trim().toLowerCase();
  const key = 'dom:' + clean;
  const [src, setSrc] = useState(() => (clean ? cachedIcon(key) : ''));

  useEffect(() => {
    let live = true;
    if (!clean) {
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

  const label = primaryDomainLabel(clean);
  const ch = (label[0] ?? '?').toUpperCase();
  const tone = hashPick(label);
  return (
    <span className={cls + ' is-mono'} style={{ '--ei-color': tone } as CSSProperties} aria-hidden="true">
      {ch}
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
  const dClean = fallbackDomain && !/^\d+\.\d+\.\d+\.\d+$/.test(fallbackDomain) && !fallbackDomain.includes(':')
    ? fallbackDomain.trim().toLowerCase()
    : '';
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

  if (!name && !dClean) return null;
  const raw = (name ? name.replace(/\.exe$/i, '') : primaryDomainLabel(dClean)).trim();
  const ch = (raw[0] ?? '•').toUpperCase();
  const tone = hashPick(raw.toLowerCase());
  return (
    <span className="ei-proc-box is-mono" style={{ '--ei-color': tone } as CSSProperties} aria-hidden="true">
      {ch}
    </span>
  );
}
