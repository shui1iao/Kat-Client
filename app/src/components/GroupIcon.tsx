import { cachedIcon, rememberIcon, forgetIcon, validCachedImage, requestIcon } from '../client/iconCache';
import { useEffect, useState, useRef, type ReactNode } from 'react';
import { Icon } from './Icon';

const failures = new Map<string, { at: number; running: boolean }>();

const REGION_RULES: [RegExp, string][] = [
  [/香港|(?:\b|_)hk(?:\b|_)|hong\s*kong/i, 'HK'],
  [/台湾|台灣|(?:\b|_)tw(?:\b|_)|taiwan/i, 'TW'],
  [/日本|(?:\b|_)jp(?:\b|_)|japan|tokyo|osaka/i, 'JP'],
  [/新加坡|狮城|(?:\b|_)sg(?:\b|_)|singapore/i, 'SG'],
  [/美国|美國|(?:\b|_)us(?:\b|_)|united\s*states|america/i, 'US'],
  [/韩国|韓國|(?:\b|_)kr(?:\b|_)|korea/i, 'KR'],
  [/英国|英國|(?:\b|_)(?:uk|gb)(?:\b|_)|britain|london/i, 'GB'],
  [/德国|德國|(?:\b|_)de(?:\b|_)|germany/i, 'DE'],
  [/法国|法國|(?:\b|_)fr(?:\b|_)|france/i, 'FR'],
  [/加拿大|(?:\b|_)ca(?:\b|_)|canada/i, 'CA'],
  [/澳大利亚|澳洲|(?:\b|_)au(?:\b|_)|australia/i, 'AU'],
  [/俄罗斯|俄国|(?:\b|_)ru(?:\b|_)|russia/i, 'RU'],
  [/印度|(?:\b|_)in(?:\b|_)|india/i, 'IN'],
  [/土耳其|(?:\b|_)tr(?:\b|_)|turkey/i, 'TR'],
  [/阿根廷|(?:\b|_)ar(?:\b|_)|argentina/i, 'AR'],
  [/荷兰|(?:\b|_)nl(?:\b|_)|netherlands/i, 'NL'],
];

function isoToFlag(iso: string): string {
  return String.fromCodePoint(...[...iso].map((c) => 127397 + c.charCodeAt(0)));
}

interface SemanticBadge {
  color: string;
  svg: ReactNode;
}

function matchSemanticIcon(groupName: string, type: string): { flag?: string; badge?: SemanticBadge } {
  const n = groupName.trim();

  // 1. Service / Category recognition first (so e.g. "AI" or "Telegram" or "流媒体" gets its dedicated icon)
  if (/chatgpt|openai|claude|copilot|(?:\b|[^a-z])ai(?:\b|[^a-z])|人工智能/i.test(n)) {
    return {
      badge: {
        color: '#10A37F',
        svg: (
          <svg width="21" height="21" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 3l1.9 5.1L19 10l-5.1 1.9L12 17l-1.9-5.1L5 10l5.1-1.9L12 3z" />
            <path d="M19 16l.9 2.1L22 19l-2.1.9L19 22l-.9-2.1L16 19l2.1-.9L19 16z" />
          </svg>
        ),
      },
    };
  }

  if (/gemini|google|谷歌/i.test(n)) {
    return {
      badge: {
        color: '#4C8DFF',
        svg: (
          <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
            <path d="M11.04 19.32Q12 21.51 12 24q0-2.49.93-4.68.96-2.19 2.58-3.81t3.81-2.55Q21.51 12 24 12q-2.49 0-4.68-.93a12.3 12.3 0 0 1-3.81-2.58 12.3 12.3 0 0 1-2.58-3.81Q12 2.49 12 0q0 2.49-.96 4.68-.93 2.19-2.55 3.81a12.3 12.3 0 0 1-3.81 2.58Q2.49 12 0 12q2.49 0 4.68.96 2.19.93 3.81 2.55t2.55 3.81" />
          </svg>
        ),
      },
    };
  }

  if (/telegram|(?:\b|_)tg(?:\b|_)|电报/i.test(n)) {
    return {
      badge: {
        color: '#2AABEE',
        svg: (
          <svg width="21" height="21" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
            <path d="M21.5 4.5L2.8 11.7c-.8.3-.8 1.4 0 1.7l4.7 1.6 1.8 5.3c.2.7 1.1.9 1.6.4l2.7-2.6 4.8 3.5c.6.4 1.5.1 1.7-.7l2.6-15.3c.2-.8-.5-1.4-1.2-1.1z" />
            <path d="M7.5 15l9.5-7.5" />
          </svg>
        ),
      },
    };
  }

  if (/netflix|disney|youtube|tiktok|emby|bahamut|bilibili|spotify|media|stream|流媒体|影视|视频|音乐/i.test(n)) {
    return {
      badge: {
        color: '#E5484D',
        svg: (
          <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
            <path d="M8 5.5v13l10.5-6.5z" />
          </svg>
        ),
      },
    };
  }

  if (/game|steam|xbox|playstation|nintendo|epic|游戏/i.test(n)) {
    return {
      badge: {
        color: '#8B5CF6',
        svg: (
          <svg width="21" height="21" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
            <rect x="2.5" y="7" width="19" height="10" rx="5" />
            <path d="M8 10v4M6 12h4" />
            <circle cx="15.5" cy="11" r="1" fill="currentColor" />
            <circle cx="17.5" cy="13" r="1" fill="currentColor" />
          </svg>
        ),
      },
    };
  }

  if (/github|gitlab|docker|dev|code|开发/i.test(n)) {
    return {
      badge: {
        color: '#6E7681',
        svg: <Icon name="config" size={20} />,
      },
    };
  }

  if (/apple|icloud|苹果/i.test(n)) {
    return {
      badge: {
        color: '#8E8E93',
        svg: <Icon name="monitor" size={20} />,
      },
    };
  }

  if (/reject|adblock|ads|广告|拦截|屏蔽/i.test(n)) {
    return {
      badge: {
        color: '#F85149',
        svg: <Icon name="shield" size={20} />,
      },
    };
  }

  if (/direct|直连|国内/i.test(n)) {
    return {
      badge: {
        color: '#10B981',
        svg: <Icon name="direct" size={20} />,
      },
    };
  }

  if (/final|match|漏网|兜底|其他|其余/i.test(n)) {
    return {
      badge: {
        color: '#F08C3A',
        svg: <Icon name="target" size={20} />,
      },
    };
  }

  // 2. Region / Country flag recognition
  for (const [re, iso] of REGION_RULES) {
    if (re.test(n)) return { flag: isoToFlag(iso) };
  }

  // 3. Role / Group Type recognition
  if (/smart|智能|自动|auto|url-?test|测速|最优/i.test(n) || type === 'smart' || type === 'url-test') {
    return {
      badge: {
        color: '#F59E0B',
        svg: <Icon name="bolt" size={20} />,
      },
    };
  }

  if (/fallback|故障|备用/i.test(n) || type === 'fallback') {
    return {
      badge: {
        color: '#22B8CF',
        svg: <Icon name="route" size={20} />,
      },
    };
  }

  if (/主选择|节点选择|代理|proxy|select|global|全局/i.test(n)) {
    return {
      badge: {
        color: '#4C8DFF',
        svg: <Icon name="nodes" size={20} />,
      },
    };
  }

  return {
    badge: {
      color: '#A371F7',
      svg: <Icon name="policies" size={20} />,
    },
  };
}

export function GroupIcon({
  value,
  type,
  group = '',
  running = false,
}: {
  value?: string;
  type: string;
  group?: string;
  running?: boolean;
}) {
  const directDataUri = value && validCachedImage(value) ? value : '';
  const [src, setSrc] = useState(() => (directDataUri ? directDataUri : value ? cachedIcon(value) : ''));
  const [attempt, setAttempt] = useState(0);
  const previousRunning = useRef(running);

  useEffect(() => {
    let live = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const started = running && !previousRunning.current;
    previousRunning.current = running;

    if (!value) {
      setSrc('');
      return;
    }
    if (validCachedImage(value)) {
      setSrc(value);
      return;
    }
    const cached = cachedIcon(value);
    if (cached) {
      setSrc(cached);
      return;
    }
    setSrc('');
    const retry = (delay = 60000) => {
      timer = setTimeout(() => {
        if (live) setAttempt((n) => n + 1);
      }, delay);
    };
    const cleanup = () => {
      live = false;
      clearTimeout(timer);
    };
    const prior = failures.get(value);
    if (prior && Date.now() - prior.at < 60000 && !started && !(running && !prior.running)) {
      retry(60000 - (Date.now() - prior.at));
      return cleanup;
    }
    void requestIcon(value, group)
      .then((uri) => {
        if (!live) return;
        if (validCachedImage(uri)) {
          failures.delete(value);
          rememberIcon(value, uri);
          setSrc(uri);
        } else {
          failures.set(value, { at: Date.now(), running });
          retry();
        }
      })
      .catch(() => {
        if (live) {
          failures.set(value, { at: Date.now(), running });
          retry();
        }
      });
    return cleanup;
  }, [value, group, running, attempt]);

  if (src) {
    return (
      <span className="pc-icon-box has-img" aria-hidden="true">
        <img
          className="pc-image"
          src={src}
          alt=""
          onError={() => {
            if (value && !validCachedImage(value)) {
              forgetIcon(value);
              failures.set(value, { at: Date.now(), running });
            }
            setSrc('');
            setAttempt((n) => n + 1);
          }}
        />
      </span>
    );
  }

  const semantic = matchSemanticIcon(group, type);
  if (semantic.flag) {
    return (
      <span className="pc-icon-box is-flag" aria-hidden="true">
        {semantic.flag}
      </span>
    );
  }

  const badge = semantic.badge!;
  return (
    <span
      className={'pc-icon-box pc-glyph t-' + type}
      style={{ '--gi-color': badge.color } as React.CSSProperties}
      aria-hidden="true"
    >
      {badge.svg}
    </span>
  );
}
