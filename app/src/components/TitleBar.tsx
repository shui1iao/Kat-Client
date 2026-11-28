import { memo } from 'react';
import { tip } from './Tooltip';
import { host } from '../client/ipc';
import type { Client } from '../client/useClient';

/** Primary-button drag on an empty chrome area moves the window; double click maximizes. */
export function useWindowDrag(c: Client) {
  return (e: React.MouseEvent<HTMLElement>) => {
    if (e.button !== 0 || !c.hasHost || c.busy.has('window')) return;
    const target = e.target;
    if (target instanceof Element && target.closest('.winbtns,button,a,input,select,textarea,[contenteditable]')) return;
    e.preventDefault();
    void c.run('window', () => host('window_action', { action: e.detail === 2 ? 'maximize' : 'drag' }));
  };
}

export function WindowButtons({
  disabled = false,
  closeLabel = '关闭窗口',
  onMinimize,
  onMaximize,
  onClose,
}: {
  disabled?: boolean;
  closeLabel?: string;
  onMinimize: () => void;
  onMaximize: () => void;
  onClose: () => void;
}) {
  return (
    <div className="winbtns">
      <button type="button" {...tip('最小化')} aria-label="最小化" disabled={disabled} onClick={onMinimize}>
        <svg width="10" height="10">
          <path d="M0 5.5h10" stroke="currentColor" />
        </svg>
      </button>
      <button type="button" {...tip('最大化')} aria-label="最大化" disabled={disabled} onClick={onMaximize}>
        <svg width="10" height="10">
          <rect x=".5" y=".5" width="9" height="9" rx="1" fill="none" stroke="currentColor" />
        </svg>
      </button>
      <button type="button" className="close" {...tip(closeLabel)} aria-label="关闭窗口" disabled={disabled} onClick={onClose}>
        <svg width="10" height="10">
          <path d="M.5.5l9 9M9.5.5l-9 9" stroke="currentColor" />
        </svg>
      </button>
    </div>
  );
}

export const TitleBar = memo(function TitleBar({
  c,
  title,
  meta,
}: {
  c: Client;
  title?: string;
  meta?: string;
}) {
  const action = (act: string) => void c.run('window', () => host('window_action', { action: act }));
  const drag = useWindowDrag(c);

  return (
    <header className="titlebar" onMouseDown={drag}>
      <div className="titlebar-heading">
        {title && <h1 className="page-title">{title}</h1>}
        {meta && <span className="page-meta num">{meta}</span>}
      </div>
      <div className="titlebar-spacer" />
      <WindowButtons
        disabled={!c.hasHost || c.busy.has('window')}
        closeLabel={c.desktop?.preferences?.close_action === 'quit' ? '恢复网络并退出' : '关闭到托盘'}
        onMinimize={() => action('minimize')}
        onMaximize={() => action('maximize')}
        onClose={() => action('close')}
      />
    </header>
  );
});
