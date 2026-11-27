import { Component, type ErrorInfo, type ReactNode } from 'react';
import { hasHost, host } from '../client/ipc';
import { errorText } from '../lib/errors';
import { WindowButtons } from './TitleBar';

/** Sanitised one-line summary; never echoes URLs, credentials or stacks. */
export function faultSummary(error: unknown): string {
  const text = errorText(error).replace(/\s+/g, ' ').trim();
  return text.length > 160 ? text.slice(0, 159) + '…' : text;
}

function reloadInterface() {
  if (location.hash) history.replaceState(null, '', location.pathname + location.search);
  location.reload();
}

type Props = {
  children: ReactNode;
  /** `page` keeps the window shell (title bar, sidebar) alive; `app` is the last-resort fallback. */
  scope?: 'app' | 'page';
  /** Changing this value (e.g. the current page id) clears a page fault. */
  resetKey?: unknown;
  onHome?: () => void;
};

export class ErrorBoundary extends Component<Props, { error: unknown; failed: boolean }> {
  state = { error: null as unknown, failed: false };
  static getDerivedStateFromError(error: unknown) { return { error, failed: true }; }
  componentDidCatch(_error: unknown, _info: ErrorInfo) { /* rendering fault is shown in place; no raw logging of user data */ }
  componentDidUpdate(prev: Props) {
    if (this.state.failed && prev.resetKey !== this.props.resetKey) this.setState({ error: null, failed: false });
  }
  render() {
    if (!this.state.failed) return this.props.children;
    const detail = faultSummary(this.state.error);
    if (this.props.scope === 'page') {
      return (
        <section className="card page-fault" role="alert">
          <span className="page-fault-mark" aria-hidden="true">!</span>
          <h2>此页面暂时无法显示</h2>
          <p>其它页面、代理与 TUN 不受影响。可以重试此页，或返回概览。</p>
          {detail && <p className="page-fault-detail">{detail}</p>}
          <div className="page-fault-actions">
            <button type="button" className="btn primary" onClick={() => this.setState({ error: null, failed: false })}>
              重试此页
            </button>
            {this.props.onHome && (
              <button type="button" className="btn" onClick={this.props.onHome}>
                返回概览
              </button>
            )}
            <button type="button" className="btn" onClick={reloadInterface}>
              重新加载界面
            </button>
          </div>
        </section>
      );
    }
    return <AppFault detail={detail} />;
  }
}

/** Last-resort window: keeps native drag and caption buttons so the frameless window stays usable. */
function AppFault({ detail }: { detail: string }) {
  const act = (action: string) => { if (hasHost()) void host('window_action', { action }).catch(() => {}); };
  return (
    <div className="app app-fault">
      <header
        className="titlebar"
        onMouseDown={(e) => {
          if (e.button !== 0 || (e.target instanceof Element && e.target.closest('button'))) return;
          e.preventDefault();
          act(e.detail === 2 ? 'maximize' : 'drag');
        }}
      >
        <div className="titlebar-heading">
          <h1 className="page-title">Kat</h1>
        </div>
        <div className="titlebar-spacer" />
        <WindowButtons
          disabled={!hasHost()}
          closeLabel="关闭窗口"
          onMinimize={() => act('minimize')}
          onMaximize={() => act('maximize')}
          onClose={() => act('close')}
        />
      </header>
      <main className="app-fault-body">
        <section className="card page-fault" role="alert">
          <span className="page-fault-mark" aria-hidden="true">!</span>
          <h2>界面出现错误</h2>
          <p>Kat 内核与网络接管仍按原状态运行。重新加载界面通常即可恢复。</p>
          {detail && <p className="page-fault-detail">{detail}</p>}
          <div className="page-fault-actions">
            <button type="button" className="btn primary" onClick={reloadInterface}>
              重新加载界面
            </button>
          </div>
        </section>
      </main>
    </div>
  );
}
