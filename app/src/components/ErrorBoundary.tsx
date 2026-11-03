import { Component, type ReactNode } from 'react';
export class ErrorBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  render() {
    return this.state.failed ? <section className="card"><p>界面出现错误</p><button className="btn" onClick={() => location.reload()}>重新加载</button></section> : this.props.children;
  }
}
