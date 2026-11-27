import { createRoot } from 'react-dom/client';
import { ErrorBoundary } from './components/ErrorBoundary';
import './design/tokens.css';
import './design/shell.css';
import './design/components.css';
import './design/pages.css';

const root = createRoot(document.getElementById('root')!);
// Restricted tray-menu entry (frozen native contract: index.html?view=tray-menu).
// This branch never mounts App/useClient or any main-window initialization
// (theme/backdrop, tray listener, polling); TrayMenu uses only
// tray_menu_state / tray_menu_select.
if (new URLSearchParams(location.search).get('view') === 'tray-menu') {
  document.documentElement.dataset.view = 'tray-menu';
  void import('./components/TrayMenu').then(({ TrayMenuWindow }) => root.render(<TrayMenuWindow />));
} else {
  void import('./App').then(({ default: App }) => root.render(<ErrorBoundary><App /></ErrorBoundary>));
}
