import { createRoot } from 'react-dom/client';
import { ErrorBoundary } from './components/ErrorBoundary';
import './styles.css';
import './pages.css';
import './theme.css';
import './finish.css';
import './r9.css';
import './r11.css';
import './ui.css';
import './k3.css';
import './acrylic.css';
import './hig.css';
import './dashboard.css';

// Local brand icon: no browser fallback request or external resource.
const icon=document.createElement('link');
icon.rel='icon';
icon.href='data:image/svg+xml,'+encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="8" fill="#4FD1A5"/><text x="16" y="23" text-anchor="middle" font-family="sans-serif" font-weight="bold" font-size="23" fill="#062118">K</text></svg>');
document.head.appendChild(icon);
const root=createRoot(document.getElementById('root')!);
// Restricted tray-menu entry (frozen native contract: index.html?view=tray-menu).
// This branch never mounts App/useClient or any main-window initialization
// (theme/backdrop, tray listener, polling); TrayMenu uses only
// tray_menu_state / tray_menu_select.
if(new URLSearchParams(location.search).get('view')==='tray-menu'){
  document.documentElement.dataset.view='tray-menu';
  void import('./components/TrayMenu').then(({TrayMenuWindow})=>root.render(<TrayMenuWindow/>));
}else{
  void import('./App').then(({default:App})=>root.render(<ErrorBoundary><App /></ErrorBoundary>));
}
