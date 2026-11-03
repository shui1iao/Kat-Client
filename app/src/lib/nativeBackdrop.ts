import { listen } from '@tauri-apps/api/event';
import { hasHost, host } from '../client/ipc';

type ActualTheme = 'light' | 'dark';
type Snapshot = { enabled: boolean; focused: boolean; theme: ActualTheme };
const root = document.documentElement;
const contrast = window.matchMedia('(forced-colors: active)');
let desired: ActualTheme | undefined;
let requested: ActualTheme | undefined;
let listening: Promise<boolean> | undefined;
let running = false;

function opaque() {
  delete root.dataset.nativeAcrylic;
  delete root.dataset.nativeAcrylicFocus;
}
function accept(value: Snapshot) {
  // A successful IPC enqueue is NOT proof of a successful material operation.
  // Only the main-window host's verified state may open this gate.
  if (value?.enabled !== true || typeof value.focused !== 'boolean' ||
      value.theme !== desired || contrast.matches) { opaque(); return; }
  root.dataset.nativeAcrylic = 'enabled';
  root.dataset.nativeAcrylicFocus = value.focused ? 'focused' : 'inactive';
}
async function pump() {
  if (running || !hasHost()) return;
  running = true;
  try {
    listening ??= listen<Snapshot>('native-backdrop', e => accept(e.payload)).then(() => true, () => false);
    if (!await listening) { opaque(); return; }
    // Serialize/coalesce theme changes: an older native reply cannot expose the
    // wrong theme, nor win the final native state after a rapid theme change.
    while (desired && desired !== requested) {
      const theme = desired;
      requested = theme;
      try { await host('window_action', { action: theme === 'dark' ? 'backdrop-dark' : 'backdrop-light' }); }
      catch { opaque(); }
    }
  } finally { running = false; }
}
export function syncNativeBackdrop(theme: ActualTheme) {
  if (theme !== desired) { desired = theme; opaque(); }
  void pump();
}
contrast.addEventListener('change', () => {
  opaque();
  requested = undefined;
  void pump();
});
