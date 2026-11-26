import { useEffect, useRef, useState } from 'react';
export type SidebarPreference = 'expanded' | 'collapsed' | null;
export const SIDEBAR_KEY = 'kat.sidebar';
export const SIDEBAR_QUERY = '(max-width: 960px)';
type ReadStorage = Pick<Storage, 'getItem'>;
type WriteStorage = Pick<Storage, 'setItem'>;
export function readSidebarPreference(storage?: ReadStorage): SidebarPreference {
  try { const value = (storage ?? window.localStorage).getItem(SIDEBAR_KEY); return value === 'expanded' || value === 'collapsed' ? value : null; } catch { return null; }
}
export function writeSidebarPreference(value: Exclude<SidebarPreference, null>, storage?: WriteStorage): boolean {
  try { (storage ?? window.localStorage).setItem(SIDEBAR_KEY, value); return true; } catch { return false; }
}
export function sidebarCollapsed(preference: SidebarPreference, narrow: boolean): boolean { return preference === null ? narrow : preference === 'collapsed'; }

let animTimer = 0;
function markSidebarAnimating() {
  document.documentElement.dataset.sidebarAnimating = '1';
  window.clearTimeout(animTimer);
  animTimer = window.setTimeout(() => {
    delete document.documentElement.dataset.sidebarAnimating;
    window.dispatchEvent(new Event('kat-sidebar-settled'));
  }, 210);
}

export function useSidebar() {
  const [preference, setPreference] = useState<SidebarPreference>(() => readSidebarPreference());
  const [narrow, setNarrow] = useState(() => window.matchMedia(SIDEBAR_QUERY).matches);
  const prevCollapsed = useRef<boolean | null>(null);
  useEffect(() => {
    const media = window.matchMedia(SIDEBAR_QUERY);
    const change = () => setNarrow(media.matches);
    change(); media.addEventListener('change', change);
    return () => media.removeEventListener('change', change);
  }, []);
  const collapsed = sidebarCollapsed(preference, narrow);
  useEffect(() => {
    if (prevCollapsed.current !== null && prevCollapsed.current !== collapsed) {
      markSidebarAnimating();
    }
    prevCollapsed.current = collapsed;
  }, [collapsed]);
  const toggle = () => {
    markSidebarAnimating();
    const next = collapsed ? 'expanded' : 'collapsed';
    setPreference(next);
    writeSidebarPreference(next);
  };
  return { collapsed, toggle };
}
