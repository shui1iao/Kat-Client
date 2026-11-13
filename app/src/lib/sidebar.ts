import { useEffect, useState } from 'react';
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
export function useSidebar() {
  const [preference, setPreference] = useState<SidebarPreference>(() => readSidebarPreference());
  const [narrow, setNarrow] = useState(() => window.matchMedia(SIDEBAR_QUERY).matches);
  useEffect(() => {
    const media = window.matchMedia(SIDEBAR_QUERY);
    const change = () => setNarrow(media.matches);
    change(); media.addEventListener('change', change);
    return () => media.removeEventListener('change', change);
  }, []);
  const collapsed = sidebarCollapsed(preference, narrow);
  const toggle = () => { const next = collapsed ? 'expanded' : 'collapsed'; setPreference(next); writeSidebarPreference(next); };
  return { collapsed, toggle };
}
