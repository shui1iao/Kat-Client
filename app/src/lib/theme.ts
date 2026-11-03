import { useEffect, useState } from 'react';
import { syncNativeBackdrop } from './nativeBackdrop';
export type Theme = 'system' | 'light' | 'dark';
const KEY = 'kat.theme';
const media = window.matchMedia('(prefers-color-scheme: dark)');
function stored(): Theme {
  try { const v = localStorage.getItem(KEY); return v === 'light' || v === 'dark' ? v : 'system'; } catch { return 'system'; }
}
function apply(theme: Theme) {
  const actual = theme === 'system' ? (media.matches ? 'dark' : 'light') : theme;
  document.documentElement.dataset.theme = actual;
  document.documentElement.dataset.themePreference = theme;
  syncNativeBackdrop(actual);
}
apply(stored());
export function useTheme(): [Theme, (v: Theme) => void] {
  const [theme, setTheme] = useState<Theme>(stored);
  useEffect(() => {
    apply(theme);
    try { localStorage.setItem(KEY, theme); } catch { }
    const change = () => apply(theme);
    media.addEventListener('change', change);
    return () => media.removeEventListener('change', change);
  }, [theme]);
  return [theme, setTheme];
}
