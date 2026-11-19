import { useEffect, useState } from 'react';
import { hasHost, host } from '../client/ipc';

export type UiScale = 100 | 110 | 115 | 125;
export const UI_SCALES: UiScale[] = [100, 110, 115, 125];
const KEY = 'kat.ui_scale';

export function defaultUiScale(): UiScale {
  return 100;
}

export function storedUiScale(): UiScale {
  try {
    const raw = Number(localStorage.getItem(KEY));
    if (UI_SCALES.includes(raw as UiScale)) return raw as UiScale;
  } catch {
    /* ignore storage restrictions */
  }
  return defaultUiScale();
}

export function applyUiScale(scale: UiScale) {
  document.documentElement.dataset.uiScale = String(scale);
  if (hasHost()) {
    void host('window_action', { action: `zoom-${scale}` }).catch(() => {});
  } else {
    document.documentElement.style.zoom = scale === 100 ? '' : String(scale / 100);
  }
}

export function useUiScale(): [UiScale, (next: UiScale) => void] {
  const [scale, setScale] = useState<UiScale>(storedUiScale);

  useEffect(() => {
    applyUiScale(scale);
    try {
      localStorage.setItem(KEY, String(scale));
    } catch {
      /* ignore storage restrictions */
    }
    const onStorage = (e: StorageEvent) => {
      if (e.key === KEY && e.newValue) {
        const parsed = Number(e.newValue);
        if (UI_SCALES.includes(parsed as UiScale)) setScale(parsed as UiScale);
      }
    };
    const onCustom = (e: Event) => {
      const detail = (e as CustomEvent<UiScale>).detail;
      if (UI_SCALES.includes(detail)) setScale(detail);
    };
    const onKeyDown = (e: KeyboardEvent) => {
      if (!(e.ctrlKey || e.metaKey) || e.altKey) return;
      if (e.key === '=' || e.key === '+') {
        e.preventDefault();
        setScale((cur) => UI_SCALES[Math.min(UI_SCALES.length - 1, UI_SCALES.indexOf(cur) + 1)]);
      } else if (e.key === '-' || e.key === '_') {
        e.preventDefault();
        setScale((cur) => UI_SCALES[Math.max(0, UI_SCALES.indexOf(cur) - 1)]);
      } else if (e.key === '0') {
        e.preventDefault();
        setScale(100);
      }
    };
    window.addEventListener('storage', onStorage);
    window.addEventListener('kat-ui-scale', onCustom);
    window.addEventListener('keydown', onKeyDown);
    return () => {
      window.removeEventListener('storage', onStorage);
      window.removeEventListener('kat-ui-scale', onCustom);
      window.removeEventListener('keydown', onKeyDown);
    };
  }, [scale]);

  return [scale, setScale];
}
