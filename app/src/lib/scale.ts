import { useEffect, useState } from 'react';
import { hasHost, host } from '../client/ipc';

export type UiScale = 100 | 110 | 115 | 125;
export const UI_SCALES: UiScale[] = [100, 110, 115, 125];
const KEY = 'kat.ui_scale.v2';
const LEGACY_KEY = 'kat.ui_scale';

export function defaultUiScale(): UiScale {
  return 110;
}

export function storedUiScale(): UiScale {
  try {
    const raw = Number(localStorage.getItem(KEY));
    if (UI_SCALES.includes(raw as UiScale)) return raw as UiScale;
    // Preserve explicit non-100 choices from v0.2.24 (where 100 was auto-written on boot).
    const legacy = Number(localStorage.getItem(LEGACY_KEY));
    if (legacy !== 100 && UI_SCALES.includes(legacy as UiScale)) {
      localStorage.setItem(KEY, String(legacy));
      return legacy as UiScale;
    }
  } catch {
    /* ignore storage restrictions */
  }
  return defaultUiScale();
}

export function applyUiScale(scale: UiScale) {
  document.documentElement.dataset.uiScale = String(scale);
  if (hasHost()) {
    document.documentElement.style.removeProperty('--browser-zoom');
    void host('window_action', { action: `zoom-${scale}` }).catch(() => {});
  } else {
    const z = scale === 100 ? '' : String(scale / 100);
    document.documentElement.style.zoom = z;
    if (z) document.documentElement.style.setProperty('--browser-zoom', z);
    else document.documentElement.style.removeProperty('--browser-zoom');
  }
}

export function useUiScale(): [UiScale, (next: UiScale) => void] {
  const [scale, setScaleState] = useState<UiScale>(storedUiScale);
  const setScale = (next: UiScale | ((cur: UiScale) => UiScale)) => {
    setScaleState((cur) => {
      const resolved = typeof next === 'function' ? next(cur) : next;
      try {
        localStorage.setItem(KEY, String(resolved));
      } catch {
        /* ignore storage restrictions */
      }
      return resolved;
    });
  };

  useEffect(() => {
    applyUiScale(scale);
    const onStorage = (e: StorageEvent) => {
      if (e.key === KEY && e.newValue) {
        const parsed = Number(e.newValue);
        if (UI_SCALES.includes(parsed as UiScale)) setScaleState(parsed as UiScale);
      }
    };
    const onCustom = (e: Event) => {
      const detail = (e as CustomEvent<UiScale>).detail;
      if (UI_SCALES.includes(detail)) setScaleState(detail);
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
        setScale(defaultUiScale());
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
