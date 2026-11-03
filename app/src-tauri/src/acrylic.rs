//! Main-window Desktop Acrylic. The documented, verifiable DWM path is used;
//! older Windows (including the unverified Win10 accent-policy path) stay solid.
//! Tauri 2.12.5 discards window-vibrancy's native result, so set_effects() alone
//! must never be treated as evidence that Acrylic was enabled.

fn allowed(transparency: Option<u32>, high_contrast: Option<bool>, composition: Option<bool>, supported: bool) -> bool {
    transparency == Some(1) && high_contrast == Some(false) && composition == Some(true) && supported
}

#[cfg(all(windows, feature = "desktop"))]
mod native {
    use super::allowed;
    use std::{ffi::c_void, mem::size_of, sync::Mutex, time::Duration};
    use tauri::{Emitter, Manager, WebviewWindow, window::{Color, Effect}, utils::config::WindowEffectsConfig};
    use windows_sys::Win32::{Foundation::HWND, System::Registry::{RegGetValueW, HKEY_CURRENT_USER, RRF_RT_REG_DWORD}, UI::WindowsAndMessaging::{SystemParametersInfoW, SPI_GETHIGHCONTRAST}};

    // SDK dwmapi.h ABI; these system DLL entry points exist since Vista. Using
    // the existing Win32 dependency without adding features or a new runtime.
    #[link(name = "dwmapi")]
    extern "system" {
        fn DwmIsCompositionEnabled(enabled: *mut i32) -> i32;
        fn DwmSetWindowAttribute(hwnd: HWND, attribute: u32, value: *const c_void, size: u32) -> i32;
        fn DwmGetWindowAttribute(hwnd: HWND, attribute: u32, value: *mut c_void, size: u32) -> i32;
    }
    const DWMWA_USE_IMMERSIVE_DARK_MODE: u32 = 20;
    const DWMWA_SYSTEMBACKDROP_TYPE: u32 = 38;
    // Microsoft: DWMSBT_TRANSIENTWINDOW = Desktop/Background Acrylic on Win11.
    const DWMSBT_TRANSIENTWINDOW: i32 = 3;
    const DWMSBT_NONE: i32 = 1;

    #[repr(C)]
    struct HighContrast { size: u32, flags: u32, scheme: *mut u16 }

    #[derive(Clone, Copy, PartialEq, Eq, serde::Serialize)]
    struct Snapshot { enabled: bool, focused: bool, theme: &'static str, reason: &'static str }
    #[derive(Default)]
    struct State { dark: bool, ready: bool, applied_dark: Option<bool>, last: Option<Snapshot> }
    #[derive(Default)]
    struct Controller(Mutex<State>);

    fn transparency() -> Option<u32> {
        let key: Vec<u16> = "Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize\0".encode_utf16().collect();
        let name: Vec<u16> = "EnableTransparency\0".encode_utf16().collect();
        let mut value = 0u32;
        let mut size = size_of::<u32>() as u32;
        // Read only, normal-user hive. Missing/denied/unknown is deliberately solid.
        let status = unsafe { RegGetValueW(HKEY_CURRENT_USER, key.as_ptr(), name.as_ptr(), RRF_RT_REG_DWORD, std::ptr::null_mut(), (&mut value as *mut u32).cast(), &mut size) };
        (status == 0 && size == size_of::<u32>() as u32).then_some(value)
    }
    fn high_contrast() -> Option<bool> {
        let mut value = HighContrast { size: size_of::<HighContrast>() as u32, flags: 0, scheme: std::ptr::null_mut() };
        let ok = unsafe { SystemParametersInfoW(SPI_GETHIGHCONTRAST, value.size, (&mut value as *mut HighContrast).cast(), 0) };
        (ok != 0).then_some(value.flags & 1 != 0) // HCF_HIGHCONTRASTON
    }
    fn composition() -> Option<bool> {
        let mut value = 0;
        (unsafe { DwmIsCompositionEnabled(&mut value) } >= 0).then_some(value != 0)
    }
    fn backdrop(hwnd: HWND) -> Option<i32> {
        let mut value = 0i32;
        (unsafe { DwmGetWindowAttribute(hwnd, DWMWA_SYSTEMBACKDROP_TYPE, (&mut value as *mut i32).cast(), size_of::<i32>() as u32) } >= 0).then_some(value)
    }
    fn set_attribute(hwnd: HWND, attribute: u32, value: i32) -> bool {
        unsafe { DwmSetWindowAttribute(hwnd, attribute, (&value as *const i32).cast(), size_of::<i32>() as u32) >= 0 }
    }
    fn opaque(dark: bool) -> Color { if dark { Color(22,31,48,255) } else { Color(245,246,248,255) } }

    fn refresh(window: &WebviewWindow, force: bool) {
        let controller = window.state::<Controller>();
        let mut state = controller.0.lock().unwrap();
        let theme = if state.dark { "dark" } else { "light" };
        let hwnd = window.hwnd().ok().map(|h| h.0);
        let current = hwnd.and_then(backdrop);
        let mut reason = "pending-theme";
        let mut enabled = false;
        let mut attempted = false;
        if state.ready {
            reason = if current.is_none() { "unsupported" } else { "system-opaque" };
            if allowed(transparency(), high_contrast(), composition(), current.is_some()) {
                if state.applied_dark == Some(state.dark) && current == Some(DWMSBT_TRANSIENTWINDOW) {
                    enabled = true;
                } else if let Some(hwnd) = hwnd {
                    attempted = true;
                    // Tauri is the effect selector. Explicit HRESULT + readback
                    // below close its swallowed-native-error gap on Win11 22H2+.
                    enabled = window.set_effects(WindowEffectsConfig { effects: vec![Effect::Acrylic], ..Default::default() }).is_ok()
                        && set_attribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, i32::from(state.dark))
                        && set_attribute(hwnd, DWMWA_SYSTEMBACKDROP_TYPE, DWMSBT_TRANSIENTWINDOW)
                        && backdrop(hwnd) == Some(DWMSBT_TRANSIENTWINDOW)
                        && window.set_background_color(Some(Color(0,0,0,0))).is_ok();
                }
                reason = if enabled { "enabled" } else { "native-failed" };
            }
        }
        if enabled {
            state.applied_dark = Some(state.dark);
        } else {
            // An opaque WebView is also the native safety net: no transparent
            // holes even while the DOM receives the disabled event.
            if attempted || state.last.is_none_or(|s| s.enabled || s.theme != theme) {
                let _ = window.set_background_color(Some(opaque(state.dark)));
            }
            if attempted || state.applied_dark.is_some() {
                let _ = window.set_effects(None::<WindowEffectsConfig>);
                if let Some(hwnd) = hwnd { let _ = set_attribute(hwnd, DWMWA_SYSTEMBACKDROP_TYPE, DWMSBT_NONE); }
            }
            state.applied_dark = None;
        }
        let snapshot = Snapshot { enabled, focused: window.is_focused().unwrap_or(false), theme, reason };
        if force || state.last != Some(snapshot) {
            // Only fixed, typed state goes to the existing local main WebView;
            // no eval, user scripts, paths, window labels, or additional IPC ACL.
            let _ = window.emit_to("main", "native-backdrop", snapshot);
            state.last = Some(snapshot);
        }
    }

    pub fn request(window: &WebviewWindow, dark: bool) -> tauri::Result<()> {
        let w = window.clone();
        window.run_on_main_thread(move || {
            { let c = w.state::<Controller>(); let mut s = c.0.lock().unwrap(); s.dark = dark; s.ready = true; }
            refresh(&w, true);
        })
    }
    pub fn install(window: &WebviewWindow) {
        let app = window.app_handle();
        app.manage(Controller::default());
        // Stay opaque until the page has registered its listener and supplied
        // its *actual* theme (kat.theme itself remains frontend-owned).
        let _ = window.set_background_color(Some(opaque(true)));
        window.on_window_event({ let a = app.clone(); move |event| {
            if matches!(event, tauri::WindowEvent::Focused(_) | tauri::WindowEvent::ThemeChanged(_)) {
                if let Some(w) = a.get_webview_window("main") { refresh(&w, false); }
            }
        }});
        // Tauri doesn't expose WM_SETTINGCHANGE/high-contrast notifications.
        // Read-only native refresh handles transparency/contrast toggled while
        // focused too (<=1s); it never changes OS settings or the window's theme.
        let a = app.clone();
        tauri::async_runtime::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                if a.get_webview_window("main").is_none() { break; }
                let a2 = a.clone();
                if a.run_on_main_thread(move || { if let Some(w) = a2.get_webview_window("main") { refresh(&w, false); } }).is_err() { break; }
            }
        });
    }
}
#[cfg(all(windows, feature = "desktop"))]
pub use native::{install, request};

#[cfg(test)]
mod tests {
    use super::allowed;
    #[test]
    fn acrylic_needs_every_positive_system_gate() {
        assert!(allowed(Some(1), Some(false), Some(true), true));
        for transparency in [None, Some(0), Some(2)] { assert!(!allowed(transparency, Some(false), Some(true), true)); }
        for contrast in [None, Some(true)] { assert!(!allowed(Some(1), contrast, Some(true), true)); }
        for composition in [None, Some(false)] { assert!(!allowed(Some(1), Some(false), composition, true)); }
        assert!(!allowed(Some(1), Some(false), Some(true), false));
    }
}
