//! Fixed local popup lifecycle and cross-DPI geometry state machine: no document/core/filesystem authority.
use crate::error::{Error, Result};
use std::time::{Duration, Instant};

pub const LABEL: &str = "tray-menu";
pub const SHADOW_PAD_LOGICAL: f64 = 12.0;
pub const ANCHOR_GAP_LOGICAL: f64 = 4.0;
pub const BLUR_UNFOCUSED_GRACE: Duration = Duration::from_millis(200);

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PopupPhase {
    Preparing,
    Visible,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PopupPoint {
    pub x: f64,
    pub y: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PopupSize {
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PopupWorkRect {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PopupOrigin {
    pub x: i32,
    pub y: i32,
}

// A session owns only geometry. No WebView-supplied position or business action.
#[derive(Debug, Clone)]
pub struct Popup {
    pub epoch: u64,
    pub layout: u64,
    pub phase: PopupPhase,
    pub focus_seen: bool,
    pub shown_at: Option<Instant>,
    pub point: PopupPoint,
    pub work: PopupWorkRect,
    pub scale: f64,
    pub client: PopupSize,
    pub limit: PopupSize,
    pub last: Option<(u32, u32, i32, i32)>,
    pub adjustments: u8,
}

#[derive(Debug, PartialEq, Eq, serde::Serialize)]
pub struct PopupReply {
    pub epoch: String,
    pub layout: String,
    pub phase: PopupPhase,
    pub client_width: u32,
    pub client_height: u32,
    pub max_width: u32,
    pub max_height: u32,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Geometry {
    pub epoch: String,
    pub layout: String,
    pub viewport_width: f64,
    pub viewport_height: f64,
    pub width: f64,
    pub height: f64,
    pub dpr: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeasureDecision {
    Ignore,
    RePrepare,
    Apply {
        size: PopupSize,
        pos: PopupOrigin,
        resize: bool,
        opening: bool,
    },
}

pub fn limit_for_work(work: PopupWorkRect, scale: f64) -> PopupSize {
    PopupSize {
        width: ((360.0 * scale).round() as u32).max(1).min(work.width.max(1)),
        height: ((560.0 * scale).round() as u32).max(1).min(work.height.max(1)),
    }
}

impl Popup {
    pub fn new(
        epoch: u64,
        phase: PopupPhase,
        point: PopupPoint,
        work: PopupWorkRect,
        scale: f64,
        client: PopupSize,
        now: Instant,
    ) -> Self {
        let shown_at = (phase == PopupPhase::Visible).then_some(now);
        Self {
            epoch,
            layout: 1,
            phase,
            focus_seen: false,
            shown_at,
            point,
            work,
            scale,
            client,
            limit: limit_for_work(work, scale),
            last: None,
            adjustments: 0,
        }
    }

    pub fn reply(&self) -> PopupReply {
        PopupReply {
            epoch: self.epoch.to_string(),
            layout: self.layout.to_string(),
            phase: self.phase,
            client_width: self.client.width,
            client_height: self.client.height,
            max_width: self.limit.width,
            max_height: self.limit.height,
        }
    }

    /// Allow blur dismissal either once focus was explicitly observed OR 200ms after
    /// showing (handles Windows foreground-stealing prevention where Focused(true) never fires).
    pub fn should_dismiss_on_blur(&self, now: Instant) -> bool {
        self.phase == PopupPhase::Visible
            && (self.focus_seen
                || self
                    .shown_at
                    .is_some_and(|t| now.saturating_duration_since(t) >= BLUR_UNFOCUSED_GRACE))
    }

    /// Pure cross-DPI state machine step for incoming `Geometry` reports.
    /// When `native_scale != self.scale` or `actual != self.client` (and `adjustments < 8`),
    /// updates `scale`, `limit`, `client`, `layout` and returns `MeasureDecision::RePrepare`
    /// so the caller re-dispatches `kat-tray-prepare` instead of silently stalling.
    pub fn evaluate_measurement(
        &mut self,
        actual: PopupSize,
        native_scale: f64,
        g: &Geometry,
    ) -> Result<MeasureDecision> {
        self.evaluate_measurement_in_work(actual, native_scale, None, g)
    }

    pub fn evaluate_measurement_in_work(
        &mut self,
        actual: PopupSize,
        native_scale: f64,
        target_work: Option<PopupWorkRect>,
        g: &Geometry,
    ) -> Result<MeasureDecision> {
        if g.epoch != self.epoch.to_string() || g.layout != self.layout.to_string() {
            return Ok(MeasureDecision::Ignore);
        }
        let valid_work = target_work.filter(|w| w.width > 0 && w.height > 0);
        let scale_changed = (native_scale - self.scale).abs() > 0.001;
        let client_changed = actual != self.client;
        let work_changed = valid_work.is_some_and(|w| w != self.work);
        if scale_changed || client_changed || work_changed {
            if !native_scale.is_finite() || native_scale <= 0.0 || self.adjustments >= 8 {
                return Err(failed());
            }
            if let Some(w) = valid_work {
                self.work = w;
            }
            self.scale = native_scale;
            self.limit = limit_for_work(self.work, native_scale);
            self.client = actual;
            self.layout += 1;
            self.adjustments = self.adjustments.saturating_add(1);
            return Ok(MeasureDecision::RePrepare);
        }
        let values = [g.viewport_width, g.viewport_height, g.width, g.height, g.dpr];
        if values.iter().any(|v| !v.is_finite() || *v <= 0.0)
            || g.viewport_width > 65536.0
            || g.viewport_height > 65536.0
            || g.width > 16384.0
            || g.height > 16384.0
            || !(0.125..=16.0).contains(&g.dpr)
        {
            return Err(Error::new("INVALID_PARAMS", "托盘菜单几何参数无效"));
        }
        let sx = f64::from(actual.width) / g.viewport_width;
        let sy = f64::from(actual.height) / g.viewport_height;
        let tolerance = 2.0 * g.dpr + 2.0;
        if (f64::from(actual.width) - g.viewport_width * g.dpr).abs() > tolerance
            || (f64::from(actual.height) - g.viewport_height * g.dpr).abs() > tolerance
            || (sx - sy).abs() > (4.0 / g.viewport_width.min(g.viewport_height)).max(g.dpr * 0.02)
        {
            return Ok(MeasureDecision::Ignore);
        }
        let mut size = PopupSize {
            width: (g.width * g.dpr)
                .ceil()
                .max(1.0)
                .min(f64::from(self.limit.width)) as u32,
            height: (g.height * g.dpr)
                .ceil()
                .max(1.0)
                .min(f64::from(self.limit.height)) as u32,
        };
        if actual.width.abs_diff(size.width) <= 1 && actual.width <= self.limit.width {
            size.width = actual.width;
        }
        if actual.height.abs_diff(size.height) <= 1 && actual.height <= self.limit.height {
            size.height = actual.height;
        }
        let pos = position(self, size);
        let target = (size.width, size.height, pos.x, pos.y);
        let opening = self.phase == PopupPhase::Preparing;
        let resize = actual != size;
        if !opening && !resize && self.last == Some(target) {
            return Ok(MeasureDecision::Ignore);
        }
        if self.adjustments >= 8 {
            return Err(failed());
        }
        Ok(MeasureDecision::Apply {
            size,
            pos,
            resize,
            opening,
        })
    }

    pub fn commit_applied(
        &mut self,
        size: PopupSize,
        pos: PopupOrigin,
        resize: bool,
        opening: bool,
        now: Instant,
    ) {
        self.last = Some((size.width, size.height, pos.x, pos.y));
        self.client = size;
        if resize {
            self.layout += 1;
            self.adjustments = self.adjustments.saturating_add(1);
        } else {
            self.adjustments = 0;
        }
        if opening {
            self.phase = PopupPhase::Visible;
            self.shown_at = Some(now);
            self.adjustments = 0;
        }
    }

    pub fn reanchor_origin(&self) -> Option<PopupOrigin> {
        (self.phase == PopupPhase::Preparing).then(|| anchor_within_work(self, self.client))
    }

    pub fn sync_reanchored(
        &mut self,
        actual: PopupSize,
        native_scale: f64,
        target_work: Option<PopupWorkRect>,
    ) {
        if let Some(w) = target_work.filter(|w| w.width > 0 && w.height > 0) {
            self.work = w;
        }
        if native_scale.is_finite() && native_scale > 0.0 {
            self.scale = native_scale;
            self.limit = limit_for_work(self.work, native_scale);
        }
        self.client = actual;
    }
}

fn failed() -> Error {
    Error::new("WINDOW_FAILED", "无法准备托盘菜单位置，请在主窗口操作")
}

/// Compute native window origin so the VISIBLE `.tray-menu` card (inset by
/// `SHADOW_PAD_LOGICAL` inside `.tray-menu-window`) anchors at the right-click
/// cursor point with symmetric `ANCHOR_GAP_LOGICAL` spacing for bottom, top,
/// left-docked, and right-docked taskbars, clamped inside monitor work area.
pub fn position(p: &Popup, size: PopupSize) -> PopupOrigin {
    let left = i64::from(p.work.x);
    let top = i64::from(p.work.y);
    let right = left + i64::from(p.work.width);
    let bottom = top + i64::from(p.work.height);
    let pad = (SHADOW_PAD_LOGICAL * p.scale).round() as i64;
    let gap = (ANCHOR_GAP_LOGICAL * p.scale).round() as i64;
    let w = i64::from(size.width);
    let h = i64::from(size.height);
    let vis_w = (w - 2 * pad).max(1);
    let vis_h = (h - 2 * pad).max(1);
    let cx = p.point.x.round() as i64;
    let cy = p.point.y.round() as i64;

    // Horizontal: symmetric `gap` for left-docked (`cx <= left`), right-docked (`cx >= right`),
    // and right/left flip near work-area edges.
    let (min_x, max_x) = if cx <= left && left + gap + vis_w <= right {
        (left + gap, (right - vis_w).max(left + gap))
    } else if cx >= right && right - gap - vis_w >= left {
        (left, right - gap - vis_w)
    } else {
        (left, (right - vis_w).max(left))
    };
    let vis_x = if cx <= left {
        cx + gap
    } else if cx >= right {
        cx - gap - vis_w
    } else if cx + gap + vis_w <= right {
        cx + gap
    } else if cx - gap - vis_w >= left {
        cx - gap - vis_w
    } else {
        cx
    };
    let clamped_vis_x = vis_x.clamp(min_x, max_x);

    // Vertical: prefer upward above cursor when cursor is in lower half or downward doesn't fit.
    let (min_y, max_y) = if cy <= top && top + gap + vis_h <= bottom {
        (top + gap, (bottom - vis_h).max(top + gap))
    } else if cy >= bottom && bottom - gap - vis_h >= top {
        (top, bottom - gap - vis_h)
    } else {
        (top, (bottom - vis_h).max(top))
    };
    let prefer_up =
        (cy - vis_h - gap >= top) && (cy + vis_h + gap > bottom || cy - top >= bottom - cy);
    let vis_y = if prefer_up {
        cy - gap - vis_h
    } else if cy + gap + vis_h <= bottom {
        cy + gap
    } else if cy - gap - vis_h >= top {
        cy - gap - vis_h
    } else {
        cy - vis_h
    };
    let clamped_vis_y = vis_y.clamp(min_y, max_y);

    PopupOrigin {
        x: (clamped_vis_x - pad) as i32,
        y: (clamped_vis_y - pad) as i32,
    }
}

/// Anchor a hidden `Preparing` window near `p.point` while strictly clamping its entire
/// outer frame inside `p.work` so shadow padding cannot straddle a dual-DPI monitor seam.
pub fn anchor_within_work(p: &Popup, size: PopupSize) -> PopupOrigin {
    let raw = position(p, size);
    let left = i64::from(p.work.x);
    let top = i64::from(p.work.y);
    let max_x = (left + i64::from(p.work.width) - i64::from(size.width)).max(left);
    let max_y = (top + i64::from(p.work.height) - i64::from(size.height)).max(top);
    PopupOrigin {
        x: i64::from(raw.x).clamp(left, max_x) as i32,
        y: i64::from(raw.y).clamp(top, max_y) as i32,
    }
}

#[cfg(all(windows, feature = "desktop"))]
mod desktop_imp {
    use super::*;
    use tauri::{Manager, WebviewWindow};

    const ESCAPE: &str = r#"(() => {
 if (window.top !== window) return;
 window.addEventListener('keydown', event => {
  if (event.key !== 'Escape' || event.isComposing) return;
  event.preventDefault(); event.stopImmediatePropagation();
  window.__TAURI_INTERNALS__.invoke('tray_menu_select', {revision:'', id:'__dismiss'}).catch(() => {});
 }, true);
})();"#;
    const PREPARE: &str = "window.dispatchEvent(new Event('kat-tray-prepare'))";

    pub fn local_page(url: &tauri::Url) -> bool {
        ((url.scheme() == "tauri" && url.host_str() == Some("localhost"))
            || (url.scheme() == "http" && url.host_str() == Some("tauri.localhost")))
            && url.port().is_none()
            && url.username().is_empty()
            && url.password().is_none()
            && url.path() == "/index.html"
            && url.query() == Some("view=tray-menu")
            && url.fragment().is_none()
    }

    pub fn caller(window: &WebviewWindow) -> Result<()> {
        if window.label() != LABEL || !window.url().ok().as_ref().is_some_and(local_page) {
            return Err(Error::new(
                "CALLER_DENIED",
                "仅本地固定托盘菜单窗口可调用此命令",
            ));
        }
        Ok(())
    }

    pub fn ensure(app: &tauri::AppHandle) -> Result<WebviewWindow> {
        static CREATE: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _create = CREATE.lock().unwrap();
        if let Some(window) = app.get_webview_window(LABEL) {
            return Ok(window);
        }
        let window = tauri::WebviewWindowBuilder::new(
            app,
            LABEL,
            tauri::WebviewUrl::App("index.html?view=tray-menu".into()),
        )
        .title("Kat 托盘菜单")
        .transparent(true)
        .decorations(false)
        .shadow(false)
        .resizable(false)
        .maximizable(false)
        .minimizable(false)
        .fullscreen(false)
        .skip_taskbar(true)
        .always_on_top(true)
        .visible(false)
        .focused(false)
        .inner_size(296.0, 440.0)
        .drag_and_drop(false)
        .devtools(false)
        .browser_extensions_enabled(false)
        .on_navigation(local_page)
        .on_new_window(|_, _| tauri::webview::NewWindowResponse::Deny)
        .on_download(|_, _| false)
        .initialization_script(ESCAPE)
        .build()
        .map_err(|_| Error::new("TRAY_CREATE_FAILED", "无法创建托盘菜单窗口，请在主窗口操作"))?;
        window.on_window_event({
            let w = window.clone();
            move |event| match event {
                tauri::WindowEvent::Focused(true) => {
                    let state = w.state::<crate::desktop::Host>();
                    let mut current = state.tray_state.lock().unwrap();
                    if let Some(p) = current.popup.as_mut() {
                        p.focus_seen = true;
                    }
                }
                tauri::WindowEvent::Focused(false) => {
                    let cancel = {
                        let state = w.state::<crate::desktop::Host>();
                        let current = state.tray_state.lock().unwrap();
                        current
                            .popup
                            .as_ref()
                            .is_some_and(|p| p.should_dismiss_on_blur(Instant::now()))
                    };
                    if cancel {
                        let _ = hide(w.app_handle());
                    }
                }
                tauri::WindowEvent::CloseRequested { api, .. } => {
                    api.prevent_close();
                    let _ = hide(w.app_handle());
                }
                _ => {}
            }
        });
        Ok(window)
    }

    pub fn prewarm(app: tauri::AppHandle) {
        tauri::async_runtime::spawn_blocking(move || {
            std::thread::sleep(Duration::from_millis(250));
            let _ = ensure(&app);
        });
    }

    pub fn prepare(
        app: &tauri::AppHandle,
        window: &WebviewWindow,
        rect: tauri::Rect,
        point: tauri::PhysicalPosition<f64>,
        epoch: u64,
    ) -> Result<()> {
        let state = app.state::<crate::desktop::Host>();
        if state.tray_state.lock().unwrap().popup_epoch != epoch {
            return Ok(());
        }
        let fallback_point = match (rect.position, rect.size) {
            (tauri::Position::Physical(p), tauri::Size::Physical(s))
                if s.width > 0 && s.height > 0 && s.width <= 1024 && s.height <= 1024 =>
            {
                Some(tauri::PhysicalPosition::new(
                    f64::from(p.x) + f64::from(s.width) * 0.5,
                    f64::from(p.y) + f64::from(s.height) * 0.5,
                ))
            }
            _ => None,
        };
        let cursor = if point.x.is_finite()
            && point.y.is_finite()
            && (point.x != 0.0 || point.y != 0.0)
        {
            point
        } else {
            fallback_point.ok_or_else(failed)?
        };
        let monitor = if let Some(main) = app.get_webview_window("main") {
            main.monitor_from_point(cursor.x, cursor.y)
                .map_err(|_| failed())?
                .or_else(|| main.primary_monitor().ok().flatten())
                .or_else(|| window.primary_monitor().ok().flatten())
        } else {
            window
                .monitor_from_point(cursor.x, cursor.y)
                .map_err(|_| failed())?
                .or_else(|| window.primary_monitor().ok().flatten())
        }
        .ok_or_else(failed)?;
        let scale = monitor.scale_factor();
        let raw_work = monitor.work_area();
        if !scale.is_finite()
            || scale <= 0.0
            || raw_work.size.width == 0
            || raw_work.size.height == 0
        {
            return Err(failed());
        }
        let work = PopupWorkRect {
            x: raw_work.position.x,
            y: raw_work.position.y,
            width: raw_work.size.width,
            height: raw_work.size.height,
        };
        let limit = limit_for_work(work, scale);
        let cursor_pt = PopupPoint {
            x: cursor.x,
            y: cursor.y,
        };

        let cached = {
            let current = state.tray_state.lock().unwrap();
            current
                .cached_size
                .filter(|(rev, sc, w, h)| {
                    *rev == current.revision()
                        && (sc - scale).abs() < 0.001
                        && *w > 0
                        && *h > 0
                        && *w <= limit.width
                        && *h <= limit.height
                })
                .map(|(_, _, w, h)| PopupSize {
                    width: w,
                    height: h,
                })
        };

        if let Some(size) = cached {
            let mut popup = Popup::new(
                epoch,
                PopupPhase::Visible,
                cursor_pt,
                work,
                scale,
                size,
                Instant::now(),
            );
            let pos = position(&popup, size);
            popup.last = Some((size.width, size.height, pos.x, pos.y));
            let tauri_size = tauri::PhysicalSize::new(size.width, size.height);
            let tauri_pos = tauri::PhysicalPosition::new(pos.x, pos.y);
            let current_size = window
                .inner_size()
                .unwrap_or(tauri::PhysicalSize::new(0, 0));
            if current_size != tauri_size {
                window.set_size(tauri_size).map_err(|_| failed())?;
            }
            window.set_position(tauri_pos).map_err(|_| failed())?;
            let actual = window.inner_size().unwrap_or(tauri_size);
            popup.client = PopupSize {
                width: actual.width,
                height: actual.height,
            };
            {
                let mut current = state.tray_state.lock().unwrap();
                if current.popup_epoch != epoch {
                    return Ok(());
                }
                current.popup = Some(popup);
            }
            let _ = window.eval(PREPARE);
            window
                .show()
                .and_then(|_| window.set_focus())
                .map_err(|_| failed())?;
            return Ok(());
        }

        window.hide().map_err(|_| failed())?;
        let initial = state
            .tray_state
            .lock()
            .unwrap()
            .cached_size
            .filter(|(_, sc, w, h)| {
                (sc - scale).abs() < 0.001
                    && *w > 0
                    && *h > 0
                    && *w <= limit.width
                    && *h <= limit.height
            })
            .map(|(_, _, w, h)| PopupSize {
                width: w,
                height: h,
            })
            .unwrap_or(PopupSize {
                width: ((296.0 * scale).round() as u32).max(1).min(limit.width),
                height: ((430.0 * scale).round() as u32).max(1).min(limit.height),
            });
        let mut popup = Popup::new(
            epoch,
            PopupPhase::Preparing,
            cursor_pt,
            work,
            scale,
            initial,
            Instant::now(),
        );
        let pos = anchor_within_work(&popup, initial);
        let tauri_initial = tauri::PhysicalSize::new(initial.width, initial.height);
        let tauri_pos = tauri::PhysicalPosition::new(pos.x, pos.y);
        window
            .set_position(tauri_pos)
            .and_then(|_| window.set_size(tauri_initial))
            .and_then(|_| window.set_position(tauri_pos))
            .map_err(|_| failed())?;
        let actual = window.inner_size().map_err(|_| failed())?;
        popup.client = PopupSize {
            width: actual.width,
            height: actual.height,
        };
        {
            let mut current = state.tray_state.lock().unwrap();
            if current.popup_epoch != epoch {
                return Ok(());
            }
            current.popup = Some(popup);
        }
        window.eval(PREPARE).map_err(|_| failed())
    }

    fn target_monitor_work(window: &WebviewWindow, point: PopupPoint) -> Option<PopupWorkRect> {
        let app = window.app_handle();
        let monitor = if let Some(main) = app.get_webview_window("main") {
            main.monitor_from_point(point.x, point.y)
                .ok()
                .flatten()
                .or_else(|| window.current_monitor().ok().flatten())
                .or_else(|| main.primary_monitor().ok().flatten())
        } else {
            window
                .monitor_from_point(point.x, point.y)
                .ok()
                .flatten()
                .or_else(|| window.current_monitor().ok().flatten())
                .or_else(|| window.primary_monitor().ok().flatten())
        }?;
        let raw_work = monitor.work_area();
        (raw_work.size.width > 0 && raw_work.size.height > 0).then_some(PopupWorkRect {
            x: raw_work.position.x,
            y: raw_work.position.y,
            width: raw_work.size.width,
            height: raw_work.size.height,
        })
    }

    pub fn measured(window: &WebviewWindow, g: Geometry) -> Result<()> {
        let state = window.state::<crate::desktop::Host>();
        let raw_actual = window.inner_size().map_err(|_| failed())?;
        let actual = PopupSize {
            width: raw_actual.width,
            height: raw_actual.height,
        };
        let native_scale = window.scale_factor().map_err(|_| failed())?;
        let active_point = state
            .tray_state
            .lock()
            .unwrap()
            .popup
            .as_ref()
            .map(|p| p.point);
        let target_work = active_point.and_then(|pt| target_monitor_work(window, pt));
        let mut current = state.tray_state.lock().unwrap();
        let revision = current.revision();
        let Some(p) = current.popup.as_mut() else {
            if g.width > 0.0
                && g.height > 0.0
                && g.dpr > 0.0
                && native_scale > 0.0
                && g.width <= 16384.0
                && g.height <= 16384.0
                && (0.125..=16.0).contains(&g.dpr)
            {
                let w = (g.width * g.dpr).ceil().max(1.0) as u32;
                let h = (g.height * g.dpr).ceil().max(1.0) as u32;
                current.cached_size = Some((revision, native_scale, w, h));
            }
            return Ok(());
        };
        let decision = p.evaluate_measurement_in_work(actual, native_scale, target_work, &g)?;
        match decision {
            MeasureDecision::Ignore => {
                if let Some((w, h, _, _)) = p.last {
                    current.cached_size = Some((revision, p.scale, w, h));
                }
                Ok(())
            }
            MeasureDecision::RePrepare => {
                let epoch = p.epoch;
                let layout = p.layout;
                let point = p.point;
                let reanchor = p.reanchor_origin();
                drop(current);
                if let Some(origin) = reanchor {
                    window
                        .set_position(tauri::PhysicalPosition::new(origin.x, origin.y))
                        .map_err(|_| failed())?;
                    let settled_raw = window.inner_size().map_err(|_| failed())?;
                    let settled_scale = window.scale_factor().map_err(|_| failed())?;
                    let settled_work = target_monitor_work(window, point);
                    let mut current = state.tray_state.lock().unwrap();
                    if let Some(p) = current
                        .popup
                        .as_mut()
                        .filter(|p| p.epoch == epoch && p.layout == layout)
                    {
                        p.sync_reanchored(
                            PopupSize {
                                width: settled_raw.width,
                                height: settled_raw.height,
                            },
                            settled_scale,
                            settled_work,
                        );
                    }
                }
                window.eval(PREPARE).map_err(|_| failed())
            }
            MeasureDecision::Apply {
                size,
                pos,
                resize,
                opening,
            } => {
                let epoch = p.epoch;
                let layout = p.layout;
                let p_scale = p.scale;
                current.cached_size = Some((revision, p_scale, size.width, size.height));
                drop(current);
                if resize {
                    window
                        .set_size(tauri::PhysicalSize::new(size.width, size.height))
                        .map_err(|_| failed())?;
                }
                window
                    .set_position(tauri::PhysicalPosition::new(pos.x, pos.y))
                    .map_err(|_| failed())?;
                if opening {
                    window
                        .show()
                        .and_then(|_| window.set_focus())
                        .map_err(|_| failed())?;
                }
                let mut current = state.tray_state.lock().unwrap();
                if let Some(p) = current
                    .popup
                    .as_mut()
                    .filter(|p| p.epoch == epoch && p.layout == layout)
                {
                    p.commit_applied(size, pos, resize, opening, Instant::now());
                }
                Ok(())
            }
        }
    }

    pub fn hide(app: &tauri::AppHandle) -> Result<()> {
        let expected = app
            .state::<crate::desktop::Host>()
            .tray_state
            .lock()
            .unwrap()
            .popup_epoch;
        let a = app.clone();
        app.run_on_main_thread(move || {
            {
                let state = a.state::<crate::desktop::Host>();
                let mut current = state.tray_state.lock().unwrap();
                if current.popup_epoch != expected {
                    return;
                }
                current.popup = None;
                current.popup_epoch = current.popup_epoch.wrapping_add(1);
            }
            if let Some(w) = a.get_webview_window(LABEL) {
                if w.hide().is_err() {
                    crate::desktop::tray_feedback(&a, failed());
                }
                if a.get_webview_window("main").is_none() {
                    let _ = w.destroy();
                } else {
                    let _ = w.eval(PREPARE);
                }
            }
        })
        .map_err(|_| failed())
    }

    pub fn destroy(app: &tauri::AppHandle) {
        let a = app.clone();
        let _ = app.run_on_main_thread(move || {
            {
                let state = a.state::<crate::desktop::Host>();
                let mut current = state.tray_state.lock().unwrap();
                current.popup = None;
                current.popup_epoch = current.popup_epoch.wrapping_add(1);
            }
            if let Some(w) = a.get_webview_window(LABEL) {
                let _ = w.destroy();
            }
        });
    }
}

#[cfg(all(windows, feature = "desktop"))]
pub use desktop_imp::*;

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_work() -> PopupWorkRect {
        PopupWorkRect {
            x: 0,
            y: 0,
            width: 1920,
            height: 1032,
        }
    }

    #[test]
    fn cross_dpi_scale_and_client_mismatch_reprepare_instead_of_stalling() {
        let now = Instant::now();
        let mut p = Popup::new(
            7,
            PopupPhase::Preparing,
            PopupPoint {
                x: 1800.0,
                y: 1050.0,
            },
            sample_work(),
            1.0,
            PopupSize {
                width: 296,
                height: 430,
            },
            now,
        );
        assert_eq!(p.reply().phase, PopupPhase::Preparing);
        let g1 = Geometry {
            epoch: "7".into(),
            layout: "1".into(),
            viewport_width: 296.0,
            viewport_height: 430.0,
            width: 280.0,
            height: 360.0,
            dpr: 1.5,
        };
        // Secondary monitor reports 1.5x native scale -> must update scale, bump layout, and request RePrepare!
        let dec = p
            .evaluate_measurement(
                PopupSize {
                    width: 444,
                    height: 645,
                },
                1.5,
                &g1,
            )
            .unwrap();
        assert_eq!(dec, MeasureDecision::RePrepare);
        assert!((p.scale - 1.5).abs() < 1e-6);
        assert_eq!(p.layout, 2);
        assert_eq!(p.adjustments, 1);

        // Next measurement matches layout 2 and 1.5x scale -> transitions to Visible!
        let g2 = Geometry {
            epoch: "7".into(),
            layout: "2".into(),
            viewport_width: 296.0,
            viewport_height: 430.0,
            width: 280.0,
            height: 360.0,
            dpr: 1.5,
        };
        let dec2 = p
            .evaluate_measurement(
                PopupSize {
                    width: 444,
                    height: 645,
                },
                1.5,
                &g2,
            )
            .unwrap();
        match dec2 {
            MeasureDecision::Apply {
                size,
                pos,
                resize,
                opening,
            } => {
                assert_eq!(
                    size,
                    PopupSize {
                        width: 420,
                        height: 540
                    }
                );
                assert!(resize);
                assert!(opening);
                p.commit_applied(size, pos, resize, opening, now);
            }
            other => panic!("expected Apply, got {other:?}"),
        }
        assert_eq!(p.phase, PopupPhase::Visible);
        assert_eq!(p.adjustments, 0);
    }

    #[test]
    fn excessive_cross_dpi_oscillation_fails_closed_at_8_adjustments() {
        let now = Instant::now();
        let mut p = Popup::new(
            1,
            PopupPhase::Preparing,
            PopupPoint { x: 500.0, y: 500.0 },
            sample_work(),
            1.0,
            PopupSize {
                width: 296,
                height: 430,
            },
            now,
        );
        for step in 0..8 {
            let next_scale = if step % 2 == 0 { 1.5 } else { 1.0 };
            let g = Geometry {
                epoch: "1".into(),
                layout: p.layout.to_string(),
                viewport_width: 296.0,
                viewport_height: 430.0,
                width: 296.0,
                height: 430.0,
                dpr: next_scale,
            };
            assert_eq!(
                p.evaluate_measurement(p.client, next_scale, &g).unwrap(),
                MeasureDecision::RePrepare
            );
        }
        let g_over = Geometry {
            epoch: "1".into(),
            layout: p.layout.to_string(),
            viewport_width: 296.0,
            viewport_height: 430.0,
            width: 296.0,
            height: 430.0,
            dpr: 2.0,
        };
        let err = p.evaluate_measurement(p.client, 2.0, &g_over).unwrap_err();
        assert_eq!(err.code, "WINDOW_FAILED");
    }

    #[test]
    fn left_right_and_bottom_taskbar_anchor_gap_is_symmetric() {
        let now = Instant::now();
        let size = PopupSize {
            width: 300,
            height: 400,
        };
        // pad = 12, gap = 4, vis_w = 276, vis_h = 376
        // 1. Left-docked taskbar: work starts at x = 64, cursor inside taskbar at x = 32
        let p_left = Popup::new(
            1,
            PopupPhase::Visible,
            PopupPoint { x: 32.0, y: 800.0 },
            PopupWorkRect {
                x: 64,
                y: 0,
                width: 1856,
                height: 1080,
            },
            1.0,
            size,
            now,
        );
        let pos_left = position(&p_left, size);
        // Visible card left = pos_left.x + 12 == 64 + 4 == 68
        assert_eq!(pos_left.x + 12, 68);

        // 2. Right-docked taskbar: work ends at x = 1856, cursor inside taskbar at x = 1890
        let p_right = Popup::new(
            2,
            PopupPhase::Visible,
            PopupPoint {
                x: 1890.0,
                y: 800.0,
            },
            PopupWorkRect {
                x: 0,
                y: 0,
                width: 1856,
                height: 1080,
            },
            1.0,
            size,
            now,
        );
        let pos_right = position(&p_right, size);
        // Visible card right = pos_right.x + 12 + 276 == 1856 - 4 == 1852
        assert_eq!(pos_right.x + 12 + 276, 1852);

        // 3. Bottom-docked taskbar: work ends at y = 1032, cursor at y = 1056
        let p_bottom = Popup::new(
            3,
            PopupPhase::Visible,
            PopupPoint {
                x: 1600.0,
                y: 1056.0,
            },
            sample_work(),
            1.0,
            size,
            now,
        );
        let pos_bottom = position(&p_bottom, size);
        // Visible card bottom = pos_bottom.y + 12 + 376 == 1032 - 4 == 1028
        assert_eq!(pos_bottom.y + 12 + 376, 1028);
    }

    #[test]
    fn blur_dismisses_immediately_when_focused_or_after_200ms_grace() {
        let t0 = Instant::now();
        let mut p = Popup::new(
            1,
            PopupPhase::Visible,
            PopupPoint { x: 100.0, y: 100.0 },
            sample_work(),
            1.0,
            PopupSize {
                width: 296,
                height: 430,
            },
            t0,
        );
        assert!(!p.should_dismiss_on_blur(t0 + Duration::from_millis(50)));
        assert!(p.should_dismiss_on_blur(t0 + Duration::from_millis(200)));

        p.shown_at = Some(t0);
        p.focus_seen = true;
        assert!(p.should_dismiss_on_blur(t0 + Duration::from_millis(10)));
    }

    #[test]
    fn dual_monitor_heterogeneous_work_and_scale_reprepare_reanchors_and_converges() {
        let now = Instant::now();
        let primary_work = PopupWorkRect {
            x: 0,
            y: 0,
            width: 1920,
            height: 1032,
        };
        // Secondary 1.75x monitor to the right with tighter height (860px < 560 * 1.75 = 980px).
        let secondary_work = PopupWorkRect {
            x: 1920,
            y: 0,
            width: 1600,
            height: 860,
        };
        // Right-click right next to the inter-monitor seam on the secondary monitor.
        let seam_point = PopupPoint {
            x: 1922.0,
            y: 845.0,
        };
        let mut p = Popup::new(
            11,
            PopupPhase::Preparing,
            seam_point,
            primary_work,
            1.0,
            PopupSize {
                width: 296,
                height: 430,
            },
            now,
        );

        let g1 = Geometry {
            epoch: "11".into(),
            layout: "1".into(),
            viewport_width: 296.0,
            viewport_height: 430.0,
            width: 310.0,
            height: 520.0,
            dpr: 1.75,
        };
        let actual_175 = PopupSize {
            width: 518,
            height: 753,
        };
        let dec1 = p
            .evaluate_measurement_in_work(actual_175, 1.75, Some(secondary_work), &g1)
            .unwrap();
        assert_eq!(dec1, MeasureDecision::RePrepare);
        assert_eq!(p.work, secondary_work);
        assert!((p.scale - 1.75).abs() < 1e-6);
        assert_eq!(
            p.limit,
            PopupSize {
                width: 630,
                height: 860,
            }
        );
        assert_eq!(p.layout, 2);
        assert_eq!(p.adjustments, 1);

        // Visible card `position` near the left seam overhangs into primary monitor due to shadow pad,
        // whereas hidden `reanchor_origin` strictly keeps the outer frame inside `secondary_work`.
        let vis_pos = position(&p, p.client);
        assert!(vis_pos.x < secondary_work.x);
        let anchor = p.reanchor_origin().expect("preparing popup must reanchor");
        assert!(anchor.x >= secondary_work.x);
        assert!(
            anchor.x + p.client.width as i32 <= secondary_work.x + secondary_work.width as i32
        );
        assert!(anchor.y >= secondary_work.y);
        assert!(
            anchor.y + p.client.height as i32 <= secondary_work.y + secondary_work.height as i32
        );

        // Simulate post-reanchor settle on secondary monitor and next measurement report -> converges!
        p.sync_reanchored(actual_175, 1.75, Some(secondary_work));
        let g2 = Geometry {
            epoch: "11".into(),
            layout: "2".into(),
            viewport_width: f64::from(actual_175.width) / 1.75,
            viewport_height: f64::from(actual_175.height) / 1.75,
            width: 310.0,
            height: 520.0,
            dpr: 1.75,
        };
        let dec2 = p
            .evaluate_measurement_in_work(actual_175, 1.75, Some(secondary_work), &g2)
            .unwrap();
        match dec2 {
            MeasureDecision::Apply {
                size,
                pos,
                resize,
                opening,
            } => {
                // 520 * 1.75 = 910 -> clamped to secondary_work limit height 860!
                assert_eq!(
                    size,
                    PopupSize {
                        width: 543,
                        height: 860,
                    }
                );
                assert!(opening);
                assert!(resize);
                p.commit_applied(size, pos, resize, opening, now);
            }
            other => panic!("expected Apply on second pass, got {other:?}"),
        }
        assert_eq!(p.phase, PopupPhase::Visible);
        assert_eq!(p.adjustments, 0);
        assert_eq!(p.reanchor_origin(), None);
    }
}
