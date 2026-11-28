//! Bounded startup/exit orchestration and Host lifecycle 4-tuple mutex state machine.
use crate::{
    error::{Error, Result},
    preferences::{NetworkIntent, StartupPlan},
};
use std::sync::atomic::{AtomicBool, Ordering};

/// Authoritative 4-tuple lifecycle state machine (`quitting`, `restarting`, `app_restarting`, `installing`)
/// shared by `Host` in `desktop.rs`, `desktop_update.rs`, and cross-platform admission matrix tests.
#[derive(Default)]
pub struct LifecycleFlags {
    pub quitting: AtomicBool,
    pub restarting: AtomicBool,
    pub app_restarting: AtomicBool,
    pub installing: AtomicBool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuitAdmission {
    Admitted,
    ShowMainBlocked,
    AlreadyQuitting,
}

pub struct FlagReset<'a>(pub &'a AtomicBool);
impl Drop for FlagReset<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

impl LifecycleFlags {
    pub const fn new() -> Self {
        Self {
            quitting: AtomicBool::new(false),
            restarting: AtomicBool::new(false),
            app_restarting: AtomicBool::new(false),
            installing: AtomicBool::new(false),
        }
    }

    pub fn from_tuple(quitting: bool, restarting: bool, app_restarting: bool, installing: bool) -> Self {
        Self {
            quitting: AtomicBool::new(quitting),
            restarting: AtomicBool::new(restarting),
            app_restarting: AtomicBool::new(app_restarting),
            installing: AtomicBool::new(installing),
        }
    }

    pub fn snapshot(&self) -> (bool, bool, bool, bool) {
        (
            self.quitting.load(Ordering::SeqCst),
            self.restarting.load(Ordering::SeqCst),
            self.app_restarting.load(Ordering::SeqCst),
            self.installing.load(Ordering::SeqCst),
        )
    }

    pub fn tray_native_busy(&self) -> bool {
        self.installing.load(Ordering::SeqCst)
            || self.quitting.load(Ordering::SeqCst)
            || self.restarting.load(Ordering::SeqCst)
            || self.app_restarting.load(Ordering::SeqCst)
    }

    pub fn ensure_not_app_restarting(&self) -> Result<()> {
        if self.app_restarting.load(Ordering::SeqCst) {
            Err(Error::new("CORE_BUSY", "应用正在重启，请等待操作完成"))
        } else {
            Ok(())
        }
    }

    /// CloseRequested & `window_action("close")` gate: never close or hide while `installing`.
    pub fn admit_close_window(&self) -> bool {
        !self.installing.load(Ordering::SeqCst)
    }

    /// Kernel restart (`restart_kernel`): mutually exclusive with `app_restarting`, `installing`, `quitting`, `restarting`.
    pub fn begin_restart_kernel(&self) -> Result<FlagReset<'_>> {
        self.ensure_not_app_restarting()?;
        if self.installing.load(Ordering::SeqCst) {
            return Err(Error::new("INSTALL_BUSY", "安装操作尚未完成，暂不能重启内核"));
        }
        if self.quitting.load(Ordering::SeqCst) || self.restarting.swap(true, Ordering::SeqCst) {
            return Err(Error::new("CORE_BUSY", "内核重启或退出正在进行中"));
        }
        if self.app_restarting.load(Ordering::SeqCst) || self.installing.load(Ordering::SeqCst) {
            self.restarting.store(false, Ordering::SeqCst);
            return Err(Error::new("CORE_BUSY", "生命周期操作正在进行中"));
        }
        Ok(FlagReset(&self.restarting))
    }

    /// Full app relaunch (`restart_app`): CAS `app_restarting`, rejecting `installing`, `quitting`, or `restarting`.
    pub fn begin_restart_app(&self) -> Result<()> {
        if self
            .app_restarting
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(Error::new("CORE_BUSY", "应用重启已在进行，请勿重复操作"));
        }
        if self.installing.load(Ordering::SeqCst) {
            self.app_restarting.store(false, Ordering::SeqCst);
            return Err(Error::new("INSTALL_BUSY", "安装操作尚未完成，暂不能重启应用"));
        }
        if self.quitting.load(Ordering::SeqCst) {
            self.app_restarting.store(false, Ordering::SeqCst);
            return Err(Error::new("CORE_BUSY", "退出尚未完成，暂不能重启应用"));
        }
        if self.restarting.load(Ordering::SeqCst) {
            self.app_restarting.store(false, Ordering::SeqCst);
            return Err(Error::new("CORE_BUSY", "内核重启尚未完成，暂不能重启应用"));
        }
        Ok(())
    }

    /// Quit admission (`quit`): blocked with `ShowMainBlocked` if `app_restarting` or `installing`.
    pub fn begin_quit(&self) -> QuitAdmission {
        if self.app_restarting.load(Ordering::SeqCst) || self.installing.load(Ordering::SeqCst) {
            return QuitAdmission::ShowMainBlocked;
        }
        if self.quitting.swap(true, Ordering::SeqCst) {
            return QuitAdmission::AlreadyQuitting;
        }
        if self.app_restarting.load(Ordering::SeqCst) || self.installing.load(Ordering::SeqCst) {
            self.quitting.store(false, Ordering::SeqCst);
            return QuitAdmission::ShowMainBlocked;
        }
        QuitAdmission::Admitted
    }

    /// Update handoff shutdown (`prepare_shutdown`): CAS `app_restarting`, rejecting other active transitions.
    pub fn begin_update_shutdown(&self) -> Result<()> {
        if self
            .app_restarting
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(Error::new("UPDATE_BUSY", "生命周期操作进行中"));
        }
        if self.installing.load(Ordering::SeqCst)
            || self.quitting.load(Ordering::SeqCst)
            || self.restarting.load(Ordering::SeqCst)
        {
            self.app_restarting.store(false, Ordering::SeqCst);
            return Err(Error::new("UPDATE_BUSY", "生命周期操作进行中"));
        }
        Ok(())
    }

    /// Rollback handoff shutdown (`prepare_rollback_shutdown`): CAS `app_restarting`, rejecting concurrent `quitting`.
    pub fn begin_rollback_shutdown(&self) -> Result<()> {
        if self
            .app_restarting
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(Error::new("UPDATE_BUSY", "回滚或重启操作进行中"));
        }
        if self.quitting.load(Ordering::SeqCst) || self.installing.load(Ordering::SeqCst) {
            self.app_restarting.store(false, Ordering::SeqCst);
            return Err(Error::new("UPDATE_BUSY", "退出或安装操作进行中，稍后重试回滚"));
        }
        Ok(())
    }

    /// Crash watcher only recovers when NO planned host lifecycle transition is active.
    pub fn allow_crash_recovery(&self) -> bool {
        !self.app_restarting.load(Ordering::SeqCst)
            && !self.quitting.load(Ordering::SeqCst)
            && !self.restarting.load(Ordering::SeqCst)
            && !self.installing.load(Ordering::SeqCst)
    }
}

#[allow(async_fn_in_trait)]
pub trait StartupOps {
    async fn start_core(&self) -> Result<()>;
    async fn preflight(&self, i: NetworkIntent) -> Result<()>;
    async fn proxy(&self) -> Result<()>;
    async fn tun(&self) -> Result<()>;
    fn tun_failure_preserves_base(&self) -> bool {
        false
    }
    async fn cleanup(&self) -> Result<()>;
}

pub async fn startup(o: &impl StartupOps, p: StartupPlan) -> Result<()> {
    match p {
        StartupPlan::StartCore => trace("startup.core", o.start_core()).await,
        StartupPlan::Restore(i) => {
            let mut tun_attempted = false;
            let result = async {
                trace("startup.core", o.start_core()).await?;
                trace("startup.preflight", o.preflight(i)).await?;
                if i.system_proxy {
                    trace("startup.proxy", o.proxy()).await?;
                }
                if i.tun {
                    tun_attempted = true;
                    trace("startup.tun", o.tun()).await?;
                }
                Ok(())
            }
            .await;
            if let Err(e) = result {
                if tun_attempted && o.tun_failure_preserves_base() {
                    return Err(e);
                }
                if o.cleanup().await.is_err() {
                    return Err(Error::new(
                        "STARTUP_RECOVERY_REQUIRED",
                        "启动失败且网络恢复需要人工确认",
                    ));
                }
                return Err(e);
            }
            Ok(())
        }
    }
}

pub async fn startup_base(o: &impl StartupOps, p: StartupPlan) -> Result<bool> {
    match p {
        StartupPlan::StartCore => {
            trace("startup.core", o.start_core()).await?;
            Ok(false)
        }
        StartupPlan::Restore(i) => {
            let result = async {
                trace("startup.core", o.start_core()).await?;
                trace("startup.preflight", o.preflight(i)).await?;
                if i.system_proxy {
                    trace("startup.proxy", o.proxy()).await?;
                }
                Ok(i.tun)
            }
            .await;
            if let Err(e) = result {
                if o.cleanup().await.is_err() {
                    return Err(Error::new(
                        "STARTUP_RECOVERY_REQUIRED",
                        "启动失败且网络恢复需要人工确认",
                    ));
                }
                return Err(e);
            }
            result
        }
    }
}

pub const QUIT_CLEANUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);
pub const QUIT_CLEANUP_POLL: std::time::Duration = std::time::Duration::from_millis(500);
pub const QUIT_CLEANUP_NOTICE: &str = "正在完成网络清理…";

#[allow(async_fn_in_trait)]
pub trait QuitOps {
    async fn cleanup(&self) -> Result<()>;
    fn set_cleanup_waiting(&self, _waiting: bool) {}
    async fn poll_cleanup_pending(&self) -> Result<bool> {
        Err(Error::new("RECOVERY_PENDING", "内核 TUN 网络清理尚未完成"))
    }
    fn cleanup_wait_budget(&self) -> (std::time::Duration, std::time::Duration) {
        (QUIT_CLEANUP_TIMEOUT, QUIT_CLEANUP_POLL)
    }
    async fn stop_core(&self);
}

pub async fn quit(o: &impl QuitOps) -> Result<()> {
    if let Err(e) = o.cleanup().await {
        if e.code != "RECOVERY_PENDING" {
            return Err(e);
        }
        if o.poll_cleanup_pending().await? {
            o.set_cleanup_waiting(true);
            let (timeout, poll) = o.cleanup_wait_budget();
            let waited = tokio::time::timeout(timeout, async {
                loop {
                    tokio::time::sleep(poll).await;
                    if !o.poll_cleanup_pending().await? {
                        return Ok(());
                    }
                }
            })
            .await;
            o.set_cleanup_waiting(false);
            match waited {
                Ok(Ok(())) => {}
                Ok(Err(err)) => return Err(err),
                Err(_) => return Err(e),
            }
        }
    }
    o.stop_core().await;
    Ok(())
}

#[allow(async_fn_in_trait)]
pub trait AppRestartOps: QuitOps {
    async fn stop_for_app_restart(&self) -> Result<()>;
}
pub async fn prepare_app_restart(o: &impl AppRestartOps) -> Result<()> {
    o.cleanup().await?;
    o.stop_for_app_restart().await
}

#[allow(async_fn_in_trait)]
pub trait RestartOps: StartupOps {
    async fn cleanup_for_restart(&self) -> Result<()> {
        StartupOps::cleanup(self).await
    }
    async fn stop_running_core(&self) -> Result<()>;
}

pub async fn restart(o: &impl RestartOps, intent: NetworkIntent) -> Result<()> {
    o.cleanup_for_restart().await?;
    o.stop_running_core().await?;
    startup(o, crate::preferences::startup_plan(intent)).await
}

pub async fn accepted_control<'a>(
    control: &'a tokio::sync::Mutex<()>,
    method: &str,
) -> Option<tokio::sync::MutexGuard<'a, ()>> {
    if serializes_accepted_read(method) {
        Some(control.lock().await)
    } else {
        None
    }
}

pub fn serializes_accepted_read(method: &str) -> bool {
    matches!(
        method,
        "core.start" | "core.stop" | "core.reload" | "document.apply" | "document.get"
    )
}

pub fn tun_network_cleared(v: &serde_json::Value) -> bool {
    v.get("intent") == Some(&serde_json::Value::Bool(false))
        && v.get("enabled") == Some(&serde_json::Value::Bool(false))
        && v.get("network_clear") == Some(&serde_json::Value::Bool(true))
}

pub async fn trace<T>(op: &str, f: impl std::future::Future<Output = Result<T>>) -> Result<T> {
    let id = crate::safe_log::component(
        "host.startup",
        crate::log_context::Component::Gui,
        op,
        crate::log_context::Phase::Begin,
        None,
        None,
    );
    let result = if op.starts_with("finalize.") || op == "startup.preflight" {
        tokio::time::timeout(std::time::Duration::from_secs(20), f)
            .await
            .unwrap_or_else(|_| {
                Err(Error::new(
                    "STARTUP_TIMEOUT",
                    &format!("{} 超时；操作状态未确认，请查看网络状态后重试", op),
                ))
            })
    } else {
        f.await
    };
    crate::safe_log::component(
        "host.startup",
        crate::log_context::Component::Gui,
        op,
        crate::log_context::Phase::Complete,
        result.as_ref().err().map(|e| e.code.as_str()),
        Some(id),
    );
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        },
        time::Duration,
    };

    struct Fake {
        events: Mutex<Vec<&'static str>>,
        fail: Option<&'static str>,
    }
    impl Fake {
        fn step(&self, s: &'static str) -> Result<()> {
            self.events.lock().unwrap().push(s);
            if self.fail == Some(s) {
                Err(Error::new("TEST_FAILURE", "fixed failure"))
            } else {
                Ok(())
            }
        }
    }
    impl StartupOps for Fake {
        async fn start_core(&self) -> Result<()> {
            self.step("start")
        }
        async fn preflight(&self, _: NetworkIntent) -> Result<()> {
            self.step("ready")
        }
        async fn proxy(&self) -> Result<()> {
            self.step("proxy")
        }
        async fn tun(&self) -> Result<()> {
            self.step("tun")
        }
        async fn cleanup(&self) -> Result<()> {
            self.step("restore")
        }
    }
    impl QuitOps for Fake {
        async fn cleanup(&self) -> Result<()> {
            self.step("restore")
        }
        async fn stop_core(&self) {
            let _ = self.step("stop");
        }
    }
    impl AppRestartOps for Fake {
        async fn stop_for_app_restart(&self) -> Result<()> {
            self.step("stop_restart")
        }
    }
    impl RestartOps for Fake {
        async fn cleanup_for_restart(&self) -> Result<()> {
            self.step("cleanup")
        }
        async fn stop_running_core(&self) -> Result<()> {
            self.step("stop")
        }
    }

    #[tokio::test]
    async fn ready_and_restore_failures_compensate() {
        for failure in ["start", "ready", "proxy", "tun"] {
            let o = Fake {
                events: Mutex::new(Vec::new()),
                fail: Some(failure),
            };
            assert!(startup(
                &o,
                StartupPlan::Restore(NetworkIntent {
                    system_proxy: true,
                    tun: true
                })
            )
            .await
            .is_err());
            let e = o.events.lock().unwrap();
            assert_eq!(e.last(), Some(&"restore"));
            if failure == "ready" {
                assert!(!e.contains(&"proxy"));
            }
        }
    }

    #[tokio::test]
    async fn restore_four_combinations() {
        for system_proxy in [false, true] {
            for tun in [false, true] {
                let o = Fake {
                    events: Mutex::new(Vec::new()),
                    fail: None,
                };
                startup(&o, StartupPlan::Restore(NetworkIntent { system_proxy, tun }))
                    .await
                    .unwrap();
                let e = o.events.lock().unwrap();
                assert_eq!(e.contains(&"proxy"), system_proxy);
                assert_eq!(e.contains(&"tun"), tun);
                assert_eq!(&e[..2], &["start", "ready"]);
                let o2 = Fake {
                    events: Mutex::new(Vec::new()),
                    fail: None,
                };
                let need_tun =
                    startup_base(&o2, StartupPlan::Restore(NetworkIntent { system_proxy, tun }))
                        .await
                        .unwrap();
                assert_eq!(need_tun, tun);
                let e2 = o2.events.lock().unwrap();
                assert_eq!(e2.contains(&"proxy"), system_proxy);
                assert!(!e2.contains(&"tun"));
            }
        }
    }

    #[tokio::test]
    async fn quit_and_prepare_app_restart_fail_closed_without_stopping_core() {
        let o = Fake {
            events: Mutex::new(Vec::new()),
            fail: Some("restore"),
        };
        assert!(quit(&o).await.is_err());
        assert_eq!(*o.events.lock().unwrap(), vec!["restore"]);

        let o_restart_fail = Fake {
            events: Mutex::new(Vec::new()),
            fail: Some("restore"),
        };
        assert!(prepare_app_restart(&o_restart_fail).await.is_err());
        assert_eq!(*o_restart_fail.events.lock().unwrap(), vec!["restore"]);

        let o_ok = Fake {
            events: Mutex::new(Vec::new()),
            fail: None,
        };
        quit(&o_ok).await.unwrap();
        assert_eq!(*o_ok.events.lock().unwrap(), vec!["restore", "stop"]);
    }

    #[test]
    fn capabilities_main_json_allows_listen_without_emit() {
        let caps: serde_json::Value =
            serde_json::from_str(include_str!("../capabilities/main.json")).unwrap();
        assert_eq!(caps["windows"], serde_json::json!(["main"]));
        let permissions = caps["permissions"].as_array().unwrap();
        assert!(permissions.contains(&serde_json::json!("core:event:allow-listen")));
        assert!(permissions.contains(&serde_json::json!("core:event:allow-unlisten")));
        assert!(!permissions
            .iter()
            .any(|p| p.as_str().unwrap_or("").contains("emit")));
    }

    #[tokio::test]
    async fn initial_document_read_waits_for_normal_start_and_tun_completion() {
        let control = Arc::new(tokio::sync::Mutex::new(()));
        let startup = control.lock().await;
        let pending = control.clone();
        let task = tokio::spawn(async move {
            let _read = accepted_control(&pending, "document.get").await;
            "accepted"
        });
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        drop(startup);
        assert_eq!(task.await.unwrap(), "accepted");
        assert!(serializes_accepted_read("document.get"));
        assert!(serializes_accepted_read("core.start"));
        assert!(!serializes_accepted_read("status"));
    }

    #[tokio::test]
    async fn restart_all_four_intents_and_compensate_on_failure() {
        for system_proxy in [false, true] {
            for tun in [false, true] {
                let o = Fake {
                    events: Mutex::new(Vec::new()),
                    fail: None,
                };
                restart(&o, NetworkIntent { system_proxy, tun })
                    .await
                    .unwrap();
                let e = o.events.lock().unwrap();
                assert_eq!(&e[..3], &["cleanup", "stop", "start"]);
                assert_eq!(e.contains(&"proxy"), system_proxy);
                assert_eq!(e.contains(&"tun"), tun);
            }
        }
        for fail in ["cleanup", "stop", "start", "ready", "proxy", "tun"] {
            let o = Fake {
                events: Mutex::new(Vec::new()),
                fail: Some(fail),
            };
            assert!(restart(
                &o,
                NetworkIntent {
                    system_proxy: true,
                    tun: true
                }
            )
            .await
            .is_err());
            let e = o.events.lock().unwrap();
            if fail == "cleanup" {
                assert_eq!(&*e, &["cleanup"]);
            } else if fail == "stop" {
                assert_eq!(&*e, &["cleanup", "stop"]);
            } else {
                assert_eq!(e.last(), Some(&"restore"));
            }
        }
    }

    #[test]
    fn only_explicit_false_and_native_clear_allow_base_even_with_finish_error() {
        use serde_json::json;
        let valid = json!({"intent":false,"enabled":false,"network_clear":true,"cleanup_complete":false,"state":"error","code":"JOURNAL_WRITE"});
        assert!(tun_network_cleared(&valid));
        for (key, value) in [
            ("intent", json!(true)),
            ("enabled", json!(true)),
            ("network_clear", json!(false)),
            ("network_clear", json!("true")),
            ("network_clear", json!(null)),
        ] {
            let mut v = valid.clone();
            v[key] = value;
            assert!(!tun_network_cleared(&v));
        }
        assert!(!tun_network_cleared(
            &json!({"intent":false,"enabled":false,"cleanup_complete":true})
        ));
    }

    struct PendingQuitFixture {
        initial_pending: bool,
        polls_until_complete: usize,
        poll_error: Option<&'static str>,
        budget: (Duration, Duration),
        polls: AtomicUsize,
        stopped: AtomicBool,
        notices: Mutex<Vec<bool>>,
        events: Mutex<Vec<&'static str>>,
    }
    impl PendingQuitFixture {
        fn new(initial_pending: bool, polls_until_complete: usize, budget: (Duration, Duration)) -> Self {
            Self {
                initial_pending,
                polls_until_complete,
                poll_error: None,
                budget,
                polls: AtomicUsize::new(0),
                stopped: AtomicBool::new(false),
                notices: Mutex::new(Vec::new()),
                events: Mutex::new(Vec::new()),
            }
        }
    }
    impl QuitOps for PendingQuitFixture {
        async fn cleanup(&self) -> Result<()> {
            self.events.lock().unwrap().push("cleanup");
            if self.initial_pending {
                Err(Error::new("RECOVERY_PENDING", "Core TUN cleanup is incomplete"))
            } else {
                Ok(())
            }
        }
        fn set_cleanup_waiting(&self, waiting: bool) {
            self.notices.lock().unwrap().push(waiting);
            self.events
                .lock()
                .unwrap()
                .push(if waiting { "notice_on" } else { "notice_off" });
        }
        async fn poll_cleanup_pending(&self) -> Result<bool> {
            let n = self.polls.fetch_add(1, Ordering::SeqCst) + 1;
            self.events.lock().unwrap().push("poll");
            if let Some(code) = self.poll_error {
                return Err(Error::new(code, "retained cleanup error"));
            }
            Ok(n < self.polls_until_complete)
        }
        fn cleanup_wait_budget(&self) -> (Duration, Duration) {
            self.budget
        }
        async fn stop_core(&self) {
            self.stopped.store(true, Ordering::SeqCst);
            self.events.lock().unwrap().push("stop_core");
        }
    }

    #[tokio::test]
    async fn quit_pending_cleanup_behaviour() {
        let f = PendingQuitFixture::new(false, 0, (Duration::from_millis(200), Duration::from_millis(10)));
        quit(&f).await.unwrap();
        assert!(f.stopped.load(Ordering::SeqCst));
        assert_eq!(*f.events.lock().unwrap(), vec!["cleanup", "stop_core"]);

        let f2 = PendingQuitFixture::new(true, 4, (Duration::from_secs(2), Duration::from_millis(10)));
        quit(&f2).await.unwrap();
        assert!(f2.stopped.load(Ordering::SeqCst));
        assert_eq!(f2.polls.load(Ordering::SeqCst), 4);
        assert_eq!(*f2.notices.lock().unwrap(), vec![true, false]);

        let f3 = PendingQuitFixture::new(true, usize::MAX, (Duration::from_millis(45), Duration::from_millis(10)));
        let err = quit(&f3).await.unwrap_err();
        assert_eq!(err.code, "RECOVERY_PENDING");
        assert!(!f3.stopped.load(Ordering::SeqCst));
    }

    /// Exhaustive 16-state (2^4) admission matrix test for Host lifecycle 4-tuple
    /// `(quitting, restarting, app_restarting, installing)`.
    #[test]
    fn host_lifecycle_four_tuple_admission_matrix() {
        for mask in 0u8..16 {
            let q = (mask & 1) != 0;
            let r = (mask & 2) != 0;
            let ar = (mask & 4) != 0;
            let inst = (mask & 8) != 0;
            let idle = mask == 0;

            // 1. tray_native_busy & crash recovery
            let flags = LifecycleFlags::from_tuple(q, r, ar, inst);
            assert_eq!(flags.tray_native_busy(), !idle);
            assert_eq!(flags.allow_crash_recovery(), idle);
            assert_eq!(flags.ensure_not_app_restarting().is_ok(), !ar);

            // 2. window close gate (`window_action("close")` & `CloseRequested`)
            assert_eq!(flags.admit_close_window(), !inst);

            // 3. restart_kernel admission & RAII reset
            let f_rk = LifecycleFlags::from_tuple(q, r, ar, inst);
            let rk_res = f_rk.begin_restart_kernel();
            assert_eq!(rk_res.is_ok(), idle, "restart_kernel mask={mask:04b}");
            if let Ok(guard) = rk_res {
                assert!(f_rk.restarting.load(Ordering::SeqCst));
                drop(guard);
                assert!(!f_rk.restarting.load(Ordering::SeqCst));
            } else {
                assert_eq!(f_rk.snapshot(), (q, r, ar, inst));
            }

            // 4. restart_app admission (must also reject `restarting == true` and preserve flags on failure)
            let f_ra = LifecycleFlags::from_tuple(q, r, ar, inst);
            let ra_res = f_ra.begin_restart_app();
            assert_eq!(ra_res.is_ok(), idle, "restart_app mask={mask:04b}");
            if ra_res.is_ok() {
                assert_eq!(f_ra.snapshot(), (false, false, true, false));
            } else {
                assert_eq!(f_ra.snapshot(), (q, r, ar, inst));
            }

            // 5. quit admission
            let f_q = LifecycleFlags::from_tuple(q, r, ar, inst);
            let q_res = f_q.begin_quit();
            if ar || inst {
                assert_eq!(q_res, QuitAdmission::ShowMainBlocked, "quit mask={mask:04b}");
                assert_eq!(f_q.snapshot(), (q, r, ar, inst));
            } else if q {
                assert_eq!(q_res, QuitAdmission::AlreadyQuitting, "quit mask={mask:04b}");
            } else {
                assert_eq!(q_res, QuitAdmission::Admitted, "quit mask={mask:04b}");
                assert!(f_q.quitting.load(Ordering::SeqCst));
            }

            // 6. prepare_update_shutdown & prepare_rollback_shutdown CAS
            let f_up = LifecycleFlags::from_tuple(q, r, ar, inst);
            assert_eq!(f_up.begin_update_shutdown().is_ok(), idle);
            if !idle {
                assert_eq!(f_up.snapshot(), (q, r, ar, inst));
            }
            let f_rb = LifecycleFlags::from_tuple(q, r, ar, inst);
            let expect_rb_ok = !ar && !q && !inst;
            assert_eq!(f_rb.begin_rollback_shutdown().is_ok(), expect_rb_ok);
            if !expect_rb_ok {
                assert_eq!(f_rb.snapshot(), (q, r, ar, inst));
            }
        }
    }
}
