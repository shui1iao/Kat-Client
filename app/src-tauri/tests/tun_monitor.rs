//! Test-only I/O dependency seam exercising the exact production `tun_operation.rs` implementation.
use kat_host::{
    core_tun_journal::RecoveryReport,
    error::{Error, Result},
    service_protocol::ServiceRequest,
    supervisor::Life,
    tun_diagnostics::{Detail, Phase, Stage},
};
pub use kat_host::{
    lifecycle, preferences, service_protocol, supervisor, tun_diagnostics, user_store,
};
use serde_json::{json, Value};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::sync::{oneshot, watch, Mutex as AsyncMutex};

mod identity {
    pub fn workspace() -> kat_host::error::Result<std::path::PathBuf> {
        let dir = std::env::temp_dir().join(format!("kat-tun-monitor-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        Ok(dir)
    }
}
mod proxy {
    pub fn restore() -> kat_host::error::Result<()> {
        Ok(())
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct SwitchLike {
    enabled: bool,
}
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct NetworkStatus {
    enabled: bool,
    system_proxy: SwitchLike,
    tun: SwitchLike,
}

struct MockSnapshot {
    updating: bool,
}
impl MockSnapshot {
    fn update_pending(&self) -> bool {
        self.updating
    }
}

#[derive(Clone)]
struct MockCore {
    controller: Arc<SharedCoreState>,
    life_rx: watch::Receiver<Life>,
}
struct SharedCoreState {
    elevated: AtomicBool,
    status_reads: AtomicUsize,
    status_error: AtomicBool,
    tun_state: Mutex<&'static str>,
    cleanup_complete: AtomicBool,
    cleanup_pending: AtomicBool,
    trace: Mutex<Vec<&'static str>>,
}
impl MockCore {
    fn elevated(&self) -> bool {
        self.controller.elevated.load(Ordering::SeqCst)
    }
    fn life(&self) -> &watch::Receiver<Life> {
        &self.life_rx
    }
    fn snapshot(&self) -> MockSnapshot {
        MockSnapshot { updating: false }
    }
    async fn restart_process(&self, _grace: Duration) -> Result<()> {
        Ok(())
    }
    async fn request(&self, method: &str, _params: Value, _timeout: Duration) -> Result<Value> {
        match method {
            "network.tun.status" => {
                self.controller.status_reads.fetch_add(1, Ordering::SeqCst);
                if self.controller.status_error.load(Ordering::SeqCst) {
                    return Err(Error::new("PIPE_IO", "test status failure"));
                }
                let st = *self.controller.tun_state.lock().unwrap();
                let cc = self.controller.cleanup_complete.load(Ordering::SeqCst);
                let cp = self.controller.cleanup_pending.load(Ordering::SeqCst);
                let enabled = st == "on" && !cc;
                self.controller
                    .trace
                    .lock()
                    .unwrap()
                    .push(if enabled { "monitor_reads_on" } else { "monitor_reads_off" });
                Ok(json!({
                    "enabled": enabled,
                    "state": st,
                    "cleanup_complete": cc,
                    "cleanup_pending": cp,
                    "interfaces_clean": cc,
                    "wfp_clean": cc
                }))
            }
            "network.egress.get" => Ok(json!({"enabled": false})),
            "status" => Ok(json!({"runtime": {"state": "running"}})),
            "core.start" => Ok(json!({})),
            _ => Ok(json!({})),
        }
    }
}

mod inner {
    use super::*;
    thread_local! {
        static SERVICE_REPORT: std::cell::RefCell<Option<RecoveryReport>> = const { std::cell::RefCell::new(None) };
    }
    pub(super) fn set_service_report(report: Option<RecoveryReport>) {
        SERVICE_REPORT.with(|slot| *slot.borrow_mut() = report);
    }
    pub(super) async fn call(_request: ServiceRequest) -> Result<Value> {
        let rep = SERVICE_REPORT.with(|slot| slot.borrow().clone()).unwrap_or(RecoveryReport {
            cleanup_complete: true,
            cleanup_pending: false,
            restored: 0,
            conflicts: 0,
            pending: 0,
            safe_code: String::new(),
        });
        Ok(json!({ "core_tun_recovery": rep }))
    }
    pub(super) struct NetworkController {
        pub operation: AsyncMutex<()>,
        pub tun_attempt: AtomicU64,
        pub desired_tun: AtomicBool,
        pub tun_engaged: AtomicBool,
        pub tun_safety_stop: AtomicBool,
        pub tun_fallback_ready: AtomicBool,
        pub quit_waiting: AtomicBool,
        pub tun_error: Mutex<Option<String>>,
        pub core: Option<MockCore>,
        pub core_state: Arc<SharedCoreState>,
        pub active: AtomicBool,
        pub owned: AtomicBool,
        pub running: AtomicBool,
        pub unsettled: AtomicBool,
        pub enables: AtomicUsize,
        pub disables: AtomicUsize,
        pub enable_error: Mutex<Option<&'static str>>,
        pub commit_gate: Mutex<Option<oneshot::Receiver<()>>>,
        pub settled_gate: Mutex<Option<oneshot::Receiver<()>>>,
    }
    impl NetworkController {
        pub fn fixture(desired: bool, active: bool) -> Self {
            let core_state = Arc::new(SharedCoreState {
                elevated: AtomicBool::new(active || desired),
                status_reads: AtomicUsize::new(0),
                status_error: AtomicBool::new(false),
                tun_state: Mutex::new(if active { "on" } else { "off" }),
                cleanup_complete: AtomicBool::new(!active),
                cleanup_pending: AtomicBool::new(false),
                trace: Mutex::new(vec![]),
            });
            let (_tx, life_rx) = watch::channel(Life::Ready);
            let core = MockCore {
                controller: core_state.clone(),
                life_rx,
            };
            Self {
                operation: AsyncMutex::new(()),
                tun_attempt: AtomicU64::new(0),
                desired_tun: AtomicBool::new(desired),
                tun_engaged: AtomicBool::new(active),
                tun_safety_stop: AtomicBool::new(false),
                tun_fallback_ready: AtomicBool::new(false),
                quit_waiting: AtomicBool::new(false),
                tun_error: Mutex::new(None),
                core: Some(core),
                core_state,
                active: AtomicBool::new(active),
                owned: AtomicBool::new(true),
                running: AtomicBool::new(true),
                unsettled: AtomicBool::new(false),
                enables: AtomicUsize::new(0),
                disables: AtomicUsize::new(0),
                enable_error: Mutex::new(None),
                commit_gate: Mutex::new(None),
                settled_gate: Mutex::new(None),
            }
        }
        fn event(&self, e: &'static str) {
            self.core_state.trace.lock().unwrap().push(e);
        }
        fn tun_failure(&self, _phase: Phase, _e: &Error, _stage: Stage) {}
        async fn endpoint(&self, _kind: &str) -> Result<u16> {
            Ok(7890)
        }
        async fn proxy_set_unlocked(&self, enabled: bool) -> Result<NetworkStatus> {
            Ok(NetworkStatus {
                enabled: false,
                system_proxy: SwitchLike { enabled },
                tun: SwitchLike { enabled: false },
            })
        }
        async fn drain_previous_watchdog(&self) -> Result<()> {
            Ok(())
        }
        async fn ensure_core_mutation_settled(&self) -> Result<()> {
            let gate = self.settled_gate.lock().unwrap().take();
            if let Some(g) = gate {
                self.event("user_has_operation_before_settled");
                g.await.unwrap();
            }
            if self.unsettled.load(Ordering::SeqCst) {
                return Err(Error::new(
                    "CORE_MUTATION_UNCERTAIN",
                    "test boundary remains unknown",
                ));
            }
            Ok(())
        }
        async fn tun_enable_unlocked(&self) -> Result<()> {
            self.enables.fetch_add(1, Ordering::SeqCst);
            self.event("enable_before_commit");
            let gate = self.commit_gate.lock().unwrap().take();
            if let Some(g) = gate {
                g.await.unwrap();
            }
            if let Some(code) = *self.enable_error.lock().unwrap() {
                if code == "WAITING_NETWORK" {
                    self.core_state.elevated.store(true, Ordering::SeqCst);
                    *self.core_state.tun_state.lock().unwrap() = "waiting_network";
                    self.core_state.cleanup_complete.store(true, Ordering::SeqCst);
                }
                return Err(Error::new(code, "test I/O result"));
            }
            self.active.store(true, Ordering::SeqCst);
            self.owned.store(true, Ordering::SeqCst);
            self.tun_engaged.store(true, Ordering::SeqCst);
            self.core_state.elevated.store(true, Ordering::SeqCst);
            *self.core_state.tun_state.lock().unwrap() = "on";
            self.core_state
                .cleanup_complete
                .store(false, Ordering::SeqCst);
            self.event("commit_on");
            Ok(())
        }
        async fn tun_disable_unlocked(&self) -> Result<()> {
            self.desired_tun.store(false, Ordering::SeqCst);
            if service_protocol::cleanup_service(
                self.owned.load(Ordering::SeqCst),
                self.running.load(Ordering::SeqCst),
            )? {
                self.disables.fetch_add(1, Ordering::SeqCst);
                self.event("disable_owned");
                self.active.store(false, Ordering::SeqCst);
                self.tun_engaged.store(false, Ordering::SeqCst);
                *self.core_state.tun_state.lock().unwrap() = "off";
                self.core_state.cleanup_complete.store(true, Ordering::SeqCst);
            }
            self.owned.store(false, Ordering::SeqCst);
            Ok(())
        }
        async fn status_unlocked(&self) -> Result<NetworkStatus> {
            let en = self.active.load(Ordering::SeqCst);
            Ok(NetworkStatus {
                enabled: en,
                system_proxy: SwitchLike { enabled: !en },
                tun: SwitchLike { enabled: en },
            })
        }
        pub async fn run_monitor_once(&self) -> Option<Error> {
            self.monitor_once().await
        }
    }
    include!("../src/windows/tun_operation.rs");
}
use inner::NetworkController;

#[tokio::test]
async fn clean_session_reports_no_ownership_or_pending_recovery() {
    let c = NetworkController::fixture(false, false);
    assert!(!c.has_owned_tun_session());
    c.recover_failed_core().await.unwrap();
    assert!(!c.tun_poll_cleanup_pending().await.unwrap());
}

#[tokio::test]
async fn tun_poll_cleanup_pending_tracks_real_recovery_report_until_complete() {
    let c = NetworkController::fixture(false, true);
    c.core_state.elevated.store(false, Ordering::SeqCst);
    inner::set_service_report(Some(RecoveryReport {
        cleanup_complete: false,
        cleanup_pending: true,
        restored: 1,
        conflicts: 0,
        pending: 2,
        safe_code: "RECOVERY_PENDING".into(),
    }));
    assert!(c.tun_poll_cleanup_pending().await.unwrap());
    inner::set_service_report(Some(RecoveryReport {
        cleanup_complete: true,
        cleanup_pending: false,
        restored: 3,
        conflicts: 0,
        pending: 0,
        safe_code: String::new(),
    }));
    assert!(!c.tun_poll_cleanup_pending().await.unwrap());
    inner::set_service_report(None);
}

fn drive_to_pending<F: Future>(f: Pin<&mut F>) {
    let mut cx = Context::from_waker(Waker::noop());
    assert!(
        matches!(f.poll(&mut cx), Poll::Pending),
        "must stop at the actual pending barrier/operation mutex"
    );
}
async fn finishes<F: Future>(f: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(2), f)
        .await
        .expect("production path must finish without recursive operation lock")
}

#[tokio::test]
async fn monitor_does_not_revoke_a_committing_enable() {
    let c = NetworkController::fixture(false, false);
    let (tx, rx) = oneshot::channel();
    *c.commit_gate.lock().unwrap() = Some(rx);
    let mut user = Box::pin(c.tun_set(true));
    drive_to_pending(user.as_mut());
    assert!(c.operation.try_lock().is_err());
    assert!(c.desired_tun.load(Ordering::SeqCst));
    assert!(!c.active.load(Ordering::SeqCst));
    let mut monitor = Box::pin(c.run_monitor_once());
    drive_to_pending(monitor.as_mut());
    let reads_before_commit = c.core_state.status_reads.load(Ordering::SeqCst);
    tx.send(()).unwrap();
    assert!(finishes(user).await.unwrap().enabled);
    finishes(monitor).await;
    assert_eq!(c.disables.load(Ordering::SeqCst), 0);
    assert_eq!(reads_before_commit, 0);
    assert!(c.desired_tun.load(Ordering::SeqCst) && c.active.load(Ordering::SeqCst));
}

#[tokio::test]
async fn waiting_monitor_rechecks_desired_after_user_disable() {
    let c = NetworkController::fixture(true, true);
    let (tx, rx) = oneshot::channel();
    *c.settled_gate.lock().unwrap() = Some(rx);
    let mut user = Box::pin(c.tun_set(false));
    drive_to_pending(user.as_mut());
    assert!(c.operation.try_lock().is_err());
    assert!(c.desired_tun.load(Ordering::SeqCst));
    let mut monitor = Box::pin(c.run_monitor_once());
    drive_to_pending(monitor.as_mut());
    tx.send(()).unwrap();
    assert!(!finishes(user).await.unwrap().enabled);
    finishes(monitor).await;
    assert_eq!(c.enables.load(Ordering::SeqCst), 0);
    assert_eq!(c.core_state.status_reads.load(Ordering::SeqCst), 0);
    assert!(!c.desired_tun.load(Ordering::SeqCst));
}

#[tokio::test]
async fn active_failure_triggers_owned_cleanup_and_base_proxy_fallback() {
    let c = NetworkController::fixture(true, true);
    *c.core_state.tun_state.lock().unwrap() = "error";
    let err = finishes(c.run_monitor_once())
        .await
        .expect("error state must report failure");
    assert_eq!(err.code, "TUN_OPERATION_FAILED");
    assert_eq!(c.disables.load(Ordering::SeqCst), 1);
    assert!(!c.desired_tun.load(Ordering::SeqCst));
    assert!(c.tun_safety_stop.load(Ordering::SeqCst));
    assert!(c.tun_fallback_ready.load(Ordering::SeqCst));
}

#[tokio::test]
async fn unavailable_owned_service_clears_intent_on_recovery_pending() {
    let c = NetworkController::fixture(false, false);
    *c.enable_error.lock().unwrap() = Some("RECOVERY_PENDING");
    let e = finishes(c.tun_set(true)).await.unwrap_err();
    assert_eq!(e.code, "RECOVERY_PENDING");
    assert!(!c.desired_tun.load(Ordering::SeqCst));
}

#[tokio::test]
async fn unknown_mutation_gate_does_not_issue_competing_egress_writes() {
    let c = NetworkController::fixture(true, true);
    c.unsettled.store(true, Ordering::SeqCst);
    assert_eq!(
        finishes(c.tun_set(false)).await.unwrap_err().code,
        "CORE_MUTATION_UNCERTAIN"
    );
    assert_eq!(
        c.enables.load(Ordering::SeqCst) + c.disables.load(Ordering::SeqCst),
        0
    );
    assert!(c.desired_tun.load(Ordering::SeqCst) && c.active.load(Ordering::SeqCst));
    let c = NetworkController::fixture(false, false);
    c.unsettled.store(true, Ordering::SeqCst);
    assert_eq!(
        finishes(c.tun_set(true)).await.unwrap_err().code,
        "CORE_MUTATION_UNCERTAIN"
    );
    assert!(!c.desired_tun.load(Ordering::SeqCst));
    assert_eq!(
        c.enables.load(Ordering::SeqCst) + c.disables.load(Ordering::SeqCst),
        0
    );
}

#[tokio::test]
async fn on_or_unreadable_status_never_triggers_monitor_mutation() {
    let c = NetworkController::fixture(true, true);
    finishes(c.run_monitor_once()).await;
    assert_eq!(
        c.enables.load(Ordering::SeqCst) + c.disables.load(Ordering::SeqCst),
        0
    );
    let c = NetworkController::fixture(true, false);
    c.core_state.status_error.store(true, Ordering::SeqCst);
    finishes(c.run_monitor_once()).await;
    assert_eq!(
        c.enables.load(Ordering::SeqCst) + c.disables.load(Ordering::SeqCst),
        0
    );
    assert!(c.desired_tun.load(Ordering::SeqCst));
}

#[tokio::test]
async fn waiting_network_keeps_desired_intent_recovers_on_monitor_and_allows_cancel() {
    let c = NetworkController::fixture(false, false);
    *c.enable_error.lock().unwrap() = Some("WAITING_NETWORK");
    let status = finishes(c.tun_set(true))
        .await
        .expect("pure WAITING_NETWORK must be accepted as waiting intent");
    assert!(!status.enabled);
    assert!(c.desired_tun.load(Ordering::SeqCst));
    assert!(!c.tun_safety_stop.load(Ordering::SeqCst));
    assert!(c.tun_error.lock().unwrap().is_none());
    assert!(!c.tun_engaged.load(Ordering::SeqCst));
    assert!(finishes(c.run_monitor_once()).await.is_none());
    assert!(c.desired_tun.load(Ordering::SeqCst));
    assert!(!c.tun_safety_stop.load(Ordering::SeqCst));
    *c.enable_error.lock().unwrap() = None;
    assert!(finishes(c.run_monitor_once()).await.is_none());
    assert!(
        c.desired_tun.load(Ordering::SeqCst)
            && c.active.load(Ordering::SeqCst)
            && c.tun_engaged.load(Ordering::SeqCst)
    );
    let c2 = NetworkController::fixture(false, false);
    *c2.enable_error.lock().unwrap() = Some("WAITING_NETWORK");
    finishes(c2.tun_set(true)).await.unwrap();
    assert!(c2.desired_tun.load(Ordering::SeqCst));
    *c2.enable_error.lock().unwrap() = None;
    finishes(c2.tun_set(false)).await.unwrap();
    assert!(!c2.desired_tun.load(Ordering::SeqCst));
    assert!(finishes(c2.run_monitor_once()).await.is_none());
    assert!(!c2.active.load(Ordering::SeqCst));
}
