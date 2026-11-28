//! Stable owner for successive instances of the one core child we launch.
//! No PID lookup, process-name matching or external kill command is used.
use crate::{
    error::{Error, Result},
    supervisor::{Life, Supervisor},
};
use serde_json::Value;
use std::{
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex as PublicationMutex, RwLock,
    },
    time::Duration,
};
use tokio::{
    process::Command,
    sync::{watch, Mutex},
};

struct Slot {
    transition: AtomicBool,
    elevated_session: AtomicBool,
    current: RwLock<Supervisor>,
    launch: Mutex<Command>,
    epoch: AtomicU64,
    entry_revision: AtomicU64,
    entry_active: AtomicU64,
    publication: Arc<PublicationMutex<()>>,
    life: watch::Sender<Life>,
}

#[derive(Clone)]
pub struct CoreProcess(Arc<Slot>);

/// Invalidates before admission, including failed/uncertain same-PID/same-port mutations.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) struct EntryMutation(Arc<Slot>);

impl Drop for EntryMutation {
    fn drop(&mut self) {
        let _publication = self.0.publication.lock().unwrap_or_else(|p| p.into_inner());
        self.0.entry_revision.fetch_add(1, Ordering::SeqCst);
        self.0.entry_active.fetch_sub(1, Ordering::SeqCst);
    }
}

fn entry_mutation(m: &str) -> bool {
    matches!(
        m,
        "document.apply"
            | "core.reload"
            | "core.start"
            | "core.stop"
            | "network.tun.disable"
            | "network.tun.prepare"
            | "network.tun.commit"
            | "network.egress.set"
            | "network.egress.pause"
            | "host.prepare-update"
            | "host.resume-update"
    )
}

impl CoreProcess {
    pub async fn spawn_fixed(executable: &Path, workspace: &Path) -> Result<Self> {
        Self::spawn(Supervisor::fixed_command(executable, workspace)?).await
    }

    pub async fn spawn(mut cmd: Command) -> Result<Self> {
        let core = Supervisor::spawn_command(&mut cmd).await?;
        let (life, _) = watch::channel(Life::Ready);
        let this = Self(Arc::new(Slot {
            transition: AtomicBool::new(false),
            elevated_session: AtomicBool::new(false),
            current: RwLock::new(core.clone()),
            launch: Mutex::new(cmd),
            epoch: AtomicU64::new(0),
            entry_revision: AtomicU64::new(0),
            entry_active: AtomicU64::new(0),
            publication: Arc::new(PublicationMutex::new(())),
            life,
        }));
        this.observe(core, 0);
        Ok(this)
    }

    pub(crate) fn snapshot(&self) -> Supervisor {
        self.0.current.read().unwrap().clone()
    }

    #[cfg(all(windows, feature = "desktop"))]
    pub(crate) fn in_transition(&self) -> bool {
        self.0.transition.load(Ordering::SeqCst)
    }

    #[cfg(all(windows, feature = "desktop"))]
    pub(crate) fn transport_identity(&self) -> Option<(u64, u64)> {
        let epoch = self.0.epoch.load(Ordering::SeqCst);
        let revision = self.0.entry_revision.load(Ordering::SeqCst);
        if self.0.entry_active.load(Ordering::SeqCst) != 0
            || self.snapshot().update_pending()
            || matches!(*self.0.life.borrow(), Life::Exited(_))
        {
            return None;
        }
        if epoch != self.0.epoch.load(Ordering::SeqCst)
            || revision != self.0.entry_revision.load(Ordering::SeqCst)
        {
            return None;
        }
        Some((epoch, revision))
    }

    #[cfg(all(windows, feature = "desktop"))]
    pub(crate) fn publication_lock(&self) -> Arc<PublicationMutex<()>> {
        self.0.publication.clone()
    }

    pub(crate) fn invalidate_update_transport(&self) -> EntryMutation {
        let _publication = self.0.publication.lock().unwrap_or_else(|p| p.into_inner());
        self.0.entry_active.fetch_add(1, Ordering::SeqCst);
        self.0.entry_revision.fetch_add(1, Ordering::SeqCst);
        EntryMutation(self.0.clone())
    }

    fn observe(&self, core: Supervisor, epoch: u64) {
        let slot = Arc::downgrade(&self.0);
        let mut life = core.life();
        tokio::spawn(async move {
            loop {
                if let Life::Exited(e) = life.borrow().clone() {
                    if let Some(slot) = slot.upgrade() {
                        let _publication = slot.publication.lock().unwrap_or_else(|p| p.into_inner());
                        let current = slot.current.read().unwrap();
                        if slot.epoch.load(Ordering::SeqCst) == epoch && current.pid() == core.pid() {
                            slot.life.send_replace(Life::Exited(e));
                        }
                    }
                    break;
                }
                if life.changed().await.is_err() {
                    break;
                }
            }
        });
    }

    pub fn life(&self) -> watch::Receiver<Life> {
        self.0.life.subscribe()
    }

    pub fn pid(&self) -> u32 {
        self.snapshot().pid()
    }

    pub async fn request(&self, m: &str, p: Value, t: Duration) -> Result<Value> {
        if self.0.transition.load(Ordering::SeqCst) {
            return Err(Error::new("CORE_HANDOVER", "内核权限切换进行中，请稍候重试"));
        }
        let _entry = entry_mutation(m).then(|| self.invalidate_update_transport());
        self.snapshot().request(m, p, t).await
    }

    pub async fn request_public(&self, m: &str, p: Value, t: Duration) -> Result<Value> {
        if self.0.transition.load(Ordering::SeqCst) {
            if matches!(
                m,
                "hello"
                    | "status"
                    | "document.get"
                    | "logs.get"
                    | "logs.connections"
                    | "logs.kernel"
                    | "diagnostics.network"
            ) {
                let deadline = std::time::Instant::now() + Duration::from_secs(3);
                while self.0.transition.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            }
            if self.0.transition.load(Ordering::SeqCst) {
                return Err(Error::new("CORE_HANDOVER", "内核权限切换进行中，请稍候重试"));
            }
        }
        let _entry = entry_mutation(m).then(|| self.invalidate_update_transport());
        self.snapshot().request_public(m, p, t).await
    }

    pub async fn ensure_mutation_settled(&self) -> Result<()> {
        self.snapshot().ensure_mutation_settled().await
    }

    pub async fn hello(&self) -> Result<Value> {
        self.snapshot().hello().await
    }

    pub async fn prepare_update_shutdown(&self, grace: Duration) -> Result<()> {
        let _entry = self.invalidate_update_transport();
        let _launch = self
            .0
            .launch
            .try_lock()
            .map_err(|_| Error::new("CORE_BUSY", "内核重启或更新正在进行中"))?;
        self.snapshot().prepare_update_shutdown(grace).await
    }

    pub async fn resume_after_update_failure(&self) -> Result<()> {
        let _entry = self.invalidate_update_transport();
        {
            let mut launch = self
                .0
                .launch
                .try_lock()
                .map_err(|_| Error::new("CORE_BUSY", "内核重启或更新正在进行中"))?;
            let old = self.snapshot();
            if old.resume_after_update_failure().await? {
                let next = Supervisor::spawn_command(&mut launch).await?;
                {
                    let _p = self.0.publication.lock().unwrap_or_else(|p| p.into_inner());
                    self.0.epoch.fetch_add(1, Ordering::SeqCst);
                    *self.0.current.write().unwrap() = next.clone();
                    self.0.elevated_session.store(false, Ordering::SeqCst);
                }
                self.observe(next.clone(), self.0.epoch.load(Ordering::SeqCst));
                next.hello()
                    .await
                    .map_err(|_| Error::new("CORE_UPDATE_RECOVERY_FAILED", "未能确认恢复后的内核就绪状态"))?;
            } else {
                old.hello()
                    .await
                    .map_err(|_| Error::new("CORE_UPDATE_RECOVERY_FAILED", "未能确认原内核就绪状态"))?;
            }
        }
        self.0.life.send_replace(Life::Ready);
        Ok(())
    }

    pub async fn restart_process(&self, grace: Duration) -> Result<bool> {
        self.restart_ordinary(grace).await
    }

    async fn restart_ordinary(&self, grace: Duration) -> Result<bool> {
        let _entry = self.invalidate_update_transport();
        let mut launch = self
            .0
            .launch
            .try_lock()
            .map_err(|_| Error::new("CORE_BUSY", "内核正在重启中"))?;
        let old = {
            let current = self.0.current.write().unwrap();
            self.0.epoch.fetch_add(1, Ordering::SeqCst);
            current.clone()
        };
        let outcome = async {
            let forced = old.terminate(grace).await?;
            let next = Supervisor::spawn_command(&mut launch).await?;
            if let Err(e) = next.hello().await {
                next.shutdown().await;
                return Err(e);
            }
            *self.0.current.write().unwrap() = next.clone();
            self.0.elevated_session.store(false, Ordering::SeqCst);
            self.0.life.send_replace(Life::Ready);
            self.observe(next, self.0.epoch.load(Ordering::SeqCst));
            Ok(forced)
        }
        .await;
        if let Err(e) = &outcome {
            self.0.life.send_replace(Life::Exited(e.clone()));
        }
        outcome
    }

    pub async fn shutdown(&self) {
        let _entry = self.invalidate_update_transport();
        let _launch = self.0.launch.lock().await;
        let core = self.snapshot();
        if core.update_pending() {
            return;
        }
        self.0.epoch.fetch_add(1, Ordering::SeqCst);
        core.shutdown().await;
        self.0
            .life
            .send_replace(Life::Exited(Error::new("CORE_STOPPED", "内核监管器已停止")));
    }
}

#[cfg(windows)]
impl CoreProcess {
    pub(crate) fn elevated(&self) -> bool {
        self.snapshot().service_owned()
    }

    pub(crate) async fn begin_startup_elevation(&self) -> Result<Option<(Supervisor, String)>> {
        if self.elevated() {
            return Ok(None);
        }
        let old = self.snapshot();
        old.ensure_mutation_settled().await?;
        let hello = old.hello().await?;
        if !hello["capabilities"]
            .as_array()
            .is_some_and(|a| a.iter().any(|c| c == "host.handover.v1"))
        {
            return Err(Error::new(
                "HANDOVER_UNSUPPORTED",
                "启用 TUN 前请先安装完整匹配的客户端与内核版本",
            ));
        }
        let (next, lease) = crate::windows::elevated::begin(old.pid(), old.creation_stamp()).await?;
        Ok(Some((next, lease)))
    }

    pub(crate) async fn ensure_elevated(
        &self,
        rebind: impl FnOnce(&Supervisor, u64) -> Result<()>,
    ) -> Result<()> {
        if self.elevated() {
            return Ok(());
        }
        let _entry = self.invalidate_update_transport();
        let mut launch = self
            .0
            .launch
            .try_lock()
            .map_err(|_| Error::new("CORE_BUSY", "内核生命周期忙，请稍候重试"))?;
        let old = self.snapshot();
        old.ensure_mutation_settled().await?;
        let status = old.request("status", Value::Null, Duration::from_secs(5)).await?;
        let running = status.pointer("/runtime/state").and_then(Value::as_str) == Some("running");
        let hello = old.hello().await?;
        if !hello["capabilities"]
            .as_array()
            .is_some_and(|a| a.iter().any(|c| c == "host.handover.v1"))
        {
            return Err(Error::new(
                "HANDOVER_UNSUPPORTED",
                "启用 TUN 前请先安装完整匹配的客户端与内核版本",
            ));
        }
        let (next, lease) = crate::windows::elevated::begin(old.pid(), old.creation_stamp()).await?;
        self.finish_elevated_with_launch(&mut launch, old, running, next, lease, rebind)
            .await
    }

    pub(crate) async fn finish_startup_elevation(
        &self,
        pre: Option<(Supervisor, String)>,
        rebind: impl FnOnce(&Supervisor, u64) -> Result<()>,
    ) -> Result<()> {
        let Some((next, lease)) = pre else {
            return self.ensure_elevated(rebind).await;
        };
        if self.elevated() {
            let _ = next.terminate(Duration::from_secs(5)).await;
            crate::windows::elevated::abort(&lease).await;
            return Ok(());
        }
        let _entry = self.invalidate_update_transport();
        let mut launch = match self.0.launch.try_lock() {
            Ok(l) => l,
            Err(_) => {
                let _ = next.terminate(Duration::from_secs(5)).await;
                crate::windows::elevated::abort(&lease).await;
                return Err(Error::new("CORE_BUSY", "内核生命周期忙，请稍候重试"));
            }
        };
        let old = self.snapshot();
        let prep = async {
            old.ensure_mutation_settled().await?;
            let status = old.request("status", Value::Null, Duration::from_secs(5)).await?;
            Ok::<bool, Error>(status.pointer("/runtime/state").and_then(Value::as_str) == Some("running"))
        }
        .await;
        let running = match prep {
            Ok(r) => r,
            Err(e) => {
                let _ = next.terminate(Duration::from_secs(5)).await;
                crate::windows::elevated::abort(&lease).await;
                return Err(e);
            }
        };
        self.finish_elevated_with_launch(&mut launch, old, running, next, lease, rebind)
            .await
    }

    async fn finish_elevated_with_launch(
        &self,
        launch: &mut Command,
        old: Supervisor,
        running: bool,
        next: Supervisor,
        lease: String,
        rebind: impl FnOnce(&Supervisor, u64) -> Result<()>,
    ) -> Result<()> {
        let epoch = self.0.epoch.load(Ordering::SeqCst) + 1;
        if let Err(e) = rebind(&next, epoch) {
            let _ = next.terminate(Duration::from_secs(5)).await;
            crate::windows::elevated::abort(&lease).await;
            return Err(e);
        }
        self.0.transition.store(true, Ordering::SeqCst);
        {
            let _p = self.0.publication.lock().unwrap_or_else(|p| p.into_inner());
            self.0.epoch.store(epoch, Ordering::SeqCst);
        }
        let result = async {
            let checkpoint = old.prepare_handover_shutdown(Duration::from_secs(20)).await?;
            let proof = crate::windows::service_client::call(
                crate::service_protocol::ServiceRequest::Elevated {
                    request: crate::elevated_protocol::ElevatedRequest::Commit {
                        lease: lease.clone(),
                        checkpoint: checkpoint.clone(),
                    },
                },
            )
            .await?;
            let active = next
                .request(
                    "host.handover.activate",
                    serde_json::json!({ "proof": proof["proof"], "checkpoint": checkpoint }),
                    Duration::from_secs(20),
                )
                .await?;
            if active["active"] != true || active["epoch"] != proof["epoch"] {
                return Err(Error::new("HANDOVER_NOT_ACTIVE", "特权内核交接激活未确认"));
            }
            next.hello().await?;
            if running {
                next.request("core.start", Value::Null, Duration::from_secs(20)).await?;
            }
            Ok(())
        }
        .await;
        if result.is_ok() {
            self.0.elevated_session.store(true, Ordering::SeqCst);
            *self.0.current.write().unwrap() = next.clone();
            self.observe(next, epoch);
            self.0.life.send_replace(Life::Ready);
        } else {
            if let Err(e) = next.terminate(Duration::from_secs(8)).await {
                self.0.transition.store(false, Ordering::SeqCst);
                self.0.life.send_replace(Life::Exited(e.clone()));
                return Err(e);
            }
            crate::windows::elevated::abort(&lease).await;
            let recovery = async {
                if old.resume_after_update_failure().await? {
                    let replacement = Supervisor::spawn_command(launch).await?;
                    replacement.hello().await?;
                    if running {
                        replacement
                            .request("core.start", Value::Null, Duration::from_secs(20))
                            .await?;
                    }
                    *self.0.current.write().unwrap() = replacement.clone();
                    self.observe(replacement, epoch);
                } else {
                    if running {
                        old.request("core.start", Value::Null, Duration::from_secs(20)).await?;
                    }
                    self.observe(old.clone(), epoch);
                }
                Ok::<(), Error>(())
            }
            .await;
            if let Err(e) = recovery {
                self.0.life.send_replace(Life::Exited(e));
            } else {
                self.0.life.send_replace(Life::Ready);
            }
        }
        self.0.transition.store(false, Ordering::SeqCst);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_mutation_classifies_stateful_methods_only() {
        for m in [
            "document.apply",
            "core.reload",
            "core.start",
            "core.stop",
            "network.tun.disable",
            "network.tun.prepare",
            "network.tun.commit",
            "network.egress.set",
            "network.egress.pause",
            "host.prepare-update",
            "host.resume-update",
        ] {
            assert!(entry_mutation(m), "{m}");
        }
        for ro in ["hello", "status", "document.get", "logs.get", "diagnostics.network"] {
            assert!(!entry_mutation(ro), "{ro}");
        }
    }
}
