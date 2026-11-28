use crate::{
    core_process::CoreProcess as Supervisor,
    error::{Error, Result},
};
use super::{identity, proxy, watchdog};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{path::PathBuf, sync::Mutex, time::Duration};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwitchStatus {
    #[serde(default)]
    pub intent: bool,
    #[serde(default)]
    pub cleanup_pending: bool,
    pub enabled: bool,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl SwitchStatus {
    pub fn off() -> Self {
        Self {
            intent: false,
            cleanup_pending: false,
            enabled: false,
            state: "off".into(),
            error: None,
        }
    }
    pub fn error(code: &str) -> Self {
        Self {
            intent: false,
            cleanup_pending: false,
            enabled: false,
            state: "error".into(),
            error: Some(code.into()),
        }
    }
    pub fn on() -> Self {
        Self {
            intent: true,
            cleanup_pending: false,
            enabled: true,
            state: "on".into(),
            error: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub installed: bool,
    pub running: bool,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStatus {
    pub system_proxy: SwitchStatus,
    pub tun: SwitchStatus,
    pub service: ServiceStatus,
}

#[derive(Debug, Clone, Deserialize)]
struct LocalEntry {
    host: String,
    port: u16,
    ready: bool,
}

pub struct NetworkController {
    pub events: std::sync::Arc<Mutex<crate::safe_log::Ring>>,
    pub(super) tun_seen: Mutex<(u64, u64)>,
    pub(super) tun_attempt: std::sync::atomic::AtomicU64,
    pub(super) core: Option<Supervisor>,
    pub(super) desired_tun: std::sync::atomic::AtomicBool,
    pub(super) tun_safety_stop: std::sync::atomic::AtomicBool,
    pub(super) tun_engaged: std::sync::atomic::AtomicBool,
    pub(super) tun_fallback_ready: std::sync::atomic::AtomicBool,
    pub(super) operation: tokio::sync::Mutex<()>,
    pub(super) proxy_error: Mutex<Option<String>>,
    pub(super) watchdog: Mutex<Option<std::process::Child>>,
    pub(super) tun_error: Mutex<Option<String>>,
    pub(super) quit_waiting: std::sync::atomic::AtomicBool,
    pub(super) quit_notice: Mutex<Option<std::sync::Arc<dyn Fn(bool) + Send + Sync>>>,
    pub(super) last_status: Mutex<Option<NetworkStatus>>,
}

#[cfg(feature = "desktop")]
fn transport_error() -> Error {
    Error::new(
        "UPDATE_TRANSPORT_NOT_READY",
        "Kat 更新出口暂不可确认，请等待内核操作完成后重试；未发送 GitHub 请求",
    )
}

#[cfg(feature = "desktop")]
fn update_port(s: &Value) -> Result<Option<u16>> {
    match s.pointer("/runtime/state").and_then(Value::as_str) {
        Some("stopped") => Ok(None),
        Some("running") => {
            if s.pointer("/local/http/host").and_then(Value::as_str) != Some("127.0.0.1")
                || s.pointer("/local/http/ready") != Some(&Value::Bool(true))
            {
                return Err(transport_error());
            }
            let port = s
                .pointer("/local/http/port")
                .and_then(Value::as_u64)
                .and_then(|n| u16::try_from(n).ok())
                .filter(|p| *p != 0)
                .ok_or_else(transport_error)?;
            Ok(Some(port))
        }
        _ => Err(transport_error()),
    }
}

#[cfg(feature = "desktop")]
async fn verify_update_http(port: u16) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let verify = async {
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .map_err(|_| transport_error())?;
        stream
            .write_all(b"OPTIONS * HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .map_err(|_| transport_error())?;
        let mut reply = Vec::new();
        let mut byte = [0u8; 1];
        while !reply.ends_with(b"\r\n\r\n") {
            if reply.len() >= 8192 {
                return Err(transport_error());
            }
            stream.read_exact(&mut byte).await.map_err(|_| transport_error())?;
            reply.push(byte[0]);
        }
        let head = std::str::from_utf8(&reply).map_err(|_| transport_error())?;
        let mut lines = head.split("\r\n");
        let status = lines.next().unwrap_or("");
        let mut fields = status.split_whitespace();
        if !matches!(fields.next(), Some("HTTP/1.1" | "HTTP/1.0")) || fields.next() != Some("204") {
            return Err(transport_error());
        }
        let markers: Vec<_> = lines
            .filter_map(|line| line.split_once(':'))
            .filter(|(name, _)| name.eq_ignore_ascii_case("Kat-Client-Proxy"))
            .collect();
        if markers.len() != 1 || markers[0].1.trim() != "1" {
            return Err(transport_error());
        }
        Ok(())
    };
    tokio::time::timeout(Duration::from_secs(3), verify)
        .await
        .map_err(|_| transport_error())?
}

impl NetworkController {
    pub fn new(workspace: PathBuf, core: Option<Supervisor>) -> Result<Self> {
        if workspace != identity::workspace()? {
            return Err(Error::new("WORKSPACE_IDENTITY", "用户工作区路径与当前登录身份不一致"));
        }
        let err = proxy::restore().err().map(|e| e.code);
        Ok(Self {
            events: std::sync::Arc::new(Mutex::new(crate::safe_log::Ring::default())),
            tun_seen: Mutex::new((0, 0)),
            tun_attempt: std::sync::atomic::AtomicU64::new(0),
            core,
            desired_tun: std::sync::atomic::AtomicBool::new(false),
            tun_safety_stop: std::sync::atomic::AtomicBool::new(false),
            tun_engaged: std::sync::atomic::AtomicBool::new(false),
            tun_fallback_ready: std::sync::atomic::AtomicBool::new(false),
            operation: tokio::sync::Mutex::new(()),
            proxy_error: Mutex::new(err),
            watchdog: Mutex::new(None),
            tun_error: Mutex::new(None),
            quit_waiting: std::sync::atomic::AtomicBool::new(false),
            quit_notice: Mutex::new(None),
            last_status: Mutex::new(None),
        })
    }

    /// No operation lock survives this bounded snapshot; long HTTP workers never hold it.
    #[cfg(feature = "desktop")]
    pub(crate) async fn update_transport_snapshot(
        &self,
        deadline: std::time::Instant,
    ) -> Result<crate::update_check::UpdateTransport> {
        let busy = || {
            Error::new(
                "UPDATE_TRANSPORT_NOT_READY",
                "Kat 更新出口暂不可确认：原生网络操作进行中；未发送 GitHub 请求",
            )
        };
        let core = {
            let _lock = self.operation.try_lock().map_err(|_| busy())?;
            self.core.clone()
        };
        let transport = match core {
            Some(core) => {
                let op = async {
                    let identity = core.transport_identity().ok_or_else(transport_error)?;
                    core.ensure_mutation_settled().await.map_err(|_| transport_error())?;
                    let status = core
                        .request("status", Value::Null, Duration::from_secs(5))
                        .await
                        .map_err(|_| transport_error())?;
                    let port = update_port(&status)?;
                    if let Some(port) = port {
                        verify_update_http(port).await?;
                    }
                    if core.transport_identity() != Some(identity) {
                        return Err(transport_error());
                    }
                    let owner = core.clone();
                    Ok(crate::update_check::UpdateTransport::owned(
                        port,
                        identity,
                        core.publication_lock(),
                        move || owner.transport_identity() == Some(identity),
                    ))
                };
                let budget = deadline
                    .checked_duration_since(std::time::Instant::now())
                    .ok_or_else(transport_error)?
                    .min(Duration::from_secs(8));
                tokio::time::timeout(budget, op)
                    .await
                    .map_err(|_| transport_error())??
            }
            None => crate::update_check::UpdateTransport::direct(),
        };
        let _lock = self.operation.try_lock().map_err(|_| busy())?;
        transport.ensure_current().map_err(|_| busy())?;
        Ok(transport)
    }

    pub(super) async fn endpoint(&self, kind: &str) -> Result<u16> {
        let c = self
            .core
            .as_ref()
            .ok_or_else(|| Error::new("CORE_MISSING", "内核不可用"))?;
        let s = c.request("status", Value::Null, Duration::from_secs(5)).await?;
        if s.pointer("/runtime/state").and_then(Value::as_str) != Some("running") {
            return Err(Error::new("CORE_NOT_READY", "切换网络设置前请先启动内核"));
        }
        let e: LocalEntry = serde_json::from_value(
            s.pointer(&format!("/local/{kind}")).cloned().unwrap_or(Value::Null),
        )
        .map_err(|_| Error::new("CORE_NOT_READY", "内核本地入口状态暂不可用"))?;
        if e.host != "127.0.0.1" || e.port == 0 || !e.ready {
            return Err(Error::new("CORE_NOT_READY", "内核本地回环入口尚未就绪"));
        }
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let verify = async {
            let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", e.port))
                .await
                .map_err(|_| Error::new("CORE_NOT_READY", "无法连接内核本地回环入口"))?;
            let _ = stream.set_nodelay(true);
            if kind == "socks" {
                stream
                    .write_all(&[5, 1, 0])
                    .await
                    .map_err(|_| Error::new("CORE_NOT_READY", "SOCKS 握手失败"))?;
                let mut reply = [0u8; 2];
                stream
                    .read_exact(&mut reply)
                    .await
                    .map_err(|_| Error::new("CORE_NOT_READY", "SOCKS 握手失败"))?;
                if reply != [5, 0] {
                    return Err(Error::new("CORE_NOT_READY", "SOCKS 本地入口不可用"));
                }
            } else {
                stream
                    .write_all(b"OPTIONS * HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                    .await
                    .map_err(|_| Error::new("CORE_NOT_READY", "HTTP 握手失败"))?;
                let mut reply = [0u8; 8];
                stream
                    .read_exact(&mut reply)
                    .await
                    .map_err(|_| Error::new("CORE_NOT_READY", "HTTP 握手失败"))?;
                if &reply != b"HTTP/1.1" && &reply != b"HTTP/1.0" {
                    return Err(Error::new("CORE_NOT_READY", "HTTP 本地入口不可用"));
                }
            }
            Ok(e.port)
        };
        tokio::time::timeout(Duration::from_secs(3), verify)
            .await
            .map_err(|_| Error::new("CORE_NOT_READY", "内核本地入口握手超时"))?
    }

    pub async fn proxy_set(&self, enabled: bool) -> Result<NetworkStatus> {
        let _lock = self.operation.lock().await;
        self.proxy_set_unlocked(enabled).await
    }

    pub(super) async fn proxy_set_unlocked(&self, enabled: bool) -> Result<NetworkStatus> {
        self.ensure_core_mutation_settled().await?;
        let result = if enabled {
            let preferences =
                crate::preferences::load(&crate::user_store::Store::new(identity::workspace()?)?)?;
            let port = self.endpoint("http").await?;
            let c = self
                .core
                .as_ref()
                .ok_or_else(|| Error::new("CORE_NOT_READY", "内核不可用"))?;
            let mut w = self.watchdog.lock().unwrap();
            let alive = w.as_mut().is_some_and(|p| matches!(p.try_wait(), Ok(None)));
            if !alive {
                *w = Some(watchdog::spawn(c.pid())?);
            }
            let result = proxy::enable(port, preferences.custom_bypass());
            if result.is_err() {
                let _ = proxy::restore();
            }
            result
        } else {
            proxy::restore()
        };
        *self.proxy_error.lock().unwrap() = result.as_ref().err().map(|e| e.code.clone());
        result?;
        self.status_unlocked().await
    }

    pub async fn bootstrap_snapshot(&self) -> Result<(crate::error::bootstrap_proxy::Endpoint, Value)> {
        let expected = crate::error::bootstrap_proxy::snapshot(&self.operation, || async {
            self.ensure_core_mutation_settled().await?;
            let core = self
                .core
                .as_ref()
                .ok_or_else(|| Error::new("CORE_MISSING", "内核不可用"))?;
            let v = core
                .request("network.egress.get", Value::Null, Duration::from_secs(5))
                .await?;
            let engaged = self.tun_engaged.load(std::sync::atomic::Ordering::SeqCst);
            if engaged {
                let actual = core
                    .request("network.tun.status", serde_json::json!({}), Duration::from_secs(5))
                    .await?;
                if actual["enabled"] != true {
                    return Err(crate::error::bootstrap_proxy::failure("egress_unavailable", false));
                }
            }
            crate::error::bootstrap_proxy::egress_snapshot(&v, engaged)
        })
        .await?;
        let endpoint = tokio::task::spawn_blocking(super::proxy::bootstrap_endpoint)
            .await
            .map_err(|_| crate::error::bootstrap_proxy::failure("proxy_read_failed", false))??;
        Ok((endpoint, expected))
    }

    pub async fn status(&self) -> Result<NetworkStatus> {
        if let Ok(_lock) = self.operation.try_lock() {
            return self.status_unlocked().await;
        }
        self.status_fast()
    }

    fn status_fast(&self) -> Result<NetworkStatus> {
        let mut system_proxy = match proxy::enabled() {
            Ok(true) => SwitchStatus::on(),
            Ok(false) => match self.proxy_error.lock().unwrap().as_ref() {
                Some(e) => SwitchStatus::error(e),
                None => SwitchStatus::off(),
            },
            Err(e) => SwitchStatus::error(&e.code),
        };
        if let Some(error) = self.proxy_error.lock().unwrap().clone() {
            system_proxy.state = "error".into();
            system_proxy.error = Some(error);
        }
        let cached = self.last_status.lock().unwrap().clone();
        let service = match super::scm::query() {
            Ok((installed, running, _)) => ServiceStatus {
                installed,
                running,
                state: if !installed {
                    "absent"
                } else if running {
                    "running"
                } else {
                    "stopped"
                }
                .into(),
            },
            Err(_) => cached.as_ref().map(|s| s.service.clone()).unwrap_or(ServiceStatus {
                installed: false,
                running: false,
                state: "error".into(),
            }),
        };
        let engaged = self.tun_engaged.load(std::sync::atomic::Ordering::SeqCst);
        let desired = self.desired_tun.load(std::sync::atomic::Ordering::SeqCst);
        let mut tun = if let Some(err) = self.tun_error.lock().unwrap().clone() {
            SwitchStatus::error(&err)
        } else if engaged && !service.running {
            SwitchStatus::error("RECOVERY_PENDING")
        } else if engaged {
            SwitchStatus::on()
        } else if let Some(last) = cached {
            let mut t = last.tun;
            if !engaged && t.enabled {
                t.enabled = false;
                t.state = "off".into();
            }
            t
        } else {
            SwitchStatus::off()
        };
        tun.intent = desired;
        Ok(NetworkStatus {
            system_proxy,
            tun,
            service,
        })
    }

    pub(super) async fn status_unlocked(&self) -> Result<NetworkStatus> {
        let monitor_failed = {
            let mut w = self.watchdog.lock().unwrap();
            w.as_mut().is_some_and(|p| !matches!(p.try_wait(), Ok(None)))
        };
        if monitor_failed && proxy::enabled()? {
            let _ = proxy::restore();
            *self.proxy_error.lock().unwrap() = Some("WATCHDOG_EXITED".into());
        }
        let mut system_proxy = match proxy::enabled() {
            Ok(true) => SwitchStatus::on(),
            Ok(false) => match self.proxy_error.lock().unwrap().as_ref() {
                Some(e) => SwitchStatus::error(e),
                None => SwitchStatus::off(),
            },
            Err(e) => SwitchStatus::error(&e.code),
        };
        if let Some(error) = self.proxy_error.lock().unwrap().clone() {
            system_proxy.state = "error".into();
            system_proxy.error = Some(error);
        }
        let tun_error = { self.tun_error.lock().unwrap().clone() };
        let (mut tun, service) = super::service_client::status(tun_error, self).await?;
        if self.tun_engaged.load(std::sync::atomic::Ordering::SeqCst) && !service.running {
            tun = SwitchStatus::error("RECOVERY_PENDING");
        }
        tun.intent = self.desired_tun.load(std::sync::atomic::Ordering::SeqCst);
        let res = NetworkStatus {
            system_proxy,
            tun,
            service,
        };
        *self.last_status.lock().unwrap() = Some(res.clone());
        Ok(res)
    }

    pub async fn core_mutation(&self, method: &str, params: Value, timeout: Duration) -> Result<Value> {
        let _entry = self.core.as_ref().map(|c| c.invalidate_update_transport());
        let _lock = self.operation.lock().await;
        self.ensure_core_mutation_settled().await?;
        let core = self
            .core
            .as_ref()
            .ok_or_else(|| Error::new("CORE_MISSING", "内核不可用"))?;
        if method == "core.stop" {
            let p = proxy::restore();
            let t = self.tun_disable_unlocked().await;
            p?;
            t?;
            return core.request(method, params, timeout).await;
        }
        let input = if method == "document.apply" {
            Some(crate::document::validation_params(&params)?)
        } else {
            None
        };
        let saved = core.request("document.get", Value::Null, Duration::from_secs(5)).await?;
        let previous = crate::document::AcceptedDocument::from_reply(&saved)?;
        let prior = core.request("document.validate", previous.params(), timeout).await?;
        let previous =
            crate::document::ValidatedDocument::from_reply(&previous.text, previous.format, &prior)?;
        let next = if let Some(input) = input {
            let text = input["text"]
                .as_str()
                .ok_or_else(|| Error::new("INVALID_PARAMS", "配置文本不能为空"))?;
            let format = if let Some(f) = input.get("format") {
                serde_json::from_value(f.clone())
                    .map_err(|_| Error::new("INVALID_PARAMS", "配置格式参数无效"))?
            } else {
                previous.format()
            };
            let validated = core.request("document.validate", input.clone(), timeout).await?;
            crate::document::ValidatedDocument::from_reply(text, format, &validated)?
        } else {
            crate::document::ValidatedDocument::from_reply(previous.text(), previous.format(), &prior)?
        };
        next.ensure_enabled()?;
        let egress_before = if self.tun_engaged.load(std::sync::atomic::Ordering::SeqCst) {
            Some(
                core.request("network.egress.get", serde_json::json!({}), Duration::from_secs(5))
                    .await?,
            )
        } else {
            None
        };
        let before = core.request("status", Value::Null, Duration::from_secs(5)).await?;
        let running = before.pointer("/runtime/state").and_then(Value::as_str) == Some("running");
        let runtime = runtime_ports(&before);
        let restore = crate::apply_policy::assess(&previous, &next, runtime, running)?;
        if restore.system_proxy {
            proxy::restore()?;
        }
        if restore.tun {
            self.tun_disable_unlocked().await?;
        }
        let result = core.request(method, params, timeout).await?;
        let after = core.request("status", Value::Null, Duration::from_secs(5)).await;
        if running {
            let good = after.as_ref().ok().is_some_and(|s| {
                s.pointer("/runtime/state").and_then(Value::as_str) == Some("running")
                    && runtime_ports(s).is_some_and(|p| p == next.ports())
            });
            if !good {
                let p = proxy::restore();
                let t = self.tun_disable_unlocked().await;
                let _ = (p, t);
                return Err(Error::new(
                    "CORE_ENTRY_NOT_READY",
                    "配置变更已完成，但本地入口未就绪；已尝试恢复系统网络",
                ));
            }
        }
        if !restore.tun {
            if let Some(before) = egress_before {
                let after = core
                    .request("network.egress.get", serde_json::json!({}), Duration::from_secs(5))
                    .await;
                let intact = after.as_ref().ok().is_some_and(|a| {
                    a["enabled"] == before["enabled"]
                        && a["ready"] == before["ready"]
                        && [
                            "generation",
                            "metric_digest",
                            "gateway_digest",
                            "address_digest",
                            "schema",
                            "ipv4_if_index",
                            "ipv6_if_index",
                            "ipv4_luid",
                            "ipv6_luid",
                            "system_dns",
                            "fingerprint",
                            "identity",
                            "dns_revision",
                            "coverage",
                        ]
                        .iter()
                        .all(|k| a[*k] == before[*k])
                });
                if !intact {
                    let _ = self.tun_disable_unlocked().await;
                    return Err(Error::new(
                        "EGRESS_RELOAD_LOST",
                        "内核热重载后出口状态不一致；已自动恢复 TUN 网络",
                    ));
                }
            }
        }
        Ok(result)
    }

    pub(super) async fn ensure_core_mutation_settled(&self) -> Result<()> {
        if let Some(core) = &self.core {
            core.ensure_mutation_settled().await?;
        }
        Ok(())
    }

    pub async fn cleanup(&self) -> Result<()> {
        let _lock = self.operation.lock().await;
        self.ensure_core_mutation_settled().await?;
        let p = proxy::restore();
        let t = self.tun_disable_unlocked().await;
        if let Err(e) = &p {
            *self.proxy_error.lock().unwrap() = Some(e.code.clone());
        }
        p?;
        t
    }
}

fn runtime_ports(s: &Value) -> Option<crate::apply_policy::Ports> {
    for kind in ["http", "socks"] {
        if s.pointer(&format!("/local/{kind}/host")).and_then(Value::as_str) != Some("127.0.0.1")
            || s.pointer(&format!("/local/{kind}/ready")) != Some(&Value::Bool(true))
        {
            return None;
        }
    }
    Some(crate::apply_policy::Ports {
        http: u16::try_from(s.pointer("/local/http/port")?.as_u64()?).ok()?,
        socks: u16::try_from(s.pointer("/local/socks/port")?.as_u64()?).ok()?,
    })
}

impl crate::lifecycle::StartupOps for NetworkController {
    async fn start_core(&self) -> Result<()> {
        self.core
            .as_ref()
            .ok_or_else(|| Error::new("STARTUP_CORE_NOT_READY", "内核不可用"))?
            .request("core.start", Value::Null, Duration::from_secs(15))
            .await?;
        Ok(())
    }
    async fn preflight(&self, i: crate::preferences::NetworkIntent) -> Result<()> {
        if i.system_proxy {
            self.endpoint("http").await?;
        }
        if i.tun {
            let (installed, running, _) = super::scm::query()?;
            if !installed || !running {
                return Err(Error::new("SERVICE_NOT_READY", "恢复 TUN 需要已安装且运行中的网络服务"));
            }
            super::security::require_installed()?;
        }
        Ok(())
    }
    async fn proxy(&self) -> Result<()> {
        self.proxy_set(true).await?;
        Ok(())
    }
    async fn tun(&self) -> Result<()> {
        self.tun_set(true).await?;
        Ok(())
    }
    fn tun_failure_preserves_base(&self) -> bool {
        self.tun_fallback_ready.load(std::sync::atomic::Ordering::SeqCst)
    }
    async fn cleanup(&self) -> Result<()> {
        NetworkController::cleanup(self).await
    }
}

impl NetworkController {
    pub fn set_quit_notice(&self, f: impl Fn(bool) + Send + Sync + 'static) {
        *self.quit_notice.lock().unwrap() = Some(std::sync::Arc::new(f));
    }
}

impl crate::lifecycle::QuitOps for NetworkController {
    async fn cleanup(&self) -> Result<()> {
        self.quit_waiting.store(true, std::sync::atomic::Ordering::SeqCst);
        let r = NetworkController::cleanup(self).await;
        if !r.as_ref().is_err_and(|e| e.code == "RECOVERY_PENDING") {
            self.quit_waiting.store(false, std::sync::atomic::Ordering::SeqCst);
        }
        r
    }
    fn set_cleanup_waiting(&self, waiting: bool) {
        self.quit_waiting.store(waiting, std::sync::atomic::Ordering::SeqCst);
        if let Some(f) = self.quit_notice.lock().unwrap().clone() {
            f(waiting);
        }
    }
    async fn poll_cleanup_pending(&self) -> Result<bool> {
        let r = self.tun_poll_cleanup_pending().await;
        if !matches!(r, Ok(true)) {
            self.quit_waiting.store(false, std::sync::atomic::Ordering::SeqCst);
        }
        r
    }
    async fn stop_core(&self) {
        self.quit_waiting.store(false, std::sync::atomic::Ordering::SeqCst);
        if let Some(c) = &self.core {
            c.shutdown().await;
        }
    }
}

impl crate::lifecycle::AppRestartOps for NetworkController {
    async fn stop_for_app_restart(&self) -> Result<()> {
        let _entry = self.core.as_ref().map(|c| c.invalidate_update_transport());
        let _lock = self.operation.lock().await;
        self.ensure_core_mutation_settled().await?;
        if let Some(core) = &self.core {
            core.snapshot().terminate(Duration::from_secs(5)).await?;
        }
        if let Some(child) = self.watchdog.lock().unwrap().as_mut() {
            drop(child.stdin.take());
        }
        let _ = tokio::time::timeout(Duration::from_millis(500), async {
            loop {
                let done = {
                    let mut owned = self.watchdog.lock().unwrap();
                    match owned.as_mut() {
                        None => true,
                        Some(child) => {
                            drop(child.stdin.take());
                            match child.try_wait() {
                                Ok(Some(_)) => {
                                    owned.take();
                                    true
                                }
                                Ok(None) => false,
                                Err(_) => {
                                    owned.take();
                                    true
                                }
                            }
                        }
                    }
                };
                if done {
                    return Ok::<(), Error>(());
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        if let Some(mut child) = self.watchdog.lock().unwrap().take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = proxy::restore();
        Ok(())
    }
}

impl crate::lifecycle::RestartOps for NetworkController {
    async fn cleanup_for_restart(&self) -> Result<()> {
        let _lock = self.operation.lock().await;
        let p = proxy::restore();
        let t = self.tun_recover_owned_unlocked().await;
        if let Err(e) = &p {
            *self.proxy_error.lock().unwrap() = Some(e.code.clone());
        }
        p?;
        t
    }
    async fn stop_running_core(&self) -> Result<()> {
        let _lock = self.operation.lock().await;
        let core = self
            .core
            .as_ref()
            .ok_or_else(|| Error::new("CORE_UNAVAILABLE", "内核不可用"))?;
        core.restart_process(Duration::from_secs(5)).await?;
        self.drain_previous_watchdog().await
    }
}

impl NetworkController {
    pub(super) async fn drain_previous_watchdog(&self) -> Result<()> {
        if let Some(child) = self.watchdog.lock().unwrap().as_mut() {
            drop(child.stdin.take());
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let done = {
                    let mut owned = self.watchdog.lock().unwrap();
                    match owned.as_mut() {
                        None => true,
                        Some(child) => {
                            drop(child.stdin.take());
                            match child.try_wait() {
                                Ok(Some(_)) => {
                                    owned.take();
                                    true
                                }
                                Ok(None) => false,
                                Err(_) => {
                                    return Err(Error::new("WATCHDOG_WAIT", "无法确认上一代代理解除监视器退出"))
                                }
                            }
                        }
                    }
                };
                if done {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| Error::new("WATCHDOG_WAIT", "上一代代理解除监视器尚未结束；系统网络已保持恢复"))??;
        Ok(())
    }

    pub async fn prepare_update_shutdown(&self) -> Result<()> {
        let _entry = self.core.as_ref().map(|c| c.invalidate_update_transport());
        self.cleanup().await?;
        let _lock = self.operation.lock().await;
        self.ensure_core_mutation_settled().await?;
        let core = self
            .core
            .as_ref()
            .ok_or_else(|| Error::new("UPDATE_SAVE", "内核不可用，无法证明状态保存成功"))?;
        core.prepare_update_shutdown(Duration::from_secs(30)).await?;
        if let Some(child) = self.watchdog.lock().unwrap().as_mut() {
            drop(child.stdin.take());
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let done = {
                    let mut owned = self.watchdog.lock().unwrap();
                    match owned.as_mut() {
                        None => true,
                        Some(child) => {
                            drop(child.stdin.take());
                            match child.try_wait() {
                                Ok(Some(status)) => {
                                    owned.take();
                                    if !status.success() {
                                        return Err(Error::new(
                                            "WATCHDOG_WAIT",
                                            "恢复网络监视器未正常结束，更新未执行",
                                        ));
                                    }
                                    true
                                }
                                Ok(None) => false,
                                Err(_) => {
                                    return Err(Error::new(
                                        "WATCHDOG_WAIT",
                                        "无法确认恢复网络监视器退出",
                                    ))
                                }
                            }
                        }
                    }
                };
                if done {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .map_err(|_| Error::new("WATCHDOG_WAIT", "恢复网络监视器尚未退出，更新未执行"))?
    }

    #[cfg(feature = "desktop")]
    pub(crate) async fn finish_recovered_epoch(&self) -> Result<()> {
        if let Some(child) = self.watchdog.lock().unwrap().as_mut() {
            drop(child.stdin.take());
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let done = {
                    let mut old = self.watchdog.lock().unwrap();
                    match old.as_mut() {
                        None => true,
                        Some(child) => {
                            drop(child.stdin.take());
                            match child.try_wait() {
                                Ok(Some(status)) => {
                                    old.take();
                                    if !status.success() {
                                        return Err(Error::new(
                                            "WATCHDOG_WAIT",
                                            "上一轮代理解除监视器恢复失败",
                                        ));
                                    }
                                    true
                                }
                                Ok(None) => false,
                                Err(_) => {
                                    return Err(Error::new(
                                        "WATCHDOG_WAIT",
                                        "上一轮代理解除监视器退出状态不确定",
                                    ))
                                }
                            }
                        }
                    }
                };
                if done {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .map_err(|_| Error::new("WATCHDOG_WAIT", "上一轮代理解除监视器尚未退出"))?
    }

    pub(super) async fn recover_handover_proxy_unlocked(
        &self,
        intent: Option<&crate::ownership::ProxyJournal>,
    ) -> Result<()> {
        let previous = self.watchdog.lock().unwrap().take();
        if let Some(mut child) = previous {
            let (child, result) = tokio::task::spawn_blocking(move || {
                let result = crate::watchdog_control::retire(&mut child);
                (child, result)
            })
            .await
            .map_err(|_| Error::new("WATCHDOG_WAIT", "上一代监视器退役状态不确定"))?;
            if let Err(e) = result {
                *self.watchdog.lock().unwrap() = Some(child);
                let _ = proxy::restore();
                return Err(e);
            }
        }
        proxy::restore()?;
        let Some(intent) = intent else { return Ok(()) };
        let core = self
            .core
            .as_ref()
            .ok_or_else(|| Error::new("CORE_MISSING", "恢复后的内核不可用"))?;
        if !matches!(*core.life().borrow(), crate::supervisor::Life::Ready) {
            return Err(Error::new("CORE_NOT_READY", "恢复后的内核就绪状态未确认"));
        }
        core.hello().await?;
        let _ = self.endpoint("http").await?;
        let child = watchdog::spawn(core.pid())?;
        *self.watchdog.lock().unwrap() = Some(child);
        if let Err(e) = proxy::resume_handover(intent) {
            let _ = proxy::restore();
            return Err(e);
        }
        let alive = {
            let mut w = self.watchdog.lock().unwrap();
            w.as_mut().is_some_and(|c| matches!(c.try_wait(), Ok(None)))
        };
        if !alive {
            let _ = proxy::restore();
            return Err(Error::new("WATCHDOG_EXITED", "恢复后的代理监视器异常退出"));
        }
        *self.proxy_error.lock().unwrap() = None;
        Ok(())
    }
}
