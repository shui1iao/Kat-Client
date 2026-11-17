//! Cross-platform update handoff protocol, post-UAC mutual authentication,
//! v0.2.19/v0.2.20 GUI shutdown state machine, and R2 residual-recovery process
//! ownership policy. Executed directly by the Windows backend and Linux tests.
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const DISPLAY_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const HIGH_INTEGRITY_RID: u32 = 0x3000;
pub const SYSTEM_SID: &str = "S-1-5-18";
pub const ADMINS_SID: &str = "S-1-5-32-544";

pub const MANAGED_CLIENT_ROLES: &[&str] = &[
    "kat-desktop.exe",
    "kat-client-core.exe",
    "kat-proxy-watchdog.exe",
    "kat-elevate-helper.exe",
];

pub fn handoff_denied() -> Error {
    Error::new("UPDATE_HANDOFF", "无法确认安装程序身份或安全交接；当前程序未被强制关闭")
}

pub fn valid_id(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

pub fn valid_tx(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn valid_kind(kind: &str, allow_uninstall: bool) -> bool {
    matches!(kind, "client" | "core" | "rollback" | "rollback-core")
        || (allow_uninstall && kind == "uninstall")
}

pub fn handoff_pipe_name(sid: &str, session: u32) -> String {
    format!(r"\\.\pipe\KatClientUpdate-v1-{sid}-{session}")
}

pub fn bridge_pipe_name(sid: &str, session: u32, bridge_pid: u32, bridge_stamp: u64) -> String {
    format!(r"\\.\pipe\KatClientBridge-v1-{sid}-{session}-{bridge_pid}-{bridge_stamp}")
}

pub fn approved_handoff_event_name(
    sid: &str,
    session: u32,
    bridge_pid: u32,
    bridge_stamp: u64,
) -> String {
    format!(r"Local\KatClientApprovedHandoff-v1-{sid}-{session}-{bridge_pid}-{bridge_stamp}")
}

/// Exact v0.2.19-compatible wire frame on `KatClientUpdate-v1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Prepare {
    pub schema: u32,
    pub phase: String,
    pub nonce: String,
    pub kind: String,
    pub offer: Option<String>,
}

/// Exact v0.2.19-compatible wire reply/ack frame on `KatClientUpdate-v1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    pub schema: u32,
    pub phase: String,
    pub nonce: String,
    pub error: Option<String>,
}

/// Private post-UAC coordination frame from elevated helper -> ordinary bridge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeRequest {
    pub schema: u32,
    pub phase: String,
    pub nonce: String,
    pub kind: String,
    pub offer: Option<String>,
}

/// Private post-UAC coordination reply from ordinary bridge -> elevated helper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeReply {
    pub schema: u32,
    pub phase: String,
    pub nonce: String,
    pub gui_was_running: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub fn validate_prepare(p: &Prepare, allow_uninstall: bool) -> Result<()> {
    if p.schema != 1
        || p.phase != "prepare"
        || !valid_id(&p.nonce)
        || !valid_kind(&p.kind, allow_uninstall)
        || p.offer.as_ref().is_some_and(|v| !valid_id(v))
        || (p.kind == "core" && p.offer.is_none())
        || (p.kind != "core" && p.offer.is_some())
    {
        return Err(handoff_denied());
    }
    Ok(())
}

pub fn parse_prepare(bytes: &[u8], allow_uninstall: bool) -> Result<Prepare> {
    let p: Prepare = serde_json::from_slice(bytes).map_err(|_| handoff_denied())?;
    validate_prepare(&p, allow_uninstall)?;
    Ok(p)
}

pub fn encode_prepare(nonce: &str, kind: &str, offer: Option<&str>) -> Result<Vec<u8>> {
    let p = Prepare {
        schema: 1,
        phase: "prepare".into(),
        nonce: nonce.into(),
        kind: kind.into(),
        offer: offer.map(str::to_owned),
    };
    validate_prepare(&p, true)?;
    serde_json::to_vec(&p).map_err(|_| handoff_denied())
}

pub fn encode_reply(nonce: &str, phase: &str, error: Option<&str>) -> Result<Vec<u8>> {
    serde_json::to_vec(&Reply {
        schema: 1,
        phase: phase.into(),
        nonce: nonce.into(),
        error: error.map(str::to_owned),
    })
    .map_err(|_| handoff_denied())
}

pub fn abort_code_to_error(raw: Option<&str>) -> Error {
    match raw.unwrap_or("UPDATE_HANDOFF") {
        "cancelled" | "UPDATE_CANCELLED" => {
            Error::new("UPDATE_CANCELLED", "已在当前客户端中取消更新；原连接与未保存状态已保留")
        }
        "INSTALL_GUI_RUNNING" => crate::installer_update::gui_running(),
        "CORE_MUTATION_UNCERTAIN" => crate::supervisor::mutation_uncertain(),
        "UPDATE_BUSY" => Error::new("UPDATE_BUSY", "当前客户端有正在进行的操作，暂未切换更新"),
        other => {
            const PREPARE_UPDATE_CODES: &[&str] = &[
                "CORE_UPDATE_IN_PROGRESS",
                "CORE_UPDATE_EXITED",
                "CORE_UPDATE_TRANSPORT",
                "CORE_UPDATE_UNSUPPORTED",
                "CORE_UPDATE_SOURCE_FAILED",
                "CORE_UPDATE_HISTORY_FAILED",
                "CORE_UPDATE_DRAIN_FAILED",
                "CORE_UPDATE_PREPARE_FAILED",
                "CORE_UPDATE_ACK_INVALID",
                "HANDOVER_CHECKPOINT",
                "CORE_UPDATE_FORCED",
                "CORE_UPDATE_EXIT_WAIT",
                "CORE_UPDATE_EXIT_NONZERO",
                "CORE_UPDATE_EXIT_TIMEOUT",
                "CORE_UPDATE_PREPARE_TIMEOUT",
            ];
            let code = PREPARE_UPDATE_CODES
                .iter()
                .copied()
                .find(|c| *c == other)
                .or_else(|| crate::safe_log::code(other))
                .unwrap_or("UPDATE_HANDOFF");
            Error::new(code, "原客户端未能完成状态保存与安全停机；已保留当前运行态")
        }
    }
}

pub fn parse_ready_or_abort(bytes: &[u8], expected_nonce: &str) -> Result<()> {
    let r: Reply = serde_json::from_slice(bytes).map_err(|_| handoff_denied())?;
    if r.schema != 1 || r.nonce != expected_nonce {
        return Err(handoff_denied());
    }
    match r.phase.as_str() {
        "ready" if r.error.is_none() => Ok(()),
        "abort" => Err(abort_code_to_error(r.error.as_deref())),
        _ => Err(handoff_denied()),
    }
}

pub fn parse_ack(bytes: &[u8], expected_nonce: &str) -> Result<()> {
    let r: Reply = serde_json::from_slice(bytes).map_err(|_| handoff_denied())?;
    if r.schema != 1 || r.phase != "ready" || r.nonce != expected_nonce || r.error.is_some() {
        return Err(handoff_denied());
    }
    Ok(())
}

pub fn encode_bridge_request(nonce: &str, kind: &str, offer: Option<&str>) -> Result<Vec<u8>> {
    if !valid_id(nonce)
        || !valid_kind(kind, true)
        || offer.is_some_and(|v| !valid_id(v))
        || (kind == "core") != offer.is_some()
    {
        return Err(handoff_denied());
    }
    serde_json::to_vec(&BridgeRequest {
        schema: 1,
        phase: "handoff_after_uac".into(),
        nonce: nonce.into(),
        kind: kind.into(),
        offer: offer.map(str::to_owned),
    })
    .map_err(|_| handoff_denied())
}

pub fn parse_bridge_request(bytes: &[u8]) -> Result<BridgeRequest> {
    let req: BridgeRequest = serde_json::from_slice(bytes).map_err(|_| handoff_denied())?;
    if req.schema != 1
        || req.phase != "handoff_after_uac"
        || !valid_id(&req.nonce)
        || !valid_kind(&req.kind, true)
        || req.offer.as_ref().is_some_and(|v| !valid_id(v))
        || (req.kind == "core") != req.offer.is_some()
    {
        return Err(handoff_denied());
    }
    Ok(req)
}

pub fn encode_bridge_reply(
    nonce: &str,
    phase: &str,
    gui_was_running: bool,
    error: Option<&str>,
) -> Result<Vec<u8>> {
    serde_json::to_vec(&BridgeReply {
        schema: 1,
        phase: phase.into(),
        nonce: nonce.into(),
        gui_was_running,
        error: error.map(str::to_owned),
    })
    .map_err(|_| handoff_denied())
}

pub fn parse_bridge_reply(bytes: &[u8], expected_nonce: &str) -> Result<bool> {
    let rep: BridgeReply = serde_json::from_slice(bytes).map_err(|_| handoff_denied())?;
    if rep.schema != 1 || rep.nonce != expected_nonce {
        return Err(handoff_denied());
    }
    match rep.phase.as_str() {
        "gui_stopped" if rep.error.is_none() => Ok(rep.gui_was_running),
        "abort" => Err(abort_code_to_error(rep.error.as_deref())),
        _ => Err(handoff_denied()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperPeerFacts {
    pub pid: u32,
    pub stamp: u64,
    pub sid: String,
    pub session: u32,
    pub elevated: bool,
    pub integrity: u32,
    pub expected_image_match: bool,
    pub hash_verified: bool,
}

/// Ordinary bridge verifies that the peer on `KatClientBridge-v1` is the exact
/// UAC-approved helper process spawned by `ShellExecuteExW("runas", ...)`.
pub fn verify_helper_peer_for_bridge(
    expected_pid: u32,
    expected_stamp: u64,
    bridge_sid: &str,
    bridge_session: u32,
    peer: &HelperPeerFacts,
) -> Result<()> {
    if expected_pid == 0
        || expected_stamp == 0
        || peer.pid != expected_pid
        || peer.stamp != expected_stamp
        || bridge_session == 0
        || peer.session != bridge_session
        || !bridge_sid.starts_with("S-1-5-21-")
        || peer.sid != bridge_sid
        || !peer.elevated
        || peer.integrity < HIGH_INTEGRITY_RID
        || !peer.expected_image_match
        || !peer.hash_verified
    {
        return Err(handoff_denied());
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeServerFacts {
    pub pid: u32,
    pub stamp: u64,
    pub sid: String,
    pub session: u32,
    pub elevated: bool,
    pub expected_image_match: bool,
}

/// Elevated helper verifies that `KatClientBridge-v1` belongs to its verified
/// initiating ordinary-user bridge process.
pub fn verify_bridge_server_for_helper(
    expected_pid: u32,
    expected_stamp: u64,
    helper_sid: &str,
    helper_session: u32,
    server: &BridgeServerFacts,
) -> Result<()> {
    if expected_pid == 0
        || expected_stamp == 0
        || server.pid != expected_pid
        || server.stamp != expected_stamp
        || helper_session == 0
        || server.session != helper_session
        || !helper_sid.starts_with("S-1-5-21-")
        || server.sid != helper_sid
        || server.elevated
        || !server.expected_image_match
    {
        return Err(handoff_denied());
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuiPeerFacts {
    pub sid: String,
    pub session: u32,
    pub impersonated_sid: Option<String>,
    pub elevated: bool,
    pub desktop_image_verified: bool,
    pub approved_helper_event_verified: bool,
}

/// Running GUI verifies the connecting ordinary bridge on `KatClientUpdate-v1`.
/// - `require_uac_event = false`: models legacy v0.2.19 GUI behavior (`TokenIsElevated == 0`
///   + signed/installed `kat-desktop.exe`).
/// - `require_uac_event = true`: v0.2.20 GUI additionally requires the unforgeable
///   admin/SYSTEM-owned `KatClientApprovedHandoff-v1` kernel event bound to that exact
///   bridge `(pid, stamp)`, rejecting pre-UAC or wrong-helper shutdown attempts.
pub fn verify_bridge_peer_for_gui(
    own_sid: &str,
    own_session: u32,
    require_uac_event: bool,
    peer: &GuiPeerFacts,
) -> Result<()> {
    if own_session == 0
        || !own_sid.starts_with("S-1-5-21-")
        || peer.session != own_session
        || peer.sid != own_sid
        || peer.impersonated_sid.as_deref() != Some(own_sid)
        || peer.elevated
        || !peer.desktop_image_verified
        || (require_uac_event && !peer.approved_helper_event_verified)
    {
        return Err(handoff_denied());
    }
    Ok(())
}

/// Protected kernel-object ownership check for `KatClientApprovedHandoff-v1`.
/// Only `SYSTEM` or `BUILTIN\Administrators` may own or modify the event.
pub fn verify_protected_event_acl(
    owner_sid: &str,
    writable_trustee_sids: &[String],
    signaled: bool,
) -> Result<()> {
    if !signaled || (owner_sid != SYSTEM_SID && owner_sid != ADMINS_SID) {
        return Err(handoff_denied());
    }
    if writable_trustee_sids
        .iter()
        .any(|s| s != SYSTEM_SID && s != ADMINS_SID)
    {
        return Err(handoff_denied());
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgePoll {
    HelperExited,
    BridgeConnected,
}

pub struct BridgeOutcome<I> {
    pub result: Result<()>,
    pub gui_was_running: bool,
    pub gui_stopped: bool,
    pub instance: Option<I>,
}

impl<I> BridgeOutcome<I> {
    /// Determines whether the bridge should launch the installed GUI after helper completion.
    /// - UAC cancelled or pre-handoff failure (`!gui_stopped`): NEVER reopen (original GUI
    ///   never exited, or user never had GUI open).
    /// - Post-handoff helper failure (`gui_stopped && result.is_err()`): reopen rolled-back GUI
    ///   when `gui_was_running` was true.
    /// - Helper succeeded (`result.is_ok()`): reopen iff `reopen_on_success` (true for
    ///   update/rollback bridges and non-deferred setup; false for `--defer-launch` / uninstall).
    pub fn should_reopen(&self, reopen_on_success: bool) -> bool {
        if self.result.is_ok() {
            reopen_on_success
        } else {
            self.gui_stopped && self.gui_was_running
        }
    }
}

pub trait BridgeBoundary {
    type Listener;
    type Helper;
    type Instance;

    fn open_bridge_listener(&mut self) -> Result<Self::Listener>;
    fn spawn_uac_helper(&mut self) -> Result<(Self::Helper, u32, u64)>;
    fn poll_helper_or_bridge(
        &mut self,
        helper: &mut Self::Helper,
        listener: &mut Self::Listener,
    ) -> Result<BridgePoll>;
    fn authenticate_and_read_bridge(
        &mut self,
        helper: &Self::Helper,
        listener: &mut Self::Listener,
        expected_pid: u32,
        expected_stamp: u64,
    ) -> Result<BridgeRequest>;
    fn disconnect_rejected_bridge(&mut self, listener: &mut Self::Listener);
    fn try_single_instance(&mut self) -> Result<Option<Self::Instance>>;
    fn handoff_running_gui(&mut self, prepare: &Prepare) -> Result<Self::Instance>;
    fn reply_bridge(&mut self, listener: &mut Self::Listener, bytes: Vec<u8>) -> Result<()>;
    fn finish_helper(&mut self, helper: Self::Helper) -> Result<()>;
}

/// Authoritative two-phase ordinary-bridge execution:
/// 1. Opens private `KatClientBridge-v1` listener BEFORE UAC without touching running GUI.
/// 2. Invokes UAC (`spawn_uac_helper`); if UAC is cancelled/fails, exits immediately with
///    `gui_stopped = false`.
/// 3. After UAC approval, accepts ONLY the exact spawned elevated helper (`pid + stamp +
///    elevated High-IL + verified image`), then performs ordinary-user `KatClientUpdate-v1`
///    handoff (compatible with both v0.2.19 and v0.2.20 GUIs) without `TerminateProcess`.
pub fn run_bridge_elevation<B: BridgeBoundary>(
    b: &mut B,
    expected_kind: &str,
    expected_offer: Option<&str>,
) -> BridgeOutcome<B::Instance> {
    let mut listener = match b.open_bridge_listener() {
        Ok(l) => l,
        Err(e) => {
            return BridgeOutcome {
                result: Err(e),
                gui_was_running: false,
                gui_stopped: false,
                instance: None,
            }
        }
    };
    let (mut helper, helper_pid, helper_stamp) = match b.spawn_uac_helper() {
        Ok(v) => v,
        Err(e) => {
            return BridgeOutcome {
                result: Err(e),
                gui_was_running: false,
                gui_stopped: false,
                instance: None,
            }
        }
    };
    let mut gui_was_running = false;
    let mut gui_stopped = false;
    let mut held_instance = None;
    let mut handoff_done = false;
    let mut handoff_abort_err: Option<Error> = None;

    while !handoff_done {
        match b.poll_helper_or_bridge(&mut helper, &mut listener) {
            Ok(BridgePoll::HelperExited) => break,
            Ok(BridgePoll::BridgeConnected) => {
                let req = match b.authenticate_and_read_bridge(
                    &helper,
                    &mut listener,
                    helper_pid,
                    helper_stamp,
                ) {
                    Ok(r) => r,
                    Err(_) => {
                        // Reject malicious/wrong peer on bridge pipe without touching running GUI;
                        // continue waiting for the real helper (or its exit).
                        b.disconnect_rejected_bridge(&mut listener);
                        continue;
                    }
                };
                if req.kind != expected_kind || req.offer.as_deref() != expected_offer {
                    let _ = encode_bridge_reply(&req.nonce, "abort", false, Some("UPDATE_HANDOFF"))
                        .and_then(|bytes| b.reply_bridge(&mut listener, bytes));
                    handoff_abort_err = Some(handoff_denied());
                    break;
                }
                match b.try_single_instance() {
                    Ok(Some(inst)) => {
                        gui_was_running = false;
                        gui_stopped = true;
                        held_instance = Some(inst);
                        let _ = encode_bridge_reply(&req.nonce, "gui_stopped", false, None)
                            .and_then(|bytes| b.reply_bridge(&mut listener, bytes));
                    }
                    Ok(None) => {
                        gui_was_running = true;
                        let prep = Prepare {
                            schema: 1,
                            phase: "prepare".into(),
                            nonce: req.nonce.clone(),
                            kind: req.kind.clone(),
                            offer: req.offer.clone(),
                        };
                        match b.handoff_running_gui(&prep) {
                            Ok(inst) => {
                                gui_stopped = true;
                                held_instance = Some(inst);
                                let _ = encode_bridge_reply(&req.nonce, "gui_stopped", true, None)
                                    .and_then(|bytes| b.reply_bridge(&mut listener, bytes));
                            }
                            Err(e) => {
                                let code = crate::safe_log::safe_code(&e.code);
                                let _ = encode_bridge_reply(&req.nonce, "abort", true, Some(&code))
                                    .and_then(|bytes| b.reply_bridge(&mut listener, bytes));
                                handoff_abort_err = Some(e);
                            }
                        }
                    }
                    Err(e) => {
                        let code = crate::safe_log::safe_code(&e.code);
                        let _ = encode_bridge_reply(&req.nonce, "abort", false, Some(&code))
                            .and_then(|bytes| b.reply_bridge(&mut listener, bytes));
                        handoff_abort_err = Some(e);
                    }
                }
                handoff_done = true;
            }
            Err(e) => {
                let _ = b.finish_helper(helper);
                return BridgeOutcome {
                    result: Err(e),
                    gui_was_running,
                    gui_stopped,
                    instance: held_instance,
                };
            }
        }
    }

    let helper_result = b.finish_helper(helper);
    let final_result = match (helper_result, handoff_abort_err) {
        (Ok(()), Some(abort)) => Err(abort),
        (Err(_), Some(abort)) => Err(abort),
        (other, None) => other,
    };
    BridgeOutcome {
        result: final_result,
        gui_was_running,
        gui_stopped,
        instance: held_instance,
    }
}

pub trait GuiHandoffResponder {
    fn read_prepare_frame(&mut self) -> Result<Vec<u8>>;
    fn inspect_peer(&mut self, kind: &str) -> Result<GuiPeerFacts>;
    fn is_awaiting_health_rollback(&self, kind: &str) -> bool;
    fn confirm_if_legacy_ui(&mut self, prepare: &Prepare) -> Result<bool>;
    fn execute_rollback_shutdown(&mut self) -> Result<()>;
    fn execute_normal_shutdown(&mut self) -> Result<()>;
    fn execute_recover_shutdown(&mut self);
    fn write_reply_frame(&mut self, bytes: Vec<u8>) -> Result<()>;
    fn read_ack_frame(&mut self) -> Result<Vec<u8>>;
    fn commit_clean_exit(&mut self) -> Result<()>;
}

/// Shared server-side `KatClientUpdate-v1` session state machine:
/// - `legacy_v0219_mode = true`: models exact v0.2.19 GUI behavior (`allow_uninstall = false`,
///   `require_uac_event = false`, prompts user confirmation before `execute_normal_shutdown`).
/// - `legacy_v0219_mode = false`: v0.2.20 GUI behavior (`allow_uninstall = true`,
///   `require_uac_event = true`, proceeds directly to `execute_normal_shutdown` once both
///   signed bridge AND protected UAC helper approval event are verified).
pub fn handle_gui_handoff_session<R: GuiHandoffResponder>(
    r: &mut R,
    own_sid: &str,
    own_session: u32,
    legacy_v0219_mode: bool,
) -> Result<bool> {
    let raw = r.read_prepare_frame()?;
    let request = parse_prepare(&raw, !legacy_v0219_mode)?;
    let peer = r.inspect_peer(&request.kind)?;
    verify_bridge_peer_for_gui(own_sid, own_session, !legacy_v0219_mode, &peer)?;

    if r.is_awaiting_health_rollback(&request.kind) {
        if let Err(e) = r.execute_rollback_shutdown() {
            r.write_reply_frame(encode_reply(&request.nonce, "abort", Some(&e.code))?)?;
            return Ok(false);
        }
    } else {
        if legacy_v0219_mode && !r.confirm_if_legacy_ui(&request)? {
            r.write_reply_frame(encode_reply(&request.nonce, "abort", Some("cancelled"))?)?;
            return Ok(false);
        }
        if let Err(e) = r.execute_normal_shutdown() {
            r.write_reply_frame(encode_reply(&request.nonce, "abort", Some(&e.code))?)?;
            return Ok(false);
        }
    }

    if let Err(e) = r
        .write_reply_frame(encode_reply(&request.nonce, "ready", None)?)
        .and_then(|_| {
            let ack = r.read_ack_frame()?;
            parse_ack(&ack, &request.nonce)
        })
    {
        r.execute_recover_shutdown();
        return Err(e);
    }

    if let Err(e) = r.commit_clean_exit() {
        r.execute_recover_shutdown();
        return Err(e);
    }
    Ok(true)
}

// ============================================================================
// R2: Target-directory + Image-identity + User/Session & SYSTEM-hosted Core
//     ownership verification for residual crash recovery ONLY.
// ============================================================================

pub fn normalize_windows_path(p: &str) -> String {
    let trimmed = p.trim_start_matches(r"\\?\").replace('/', r"\");
    let mut out = trimmed;
    while out.len() > 3 && out.ends_with('\\') {
        out.pop();
    }
    out.to_ascii_lowercase()
}

pub fn same_windows_path(a: &str, b: &str) -> bool {
    normalize_windows_path(a) == normalize_windows_path(b)
}

pub fn join_windows_path(dir: &str, leaf: &str) -> String {
    let mut base = dir.trim_start_matches(r"\\?\").replace('/', r"\");
    while base.len() > 3 && base.ends_with('\\') {
        base.pop();
    }
    if base.ends_with('\\') {
        format!("{base}{leaf}")
    } else {
        format!(r"{base}\{leaf}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceCoreOwnership {
    pub core_pid: u32,
    pub core_created: u64,
    pub owner_sid: String,
    pub session: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResidualCandidate {
    pub pid: u32,
    pub self_pid: u32,
    pub skip_pid: u32,
    pub exe_name: String,
    pub image_path: Option<String>,
    pub image_protected: bool,
    pub image_sha256: Option<String>,
    pub proc_sid: Option<String>,
    pub proc_session: Option<u32>,
    pub proc_stamp: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResidualTargetPolicy {
    pub target_root: String,
    pub target_sid: String,
    pub caller_session: u32,
    /// Role -> allowed SHA-256 digests from journal old_record / new_record.
    /// Empty map only when recovering a legacy schema-1 installation without per-file hashes.
    pub approved_role_hashes: BTreeMap<String, Vec<String>>,
    /// Populated from protected core-tun-journal-v2.json (LaunchIdentity) when present.
    pub service_core: Option<ServiceCoreOwnership>,
}

/// Evaluates whether `candidate` is an owned residual Kat client process eligible for
/// termination during dirty-journal recovery (`recover_before_new` / `clear_or_recover_before_setup`),
/// or during normal post-handoff non-destructive verification (`require_approved_hash = false`).
///
/// Strictly requires ALL THREE of:
/// 1. Target install directory (`image_path == <target_root>\<role>`), with ZERO name-OR fallback;
/// 2. Protected image ACL + journal-approved SHA-256 identity (when schema-2 hashes exist);
/// 3. User & session ownership (`proc_sid == target_sid` in matching non-zero interactive session,
///    OR `proc_sid == S-1-5-18` ONLY for `kat-client-core.exe` when authenticated
///    `ServiceCoreOwnership` proves SYSTEM is hosting this exact `(pid, proc_stamp)` on behalf of
///    `target_sid` in matching session).
pub fn evaluate_process_ownership(
    candidate: &ResidualCandidate,
    policy: &ResidualTargetPolicy,
    require_approved_hash: bool,
) -> bool {
    if candidate.pid == 0
        || candidate.pid == candidate.self_pid
        || (candidate.skip_pid != 0 && candidate.pid == candidate.skip_pid)
    {
        return false;
    }
    if !policy.target_sid.starts_with("S-1-5-21-") || policy.target_root.is_empty() {
        return false;
    }
    let role = candidate.exe_name.to_ascii_lowercase();
    if !MANAGED_CLIENT_ROLES.contains(&role.as_str()) {
        return false;
    }

    // 1. Exact target directory + role filename match (never name-only OR fallback).
    let Some(img) = candidate.image_path.as_deref() else {
        return false;
    };
    let expected_img = join_windows_path(&policy.target_root, &role);
    if !same_windows_path(img, &expected_img) {
        return false;
    }

    // 2. Protected ACL + cryptographic image identity.
    if !candidate.image_protected {
        return false;
    }
    if require_approved_hash && !policy.approved_role_hashes.is_empty() {
        let Some(allowed) = policy.approved_role_hashes.get(&role) else {
            return false;
        };
        if allowed.is_empty() {
            return false;
        }
        let Some(actual) = candidate.image_sha256.as_deref() else {
            return false;
        };
        if !allowed.iter().any(|h| h.eq_ignore_ascii_case(actual)) {
            return false;
        }
    }

    // 3. User & session ownership (distinguishing SYSTEM-hosted core via LaunchIdentity).
    let (Some(sid), Some(session)) = (candidate.proc_sid.as_deref(), candidate.proc_session) else {
        return false;
    };
    if sid == policy.target_sid {
        if session == 0 {
            return false;
        }
        if policy.caller_session != 0 && session != policy.caller_session {
            return false;
        }
        return true;
    }
    if sid == SYSTEM_SID && role == "kat-client-core.exe" {
        let (Some(stamp), Some(svc)) = (candidate.proc_stamp, policy.service_core.as_ref()) else {
            return false;
        };
        if svc.core_pid == candidate.pid
            && svc.core_created == stamp
            && svc.owner_sid == policy.target_sid
            && svc.session != 0
            && (policy.caller_session == 0 || svc.session == policy.caller_session)
        {
            return true;
        }
    }
    false
}

pub fn evaluate_residual_kill(
    candidate: &ResidualCandidate,
    policy: &ResidualTargetPolicy,
) -> bool {
    evaluate_process_ownership(candidate, policy, true)
}
