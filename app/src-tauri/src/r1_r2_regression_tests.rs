//! Behavioral regression tests for R1 (post-UAC authenticated smooth handoff,
//! v0.2.19 running-GUI upgrade compatibility, UAC cancel preservation, malicious
//! peer rejection, ack/prepare failure recovery), R2 (target-dir + approved hash +
//! SID/session + SYSTEM LaunchIdentity residual kill policy), and DisplayVersion.
use crate::{
    error::{Error, Result},
    preferences::{self, CloseAction, DesktopPreferences, NetworkIntent, StartupPlan},
    update_handoff_protocol::*,
    user_store::Store,
    window_geometry::{self, Rect, WindowState},
};
use std::collections::{BTreeMap, VecDeque};

const USER_A: &str = "S-1-5-21-1111111111-2222222222-3333333333-1001";
const USER_B: &str = "S-1-5-21-1111111111-2222222222-3333333333-1002";
const VALID_NONCE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const VALID_OFFER: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

fn temp_workspace(tag: &str) -> std::path::PathBuf {
    static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "kat-r1r2-{tag}-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[derive(Default)]
struct SimulatedGuiServer {
    legacy_v0219: bool,
    awaiting_health_rollback: bool,
    legacy_user_confirms: bool,
    peer_facts: Option<GuiPeerFacts>,
    prepare_in: Vec<u8>,
    ack_in: Option<Vec<u8>>,
    replies_out: Vec<Vec<u8>>,
    fail_shutdown_code: Option<&'static str>,
    fail_commit_exit: bool,
    store_dir: Option<std::path::PathBuf>,
    core_running_before_handoff: bool,
    unpersisted_draft_preserved: bool,
    window_saved: bool,
    intent_verified: bool,
    core_prepare_update_called: bool,
    recover_called: bool,
    exited_zero: bool,
}

impl GuiHandoffResponder for SimulatedGuiServer {
    fn read_prepare_frame(&mut self) -> Result<Vec<u8>> {
        if self.prepare_in.is_empty() {
            return Err(handoff_denied());
        }
        Ok(self.prepare_in.clone())
    }
    fn inspect_peer(&mut self, _kind: &str) -> Result<GuiPeerFacts> {
        self.peer_facts.clone().ok_or_else(handoff_denied)
    }
    fn is_awaiting_health_rollback(&self, kind: &str) -> bool {
        self.awaiting_health_rollback && matches!(kind, "rollback" | "rollback-core")
    }
    fn confirm_if_legacy_ui(&mut self, _prepare: &Prepare) -> Result<bool> {
        Ok(self.legacy_user_confirms)
    }
    fn execute_rollback_shutdown(&mut self) -> Result<()> {
        if let Some(code) = self.fail_shutdown_code {
            return Err(Error::new(code, "simulated rollback shutdown error"));
        }
        self.core_prepare_update_called = true;
        Ok(())
    }
    fn execute_normal_shutdown(&mut self) -> Result<()> {
        if let Some(dir) = &self.store_dir {
            let store = Store::new(dir.clone())?;
            let _intent = preferences::intent(&store)?;
            self.intent_verified = true;
            window_geometry::save(
                &store,
                &WindowState {
                    schema: 1,
                    normal: Rect {
                        x: 140,
                        y: 90,
                        width: 1180,
                        height: 760,
                    },
                    work: Rect {
                        x: 0,
                        y: 40,
                        width: 1920,
                        height: 1040,
                    },
                    dpi: 96,
                    maximized: false,
                },
            )?;
            self.window_saved = true;
            store.save(
                "update-resume.json",
                &serde_json::json!({
                    "schema": 1,
                    "at": 1794901000u64,
                    "core_running": self.core_running_before_handoff,
                }),
                1024,
            )?;
        }
        if let Some(code) = self.fail_shutdown_code {
            self.execute_recover_shutdown();
            return Err(Error::new(code, "simulated prepare_shutdown failure"));
        }
        self.core_prepare_update_called = true;
        Ok(())
    }
    fn execute_recover_shutdown(&mut self) {
        self.recover_called = true;
    }
    fn write_reply_frame(&mut self, bytes: Vec<u8>) -> Result<()> {
        self.replies_out.push(bytes);
        Ok(())
    }
    fn read_ack_frame(&mut self) -> Result<Vec<u8>> {
        self.ack_in.clone().ok_or_else(handoff_denied)
    }
    fn commit_clean_exit(&mut self) -> Result<()> {
        if self.fail_commit_exit {
            return Err(Error::new("UPDATE_EXIT_FAILED", "simulated exit scheduling failure"));
        }
        self.exited_zero = true;
        Ok(())
    }
}

enum BridgeStep {
    PeerAttempt {
        facts: HelperPeerFacts,
        raw_request: Vec<u8>,
    },
    HelperExit(Result<()>),
}

struct SimulatedBridgeHarness {
    uac_result: Result<(u32, u64)>,
    steps: VecDeque<BridgeStep>,
    gui_already_stopped: bool,
    running_gui: Option<SimulatedGuiServer>,
    bridge_peer_facts_for_gui: GuiPeerFacts,
    disconnected_malicious_peers: usize,
    bridge_replies: Vec<BridgeReply>,
    handoff_attempted: bool,
}

impl BridgeBoundary for SimulatedBridgeHarness {
    type Listener = ();
    type Helper = (u32, u64);
    type Instance = &'static str;

    fn open_bridge_listener(&mut self) -> Result<Self::Listener> {
        Ok(())
    }
    fn spawn_uac_helper(&mut self) -> Result<(Self::Helper, u32, u64)> {
        let (pid, stamp) = self.uac_result.clone()?;
        Ok(((pid, stamp), pid, stamp))
    }
    fn poll_helper_or_bridge(
        &mut self,
        _helper: &mut Self::Helper,
        _listener: &mut Self::Listener,
    ) -> Result<BridgePoll> {
        match self.steps.front() {
            Some(BridgeStep::PeerAttempt { .. }) => Ok(BridgePoll::BridgeConnected),
            Some(BridgeStep::HelperExit(_)) | None => Ok(BridgePoll::HelperExited),
        }
    }
    fn authenticate_and_read_bridge(
        &mut self,
        helper: &Self::Helper,
        _listener: &mut Self::Listener,
        expected_pid: u32,
        expected_stamp: u64,
    ) -> Result<BridgeRequest> {
        assert_eq!(*helper, (expected_pid, expected_stamp));
        let Some(BridgeStep::PeerAttempt { facts, raw_request }) = self.steps.pop_front() else {
            return Err(handoff_denied());
        };
        verify_helper_peer_for_bridge(expected_pid, expected_stamp, USER_A, 1, &facts)?;
        parse_bridge_request(&raw_request)
    }
    fn disconnect_rejected_bridge(&mut self, _listener: &mut Self::Listener) {
        self.disconnected_malicious_peers += 1;
    }
    fn try_single_instance(&mut self) -> Result<Option<Self::Instance>> {
        if self.gui_already_stopped {
            Ok(Some("singleton-acquired-directly"))
        } else {
            Ok(None)
        }
    }
    fn handoff_running_gui(&mut self, prepare: &Prepare) -> Result<Self::Instance> {
        self.handoff_attempted = true;
        let gui = self.running_gui.as_mut().ok_or_else(handoff_denied)?;
        gui.prepare_in = encode_prepare(&prepare.nonce, &prepare.kind, prepare.offer.as_deref())?;
        gui.peer_facts = Some(self.bridge_peer_facts_for_gui.clone());
        gui.ack_in = Some(encode_reply(&prepare.nonce, "ready", None)?);
        let legacy = gui.legacy_v0219;
        let exited = handle_gui_handoff_session(gui, USER_A, 1, legacy)?;
        let reply_frame = gui.replies_out.last().ok_or_else(handoff_denied)?.clone();
        parse_ready_or_abort(&reply_frame, &prepare.nonce)?;
        if !exited || !gui.exited_zero {
            return Err(handoff_denied());
        }
        Ok("singleton-acquired-after-clean-gui-exit0")
    }
    fn reply_bridge(&mut self, _listener: &mut Self::Listener, bytes: Vec<u8>) -> Result<()> {
        let parsed: BridgeReply = serde_json::from_slice(&bytes).map_err(|_| handoff_denied())?;
        self.bridge_replies.push(parsed);
        Ok(())
    }
    fn finish_helper(&mut self, _helper: Self::Helper) -> Result<()> {
        match self.steps.pop_front() {
            Some(BridgeStep::HelperExit(res)) => res,
            _ => Ok(()),
        }
    }
}

#[test]
fn display_version_matches_cargo_pkg_version_0_2_20() {
    assert_eq!(DISPLAY_VERSION, "0.2.21");
    assert_eq!(DISPLAY_VERSION, env!("CARGO_PKG_VERSION"));
}

#[test]
fn r1_new_setup_upgrades_running_v0219_gui_via_ordinary_bridge_and_preserves_state() {
    let ws = temp_workspace("v0219-upgrade");
    let store = Store::new(ws.clone()).unwrap();
    // Save user proxy + TUN intent before upgrade.
    preferences::save(
        &store,
        &DesktopPreferences {
            close_action: CloseAction::Tray,
            remember_window: true,
            ..Default::default()
        },
    )
    .unwrap();
    preferences::set_intent(&store, Some(true), Some(true)).unwrap();

    // 1. Prove why direct elevated helper -> v0.2.19 GUI would fail: v0.2.19 rejects elevated!=false.
    let elevated_peer = GuiPeerFacts {
        sid: USER_A.into(),
        session: 1,
        impersonated_sid: Some(USER_A.into()),
        elevated: true,
        desktop_image_verified: true,
        approved_helper_event_verified: true,
    };
    assert_eq!(
        verify_bridge_peer_for_gui(USER_A, 1, false, &elevated_peer)
            .unwrap_err()
            .code,
        "UPDATE_HANDOFF",
        "v0.2.19 GUI strictly rejects elevated peers"
    );

    // 2. Post-UAC two-stage handoff: elevated helper -> ordinary setup_bridge -> running v0.2.19 GUI.
    let helper_pid = 4242;
    let helper_stamp = 99887766;
    let req_bytes = encode_bridge_request(VALID_NONCE, "client", None).unwrap();
    let mut harness = SimulatedBridgeHarness {
        uac_result: Ok((helper_pid, helper_stamp)),
        steps: VecDeque::from([
            BridgeStep::PeerAttempt {
                facts: HelperPeerFacts {
                    pid: helper_pid,
                    stamp: helper_stamp,
                    sid: USER_A.into(),
                    session: 1,
                    elevated: true,
                    integrity: HIGH_INTEGRITY_RID,
                    expected_image_match: true,
                    hash_verified: true,
                },
                raw_request: req_bytes,
            },
            BridgeStep::HelperExit(Ok(())),
        ]),
        gui_already_stopped: false,
        running_gui: Some(SimulatedGuiServer {
            legacy_v0219: true,
            legacy_user_confirms: true,
            store_dir: Some(ws.clone()),
            core_running_before_handoff: true,
            ..Default::default()
        }),
        bridge_peer_facts_for_gui: GuiPeerFacts {
            sid: USER_A.into(),
            session: 1,
            impersonated_sid: Some(USER_A.into()),
            elevated: false, // Ordinary kat-desktop.exe bridge satisfies v0.2.19!
            desktop_image_verified: true,
            approved_helper_event_verified: true,
        },
        disconnected_malicious_peers: 0,
        bridge_replies: vec![],
        handoff_attempted: false,
    };

    let outcome = run_bridge_elevation(&mut harness, "client", None);
    assert!(outcome.result.is_ok());
    assert!(outcome.gui_was_running);
    assert!(outcome.gui_stopped);
    assert_eq!(outcome.instance, Some("singleton-acquired-after-clean-gui-exit0"));
    assert_eq!(harness.bridge_replies.len(), 1);
    assert_eq!(harness.bridge_replies[0].phase, "gui_stopped");
    parse_bridge_reply(
        &serde_json::to_vec(&harness.bridge_replies[0]).unwrap(),
        VALID_NONCE,
    )
    .unwrap();

    let gui = harness.running_gui.unwrap();
    assert!(gui.window_saved);
    assert!(gui.intent_verified);
    assert!(gui.core_prepare_update_called);
    assert!(gui.exited_zero);
    assert!(!gui.recover_called);

    // Verify saved window geometry, startup/network intent, and update-resume.json on disk.
    let saved_geom = window_geometry::load(&store).unwrap().unwrap();
    assert_eq!((saved_geom.normal.width, saved_geom.normal.height), (1180, 760));
    assert_eq!(
        preferences::startup_plan(preferences::intent(&store).unwrap()),
        StartupPlan::Restore(NetworkIntent {
            system_proxy: true,
            tun: true
        })
    );
    let resume: serde_json::Value = store.load("update-resume.json", 1024).unwrap().unwrap();
    assert_eq!(resume["core_running"], serde_json::json!(true));
    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn r1_uac_cancelled_never_signals_running_v0219_or_v0220_gui_and_never_reopens() {
    for legacy_v0219 in [true, false] {
        let mut harness = SimulatedBridgeHarness {
            uac_result: Err(Error::new("UPDATE_UAC_CANCELLED", "user cancelled UAC").native(1223)),
            steps: VecDeque::new(),
            gui_already_stopped: false,
            running_gui: Some(SimulatedGuiServer {
                legacy_v0219,
                unpersisted_draft_preserved: true,
                ..Default::default()
            }),
            bridge_peer_facts_for_gui: GuiPeerFacts {
                sid: USER_A.into(),
                session: 1,
                impersonated_sid: Some(USER_A.into()),
                elevated: false,
                desktop_image_verified: true,
                approved_helper_event_verified: false,
            },
            disconnected_malicious_peers: 0,
            bridge_replies: vec![],
            handoff_attempted: false,
        };

        let outcome = run_bridge_elevation(&mut harness, "core", Some(VALID_OFFER));
        assert_eq!(outcome.result.as_ref().unwrap_err().code, "UPDATE_UAC_CANCELLED");
        assert!(!outcome.gui_was_running);
        assert!(!outcome.gui_stopped);
        assert!(outcome.instance.is_none());
        assert!(!outcome.should_reopen(true), "cancelled UAC must never reopen a duplicate GUI");
        assert!(!harness.handoff_attempted, "cancelled UAC must never touch KatClientUpdate-v1");

        let gui = harness.running_gui.unwrap();
        assert!(gui.unpersisted_draft_preserved);
        assert!(!gui.core_prepare_update_called);
        assert!(!gui.exited_zero);
    }
}

#[test]
fn r1_malicious_and_unauthenticated_peers_rejected_at_every_boundary() {
    let helper_pid = 7777;
    let helper_stamp = 555555;
    let valid_req = encode_bridge_request(VALID_NONCE, "core", Some(VALID_OFFER)).unwrap();

    // 1. Pre-UAC / unprivileged / wrong-PID / wrong-stamp / wrong-SID / wrong-session / low-IL
    //    peers attempting to trigger handoff on `KatClientBridge-v1` are all disconnected while
    //    the real elevated helper that connects afterward still succeeds!
    let bad_peers = [
        // Unprivileged medium-IL process with same SID
        HelperPeerFacts {
            pid: helper_pid,
            stamp: helper_stamp,
            sid: USER_A.into(),
            session: 1,
            elevated: false,
            integrity: 0x2000,
            expected_image_match: true,
            hash_verified: true,
        },
        // Elevated process with wrong PID (not spawned by this bridge)
        HelperPeerFacts {
            pid: helper_pid + 1,
            stamp: helper_stamp,
            sid: USER_A.into(),
            session: 1,
            elevated: true,
            integrity: HIGH_INTEGRITY_RID,
            expected_image_match: true,
            hash_verified: true,
        },
        // Recycled PID with mismatched creation stamp
        HelperPeerFacts {
            pid: helper_pid,
            stamp: helper_stamp + 1,
            sid: USER_A.into(),
            session: 1,
            elevated: true,
            integrity: HIGH_INTEGRITY_RID,
            expected_image_match: true,
            hash_verified: true,
        },
        // Different administrator SID
        HelperPeerFacts {
            pid: helper_pid,
            stamp: helper_stamp,
            sid: USER_B.into(),
            session: 1,
            elevated: true,
            integrity: HIGH_INTEGRITY_RID,
            expected_image_match: true,
            hash_verified: true,
        },
        // Unapproved helper image hash
        HelperPeerFacts {
            pid: helper_pid,
            stamp: helper_stamp,
            sid: USER_A.into(),
            session: 1,
            elevated: true,
            integrity: HIGH_INTEGRITY_RID,
            expected_image_match: true,
            hash_verified: false,
        },
    ];

    let mut steps: VecDeque<BridgeStep> = bad_peers
        .into_iter()
        .map(|facts| BridgeStep::PeerAttempt {
            facts,
            raw_request: valid_req.clone(),
        })
        .collect();
    steps.push_back(BridgeStep::PeerAttempt {
        facts: HelperPeerFacts {
            pid: helper_pid,
            stamp: helper_stamp,
            sid: USER_A.into(),
            session: 1,
            elevated: true,
            integrity: HIGH_INTEGRITY_RID,
            expected_image_match: true,
            hash_verified: true,
        },
        raw_request: valid_req,
    });
    steps.push_back(BridgeStep::HelperExit(Ok(())));

    let mut harness = SimulatedBridgeHarness {
        uac_result: Ok((helper_pid, helper_stamp)),
        steps,
        gui_already_stopped: false,
        running_gui: Some(SimulatedGuiServer {
            legacy_v0219: false,
            ..Default::default()
        }),
        bridge_peer_facts_for_gui: GuiPeerFacts {
            sid: USER_A.into(),
            session: 1,
            impersonated_sid: Some(USER_A.into()),
            elevated: false,
            desktop_image_verified: true,
            approved_helper_event_verified: true,
        },
        disconnected_malicious_peers: 0,
        bridge_replies: vec![],
        handoff_attempted: false,
    };

    let outcome = run_bridge_elevation(&mut harness, "core", Some(VALID_OFFER));
    assert!(outcome.result.is_ok());
    assert_eq!(harness.disconnected_malicious_peers, 5);
    assert!(outcome.gui_stopped);

    // 2. Direct pre-UAC connection to v0.2.20 GUI without BA/SY-owned UAC approval event MUST fail.
    let mut v0220_gui = SimulatedGuiServer {
        legacy_v0219: false,
        prepare_in: encode_prepare(VALID_NONCE, "client", None).unwrap(),
        peer_facts: Some(GuiPeerFacts {
            sid: USER_A.into(),
            session: 1,
            impersonated_sid: Some(USER_A.into()),
            elevated: false,
            desktop_image_verified: true,
            approved_helper_event_verified: false, // Pre-UAC / squatted event!
        }),
        ack_in: Some(encode_reply(VALID_NONCE, "ready", None).unwrap()),
        ..Default::default()
    };
    assert_eq!(
        handle_gui_handoff_session(&mut v0220_gui, USER_A, 1, false)
            .unwrap_err()
            .code,
        "UPDATE_HANDOFF"
    );
    assert!(!v0220_gui.core_prepare_update_called);
    assert!(!v0220_gui.exited_zero);

    // 3. Kernel event DACL check rejects user-writable / squatted events and unsignaled events.
    assert!(verify_protected_event_acl(ADMINS_SID, &[SYSTEM_SID.into(), ADMINS_SID.into()], true).is_ok());
    assert!(verify_protected_event_acl(USER_A, &[SYSTEM_SID.into(), ADMINS_SID.into()], true).is_err());
    assert!(verify_protected_event_acl(ADMINS_SID, &[SYSTEM_SID.into(), USER_A.into()], true).is_err());
    assert!(verify_protected_event_acl(ADMINS_SID, &[SYSTEM_SID.into(), ADMINS_SID.into()], false).is_err());

    // 4. Reverse helper->bridge server verification rejects spoofed or elevated pipe server.
    assert!(verify_bridge_server_for_helper(
        900,
        12345,
        USER_A,
        1,
        &BridgeServerFacts {
            pid: 900,
            stamp: 12345,
            sid: USER_A.into(),
            session: 1,
            elevated: false,
            expected_image_match: true,
        }
    )
    .is_ok());
    for bad_server in [
        BridgeServerFacts {
            pid: 901,
            stamp: 12345,
            sid: USER_A.into(),
            session: 1,
            elevated: false,
            expected_image_match: true,
        },
        BridgeServerFacts {
            pid: 900,
            stamp: 12345,
            sid: USER_A.into(),
            session: 1,
            elevated: true,
            expected_image_match: true,
        },
        BridgeServerFacts {
            pid: 900,
            stamp: 12345,
            sid: USER_B.into(),
            session: 1,
            elevated: false,
            expected_image_match: true,
        },
    ] {
        assert!(verify_bridge_server_for_helper(900, 12345, USER_A, 1, &bad_server).is_err());
    }
}

#[test]
fn r1_history_failure_legacy_cancel_and_missing_ack_abort_and_recover_without_stopping() {
    // 1. Core history persistence failure -> GUI aborts, runs recover_shutdown, helper receives abort.
    let helper_pid = 3131;
    let helper_stamp = 414141;
    let mut harness = SimulatedBridgeHarness {
        uac_result: Ok((helper_pid, helper_stamp)),
        steps: VecDeque::from([
            BridgeStep::PeerAttempt {
                facts: HelperPeerFacts {
                    pid: helper_pid,
                    stamp: helper_stamp,
                    sid: USER_A.into(),
                    session: 1,
                    elevated: true,
                    integrity: HIGH_INTEGRITY_RID,
                    expected_image_match: true,
                    hash_verified: true,
                },
                raw_request: encode_bridge_request(VALID_NONCE, "client", None).unwrap(),
            },
            BridgeStep::HelperExit(Err(Error::new("CORE_UPDATE_HISTORY_FAILED", "aborted before stop"))),
        ]),
        gui_already_stopped: false,
        running_gui: Some(SimulatedGuiServer {
            legacy_v0219: false,
            fail_shutdown_code: Some("CORE_UPDATE_HISTORY_FAILED"),
            ..Default::default()
        }),
        bridge_peer_facts_for_gui: GuiPeerFacts {
            sid: USER_A.into(),
            session: 1,
            impersonated_sid: Some(USER_A.into()),
            elevated: false,
            desktop_image_verified: true,
            approved_helper_event_verified: true,
        },
        disconnected_malicious_peers: 0,
        bridge_replies: vec![],
        handoff_attempted: false,
    };

    let outcome = run_bridge_elevation(&mut harness, "client", None);
    assert_eq!(outcome.result.as_ref().unwrap_err().code, "CORE_UPDATE_HISTORY_FAILED");
    assert!(outcome.gui_was_running);
    assert!(!outcome.gui_stopped);
    assert!(!outcome.should_reopen(true));
    assert_eq!(harness.bridge_replies[0].phase, "abort");
    let gui = harness.running_gui.unwrap();
    assert!(gui.recover_called);
    assert!(!gui.exited_zero);

    // 2. Missing/corrupted ACK after GUI sends `ready` triggers `execute_recover_shutdown` and refuses exit.
    let mut ack_timeout_gui = SimulatedGuiServer {
        legacy_v0219: false,
        prepare_in: encode_prepare(VALID_NONCE, "uninstall", None).unwrap(),
        peer_facts: Some(GuiPeerFacts {
            sid: USER_A.into(),
            session: 1,
            impersonated_sid: Some(USER_A.into()),
            elevated: false,
            desktop_image_verified: true,
            approved_helper_event_verified: true,
        }),
        ack_in: None, // ACK timeout!
        ..Default::default()
    };
    assert!(handle_gui_handoff_session(&mut ack_timeout_gui, USER_A, 1, false).is_err());
    assert!(ack_timeout_gui.recover_called, "ACK timeout must recover GUI/Core state");
    assert!(!ack_timeout_gui.exited_zero);

    // 3. Legacy v0.2.19 UI cancel replies `abort(cancelled)` without running `prepare_shutdown`.
    let mut v0219_cancel_gui = SimulatedGuiServer {
        legacy_v0219: true,
        legacy_user_confirms: false,
        prepare_in: encode_prepare(VALID_NONCE, "client", None).unwrap(),
        peer_facts: Some(GuiPeerFacts {
            sid: USER_A.into(),
            session: 1,
            impersonated_sid: Some(USER_A.into()),
            elevated: false,
            desktop_image_verified: true,
            approved_helper_event_verified: false,
        }),
        ..Default::default()
    };
    assert!(!handle_gui_handoff_session(&mut v0219_cancel_gui, USER_A, 1, true).unwrap());
    assert!(!v0219_cancel_gui.core_prepare_update_called);
    assert!(!v0219_cancel_gui.exited_zero);
    assert_eq!(
        parse_ready_or_abort(&v0219_cancel_gui.replies_out[0], VALID_NONCE)
            .unwrap_err()
            .code,
        "UPDATE_CANCELLED"
    );
}

#[test]
fn r2_residual_kill_enforces_target_dir_approved_hash_user_session_and_system_hosted_core() {
    let hash_desktop = "1".repeat(64);
    let hash_core_old = "2".repeat(64);
    let hash_core_new = "3".repeat(64);
    let hash_watchdog = "4".repeat(64);
    let hash_elevate = "5".repeat(64);

    let mut approved = BTreeMap::new();
    approved.insert("kat-desktop.exe".into(), vec![hash_desktop.clone()]);
    approved.insert(
        "kat-client-core.exe".into(),
        vec![hash_core_old.clone(), hash_core_new.clone()],
    );
    approved.insert("kat-proxy-watchdog.exe".into(), vec![hash_watchdog.clone()]);
    approved.insert("kat-elevate-helper.exe".into(), vec![hash_elevate.clone()]);

    let policy = ResidualTargetPolicy {
        target_root: r"C:\Program Files\Kat".into(),
        target_sid: USER_A.into(),
        caller_session: 1,
        approved_role_hashes: approved,
        service_core: Some(ServiceCoreOwnership {
            core_pid: 8800,
            core_created: 777_000_111,
            owner_sid: USER_A.into(),
            session: 1,
        }),
    };

    let base_owned_core = ResidualCandidate {
        pid: 5001,
        self_pid: 100,
        skip_pid: 200,
        exe_name: "kat-client-core.exe".into(),
        image_path: Some(r"c:\program files\kat\kat-client-core.exe".into()),
        image_protected: true,
        image_sha256: Some(hash_core_old.clone()),
        proc_sid: Some(USER_A.into()),
        proc_session: Some(1),
        proc_stamp: Some(123456),
    };

    // Positive 1: Owned residual process in target_root + approved hash + same SID & session.
    assert!(evaluate_residual_kill(&base_owned_core, &policy));

    // Positive 2: SYSTEM-hosted kat-client-core.exe matching exact LaunchIdentity (pid + stamp + owner_sid + session).
    let system_owned_core = ResidualCandidate {
        pid: 8800,
        proc_sid: Some(SYSTEM_SID.into()),
        proc_session: Some(0),
        proc_stamp: Some(777_000_111),
        image_sha256: Some(hash_core_new.clone()),
        ..base_owned_core.clone()
    };
    assert!(evaluate_residual_kill(&system_owned_core, &policy));

    // Negative 1 (Bug R2 line 174 regression): Same process names in OTHER directories MUST NEVER be killed!
    for (role, hash) in [
        ("kat-client-core.exe", &hash_core_old),
        ("kat-proxy-watchdog.exe", &hash_watchdog),
        ("kat-elevate-helper.exe", &hash_elevate),
        ("kat-desktop.exe", &hash_desktop),
    ] {
        for other_dir in [
            r"D:\Portable\Kat",
            r"C:\Program Files\Kat Beta",
            r"C:\Users\alice\Downloads",
        ] {
            let cross_dir = ResidualCandidate {
                exe_name: role.into(),
                image_path: Some(format!(r"{other_dir}\{role}")),
                image_sha256: Some(hash.clone()),
                ..base_owned_core.clone()
            };
            assert!(
                !evaluate_residual_kill(&cross_dir, &policy),
                "must never kill same-named {role} in {other_dir}"
            );
        }
    }

    // Negative 2: Same target directory + same exe name + DIFFERENT user SID (multi-user host).
    let other_user = ResidualCandidate {
        proc_sid: Some(USER_B.into()),
        ..base_owned_core.clone()
    };
    assert!(!evaluate_residual_kill(&other_user, &policy));

    // Negative 3: Same target directory + same user SID + DIFFERENT session or session 0.
    for bad_session in [0, 2, 3] {
        let wrong_session = ResidualCandidate {
            proc_session: Some(bad_session),
            ..base_owned_core.clone()
        };
        assert!(!evaluate_residual_kill(&wrong_session, &policy));
    }

    // Negative 4: Unprotected ACL or unapproved/tampered SHA-256 hash or missing image path.
    assert!(!evaluate_residual_kill(
        &ResidualCandidate {
            image_protected: false,
            ..base_owned_core.clone()
        },
        &policy
    ));
    assert!(!evaluate_residual_kill(
        &ResidualCandidate {
            image_sha256: Some("f".repeat(64)),
            ..base_owned_core.clone()
        },
        &policy
    ));
    assert!(!evaluate_residual_kill(
        &ResidualCandidate {
            image_path: None,
            ..base_owned_core.clone()
        },
        &policy
    ));

    // Negative 5: Initiating bridge (skip_pid) and helper itself (self_pid) are never killed.
    assert!(!evaluate_residual_kill(
        &ResidualCandidate {
            pid: 100,
            ..base_owned_core.clone()
        },
        &policy
    ));
    assert!(!evaluate_residual_kill(
        &ResidualCandidate {
            pid: 200,
            ..base_owned_core.clone()
        },
        &policy
    ));

    // Negative 6: SYSTEM-hosted kat-client-core.exe belonging to ANOTHER user, wrong PID,
    // recycled creation stamp, wrong session, missing journal, or non-core role as SYSTEM!
    let mut policy_other_owner = policy.clone();
    policy_other_owner.service_core.as_mut().unwrap().owner_sid = USER_B.into();
    assert!(
        !evaluate_residual_kill(&system_owned_core, &policy_other_owner),
        "must never kill SYSTEM-hosted core owned by another user"
    );

    let mut policy_other_session = policy.clone();
    policy_other_session.service_core.as_mut().unwrap().session = 2;
    assert!(!evaluate_residual_kill(&system_owned_core, &policy_other_session));

    let mut policy_no_journal = policy.clone();
    policy_no_journal.service_core = None;
    assert!(!evaluate_residual_kill(&system_owned_core, &policy_no_journal));

    assert!(
        !evaluate_residual_kill(
            &ResidualCandidate {
                proc_stamp: Some(777_000_112), // Recycled PID!
                ..system_owned_core.clone()
            },
            &policy
        ),
        "recycled PID with different creation_stamp must be rejected"
    );

    assert!(
        !evaluate_residual_kill(
            &ResidualCandidate {
                exe_name: "kat-proxy-watchdog.exe".into(),
                image_path: Some(r"C:\Program Files\Kat\kat-proxy-watchdog.exe".into()),
                image_sha256: Some(hash_watchdog),
                ..system_owned_core
            },
            &policy
        ),
        "non-core roles never run as SYSTEM"
    );
}
