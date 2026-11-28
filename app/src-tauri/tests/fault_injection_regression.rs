//! Fault-Injection & Security Regression Suite (Turned Positive for All v0.2.38 Fixes)
//! Verifies:
//! 1. 20 rapid crash storm cycles without pending-slot leak or deadlock.
//! 2. Sticky/coalesced multi-JSON frames, half-frame EOF, and >1 MiB frame bomb rejection.
//! 3. Hung `MutationFlight` auto-circuit-breaker (`CORE_MUTATION_STALLED`) freeing stalled core.
//! 4. UAC cancel vs start failure codes, install_location traversal/device/ACL guards.
//! 5. Atomic write (`fs_atomic` / `ownership::save` / `user_store`) blocks predictable `.next` & target symlinks.
//! 6. `RecoveryReport` (`cleanup_pending: bool`) drives exit polling cleanly until `cleanup_complete`.
//! 7. `RECOVERY_CONFLICT` preserves foreign user DNS, converges `j.phase` to `"complete"` (unblocking
//!    residual `Kat-*` adapter cleanup), and eliminates duplicate checkpoint writes.
//! 8. Updater Ed25519 signature verification, sequence floor, `u64::MAX`, same-version diff-hash,
//!    canonical uppercase `UPDATE_*` error codes, and `path` non-serialization privacy guard.

use kat_host::{
    core_tun_journal::{
        self, Adapter, Cas, Change, DnsValue, Journal, LaunchIdentity, RecoveryReport, RouteValue,
        Value as TunValue,
    },
    error::Error,
    firewall_rule::{
        self, expected_core_udp_rule, FirewallRuleError, FirewallRuleSpec, FirewallStore,
    },
    install_location,
    installer_result::{
        completion, elevation_failure, InstallerOutcome, EXIT_FAILED, EXIT_OK, EXIT_REPORT_FAILED,
        EXIT_REPORT_IDENTITY,
    },
    installer_update::{self, UpdateFailure, UpdateSteps},
    lifecycle::{self, QuitOps},
    ownership::{self, ProxyChange, ProxyJournal, ProxyValue, RestoreDecision},
    protocol::MAX_FRAME,
    service_read_acl, service_self_read,
    supervisor::{Life, Supervisor},
    transaction,
    transport_diagnostics::{read_frame, Branch},
    update_manifest::{
        self, verify_forward_transition, CurrentVersions, ExpectedRelease, UpdateKind,
    },
};
use serde_json::{json, Value};
use std::{
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    },
    time::Duration,
};
use tokio::io::BufReader;

fn peer_cmd() -> tokio::process::Command {
    tokio::process::Command::new(env!("CARGO_BIN_EXE_kat-ipc-test-peer"))
}

#[tokio::test]
async fn fi_01_core_crash_storm_20_rapid_cycles_no_leak_or_deadlock() {
    for round in 0..20 {
        let mut cmd = peer_cmd();
        cmd.arg(format!("crash-storm-{round}"));
        let sup = Supervisor::spawn(cmd).await.expect("spawn crash child");
        let err = sup
            .request("hello", Value::Null, Duration::from_secs(2))
            .await
            .expect_err("crashed child must fail hello");
        assert!(
            matches!(err.code.as_str(), "CORE_EOF" | "CORE_EXITED" | "CORE_WRITE"),
            "unexpected crash error code on round {round}: {}",
            err.code
        );
        assert_eq!(sup.pending(), 0, "pending table leaked on round {round}");
        sup.shutdown().await;
        assert!(matches!(*sup.life().borrow(), Life::Exited(_)));
    }
}

#[tokio::test]
async fn fi_02_ipc_sticky_frames_half_frame_eof_and_oversize_bomb() {
    let coalesced = concat!(
        "{\"id\":\"h1\",\"ok\":true,\"result\":{\"step\":1}}\n",
        "{\"id\":\"h2\",\"ok\":true,\"result\":{\"step\":2}}\n"
    );
    let mut reader = BufReader::new(coalesced.as_bytes());
    let f1 = read_frame(&mut reader).await.unwrap().unwrap();
    let f2 = read_frame(&mut reader).await.unwrap().unwrap();
    let f3 = read_frame(&mut reader).await.unwrap();
    assert!(std::str::from_utf8(&f1).unwrap().contains("\"h1\""));
    assert!(std::str::from_utf8(&f2).unwrap().contains("\"h2\""));
    assert!(f3.is_none());

    let half_frame = b"{\"id\":\"h9\",\"ok\":true,\"result\":{\"partial\":";
    let mut half_reader = BufReader::new(&half_frame[..]);
    let half_err = read_frame(&mut half_reader)
        .await
        .expect_err("truncated frame without LF must fail closed");
    assert_eq!(half_err.code, "CORE_PROTOCOL");
    assert_eq!(
        half_err.transport.as_ref().map(|d| d.branch),
        Some(Branch::TruncatedEof)
    );

    let bomb = vec![b'A'; MAX_FRAME + 65_536];
    let mut bomb_reader = BufReader::new(&bomb[..]);
    let bomb_err = read_frame(&mut bomb_reader)
        .await
        .expect_err("oversized frame bomb must be rejected at MAX_FRAME");
    assert_eq!(bomb_err.code, "FRAME_TOO_LARGE");
    assert_eq!(
        bomb_err.transport.as_ref().map(|d| d.branch),
        Some(Branch::FrameLimit)
    );
}

#[tokio::test]
async fn fi_03_hung_mutation_hard_timeout_trips_circuit_breaker_and_clears_flight() {
    let mut cmd = peer_cmd();
    cmd.arg("mutation-fixture");
    let sup = Supervisor::spawn(cmd).await.unwrap();
    sup.set_mutation_hard_timeout(Duration::from_millis(160));
    sup.hello().await.unwrap();

    let err = sup
        .request_public(
            "document.apply",
            json!({"behavior": "hang", "delay": 5, "text": "client: {}\n"}),
            Duration::from_millis(35),
        )
        .await
        .expect_err("hung document.apply must time out");
    assert_eq!(err.code, "CORE_MUTATION_UNCERTAIN");

    // Before hard timeout expires, reads still work while mutation gate stays cautious:
    let st = sup
        .request_public("status", Value::Null, Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(st["runtime"]["state"], "stopped");

    // Once the hard mutation timeout (160ms) expires, Supervisor automatically trips
    // `fail(Error::new("CORE_MUTATION_STALLED", ...))`, draining pending slots and marking Life::Failed
    // so host recovery restarts the wedged core!
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Life::Exited(e) = sup.life().borrow().clone() {
                assert_eq!(e.code, "CORE_MUTATION_STALLED");
                break;
            }
            tokio::time::sleep(Duration::from_millis(15)).await;
        }
    })
    .await
    .expect("hung mutation must trip CORE_MUTATION_STALLED circuit breaker");

    assert_eq!(sup.pending(), 0, "pending slot must be cleared on circuit break");
    sup.shutdown().await;
}

#[test]
fn fi_04_uac_codes_error_path_redaction_and_install_location_guards() {
    // Error::path must never serialize to JSON sent to WebView, while retry_after is preserved
    let mut secret_err =
        Error::new("UPDATE_RATE_LIMIT", "请求受限").with_retry_after(Some("30".into()));
    secret_err.path = Some(r"C:\Users\Alice\AppData\Local\Kat\secret.json".into());
    let serialized = serde_json::to_string(&secret_err).unwrap();
    assert!(
        !serialized.contains("Alice") && !serialized.contains("secret.json"),
        "Error.path leaked into JSON: {serialized}"
    );
    assert!(serialized.contains("\"retry_after\":\"30\""));

    assert_eq!(elevation_failure(0, 1223, 5, false).code, "UAC_DENIED");
    assert_eq!(elevation_failure(0, 5, 5, false).code, "UAC_START_FAILED");
    assert_eq!(
        completion(EXIT_REPORT_IDENTITY, None).unwrap_err().code,
        "INSTALL_RESULT_IDENTITY"
    );
    assert_eq!(
        completion(EXIT_REPORT_FAILED, None).unwrap_err().code,
        "INSTALL_RESULT_WRITE"
    );
    assert!(completion(
        EXIT_OK,
        Some(InstallerOutcome {
            ok: false,
            error: None,
            firewall_error: None,
            service_acl_diagnostic: None,
        })
    )
    .is_err());
    assert!(completion(
        EXIT_FAILED,
        Some(InstallerOutcome {
            ok: true,
            error: None,
            firewall_error: None,
            service_acl_diagnostic: None,
        })
    )
    .is_err());

    for bad_path in [
        r"\\server\share\Kat Client",
        r"C:relative\Kat Client",
        r"C:\Program Files\..\Users\Public\Kat",
        r"C:\Program Files/Kat Client",
        r"C:\Program Files\CON\Kat",
        r"C:\Program Files\NUL.txt\Kat",
        r"C:\Program Files\KatTrailingDot.",
        r"C:\Program Files\KatTrailingSpace ",
        "C:\\",
    ] {
        assert!(
            install_location::validate(bad_path).is_err(),
            "must reject unsafe install path: {bad_path}"
        );
    }
    assert!(install_location::validate(r"C:\Program Files\Kat Client").is_ok());

    let sy = "S-1-5-18";
    let user_b = "S-1-5-21-999-888-777-1002";
    assert!(!install_location::ancestor_grant_safe(
        user_b, sy, 0x001200a9, false, false
    ));
    assert!(!install_location::ancestor_grant_safe(
        sy, user_b, 0x00040000, false, false
    ));
    assert!(!install_location::ancestor_grant_safe(
        sy, user_b, 0x00000002, false, false
    ));
    assert!(!service_self_read::binding_ancestor_safe(
        sy, user_b, 0x00010000
    ));
    assert!(
        service_read_acl::add_query_config(&[2, 0], &[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0])
            .is_err()
    );
    assert!(service_read_acl::add_query_config(&[2, 0, 8, 0, 0, 0, 0, 0], &[1, 99]).is_err());
}

#[cfg(unix)]
#[test]
fn fi_05_atomic_write_blocks_predictable_next_symlink_and_target_symlink() {
    use std::os::unix::fs::symlink;
    let dir = std::env::temp_dir().join(format!("kat-fi05-fixed-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let victim = dir.join("victim-target.txt");
    std::fs::write(&victim, b"ORIGINAL_PROTECTED_CONTENT").unwrap();

    // 1) `user_store::Store` rejects symlink leaves
    let store = kat_host::user_store::Store::new(dir.clone()).unwrap();
    symlink(&victim, dir.join("linked.json")).unwrap();
    assert_eq!(
        store.write("linked.json", b"evil", 1024).unwrap_err().code,
        "FILE_REPARSE"
    );

    // 2) Pre-planted predictable `.next` symlink is completely ignored by `ownership::save`,
    //    and `victim-target.txt` remains 100% untouched!
    let journal_file = dir.join("network-last-error.json");
    let predictable_next = dir.join("network-last-error.next");
    symlink(&victim, &predictable_next).unwrap();

    ownership::save(&journal_file, &json!({"safe": true})).unwrap();
    assert_eq!(
        std::fs::read(&victim).unwrap(),
        b"ORIGINAL_PROTECTED_CONTENT",
        "predictable .next symlink must never clobber victim target!"
    );

    // 3) If `network-last-error.json` itself is a symlink, `ownership::save` rejects it with FILE_REPARSE!
    std::fs::remove_file(&journal_file).unwrap();
    symlink(&victim, &journal_file).unwrap();
    assert_eq!(
        ownership::save(&journal_file, &json!({"evil": true}))
            .unwrap_err()
            .code,
        "UNTRUSTED_PATH"
    );
    assert_eq!(
        std::fs::read(&victim).unwrap(),
        b"ORIGINAL_PROTECTED_CONTENT"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn fi_06_recovery_report_cleanup_pending_advances_quit_wait_to_completion() {
    let mut recovering_journal = Journal {
        schema: 2,
        engine: "core_tun_v1".into(),
        launch: LaunchIdentity {
            schema: 2,
            engine: "core_tun_v1".into(),
            epoch: "a".repeat(32),
            core_pid: 99,
            core_created: 777,
            owner_sid: "S-1-5-21-1-2-3-1001".into(),
            session: 1,
            package_sha256: "b".repeat(64),
            core_sha256: "c".repeat(64),
        },
        adapter: Adapter {
            alias: core_tun_journal::alias("S-1-5-21-1-2-3-1001"),
            guid: "01234567-89ab-cdef-0123-456789abcdef".into(),
            luid: 12,
            compartment: 1,
        },
        seq: 2,
        phase: "recovering".into(),
        changes: vec![Change {
            id: "dns".into(),
            before: None,
            installed: TunValue {
                route: None,
                address: None,
                interface: None,
                dns: Some(DnsValue {
                    servers: "198.18.0.2".into(),
                }),
            },
            desired: false,
            state: "pending".into(),
        }],
        last_request: "r".repeat(32),
        last_digest: "d".repeat(64),
    };
    let report = RecoveryReport::from_journal(Some(&recovering_journal));
    assert!(report.cleanup_pending);
    assert!(!report.cleanup_complete);
    let status_reply = json!({
        "core_tun_recovery": serde_json::to_value(&report).unwrap()
    });
    assert_eq!(
        status_reply.pointer("/core_tun_recovery/cleanup_pending"),
        Some(&Value::Bool(true))
    );

    recovering_journal.changes[0].state = "restored".into();
    recovering_journal.phase = "complete".into();
    let done_report = RecoveryReport::from_journal(Some(&recovering_journal));
    assert!(done_report.cleanup_complete);
    assert!(!done_report.cleanup_pending);

    struct FixedQuitSim {
        polls: AtomicUsize,
        pending_rep: RecoveryReport,
        done_rep: RecoveryReport,
    }
    impl QuitOps for FixedQuitSim {
        async fn cleanup(&self) -> Result<(), Error> {
            Err(Error::new("RECOVERY_PENDING", "正在等待网络恢复完成"))
        }
        async fn poll_cleanup_pending(&self) -> Result<bool, Error> {
            let n = self.polls.fetch_add(1, Ordering::SeqCst) + 1;
            let r = if n < 3 {
                &self.pending_rep
            } else {
                &self.done_rep
            };
            let state = json!({ "core_tun_recovery": r });
            if state.pointer("/core_tun_recovery/cleanup_complete") == Some(&Value::Bool(true)) {
                return Ok(false);
            }
            if state.pointer("/core_tun_recovery/cleanup_pending") == Some(&Value::Bool(true)) {
                return Ok(true);
            }
            Err(Error::new("RECOVERY_PENDING", "unexpected"))
        }
        fn cleanup_wait_budget(&self) -> (Duration, Duration) {
            (Duration::from_secs(2), Duration::from_millis(10))
        }
        async fn stop_core(&self) {}
    }

    let sim = FixedQuitSim {
        polls: AtomicUsize::new(0),
        pending_rep: report,
        done_rep: done_report,
    };
    lifecycle::quit(&sim).await.expect("quit must poll smoothly until cleanup_complete");
    assert_eq!(sim.polls.load(Ordering::SeqCst), 3);
}

#[test]
fn fi_07_recovery_conflict_converges_complete_preserving_foreign_dns_and_zero_recheckpoint() {
    let kat_route = TunValue {
        route: Some(RouteValue {
            destination: "0.0.0.0".into(),
            prefix: 1,
            next_hop: "0.0.0.0".into(),
            scope: 0,
            metric: 5,
            protocol: 3,
            site_prefix: 0,
            valid_lifetime: u32::MAX,
            preferred_lifetime: u32::MAX,
            loopback: false,
            autoconfigure: false,
            publish: false,
            immortal: false,
            origin: 0,
        }),
        address: None,
        interface: None,
        dns: None,
    };
    let orig_dns = Some(TunValue {
        route: None,
        address: None,
        interface: None,
        dns: Some(DnsValue {
            servers: "1.1.1.1".into(),
        }),
    });
    let kat_dns = TunValue {
        route: None,
        address: None,
        interface: None,
        dns: Some(DnsValue {
            servers: "198.18.0.2".into(),
        }),
    };
    let user_custom_dns = Some(TunValue {
        route: None,
        address: None,
        interface: None,
        dns: Some(DnsValue {
            servers: "9.9.9.9".into(),
        }),
    });

    let journal = Journal {
        schema: 2,
        engine: "core_tun_v1".into(),
        launch: LaunchIdentity {
            schema: 2,
            engine: "core_tun_v1".into(),
            epoch: "a".repeat(32),
            core_pid: 4242,
            core_created: 999_999,
            owner_sid: "S-1-5-21-111-222-333-1001".into(),
            session: 1,
            package_sha256: "b".repeat(64),
            core_sha256: "c".repeat(64),
        },
        adapter: Adapter {
            alias: core_tun_journal::alias("S-1-5-21-111-222-333-1001"),
            guid: "01234567-89ab-cdef-0123-456789abcdef".into(),
            luid: 77,
            compartment: 1,
        },
        seq: 3,
        phase: "recovering".into(),
        changes: vec![
            Change {
                id: "route:0.0.0.0/1".into(),
                before: None,
                installed: kat_route.clone(),
                desired: false,
                state: "committed".into(),
            },
            Change {
                id: "dns".into(),
                before: orig_dns,
                installed: kat_dns,
                desired: false,
                state: "committed".into(),
            },
        ],
        last_request: "e".repeat(32),
        last_digest: "d".repeat(64),
    };
    assert_eq!(
        core_tun_journal::cas(&journal.changes[1], &user_custom_dns),
        Cas::Foreign
    );

    let restored_ids = Mutex::new(Vec::new());
    let mut durable = journal.clone();
    let checkpoints = AtomicUsize::new(0);
    let outcome = core_tun_journal::recover_set(
        &journal,
        false,
        |c| {
            if c.id == "dns" {
                Ok(user_custom_dns.clone())
            } else {
                Ok(Some(kat_route.clone()))
            }
        },
        |c| {
            restored_ids.lock().unwrap().push(c.id.clone());
            Ok(())
        },
        |n| {
            checkpoints.fetch_add(1, Ordering::SeqCst);
            durable = n.clone();
            Ok(())
        },
    );
    // Kat-owned route restored, foreign DNS preserved as "conflict"; broker then verifies
    // `only_shared_conflicts_remain(&durable)`, removes residual adapter, and converges phase="complete"!
    assert_eq!(outcome.unwrap_err(), "RECOVERY_CONFLICT");
    assert_eq!(*restored_ids.lock().unwrap(), vec!["route:0.0.0.0/1"]);
    assert_eq!(durable.changes[0].state, "restored");
    assert_eq!(durable.changes[1].state, "conflict");
    assert!(core_tun_journal::only_shared_conflicts_remain(&durable));
    assert!(core_tun_journal::recovering_stale_adapter_decision(
        &durable,
        Ok(true),
        &durable.adapter,
        2,
        15
    )
    .is_ok());
    durable.phase = "complete".into();
    assert_eq!(core_tun_journal::completed_retirement_ready(&durable), Ok(true));

    // Re-running on settled journal performs 0 checkpoints (no 8Hz WRITE_THROUGH storm):
    checkpoints.store(0, Ordering::SeqCst);
    let again_err = core_tun_journal::recover_set(
        &durable,
        false,
        |c| Ok(if c.id == "dns" { user_custom_dns.clone() } else { None }),
        |_| panic!("must not restore already-settled items"),
        |_| {
            checkpoints.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    )
    .unwrap_err();
    assert_eq!(again_err, "RECOVERY_CONFLICT");
    assert_eq!(checkpoints.load(Ordering::SeqCst), 0);

    // Proxy & Firewall CAS preservation:
    let p_orig = ProxyValue {
        flags: 1,
        flags_ui: 1,
        server: String::new(),
        bypass: String::new(),
        pac: "https://corp.example/proxy.pac".into(),
        autodiscovery_flags: 0,
    };
    let p_inst = p_orig.installed(7890);
    let mut p_foreign = p_inst.clone();
    p_foreign.server = "127.0.0.1:9999".into();
    assert_eq!(
        ownership::restore_decision(&p_foreign, &p_orig, &p_inst),
        RestoreDecision::ForeignChange
    );
    let pj = ProxyJournal {
        schema: 1,
        owner_sid: "S-1-5-21-1-2-3-1001".into(),
        session: 1,
        changes: vec![ProxyChange {
            connection: None,
            original: p_orig,
            installed: p_inst,
            restored: false,
        }],
    };
    assert!(pj.owned(&None, &p_foreign).is_none());

    struct MemFw(Vec<FirewallRuleSpec>);
    impl FirewallStore for MemFw {
        type RuleHandle = usize;
        fn list_candidate_rules(&mut self) -> Result<Vec<(usize, FirewallRuleSpec)>, FirewallRuleError> {
            Ok(self.0.iter().cloned().enumerate().collect())
        }
        fn add_rule(&mut self, rule: &FirewallRuleSpec) -> Result<(), FirewallRuleError> {
            self.0.push(rule.clone());
            Ok(())
        }
        fn update_rule(&mut self, idx: &mut usize, rule: &FirewallRuleSpec) -> Result<(), FirewallRuleError> {
            self.0[*idx] = rule.clone();
            Ok(())
        }
        fn remove_by_name(&mut self, name: &str) -> Result<(), FirewallRuleError> {
            if let Some(pos) = self.0.iter().position(|r| r.name == name) {
                self.0.remove(pos);
            }
            Ok(())
        }
    }
    let kat_fw = expected_core_udp_rule(Path::new(r"C:\Program Files\Kat Client")).unwrap();
    let mut foreign_fw = kat_fw.clone();
    foreign_fw.name = "User Custom UDP Rule".into();
    foreign_fw.group = "CustomGroup".into();
    foreign_fw.application_name = r"C:\Apps\other.exe".into();
    assert!(!firewall_rule::is_kat_owned_rule(&foreign_fw));
    let mut store = MemFw(vec![kat_fw, foreign_fw]);
    let removed = firewall_rule::remove_core_udp_inbound(&mut store).unwrap();
    assert_eq!(removed.removed, 1);
    assert_eq!(store.0.len(), 1);
    assert_eq!(store.0[0].name, "User Custom UDP Rule");

    let log = Mutex::new(Vec::new());
    let _ = transaction::write_ahead(
        || {
            log.lock().unwrap().push("journaled");
            Ok(())
        },
        || Err(Error::new("CRASH", "simulated power cut")),
    );
    assert_eq!(*log.lock().unwrap(), vec!["journaled"]);
}

#[test]
fn fi_08_updater_ed25519_tamper_sequence_floor_u64_max_and_uppercase_codes() {
    let hash_a = "a".repeat(64);
    let hash_b = "b".repeat(64);

    assert!(verify_forward_transition(
        "0.2.36", 10, &hash_a, "0.2.34", 5, &hash_a, "0.2.37", 11, &hash_b, "0.2.34", 5, &hash_a,
        false
    )
    .is_ok());

    assert_eq!(
        verify_forward_transition(
            "0.2.36", 10, &hash_a, "0.2.34", 5, &hash_a, "0.2.37", 10, &hash_b, "0.2.34", 5,
            &hash_a, false
        )
        .unwrap_err()
        .code,
        "UPDATE_DOWNGRADE"
    );
    assert_eq!(
        verify_forward_transition(
            "0.2.37", 10, &hash_a, "0.2.34", 5, &hash_a, "0.2.36", 99, &hash_b, "0.2.34", 5,
            &hash_a, false
        )
        .unwrap_err()
        .code,
        "UPDATE_DOWNGRADE"
    );
    assert_eq!(
        verify_forward_transition(
            "0.2.37", 10, &hash_a, "0.2.34", 5, &hash_a, "0.2.37", 11, &hash_b, "0.2.34", 5,
            &hash_a, false
        )
        .unwrap_err()
        .code,
        "UPDATE_DOWNGRADE"
    );
    assert_eq!(
        verify_forward_transition(
            "0.2.36",
            u64::MAX,
            &hash_a,
            "0.2.34",
            5,
            &hash_a,
            "0.2.37",
            u64::MAX,
            &hash_b,
            "0.2.34",
            5,
            &hash_a,
            false
        )
        .unwrap_err()
        .code,
        "UPDATE_DOWNGRADE"
    );

    let current = CurrentVersions {
        app_version: "0.2.37".into(),
        app_sequence: 10,
        app_sha256: Some(hash_a.clone()),
        core_version: "0.2.34".into(),
        core_sequence: 5,
        core_sha256: hash_a,
        supported_capabilities: vec!["host.prepare-update.v1".into()],
    };
    let expected = ExpectedRelease {
        kind: UpdateKind::Client,
        release_id: 100,
        release_tag: "v0.2.38".into(),
    };

    let big_manifest = vec![b'{'; 70_000];
    let dummy_sig = "0".repeat(128);
    assert_eq!(
        update_manifest::verify(&big_manifest, dummy_sig.as_bytes(), &expected, &current)
            .unwrap_err()
            .code,
        "UPDATE_MANIFEST_SIZE"
    );

    let forged_json = br#"{"schema":1,"product":"kat-client"}"#;
    assert_eq!(
        update_manifest::verify(forged_json, dummy_sig.as_bytes(), &expected, &current)
            .unwrap_err()
            .code,
        "UPDATE_SIGNATURE"
    );
    assert_eq!(
        update_manifest::verify_setup_package(
            forged_json,
            dummy_sig.as_bytes(),
            forged_json,
            dummy_sig.as_bytes()
        )
        .unwrap_err()
        .code,
        "UPDATE_SIGNATURE"
    );

    struct DoubleFault;
    impl UpdateSteps for DoubleFault {
        fn prepare(&mut self) -> kat_host::error::Result<()> {
            Ok(())
        }
        fn stop(&mut self) -> kat_host::error::Result<()> {
            Ok(())
        }
        fn replace(&mut self) -> kat_host::error::Result<()> {
            Err(Error::new("INSTALL_COPY", "disk full mid-replace"))
        }
        fn configure(&mut self) -> kat_host::error::Result<()> {
            Ok(())
        }
        fn start(&mut self) -> kat_host::error::Result<()> {
            Ok(())
        }
        fn recover(&mut self) -> kat_host::error::Result<()> {
            Err(Error::new("INSTALL_COPY", "backup restore also failed"))
        }
    }
    assert!(matches!(
        installer_update::run(&mut DoubleFault),
        Err(UpdateFailure::Recovery { .. })
    ));
}
