//! Pure production validators only. No mock token/privilege-success evidence.
use kat_host::{elevated_protocol::{ElevatedRequest,Checkpoint},service_protocol,protocol,installer_files::*};
use serde_json::{json,Value};
#[test]fn private_launch_and_tun_methods_never_enter_webview(){for method in ["host.handover.ready","host.handover.activate","host.prepare-update","network.tun.prepare","network.tun.commit","network.tun.disable","network.tun.status","network.egress.set"]{assert_eq!(protocol::validate_public(method,&json!({})).unwrap_err().code,"METHOD_DENIED");}for method in ["hello","logs.get","status","document.get"]{protocol::validate_public(method,&Value::Null).unwrap();}}
#[test]fn fixed_role_wire_rejects_paths_replays_and_unbounded_fields(){let lease="a".repeat(64);for request in [json!({"op":"claim","lease":lease,"path":"C:\\arbitrary"}),json!({"op":"prepare","old_pid":1,"old_stamp":1,"token":4}),json!({"op":"exec","lease":lease}),json!({"op":"claim","lease":"z".repeat(64)})]{let bytes=serde_json::to_vec(&json!({"action":"elevated","request":request})).unwrap();assert!(service_protocol::decode(&bytes).is_err());}let duplicate=format!(r#"{{"action":"elevated","request":{{"op":"claim","lease":"{lease}","lease":"{lease}"}}}}"#);assert!(service_protocol::decode(duplicate.as_bytes()).is_err());assert!(service_protocol::decode(&vec![b' ';service_protocol::PIPE_LIMIT+1]).is_err());assert!(service_protocol::decode(br#"{"action":"lookup_original_flow","query":{}}"#).is_err());assert!(ElevatedRequest::Prepare{old_pid:0,old_stamp:1}.validate().is_err());assert!(Checkpoint{schema:1,source_sha256:"A".repeat(64),history_sha256:"b".repeat(64)}.validate().is_err());}
#[test]fn c50_inventory_retires_bridge_and_pins_fixed_helper(){let app:std::collections::BTreeSet<_>=APP_FILES.iter().copied().collect();let runtime:std::collections::BTreeSet<_>=RUNTIME_FILES.iter().copied().collect();assert!(app.is_disjoint(&runtime));assert_eq!(app.union(&runtime).copied().collect::<std::collections::BTreeSet<_>>(),FILES.iter().copied().collect());assert!(app.contains("kat-elevate-helper.exe"));assert!(app.contains("kat-proxy-watchdog.exe"));assert!(runtime.contains("network/wintun.dll"));assert!(!FILES.contains(&"network/tun2socks.exe"));assert!(RETIRED_TUN.contains(&"network/tun2socks.exe"));for names in [FILES,LEGACY_FILES]{let hashes=names.iter().map(|n|(n.to_string(),"a".repeat(64))).collect();assert!(valid_inventory(&hashes));}}

#[cfg(unix)]
#[test]fn handover_failed_after_rebind_ack_or_uncertain_retires_exact_child_before_resume(){
 use std::{process::{Command,Stdio},io::Write};
 use kat_host::{watchdog_control::{ack,retire},ownership::{ProxyValue,ProxyChange,ProxyJournal}};
 // These are real pipe/child lifetime primitives used by native CONTROL, not
 // mocked tokens, Windows HANDLE binding, WinInet IO, or a fake launch success.
 for expected in ["rebound 2\n","unconfirmed\n"]{
  let mut old=Command::new("/bin/sh").args(["-c","read cmd; printf 'rebound 2\\n'; cat >/dev/null"]).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
  writeln!(old.stdin.as_mut().unwrap(),"rebind 22 33 2").unwrap();
  let result=ack(&mut old,expected);
  assert_eq!(result.is_ok(),expected=="rebound 2\n");
  assert!(old.try_wait().unwrap().is_none()); // Error did NOT mean unchanged/dead.
  retire(&mut old).unwrap();assert!(old.try_wait().unwrap().unwrap().success());
  let original=ProxyValue{flags:1,flags_ui:1,server:String::new(),bypass:"existing".into(),pac:String::new(),autodiscovery_flags:0};
  let journal=ProxyJournal{schema:1,owner_sid:"test".into(),session:1,changes:vec![ProxyChange{connection:None,original:original.clone(),installed:original.installed(1234),restored:false}]};
  assert!(journal.handover_restored(&[(None,original.clone())]));
  let mut foreign=original.clone();foreign.bypass="foreign edit".into();
  assert!(!journal.handover_restored(&[(None,foreign)]));
  assert!(!journal.handover_restored(&[(None,original.clone()),(Some("new".into()),original)]));
  // A fresh monitor must ACK before native resume_handover may write settings.
  let mut next=Command::new("/bin/sh").args(["-c","printf 'ready\\n'; cat >/dev/null"]).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
  ack(&mut next,"ready\n").unwrap();assert!(next.try_wait().unwrap().is_none());retire(&mut next).unwrap();
 }
}

#[test]
fn firewall_udp_inbound_spec_idempotent_update_exact_uninstall_and_nonblocking_outcome() {
 use std::path::Path;
 use kat_host::firewall_rule::*;
 use kat_host::installer_result::{
  completion, fw_error_clear, fw_error_record, report_exit, InstallerOutcome, EXIT_OK,
 };

 #[derive(Default)]
 struct MockFirewall {
  rules: Vec<FirewallRuleSpec>,
  fail_stage: Option<(FirewallStage, Option<i32>)>,
  adds: usize,
  updates: usize,
  removes: usize,
 }
 impl FirewallStore for MockFirewall {
  type RuleHandle = usize;
  fn list_candidate_rules(&mut self) -> Result<Vec<(usize, FirewallRuleSpec)>, FirewallRuleError> {
   if let Some((stage @ (FirewallStage::ComInit | FirewallStage::PolicyCreate | FirewallStage::RulesGet | FirewallStage::RulesEnum), hr)) = self.fail_stage {
    return Err(FirewallRuleError::new(stage, hr));
   }
   Ok(self.rules.iter().cloned().enumerate().collect())
  }
  fn update_rule(&mut self, handle: &mut usize, spec: &FirewallRuleSpec) -> Result<(), FirewallRuleError> {
   if let Some((stage @ (FirewallStage::RuleConfigure | FirewallStage::RuleVerify), hr)) = self.fail_stage {
    return Err(FirewallRuleError::new(stage, hr));
   }
   self.rules[*handle] = spec.clone();
   self.updates += 1;
   Ok(())
  }
  fn add_rule(&mut self, spec: &FirewallRuleSpec) -> Result<(), FirewallRuleError> {
   if let Some((stage @ (FirewallStage::RuleCreate | FirewallStage::RuleConfigure | FirewallStage::RuleAdd | FirewallStage::RuleVerify), hr)) = self.fail_stage {
    return Err(FirewallRuleError::new(stage, hr));
   }
   self.rules.push(spec.clone());
   self.adds += 1;
   Ok(())
  }
  fn remove_by_name(&mut self, name: &str) -> Result<(), FirewallRuleError> {
   if let Some((stage @ FirewallStage::RuleRemove, hr)) = self.fail_stage {
    return Err(FirewallRuleError::new(stage, hr));
   }
   let idx = self.rules.iter().position(|r| r.name == name).ok_or_else(|| FirewallRuleError::new(FirewallStage::RuleRemove, Some(-2147024894)))?;
   self.rules.remove(idx);
   self.removes += 1;
   Ok(())
  }
 }

 // 1. Rule parameter construction: inbound, allow, UDP only (17), exact kat-client-core.exe path, unrestricted ports, all profiles.
 let spec = expected_core_udp_rule(Path::new(r"C:\Program Files\Kat Client")).unwrap();
 assert_eq!(spec.name, "Kat Client Core UDP Inbound");
 assert_eq!(spec.group, "Kat Client");
 assert_eq!(spec.application_name, r"C:\Program Files\Kat Client\kat-client-core.exe");
 assert_eq!(spec.protocol, NET_FW_IP_PROTOCOL_UDP);
 assert_ne!(spec.protocol, NET_FW_IP_PROTOCOL_TCP);
 assert_eq!(spec.direction, NET_FW_RULE_DIR_IN);
 assert_eq!(spec.action, NET_FW_ACTION_ALLOW);
 assert_eq!(spec.local_ports, "*");
 assert_eq!(spec.remote_ports, "*");
 assert_eq!(spec.profiles, NET_FW_PROFILE2_ALL);
 assert!(spec.enabled);

 // 2. Idempotent creation and reconciliation when parameters or install path change.
 let mut fw = MockFirewall::default();
 let other_rule_diff_group = FirewallRuleSpec {
  name: "Windows Defender Firewall Remote Management".into(),
  group: "Windows Defender Firewall".into(),
  description: "System".into(),
  application_name: r"C:\Windows\System32\svchost.exe".into(),
  service_name: Some("mpssvc".into()),
  protocol: NET_FW_IP_PROTOCOL_TCP,
  local_ports: "445".into(),
  remote_ports: "*".into(),
  local_addresses: "*".into(),
  remote_addresses: "*".into(),
  direction: NET_FW_RULE_DIR_IN,
  interface_types: "All".into(),
  enabled: true,
  profiles: NET_FW_PROFILE2_ALL,
  action: NET_FW_ACTION_ALLOW,
 };
 let other_rule_same_group = FirewallRuleSpec {
  name: "KatCtl-SSH-HostOnly".into(),
  group: RULE_GROUP.into(),
  description: "Host SSH".into(),
  application_name: r"C:\Program Files\OpenSSH\sshd.exe".into(),
  service_name: None,
  protocol: NET_FW_IP_PROTOCOL_TCP,
  local_ports: "22".into(),
  remote_ports: "*".into(),
  local_addresses: "*".into(),
  remote_addresses: "172.30.0.1".into(),
  direction: NET_FW_RULE_DIR_IN,
  interface_types: "All".into(),
  enabled: true,
  profiles: NET_FW_PROFILE2_ALL,
  action: NET_FW_ACTION_ALLOW,
 };
 fw.rules.push(other_rule_diff_group.clone());
 fw.rules.push(other_rule_same_group.clone());

 let first = ensure_core_udp_inbound(&mut fw, Path::new(r"C:\Program Files\Kat Client")).unwrap();
 assert_eq!(first, EnsureOutcome { created: true, updated: false, deduplicated: 0 });
 assert_eq!(fw.rules.len(), 3);
 assert_eq!(fw.adds, 1);

 // Re-run with same path: idempotent no-op.
 let second = ensure_core_udp_inbound(&mut fw, Path::new(r"C:\Program Files\Kat Client\")).unwrap();
 assert_eq!(second, EnsureOutcome { created: false, updated: false, deduplicated: 0 });
 assert_eq!(fw.rules.len(), 3);
 assert_eq!(fw.adds, 1);
 assert_eq!(fw.updates, 0);

 // Simulate drifted rule parameters and moved install directory -> updated in-place without adding duplicate.
 fw.rules[2].protocol = NET_FW_IP_PROTOCOL_TCP;
 fw.rules[2].direction = NET_FW_RULE_DIR_OUT;
 fw.rules[2].action = NET_FW_ACTION_BLOCK;
 fw.rules[2].local_ports = "1080".into();
 fw.rules[2].enabled = false;
 let third = ensure_core_udp_inbound(&mut fw, Path::new(r"D:\Apps\Kat Client")).unwrap();
 assert_eq!(third, EnsureOutcome { created: false, updated: true, deduplicated: 0 });
 assert_eq!(fw.rules.len(), 3);
 assert_eq!(fw.updates, 1);
 assert_eq!(fw.rules[2], expected_core_udp_rule(Path::new(r"D:\Apps\Kat Client")).unwrap());

 // Simulate duplicate Kat rules -> deduplicated to 1.
 fw.rules.push(fw.rules[2].clone());
 assert_eq!(fw.rules.len(), 4);
 let fourth = ensure_core_udp_inbound(&mut fw, Path::new(r"D:\Apps\Kat Client")).unwrap();
 assert_eq!(fourth, EnsureOutcome { created: false, updated: true, deduplicated: 1 });
 assert_eq!(fw.rules.len(), 3);
 assert_eq!(fw.rules[2], expected_core_udp_rule(Path::new(r"D:\Apps\Kat Client")).unwrap());

 // 3. Accurate deletion on uninstall: removes only (RULE_NAME, RULE_GROUP), preserves all other rules.
 let removed = remove_core_udp_inbound(&mut fw).unwrap();
 assert_eq!(removed, RemoveOutcome { removed: 1 });
 assert_eq!(fw.rules, vec![other_rule_diff_group.clone(), other_rule_same_group.clone()]);

 // Foreign rule with same name but different group is never overwritten or deleted.
 let foreign_same_name = FirewallRuleSpec {
  name: RULE_NAME.into(),
  group: "Other Group".into(),
  ..other_rule_diff_group.clone()
 };
 fw.rules.push(foreign_same_name.clone());
 assert_eq!(ensure_core_udp_inbound(&mut fw, Path::new(r"C:\Program Files\Kat Client")).unwrap_err().stage, FirewallStage::RuleConflict);
 assert_eq!(remove_core_udp_inbound(&mut fw).unwrap(), RemoveOutcome { removed: 0 });
 assert_eq!(fw.rules, vec![other_rule_diff_group, other_rule_same_group, foreign_same_name]);
 fw.rules.pop();

 // 4. Failure recording: typed error is recorded in InstallerOutcome, never pretends firewall succeeded, and does not block normal installation.
 fw_error_clear();
 fw.fail_stage = Some((FirewallStage::RuleAdd, Some(-2147024891))); // E_ACCESSDENIED (0x80070005)
 let err = ensure_core_udp_inbound(&mut fw, Path::new(r"C:\Program Files\Kat Client")).unwrap_err();
 assert_eq!(err.code, "FIREWALL_RULE_FAILED");
 assert_eq!(err.stage, FirewallStage::RuleAdd);
 assert_eq!(err.hresult, Some(-2147024891));
 fw_error_record(err.clone());

 let install_res: kat_host::error::Result<()> = Ok(());
 let outcome = InstallerOutcome::from_result(&install_res);
 assert!(outcome.ok);
 assert!(outcome.error.is_none());
 assert_eq!(outcome.firewall_error, Some(err));
 let encoded = serde_json::to_string(&outcome).unwrap();
 assert!(encoded.contains("\"firewall_error\""));
 assert!(encoded.contains("\"FIREWALL_RULE_FAILED\""));
 assert!(encoded.contains("\"rule_add\""));
 let decoded: InstallerOutcome = serde_json::from_str(&encoded).unwrap();
 assert_eq!(report_exit(&install_res, Ok(())), EXIT_OK);
 assert!(completion(EXIT_OK, Some(decoded)).is_ok());
 fw_error_clear();
}

#[test]
fn stage5_same_package_signing_and_exact_manifest_retirement() {
 use kat_host::update_manifest::{verify_package, verify_forward_transition};
 use std::sync::atomic::{AtomicUsize, Ordering};
 static NEXT: AtomicUsize = AtomicUsize::new(0);
 let base = std::env::temp_dir().join(format!("kat-stage5-retire-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::SeqCst)));
 let (source, app_root, runtime_root, app_work, rt_work) = (
  base.join("source"), base.join("app"), base.join("runtime"), base.join("app-work"), base.join("rt-work")
 );
 for d in [&source, &app_root, &runtime_root, &app_work, &rt_work] {
  std::fs::create_dir_all(d.join("network")).unwrap();
 }
 std::fs::remove_dir_all(app_work.join("network")).unwrap();
 std::fs::remove_dir_all(rt_work.join("network")).unwrap();
 for &n in FILES {
  std::fs::write(source.join(n), b"new-c50").unwrap();
 }
 // Simulate c49 installation with legacy bridge files and unknown user files.
 for &n in LEGACY_FILES {
  std::fs::write(app_root.join(n), b"old-c49").unwrap();
 }
 for &n in LEGACY_RUNTIME_FILES {
  std::fs::write(runtime_root.join(n), b"old-c49-rt").unwrap();
 }
 std::fs::write(app_root.join("user-custom-note.txt"), b"keep-app-unknown").unwrap();
 std::fs::write(runtime_root.join("network/custom-profile.dat"), b"keep-rt-unknown").unwrap();

 let mut app_update = FileUpdate::stage_selected(
  &source, &app_root, &app_work, APP_FILES,
  |p| std::fs::create_dir(p).map_err(|e| kat_host::error::Error::io("DIR", &e)),
  |p| std::fs::OpenOptions::new().write(true).create_new(true).open(p).map_err(|e| kat_host::error::Error::io("FILE", &e)),
 ).unwrap();
 let mut rt_update = FileUpdate::stage_selected(
  &source, &runtime_root, &rt_work, RUNTIME_FILES,
  |p| std::fs::create_dir(p).map_err(|e| kat_host::error::Error::io("DIR", &e)),
  |p| std::fs::OpenOptions::new().write(true).create_new(true).open(p).map_err(|e| kat_host::error::Error::io("FILE", &e)),
 ).unwrap();

 rt_update.activate(|_| Ok(())).unwrap();
 rt_update.retire(RETIRED_TUN).unwrap();
 app_update.activate(|_| Ok(())).unwrap();
 app_update.retire(RETIRED_APP_PRIVILEGED).unwrap();

 // Retired bridge and license are removed from live roots; unknown data is untouched.
 for &retired in RETIRED_TUN {
  assert!(!runtime_root.join(retired).exists(), "runtime retired file still present: {retired}");
  assert!(!app_root.join(retired).exists(), "app retired file still present: {retired}");
 }
 assert_eq!(std::fs::read(app_root.join("user-custom-note.txt")).unwrap(), b"keep-app-unknown");
 assert_eq!(std::fs::read(runtime_root.join("network/custom-profile.dat")).unwrap(), b"keep-rt-unknown");
 assert!(app_root.join("kat-elevate-helper.exe").exists());

 // If unfinalized update rolls back, retired c49 files are restored and unknown data still kept.
 app_update.restore().unwrap();
 rt_update.restore().unwrap();
 assert_eq!(std::fs::read(runtime_root.join("network/tun2socks.exe")).unwrap(), b"old-c49-rt");
 assert_eq!(std::fs::read(app_root.join("network/tun2socks.exe")).unwrap(), b"old-c49");
 assert!(!app_root.join("kat-elevate-helper.exe").exists());
 assert_eq!(std::fs::read(app_root.join("user-custom-note.txt")).unwrap(), b"keep-app-unknown");
 let _ = std::fs::remove_dir_all(&base);

 // Higher-sequence rollback package transition and floor rules (§5.3).
 let h1 = "a".repeat(64);
 let h2 = "b".repeat(64);
 // Higher sequence + higher/compatible version succeeds (used by signed behavior-rollback package).
 assert!(verify_forward_transition("0.1.34", 100, &h1, "0.7.34", 100, &h1, "0.1.35", 101, &h2, "0.7.35", 101, &h2, false).is_ok());
 // Lower sequence, replayed sequence on newer version, lower version, or same-version different-hash is rejected.
 assert!(verify_forward_transition("0.1.34", 100, &h1, "0.7.34", 100, &h1, "0.1.33", 101, &h2, "0.7.35", 101, &h2, false).is_err());
 assert!(verify_forward_transition("0.1.34", 100, &h1, "0.7.34", 100, &h1, "0.1.35", 100, &h2, "0.7.35", 101, &h2, false).is_err());
 assert!(verify_forward_transition("0.1.34", 100, &h1, "0.7.34", 100, &h1, "0.1.34", 100, &h2, "0.7.34", 100, &h1, false).is_err());
 // Tampered package auth signature or retired component in package auth is rejected.
 let bad_auth = serde_json::to_vec(&json!({
  "schema": 1, "product": "kat-client-package", "key_id": "0afa646ee76f17d8",
  "os": "windows", "arch": "amd64", "app_version": "0.1.34",
  "stdio_protocol": 1, "service_protocol": 1, "record_schema": 2, "workspace_schema": 1,
  "source_revision": "a".repeat(64),
  "components": {"kat-desktop.exe": h1, "kat-install-helper.exe": h1, "kat-network-service.exe": h1, "kat-client-core.exe": h1, "tun2socks.exe": h1}
 })).unwrap();
 assert!(verify_package(&bad_auth, &"0".repeat(128).into_bytes()).is_err());
}

#[test]
fn stage5_legacy_recovery_gate_and_single_engine_exclusivity() {
 use kat_host::{error::Error, service_protocol::{legacy_cleanup_gate, verify_single_engine_takeover}};
 // Legacy cleanup gate only succeeds when no conflict, no error, bridge exited, and adapter absent.
 assert!(legacy_cleanup_gate(false, None, false, false).is_ok());
 assert_eq!(legacy_cleanup_gate(true, None, false, false).unwrap_err().code, "RECOVERY_CONFLICT");
 assert_eq!(legacy_cleanup_gate(false, Some(Error::new("ROUTE_REMOVE", "err")), false, false).unwrap_err().code, "ROUTE_REMOVE");
 assert_eq!(legacy_cleanup_gate(false, None, true, false).unwrap_err().code, "TUN_BRIDGE_ACTIVE");
 assert_eq!(legacy_cleanup_gate(false, None, false, true).unwrap_err().code, "LEGACY_ADAPTER_PRESENT");

 // Two engines cannot take over simultaneously.
 assert!(verify_single_engine_takeover(false, false, false, false).is_ok());
 assert_eq!(verify_single_engine_takeover(true, false, false, false).unwrap_err().code, "CORE_TUN_RECOVERY_REQUIRED");
 assert_eq!(verify_single_engine_takeover(false, true, false, false).unwrap_err().code, "LEGACY_RECOVERY_REQUIRED");
 assert_eq!(verify_single_engine_takeover(false, false, true, false).unwrap_err().code, "LEGACY_RECOVERY_REQUIRED");
 assert_eq!(verify_single_engine_takeover(false, false, false, true).unwrap_err().code, "LEGACY_RECOVERY_REQUIRED");
}

#[test]
fn stage5_named_pipe_gui_crash_first_preserves_private_fatal_and_reloads_snapshot() {
 use kat_host::{crash_private::{self, Capture}, user_store::Store};
 use std::sync::atomic::{AtomicUsize, Ordering};
 static NEXT: AtomicUsize = AtomicUsize::new(0);
 let dir = std::env::temp_dir().join(format!("kat-stage5-crash-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::SeqCst)));
 let store = Store::new(dir.clone()).unwrap();
 crash_private::init(&store, 7);

 // Simulate service-owned stderr drain capturing a fatal panic after GUI control pipe broke first:
 // write >128KiB fatal trace in chunks, verify 128KiB single-slot cap and complete=true on EOF.
 let mut cap = Capture::new(7788);
 cap.feed(b"ordinary log before gui exit
", 91);
 let mut trace = b"panic: stage5 elevated core crash after gui pipe eof
goroutine 1 [running]:
main.main()
".to_vec();
 trace.extend(vec![b'A'; 140 * 1024]);
 for chunk in trace.chunks(4096) {
  cap.feed(chunk, 91);
 }
 let summary = cap.finish(true).unwrap();
 assert!(summary.present && summary.complete && !summary.write_failed && summary.truncated);
 assert_eq!(summary.capacity_bytes, 128 * 1024);
 assert_eq!(summary.saved_bytes, (128 * 1024 - 512) as u64);

 // Verify on-disk file is strictly 128KiB and snapshot() reloads it from disk.
 let crash_file = dir.join("diagnostic-private-crash/latest-crash.bin");
 assert_eq!(crash_file.metadata().unwrap().len(), 128 * 1024);
 let reloaded = crash_private::snapshot().unwrap();
 assert!(reloaded.present && reloaded.complete && reloaded.truncated);
 assert_eq!(reloaded.pid, 7788);
 assert_eq!(reloaded.saved_bytes, summary.saved_bytes);
 let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn stage5_v2_handoff_requires_clean_interpreted_journal() {
 use kat_host::core_tun_journal::*;
 let mut j = Journal {
  schema: 2,
  engine: ENGINE.into(),
  launch: LaunchIdentity {
   schema: 2,
   engine: ENGINE.into(),
   epoch: "a".repeat(32),
   core_pid: 42,
   core_created: 99,
   owner_sid: "S-1-5-21-1".into(),
   session: 1,
   package_sha256: "b".repeat(64),
   core_sha256: "c".repeat(64),
  },
  adapter: Adapter {
   alias: alias("S-1-5-21-1"),
   guid: "11111111-1111-1111-1111-111111111111".into(),
   luid: 7,
   compartment: 1,
  },
  seq: 3,
  phase: "complete".into(),
  changes: vec![Change {
   id: "dns".into(),
   before: Some(Value { route: None, address: None, interface: None, dns: Some(DnsValue { servers: "".into() }) }),
   installed: Value { route: None, address: None, interface: None, dns: Some(DnsValue { servers: "198.18.0.2".into() }) },
   desired: false,
   state: "restored".into(),
  }],
  last_request: "d".repeat(32),
  last_digest: "e".repeat(64),
 };
 let raw = serde_json::to_vec(&j).unwrap();
 assert!(handoff_v2_journal_decision(&raw, Ok(true), Ok(())).is_ok());
 assert_eq!(handoff_v2_journal_decision(&raw, Ok(false), Ok(())).unwrap_err(), "CORE_STILL_ACTIVE");
 assert_eq!(handoff_v2_journal_decision(&raw, Err("PROCESS_IDENTITY"), Ok(())).unwrap_err(), "PROCESS_IDENTITY");
 assert_eq!(handoff_v2_journal_decision(&raw, Ok(true), Err("ADAPTER_REMAINS")).unwrap_err(), "ADAPTER_REMAINS");
 j.phase = "active".into();
 assert_eq!(handoff_v2_journal_decision(&serde_json::to_vec(&j).unwrap(), Ok(true), Ok(())).unwrap_err(), "RECOVERY_PENDING");
 j.phase = "complete".into();
 j.changes[0].state = "conflict".into();
 assert_eq!(handoff_v2_journal_decision(&serde_json::to_vec(&j).unwrap(), Ok(true), Ok(())).unwrap_err(), "RECOVERY_PENDING");
 assert_eq!(handoff_v2_journal_decision(br#"{"schema":99,"engine":"future_v9"}"#, Ok(true), Ok(())).unwrap_err(), "JOURNAL_INVALID");
 assert_eq!(handoff_v2_journal_decision(&vec![b'x'; MAX_BYTES + 1], Ok(true), Ok(())).unwrap_err(), "JOURNAL_LIMIT");
}

#[test]
fn review_036_windows_lifecycle_legacy_installer_recovery_and_stderr_drain_guards() {
 let fw = include_str!("../src/windows/firewall.rs");
 let store_def = fw.split("struct ComFirewallStore {").nth(1).unwrap().split("}").next().unwrap();
 let rules_pos = store_def.find("rules: ComPtr").unwrap();
 let policy_pos = store_def.find("_policy: ComPtr").unwrap();
 let com_pos = store_def.find("_com: ComInitGuard").unwrap();
 assert!(rules_pos < com_pos && policy_pos < com_pos, "COM pointers must drop before CoUninitialize");

 let ui = include_str!("../src/windows/update_install.rs");
 let elr = ui.split("fn ensure_legacy_recovered(").nth(1).unwrap();
 assert!(elr.contains("super::engine::Engine::recover_in_installer(dir,sid.to_owned(),root)?"));
 assert!(!elr.contains("Engine::new("));
 let rb = ui.split("fn rollback(").nth(1).unwrap().split("fn cleanup(").next().unwrap();
 assert!(rb.contains("super::firewall::ensure_core_udp_inbound"));
 assert!(rb.contains("super::firewall::remove_core_udp_inbound"));

 let lrec = include_str!("../src/windows/legacy_tun_recovery.rs");
 let rec_fn = lrec.split("fn recover_in_installer(").nth(1).unwrap();
 assert!(!rec_fn.contains("require_installed()"));
 assert!(rec_fn.contains("security::verify_protected(dir)?"));
 let cleanup_fn = lrec.split("pub fn cleanup(&mut self)->Result<()>{").nth(1).unwrap();
 assert!(cleanup_fn.find("if self.journal.is_none(){return Ok(());}").unwrap() < cleanup_fn.find("core-tun-journal-v2.json").unwrap());

 let es = include_str!("../src/windows/elevated_stderr.rs");
 assert!(es.contains("super::pipe::stream_accept(pipe.0,&STOP_ACCEPT,15000)"));
 assert!(es.contains("pub fn snapshot_only("));
 assert!(es.contains("pub fn cancel_accept()"));

 let el = include_str!("../src/windows/elevated.rs");
 let view_fn = el.split("fn view(l:&Launch)->Value{").nth(1).unwrap().split("fn verify_package").next().unwrap();
 assert!(view_fn.contains("if exited{super::elevated_stderr::summary(&l.lease)}else{super::elevated_stderr::snapshot_only(&l.lease)}"));

 let ctr = include_str!("../src/windows/core_tun_recovery.rs");
 let open_fn = ctr.split("pub fn open()->Result<Self>{").nth(1).unwrap().split("pub fn attach").next().unwrap();
 assert!(open_fn.contains(r#"for stale_name in ["core-tun-journal-v2.next","core-tun-journal-v2.json.next"]"#));

 let inst = include_str!("../src/windows/installer.rs");
 assert!(inst.contains(r#"["core-tun-journal-v2.json","core-tun-journal-v2.next","core-tun-journal-v2.json.next"].iter().any(|n|dir.join(n).exists())"#));

 let ub = include_str!("../src/windows/update_bridge.rs");
 assert!(ub.contains("r.firewall_error.as_ref()"));
}

#[test]
fn stage5_recover_after_exit_removes_only_kat_owned_residual_adapter_and_keeps_pending_on_failure() {
 use kat_host::core_tun_journal::*;
 let launch = LaunchIdentity {
  schema: 2,
  engine: ENGINE.into(),
  epoch: "a".repeat(32),
  core_pid: 4056,
  core_created: 123456,
  owner_sid: "S-1-5-21-1000".into(),
  session: 1,
  package_sha256: "b".repeat(64),
  core_sha256: "c".repeat(64),
 };
 let owned_adapter = Adapter {
  alias: alias("S-1-5-21-1000"),
  guid: "11111111-2222-3333-4444-555555555555".into(),
  luid: 99,
  compartment: 1,
 };
 let mut j = Journal {
  schema: 2,
  engine: ENGINE.into(),
  launch,
  adapter: owned_adapter.clone(),
  seq: 4,
  phase: "recovering".into(),
  changes: vec![Change {
   id: "dns".into(),
   before: Some(Value { route: None, address: None, interface: None, dns: Some(DnsValue { servers: "".into() }) }),
   installed: Value { route: None, address: None, interface: None, dns: Some(DnsValue { servers: "198.18.0.2".into() }) },
   desired: false,
   state: "restored".into(),
  }],
  last_request: "d".repeat(32),
  last_digest: "e".repeat(64),
 };

 // 1. Owned residual adapter in Disconnected/Down state (oper == 2) after core exit is eligible for removal.
 assert!(recovering_stale_adapter_decision(&j, Ok(true), &owned_adapter, 2, 15).is_ok());

 // 2. Live core or query failure must never remove the adapter.
 assert_eq!(recovering_stale_adapter_decision(&j, Ok(false), &owned_adapter, 2, 15).unwrap_err(), "CORE_STILL_ACTIVE");
 assert_eq!(recovering_stale_adapter_decision(&j, Err("PROCESS_IDENTITY"), &owned_adapter, 2, 15).unwrap_err(), "PROCESS_IDENTITY");

 // 3. Active/Up adapter (oper == 1) or zero LUID/ifIndex is refused.
 assert_eq!(recovering_stale_adapter_decision(&j, Ok(true), &owned_adapter, 1, 15).unwrap_err(), "LEGACY_ADAPTER_PRESENT");
 assert_eq!(recovering_stale_adapter_decision(&j, Ok(true), &owned_adapter, 2, 0).unwrap_err(), "LEGACY_ADAPTER_PRESENT");

 // 4. Foreign adapter (different alias, different GUID, or different LUID) is never touched.
 let mut foreign_alias = owned_adapter.clone();
 foreign_alias.alias = "Foreign-VPN".into();
 assert_eq!(recovering_stale_adapter_decision(&j, Ok(true), &foreign_alias, 2, 15).unwrap_err(), "LEGACY_ADAPTER_PRESENT");
 let mut foreign_guid = owned_adapter.clone();
 foreign_guid.guid = "99999999-2222-3333-4444-555555555555".into();
 assert_eq!(recovering_stale_adapter_decision(&j, Ok(true), &foreign_guid, 2, 15).unwrap_err(), "LEGACY_ADAPTER_PRESENT");
 let mut foreign_luid = owned_adapter.clone();
 foreign_luid.luid = 777;
 assert_eq!(recovering_stale_adapter_decision(&j, Ok(true), &foreign_luid, 2, 15).unwrap_err(), "LEGACY_ADAPTER_PRESENT");

 // 5. Adapter-owned changes (interface/address/dns on j.adapter.luid) may still be pending when removing
 // the oper == 2 adapter (because Windows returns ERROR_NOT_FOUND 1168 on MIB_IPINTERFACE_ROW once addresses
 // are removed on a Disconnected Wintun adapter), whereas unrestored non-adapter changes (routes) keep recovery pending.
 j.changes[0].state = "pending".into();
 assert!(recovering_stale_adapter_decision(&j, Ok(true), &owned_adapter, 2, 15).is_ok());

 let route_change = Change {
  id: "route:0.0.0.0/1".into(),
  before: None,
  installed: Value {
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
  },
  desired: false,
  state: "pending".into(),
 };
 j.changes.push(route_change);
 assert_eq!(recovering_stale_adapter_decision(&j, Ok(true), &owned_adapter, 2, 15).unwrap_err(), "RECOVERY_PENDING");
 j.changes[1].state = "restored".into();
 assert!(recovering_stale_adapter_decision(&j, Ok(true), &owned_adapter, 2, 15).is_ok());

 // 6. Static wiring check: recover_after_exit restores non-adapter changes, removes the oper==2 adapter,
 // marks adapter-owned changes absent/restored, and only then runs verify_complete -> phase="complete".
 let ctr = include_str!("../src/windows/core_tun_recovery.rs");
 let rec_fn = ctr.split("pub fn recover_after_exit(&mut self)->Result<RecoveryReport>{").nth(1).unwrap().split("fn remove_recovering_adapter").next().unwrap();
 let flt_pos = rec_fn.find("recover_filtered_set(").unwrap();
 let rem_pos = rec_fn.find("self.remove_recovering_adapter(&j)?;").unwrap();
 let set_pos = rec_fn.find("recover_set(&j,absent,").unwrap();
 let ver_pos = rec_fn.find("verify_complete(&j)?;").unwrap();
 let cmp_pos = rec_fn.find(r#"j.phase="complete".into();"#).unwrap();
 assert!(flt_pos < rem_pos && rem_pos < set_pos && set_pos < ver_pos && ver_pos < cmp_pos);

 // 7. End-to-end simulation: interface:2/23 returns ERROR_NOT_FOUND (1168 -> Ok(None)) while residual
 // Kat adapter is oper == 2; routes restore first, remove_recovering_adapter removes the oper == 2
 // adapter, then adapter-owned interface/address/dns entries resolve as absent -> restored -> complete.
 // Also verify that a physical interface returning 1168 (or different LUID) is NEVER misclassified as absent.
 let iface_before = Value {
  route: None,
  address: None,
  interface: Some(InterfaceValue { family: 2, mtu: 1500, metric: 25, automatic_metric: true, dad_transmits: 3 }),
  dns: None,
 };
 let iface_installed = Value {
  route: None,
  address: None,
  interface: Some(InterfaceValue { family: 2, mtu: 1420, metric: 5, automatic_metric: false, dad_transmits: 0 }),
  dns: None,
 };
 let addr_installed = Value {
  route: None,
  address: Some(AddressValue { address: "198.18.0.1".into(), prefix: 30, prefix_origin: 1, suffix_origin: 1, skip_as_source: false }),
  interface: None,
  dns: None,
 };
 let full_journal = Journal {
  schema: 2,
  engine: ENGINE.into(),
  launch: j.launch.clone(),
  adapter: owned_adapter.clone(),
  seq: 5,
  phase: "recovering".into(),
  changes: vec![
   Change { id: "interface:2".into(), before: Some(iface_before), installed: iface_installed, desired: false, state: "pending".into() },
   Change { id: "address:198.18.0.1".into(), before: None, installed: addr_installed, desired: false, state: "pending".into() },
   Change { id: "dns".into(), before: j.changes[0].before.clone(), installed: j.changes[0].installed.clone(), desired: false, state: "pending".into() },
   Change { id: "route:0.0.0.0/1".into(), before: None, installed: j.changes[1].installed.clone(), desired: false, state: "pending".into() },
  ],
  last_request: "d".repeat(32),
  last_digest: "e".repeat(64),
 };

 // Step 7a: Before adapter removal (adapter_absent = false), if recover_set ran directly on interface:2
 // when GetIpInterfaceEntry returned 1168 -> Ok(None), CAS would see None != Some(iface_before) and fail
 // with RECOVERY_CONFLICT; similarly a physical LUID (777 != owned_adapter.luid 99) is never treated as Kat-owned.
 assert!(!is_kat_adapter_owned_change(&owned_adapter, &full_journal.changes[0], 777));
 assert!(!is_kat_adapter_owned_change(&owned_adapter, &full_journal.changes[3], owned_adapter.luid));
 assert!(is_kat_adapter_owned_change(&owned_adapter, &full_journal.changes[0], owned_adapter.luid));
 assert_eq!(
  recover_set(&full_journal, false, |_| Ok(None), |_| Ok(()), |_| Ok(())).unwrap_err(),
  "RECOVERY_CONFLICT"
 );

 // Step 7b: With the .39 recovery order for dead==true && oper==2:
 // Phase 1 restores non-adapter-owned entries (routes) while leaving adapter-owned entries pending.
 let after_routes = recover_filtered_set(
  &full_journal,
  false,
  |c| !is_kat_adapter_owned_change(&owned_adapter, c, owned_adapter.luid),
  |c| Ok(Some(c.installed.clone())),
  |_| Ok(()),
  |_| Ok(()),
 ).unwrap();
 assert_eq!(after_routes.changes[3].state, "restored");
 assert_eq!(after_routes.changes[0].state, "pending");

 // Phase 2: recovering_stale_adapter_decision permits removing the oper==2 Kat adapter now that routes are restored.
 assert!(recovering_stale_adapter_decision(&after_routes, Ok(true), &owned_adapter, 2, 15).is_ok());

 // Phase 3: Once the adapter is removed (adapter_absent = true), GetIpInterfaceEntry / GetInterfaceDnsSettings
 // returning 1168 -> Ok(None) marks all Kat adapter-owned entries (interface:2, address, dns) as restored.
 let mut after_adapter_removed = recover_set(
  &after_routes,
  true,
  |_| Ok(None),
  |_| panic!("deleted adapter entries must not invoke OS restore"),
  |_| Ok(()),
 ).unwrap();
 assert!(after_adapter_removed.changes.iter().all(|c| c.state == "restored"));
 after_adapter_removed.phase = "complete".into();
 assert!(handoff_v2_journal_decision(&serde_json::to_vec(&after_adapter_removed).unwrap(), Ok(true), Ok(())).is_ok());

 // Step 7c: Physical interface returning 1168 (ERROR_NOT_FOUND) in netapi::interface_snapshot / platformDNSOwner
 // is never treated as Ok(None): core_tun_os::read only maps ERROR_NOT_FOUND to Ok(None) after checking
 // adapter_present(a) for the journal's Kat adapter, and netapi.rs keeps rc != 0 as Err(rc).
 let cto = include_str!("../src/windows/core_tun_os.rs");
 let read_fn = cto.split("pub fn read(a:&Adapter,c:&Change)->Result<Option<Value>>{").nth(1).unwrap().split("pub fn restore").next().unwrap();
 assert!(read_fn.contains("if !adapter_present(a)?{return Ok(None)}"));
 assert!(read_fn.contains("let n=unsafe{GetIpInterfaceEntry(&mut r)};if n==ERROR_NOT_FOUND{return Ok(None)}rc(n)?;"));
 assert!(read_fn.contains("let n=unsafe{ConvertInterfaceLuidToGuid(&luid(a.luid),&mut g)};if n==ERROR_NOT_FOUND{return Ok(None)}rc(n)?;"));
 assert!(read_fn.contains("let n=unsafe{GetInterfaceDnsSettings(g,&mut s)};if n==ERROR_NOT_FOUND{return Ok(None)}rc(n)?;"));
 let netapi = include_str!("../src/windows/netapi.rs");
 assert!(netapi.contains("let rc=unsafe{GetIpInterfaceEntry(&mut r)};if rc!=0{return Err(rc);}"));
}
