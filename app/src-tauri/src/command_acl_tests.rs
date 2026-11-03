//! Host registrations must be callable under the generated Tauri ACL as well.
//! Runs on Linux too: a WebView-isolated transport does not exercise Tauri ACL.
use std::collections::BTreeSet;

fn array<'a>(source: &'a str, marker: &str) -> &'a str {
    assert_eq!(source.matches(marker).count(), 1, "expected one {marker}");
    source.split_once(marker).unwrap().1.split_once(']').unwrap().0
}

fn commands(list: &str, quoted: bool) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for item in list.split(',').map(str::trim).filter(|v| !v.is_empty()) {
        let name = if quoted {
            item.strip_prefix('"').and_then(|v| v.strip_suffix('"')).expect("quoted command")
        } else { item };
        assert!(!name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'), "invalid command {name}");
        assert!(names.insert(name.to_owned()), "duplicate command {name}");
    }
    assert!(!names.is_empty(), "command list must not be empty");
    names
}

fn declared() -> [BTreeSet<String>; 3] {
    let desktop = include_str!("desktop.rs");
    let build = include_str!("../build.rs");
    let host = include_str!("../permissions/host.toml");
    let permission: Vec<_> = host.split("[[permission]]").filter(|section| {
        section.lines().any(|line| line.split_once('=').is_some_and(|(key, value)| {
            key.trim() == "identifier" && value.trim() == "\"host-controls\""
        }))
    }).collect();
    assert_eq!(permission.len(), 1, "expected one host-controls permission");
    [
        commands(array(desktop, "tauri::generate_handler!["), false),
        commands(array(build, "AppManifest::new().commands(&["), true),
        commands(array(permission[0], "commands.allow = ["), true),
    ]
}

fn assert_equal(lists: &[BTreeSet<String>; 3]) {
    assert_eq!(lists[0], lists[1], "generate_handler! and AppManifest commands differ");
    assert_eq!(lists[0], lists[2], "generate_handler! and host-controls allow differ");
}

#[test]
fn registered_manifest_and_host_allow_commands_are_identical() {
    let lists = declared();
    assert!(lists[0].contains("core_restart"), "restart must remain registered and permitted");
    assert_equal(&lists);
}

#[test]
fn consistency_guard_rejects_missing_extra_and_duplicate_entries() {
    // Every direction is checked, not just registration being a subset of ACL.
    let lists = declared();
    for side in 0..3 {
        let mut missing = lists.clone();
        missing[side].remove("core_restart");
        assert!(std::panic::catch_unwind(|| assert_equal(&missing)).is_err());
        let mut extra = lists.clone();
        extra[side].insert("unexpected_command".into());
        assert!(std::panic::catch_unwind(|| assert_equal(&extra)).is_err());
    }
    assert!(std::panic::catch_unwind(|| commands("duplicate, duplicate", false)).is_err());
}
