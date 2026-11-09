//! Kat-owned Windows Firewall rule specification and pure reconciliation logic.
//! Only inbound UDP for the installed `kat-client-core.exe` is managed; never TCP,
//! never other executables, and never firewall profile state or Defender settings.
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const RULE_NAME: &str = "Kat Client Core UDP Inbound";
pub const RULE_GROUP: &str = "Kat Client";
pub const RULE_DESCRIPTION: &str = "Allow inbound UDP traffic for Kat Client Core (Full Cone NAT / EIF)";
pub const CORE_EXE_NAME: &str = "kat-client-core.exe";
pub const FIREWALL_ERROR_CODE: &str = "FIREWALL_RULE_FAILED";

pub const NET_FW_IP_PROTOCOL_TCP: i32 = 6;
pub const NET_FW_IP_PROTOCOL_UDP: i32 = 17;
pub const NET_FW_RULE_DIR_IN: i32 = 1;
pub const NET_FW_RULE_DIR_OUT: i32 = 2;
pub const NET_FW_ACTION_BLOCK: i32 = 0;
pub const NET_FW_ACTION_ALLOW: i32 = 1;
pub const NET_FW_PROFILE2_ALL: i32 = 0x7fff_ffff;
pub const WILDCARD: &str = "*";
pub const INTERFACE_TYPES_ALL: &str = "All";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FirewallStage {
    TargetPath,
    ComInit,
    BstrAlloc,
    PolicyCreate,
    RulesGet,
    RulesEnum,
    RuleInspect,
    RuleConflict,
    RuleCreate,
    RuleConfigure,
    RuleAdd,
    RuleRemove,
    RuleVerify,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FirewallRuleError {
    pub code: String,
    pub stage: FirewallStage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hresult: Option<i32>,
}

impl FirewallRuleError {
    pub fn new(stage: FirewallStage, hresult: Option<i32>) -> Self {
        Self {
            code: FIREWALL_ERROR_CODE.to_string(),
            stage,
            hresult,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallRuleSpec {
    pub name: String,
    pub group: String,
    pub description: String,
    pub application_name: String,
    pub service_name: Option<String>,
    pub protocol: i32,
    pub local_ports: String,
    pub remote_ports: String,
    pub local_addresses: String,
    pub remote_addresses: String,
    pub direction: i32,
    pub interface_types: String,
    pub enabled: bool,
    pub profiles: i32,
    pub action: i32,
}

impl FirewallRuleSpec {
    pub fn matches_readback(&self, actual: &Self) -> bool {
        actual.name == self.name
            && actual.group == self.group
            && same_windows_path(&actual.application_name, &self.application_name)
            && actual.service_name.as_deref().unwrap_or("").is_empty()
            && actual.protocol == NET_FW_IP_PROTOCOL_UDP
            && is_unrestricted(&actual.local_ports)
            && is_unrestricted(&actual.remote_ports)
            && is_unrestricted(&actual.local_addresses)
            && is_unrestricted(&actual.remote_addresses)
            && actual.direction == NET_FW_RULE_DIR_IN
            && actual.interface_types.eq_ignore_ascii_case(INTERFACE_TYPES_ALL)
            && actual.enabled
            && actual.profiles == NET_FW_PROFILE2_ALL
            && actual.action == NET_FW_ACTION_ALLOW
    }
}

pub fn is_unrestricted(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.is_empty() || trimmed == WILDCARD
}

pub fn normalize_windows_path(raw: &str) -> String {
    let mut out = raw.trim().replace('/', "\\");
    while out.len() > 3 && out.ends_with('\\') {
        out.pop();
    }
    out
}

pub fn same_windows_path(a: &str, b: &str) -> bool {
    normalize_windows_path(a).eq_ignore_ascii_case(&normalize_windows_path(b))
}

pub fn expected_core_udp_rule(install_root: &Path) -> Result<FirewallRuleSpec, FirewallRuleError> {
    let root_str = normalize_windows_path(&install_root.to_string_lossy());
    if root_str.is_empty() || root_str.contains('\0') {
        return Err(FirewallRuleError::new(FirewallStage::TargetPath, None));
    }
    let app_path = format!("{root_str}\\{CORE_EXE_NAME}");
    if !app_path
        .rsplit('\\')
        .next()
        .is_some_and(|leaf| leaf.eq_ignore_ascii_case(CORE_EXE_NAME))
    {
        return Err(FirewallRuleError::new(FirewallStage::TargetPath, None));
    }
    Ok(FirewallRuleSpec {
        name: RULE_NAME.to_string(),
        group: RULE_GROUP.to_string(),
        description: RULE_DESCRIPTION.to_string(),
        application_name: app_path,
        service_name: None,
        protocol: NET_FW_IP_PROTOCOL_UDP,
        local_ports: WILDCARD.to_string(),
        remote_ports: WILDCARD.to_string(),
        local_addresses: WILDCARD.to_string(),
        remote_addresses: WILDCARD.to_string(),
        direction: NET_FW_RULE_DIR_IN,
        interface_types: INTERFACE_TYPES_ALL.to_string(),
        enabled: true,
        profiles: NET_FW_PROFILE2_ALL,
        action: NET_FW_ACTION_ALLOW,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnsureOutcome {
    pub created: bool,
    pub updated: bool,
    pub deduplicated: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoveOutcome {
    pub removed: usize,
}

pub trait FirewallStore {
    type RuleHandle;
    fn list_candidate_rules(&mut self) -> Result<Vec<(Self::RuleHandle, FirewallRuleSpec)>, FirewallRuleError>;
    fn update_rule(&mut self, handle: &mut Self::RuleHandle, spec: &FirewallRuleSpec) -> Result<(), FirewallRuleError>;
    fn add_rule(&mut self, spec: &FirewallRuleSpec) -> Result<(), FirewallRuleError>;
    fn remove_by_name(&mut self, name: &str) -> Result<(), FirewallRuleError>;
}

pub fn is_kat_owned_rule(rule: &FirewallRuleSpec) -> bool {
    rule.name == RULE_NAME && rule.group == RULE_GROUP
}

pub fn ensure_core_udp_inbound<S: FirewallStore>(
    store: &mut S,
    install_root: &Path,
) -> Result<EnsureOutcome, FirewallRuleError> {
    let expected = expected_core_udp_rule(install_root)?;
    let candidates = store.list_candidate_rules()?;
    let mut owned_handles = Vec::new();
    let mut foreign_same_name = 0usize;
    for (handle, summary) in candidates {
        if summary.name == RULE_NAME {
            if summary.group == RULE_GROUP {
                owned_handles.push((handle, summary));
            } else {
                foreign_same_name += 1;
            }
        }
    }
    if foreign_same_name > 0 {
        return Err(FirewallRuleError::new(FirewallStage::RuleConflict, None));
    }
    match owned_handles.len() {
        0 => {
            store.add_rule(&expected)?;
            Ok(EnsureOutcome {
                created: true,
                updated: false,
                deduplicated: 0,
            })
        }
        1 => {
            let (mut handle, existing) = owned_handles.pop().unwrap();
            if existing.matches_readback(&expected) && existing.description == expected.description {
                return Ok(EnsureOutcome {
                    created: false,
                    updated: false,
                    deduplicated: 0,
                });
            }
            store.update_rule(&mut handle, &expected)?;
            Ok(EnsureOutcome {
                created: false,
                updated: true,
                deduplicated: 0,
            })
        }
        count => {
            drop(owned_handles);
            for _ in 0..count {
                store.remove_by_name(RULE_NAME)?;
            }
            store.add_rule(&expected)?;
            Ok(EnsureOutcome {
                created: false,
                updated: true,
                deduplicated: count - 1,
            })
        }
    }
}

pub fn remove_core_udp_inbound<S: FirewallStore>(
    store: &mut S,
) -> Result<RemoveOutcome, FirewallRuleError> {
    let candidates = store.list_candidate_rules()?;
    let mut owned_count = 0usize;
    let mut foreign_same_name = 0usize;
    for (_handle, summary) in candidates {
        if summary.name == RULE_NAME {
            if summary.group == RULE_GROUP {
                owned_count += 1;
            } else {
                foreign_same_name += 1;
            }
        }
    }
    if owned_count == 0 {
        return Ok(RemoveOutcome { removed: 0 });
    }
    if foreign_same_name > 0 {
        return Err(FirewallRuleError::new(FirewallStage::RuleConflict, None));
    }
    for _ in 0..owned_count {
        store.remove_by_name(RULE_NAME)?;
    }
    Ok(RemoveOutcome {
        removed: owned_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeFirewallStore {
        rules: Vec<FirewallRuleSpec>,
        fail_stage: Option<(FirewallStage, Option<i32>)>,
        updates: usize,
        adds: usize,
        removes: usize,
    }

    impl FirewallStore for FakeFirewallStore {
        type RuleHandle = usize;

        fn list_candidate_rules(&mut self) -> Result<Vec<(Self::RuleHandle, FirewallRuleSpec)>, FirewallRuleError> {
            if let Some((stage @ (FirewallStage::ComInit | FirewallStage::PolicyCreate | FirewallStage::RulesGet | FirewallStage::RulesEnum), hr)) = self.fail_stage {
                return Err(FirewallRuleError::new(stage, hr));
            }
            Ok(self.rules.iter().cloned().enumerate().collect())
        }

        fn update_rule(&mut self, handle: &mut Self::RuleHandle, spec: &FirewallRuleSpec) -> Result<(), FirewallRuleError> {
            if let Some((stage @ (FirewallStage::RuleConfigure | FirewallStage::RuleVerify), hr)) = self.fail_stage {
                return Err(FirewallRuleError::new(stage, hr));
            }
            let slot = self.rules.get_mut(*handle).ok_or_else(|| FirewallRuleError::new(FirewallStage::RuleConfigure, None))?;
            *slot = spec.clone();
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
            let pos = self.rules.iter().position(|r| r.name == name).ok_or_else(|| FirewallRuleError::new(FirewallStage::RuleRemove, Some(-2147024894)))?;
            self.rules.remove(pos);
            self.removes += 1;
            Ok(())
        }
    }

    #[test]
    fn rule_spec_constructs_exact_inbound_udp_core_only_all_profiles_unrestricted_ports() {
        let spec = expected_core_udp_rule(Path::new(r"C:\Program Files\Kat Client")).unwrap();
        assert_eq!(spec.name, RULE_NAME);
        assert_eq!(spec.group, RULE_GROUP);
        assert_eq!(spec.application_name, r"C:\Program Files\Kat Client\kat-client-core.exe");
        assert_eq!(spec.service_name, None);
        assert_eq!(spec.protocol, NET_FW_IP_PROTOCOL_UDP);
        assert_ne!(spec.protocol, NET_FW_IP_PROTOCOL_TCP);
        assert_eq!(spec.direction, NET_FW_RULE_DIR_IN);
        assert_eq!(spec.action, NET_FW_ACTION_ALLOW);
        assert_eq!(spec.local_ports, "*");
        assert_eq!(spec.remote_ports, "*");
        assert_eq!(spec.local_addresses, "*");
        assert_eq!(spec.remote_addresses, "*");
        assert_eq!(spec.interface_types, "All");
        assert_eq!(spec.profiles, NET_FW_PROFILE2_ALL);
        assert!(spec.enabled);
        assert!(spec.matches_readback(&spec));
        assert!(expected_core_udp_rule(Path::new("")).is_err());
    }

    #[test]
    fn idempotent_update_reconciles_changed_path_and_drifted_fields_without_duplicating() {
        let mut store = FakeFirewallStore::default();
        let foreign_other = FirewallRuleSpec {
            name: "Windows Remote Desktop".into(),
            group: "Remote Desktop".into(),
            description: "Built-in".into(),
            application_name: r"C:\Windows\System32\svchost.exe".into(),
            service_name: Some("TermService".into()),
            protocol: NET_FW_IP_PROTOCOL_TCP,
            local_ports: "3389".into(),
            remote_ports: "*".into(),
            local_addresses: "*".into(),
            remote_addresses: "*".into(),
            direction: NET_FW_RULE_DIR_IN,
            interface_types: "All".into(),
            enabled: true,
            profiles: NET_FW_PROFILE2_ALL,
            action: NET_FW_ACTION_ALLOW,
        };
        store.rules.push(foreign_other.clone());

        // 1. Fresh install creates the Kat UDP inbound rule.
        let out1 = ensure_core_udp_inbound(&mut store, Path::new(r"C:\Program Files\Kat Client")).unwrap();
        assert_eq!(out1, EnsureOutcome { created: true, updated: false, deduplicated: 0 });
        assert_eq!(store.rules.len(), 2);
        assert_eq!(store.adds, 1);

        // 2. Repeat update with identical path and parameters is a no-op (no add, no update).
        let out2 = ensure_core_udp_inbound(&mut store, Path::new(r"C:\Program Files\Kat Client\")).unwrap();
        assert_eq!(out2, EnsureOutcome { created: false, updated: false, deduplicated: 0 });
        assert_eq!(store.rules.len(), 2);
        assert_eq!(store.adds, 1);
        assert_eq!(store.updates, 0);

        // 3. Corrupt parameters and change install path -> updates in-place, keeps count at 2.
        store.rules[1].protocol = NET_FW_IP_PROTOCOL_TCP;
        store.rules[1].direction = NET_FW_RULE_DIR_OUT;
        store.rules[1].action = NET_FW_ACTION_BLOCK;
        store.rules[1].local_ports = "53".into();
        store.rules[1].enabled = false;
        store.rules[1].profiles = 1;
        let out3 = ensure_core_udp_inbound(&mut store, Path::new(r"D:\tool\Kat")).unwrap();
        assert_eq!(out3, EnsureOutcome { created: false, updated: true, deduplicated: 0 });
        assert_eq!(store.rules.len(), 2);
        assert_eq!(store.updates, 1);
        assert_eq!(store.rules[0], foreign_other);
        assert_eq!(store.rules[1], expected_core_udp_rule(Path::new(r"D:\tool\Kat")).unwrap());

        // 4. Duplicate Kat rules are deduplicated back to a single rule.
        store.rules.push(store.rules[1].clone());
        assert_eq!(store.rules.len(), 3);
        let out4 = ensure_core_udp_inbound(&mut store, Path::new(r"D:\tool\Kat")).unwrap();
        assert_eq!(out4, EnsureOutcome { created: false, updated: true, deduplicated: 1 });
        assert_eq!(store.rules.len(), 2);
        assert_eq!(store.rules[0], foreign_other);
        assert_eq!(store.rules[1], expected_core_udp_rule(Path::new(r"D:\tool\Kat")).unwrap());
    }

    #[test]
    fn uninstall_deletes_only_exact_name_and_group_preserving_all_other_rules() {
        let mut store = FakeFirewallStore::default();
        let same_group_other_name = FirewallRuleSpec {
            name: "KatCtl-SSH-HostOnly".into(),
            group: RULE_GROUP.into(),
            description: "Other rule in same group".into(),
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
        let unrelated = FirewallRuleSpec {
            name: "Core Networking - DNS (UDP-Out)".into(),
            group: "Core Networking".into(),
            description: "System rule".into(),
            application_name: r"C:\Windows\System32\svchost.exe".into(),
            service_name: Some("Dnscache".into()),
            protocol: NET_FW_IP_PROTOCOL_UDP,
            local_ports: "*".into(),
            remote_ports: "53".into(),
            local_addresses: "*".into(),
            remote_addresses: "*".into(),
            direction: NET_FW_RULE_DIR_OUT,
            interface_types: "All".into(),
            enabled: true,
            profiles: NET_FW_PROFILE2_ALL,
            action: NET_FW_ACTION_ALLOW,
        };
        let kat_rule = expected_core_udp_rule(Path::new(r"C:\Program Files\Kat Client")).unwrap();
        store.rules = vec![same_group_other_name.clone(), kat_rule, unrelated.clone()];

        let rem1 = remove_core_udp_inbound(&mut store).unwrap();
        assert_eq!(rem1, RemoveOutcome { removed: 1 });
        assert_eq!(store.rules, vec![same_group_other_name.clone(), unrelated.clone()]);

        // Second uninstall when already absent is a no-op.
        let rem2 = remove_core_udp_inbound(&mut store).unwrap();
        assert_eq!(rem2, RemoveOutcome { removed: 0 });
        assert_eq!(store.rules, vec![same_group_other_name, unrelated]);
    }

    #[test]
    fn foreign_rule_with_same_name_but_different_group_is_never_overwritten_or_deleted() {
        let mut store = FakeFirewallStore::default();
        let foreign_same_name = FirewallRuleSpec {
            name: RULE_NAME.into(),
            group: "Foreign Security Product".into(),
            description: "Not owned by Kat".into(),
            application_name: r"C:\Foreign\app.exe".into(),
            service_name: None,
            protocol: NET_FW_IP_PROTOCOL_TCP,
            local_ports: "443".into(),
            remote_ports: "*".into(),
            local_addresses: "*".into(),
            remote_addresses: "*".into(),
            direction: NET_FW_RULE_DIR_IN,
            interface_types: "All".into(),
            enabled: true,
            profiles: NET_FW_PROFILE2_ALL,
            action: NET_FW_ACTION_ALLOW,
        };
        store.rules.push(foreign_same_name.clone());

        let err = ensure_core_udp_inbound(&mut store, Path::new(r"C:\Program Files\Kat Client")).unwrap_err();
        assert_eq!(err.code, FIREWALL_ERROR_CODE);
        assert_eq!(err.stage, FirewallStage::RuleConflict);
        assert_eq!(store.rules, vec![foreign_same_name.clone()]);

        // Uninstall with only foreign same-name rule does not delete it.
        let rem = remove_core_udp_inbound(&mut store).unwrap();
        assert_eq!(rem, RemoveOutcome { removed: 0 });
        assert_eq!(store.rules, vec![foreign_same_name]);
    }
}
