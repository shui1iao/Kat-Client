//! Windows Firewall (`INetFwPolicy2` / `INetFwRules` / `INetFwRule`) COM adapter.
//! Executed only inside the existing elevated installer helper (`kat-install-helper.exe`)
//! or elevated uninstaller (`kat-network-service.exe --setup-uninstall` / `--uninstall`).
//! Never disables or alters firewall profiles, never touches Defender, never adds TCP rules.
use crate::firewall_rule::{
    ensure_core_udp_inbound as ensure_with_store, remove_core_udp_inbound as remove_with_store,
    EnsureOutcome, FirewallRuleError, FirewallRuleSpec, FirewallStage, FirewallStore, RemoveOutcome,
    RULE_NAME,
};
use core::ffi::c_void;
use std::path::Path;
use windows_sys::core::GUID;

#[link(name = "ole32")]
extern "system" {
    fn CoInitializeEx(pvReserved: *const c_void, dwCoInit: u32) -> i32;
    fn CoUninitialize();
    fn CoCreateInstance(
        rclsid: *const GUID,
        pUnkOuter: *mut c_void,
        dwClsContext: u32,
        riid: *const GUID,
        ppv: *mut *mut c_void,
    ) -> i32;
}

#[link(name = "oleaut32")]
extern "system" {
    fn SysAllocStringLen(strIn: *const u16, ui: u32) -> *mut u16;
    fn SysFreeString(bstrString: *mut u16);
    fn SysStringLen(pbstr: *const u16) -> u32;
    fn VariantInit(pvarg: *mut Variant);
    fn VariantClear(pvarg: *mut Variant) -> i32;
}

const COINIT_APARTMENTTHREADED: u32 = 2;
const CLSCTX_INPROC_SERVER: u32 = 1;
const RPC_E_CHANGED_MODE: i32 = 0x8001_0106u32 as i32;
const S_OK: i32 = 0;
const S_FALSE: i32 = 1;
const VT_DISPATCH: u16 = 9;
const VT_UNKNOWN: u16 = 13;
const VARIANT_TRUE: i16 = -1;
const VARIANT_FALSE: i16 = 0;

const CLSID_NET_FW_POLICY2: GUID = GUID::from_u128(0xe2b3c97f_6ae1_41ac_817a_f6f92166d7dd);
const IID_INET_FW_POLICY2: GUID = GUID::from_u128(0x98325047_c671_4174_8d81_defcd3f03186);
const CLSID_NET_FW_RULE: GUID = GUID::from_u128(0x2c5bc43e_3369_4c33_ab0c_be9469677af4);
const IID_INET_FW_RULE: GUID = GUID::from_u128(0xaf230d27_baba_4e42_aced_f524f22cfce2);
const IID_IENUM_VARIANT: GUID = GUID::from_u128(0x00020404_0000_0000_c000_000000000046);

#[repr(C)]
struct Variant {
    vt: u16,
    reserved1: u16,
    reserved2: u16,
    reserved3: u16,
    ptr: *mut c_void,
    pad: u64,
}

struct VariantGuard(Variant);
impl VariantGuard {
    fn new() -> Self {
        let mut v = Variant {
            vt: 0,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
            ptr: std::ptr::null_mut(),
            pad: 0,
        };
        unsafe { VariantInit(&mut v) };
        Self(v)
    }
}
impl Drop for VariantGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = VariantClear(&mut self.0);
        }
    }
}

struct ComInitGuard {
    uninit: bool,
}
impl ComInitGuard {
    fn init() -> Result<Self, FirewallRuleError> {
        let hr = unsafe { CoInitializeEx(std::ptr::null(), COINIT_APARTMENTTHREADED) };
        if hr == S_OK || hr == S_FALSE {
            Ok(Self { uninit: true })
        } else if hr == RPC_E_CHANGED_MODE {
            Ok(Self { uninit: false })
        } else {
            Err(FirewallRuleError::new(FirewallStage::ComInit, Some(hr)))
        }
    }
}
impl Drop for ComInitGuard {
    fn drop(&mut self) {
        if self.uninit {
            unsafe { CoUninitialize() };
        }
    }
}

struct Bstr(*mut u16);
impl Bstr {
    fn new(s: &str) -> Result<Self, FirewallRuleError> {
        let wide: Vec<u16> = s.encode_utf16().collect();
        let ptr = unsafe { SysAllocStringLen(wide.as_ptr(), wide.len() as u32) };
        if ptr.is_null() {
            return Err(FirewallRuleError::new(FirewallStage::BstrAlloc, None));
        }
        Ok(Self(ptr))
    }
}
impl Drop for Bstr {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { SysFreeString(self.0) };
        }
    }
}

pub struct ComPtr(*mut c_void);
impl ComPtr {
    unsafe fn slot(&self, index: usize) -> *const c_void {
        *(*(self.0 as *const *const *const c_void)).add(index)
    }

    unsafe fn query_interface(&self, iid: &GUID, stage: FirewallStage) -> Result<ComPtr, FirewallRuleError> {
        let mut out = std::ptr::null_mut();
        let f: unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> i32 =
            std::mem::transmute(self.slot(0));
        let hr = f(self.0, iid, &mut out);
        if hr < 0 || out.is_null() {
            return Err(FirewallRuleError::new(stage, Some(hr)));
        }
        Ok(ComPtr(out))
    }

    unsafe fn get_bstr(&self, slot: usize, stage: FirewallStage) -> Result<Option<String>, FirewallRuleError> {
        let mut raw: *mut u16 = std::ptr::null_mut();
        let f: unsafe extern "system" fn(*mut c_void, *mut *mut u16) -> i32 =
            std::mem::transmute(self.slot(slot));
        let hr = f(self.0, &mut raw);
        if hr < 0 {
            return Err(FirewallRuleError::new(stage, Some(hr)));
        }
        if raw.is_null() {
            return Ok(None);
        }
        let len = SysStringLen(raw) as usize;
        let text = String::from_utf16_lossy(std::slice::from_raw_parts(raw, len));
        SysFreeString(raw);
        Ok(Some(text))
    }

    unsafe fn put_bstr(&self, slot: usize, value: Option<&str>, stage: FirewallStage) -> Result<(), FirewallRuleError> {
        let f: unsafe extern "system" fn(*mut c_void, *mut u16) -> i32 =
            std::mem::transmute(self.slot(slot));
        let hr = match value {
            Some(s) => {
                let b = Bstr::new(s)?;
                f(self.0, b.0)
            }
            None => f(self.0, std::ptr::null_mut()),
        };
        if hr < 0 {
            return Err(FirewallRuleError::new(stage, Some(hr)));
        }
        Ok(())
    }

    unsafe fn get_i32(&self, slot: usize, stage: FirewallStage) -> Result<i32, FirewallRuleError> {
        let mut val: i32 = 0;
        let f: unsafe extern "system" fn(*mut c_void, *mut i32) -> i32 =
            std::mem::transmute(self.slot(slot));
        let hr = f(self.0, &mut val);
        if hr < 0 {
            return Err(FirewallRuleError::new(stage, Some(hr)));
        }
        Ok(val)
    }

    unsafe fn put_i32(&self, slot: usize, val: i32, stage: FirewallStage) -> Result<(), FirewallRuleError> {
        let f: unsafe extern "system" fn(*mut c_void, i32) -> i32 =
            std::mem::transmute(self.slot(slot));
        let hr = f(self.0, val);
        if hr < 0 {
            return Err(FirewallRuleError::new(stage, Some(hr)));
        }
        Ok(())
    }

    unsafe fn get_bool(&self, slot: usize, stage: FirewallStage) -> Result<bool, FirewallRuleError> {
        let mut val: i16 = 0;
        let f: unsafe extern "system" fn(*mut c_void, *mut i16) -> i32 =
            std::mem::transmute(self.slot(slot));
        let hr = f(self.0, &mut val);
        if hr < 0 {
            return Err(FirewallRuleError::new(stage, Some(hr)));
        }
        Ok(val != VARIANT_FALSE)
    }

    unsafe fn put_bool(&self, slot: usize, enabled: bool, stage: FirewallStage) -> Result<(), FirewallRuleError> {
        let f: unsafe extern "system" fn(*mut c_void, i16) -> i32 =
            std::mem::transmute(self.slot(slot));
        let hr = f(self.0, if enabled { VARIANT_TRUE } else { VARIANT_FALSE });
        if hr < 0 {
            return Err(FirewallRuleError::new(stage, Some(hr)));
        }
        Ok(())
    }
}

impl Drop for ComPtr {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let release: unsafe extern "system" fn(*mut c_void) -> u32 =
                    std::mem::transmute(self.slot(2));
                release(self.0);
            }
        }
    }
}

struct ComFirewallStore {
    rules: ComPtr,
    _policy: ComPtr,
    _com: ComInitGuard,
}

impl ComFirewallStore {
    fn open() -> Result<Self, FirewallRuleError> {
        let com = ComInitGuard::init()?;
        let mut policy_ptr = std::ptr::null_mut();
        let hr = unsafe {
            CoCreateInstance(
                &CLSID_NET_FW_POLICY2,
                std::ptr::null_mut(),
                CLSCTX_INPROC_SERVER,
                &IID_INET_FW_POLICY2,
                &mut policy_ptr,
            )
        };
        if hr < 0 || policy_ptr.is_null() {
            return Err(FirewallRuleError::new(FirewallStage::PolicyCreate, Some(hr)));
        }
        let policy = ComPtr(policy_ptr);
        let mut rules_ptr = std::ptr::null_mut();
        let hr = unsafe {
            // INetFwPolicy2::get_Rules is vtable slot 18.
            let get_rules: unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> i32 =
                std::mem::transmute(policy.slot(18));
            get_rules(policy.0, &mut rules_ptr)
        };
        if hr < 0 || rules_ptr.is_null() {
            return Err(FirewallRuleError::new(FirewallStage::RulesGet, Some(hr)));
        }
        Ok(Self {
            _com: com,
            _policy: policy,
            rules: ComPtr(rules_ptr),
        })
    }
}

unsafe fn read_rule_spec(rule: &ComPtr, stage: FirewallStage) -> Result<FirewallRuleSpec, FirewallRuleError> {
    Ok(FirewallRuleSpec {
        name: rule.get_bstr(7, stage)?.unwrap_or_default(),
        description: rule.get_bstr(9, stage)?.unwrap_or_default(),
        application_name: rule.get_bstr(11, stage)?.unwrap_or_default(),
        service_name: rule.get_bstr(13, stage)?.filter(|s| !s.is_empty()),
        protocol: rule.get_i32(15, stage)?,
        local_ports: rule.get_bstr(17, stage)?.unwrap_or_default(),
        remote_ports: rule.get_bstr(19, stage)?.unwrap_or_default(),
        local_addresses: rule.get_bstr(21, stage)?.unwrap_or_default(),
        remote_addresses: rule.get_bstr(23, stage)?.unwrap_or_default(),
        direction: rule.get_i32(27, stage)?,
        interface_types: rule.get_bstr(31, stage)?.unwrap_or_default(),
        enabled: rule.get_bool(33, stage)?,
        group: rule.get_bstr(35, stage)?.unwrap_or_default(),
        profiles: rule.get_i32(37, stage)?,
        action: rule.get_i32(41, stage)?,
    })
}

unsafe fn apply_rule_spec(rule: &ComPtr, spec: &FirewallRuleSpec) -> Result<(), FirewallRuleError> {
    let stage = FirewallStage::RuleConfigure;
    rule.put_bstr(8, Some(&spec.name), stage)?;
    rule.put_bstr(10, Some(&spec.description), stage)?;
    rule.put_bstr(36, Some(&spec.group), stage)?;
    rule.put_bstr(12, Some(&spec.application_name), stage)?;
    if rule.get_bstr(13, stage)?.is_some_and(|s| !s.is_empty()) {
        rule.put_bstr(14, None, stage)?;
    }
    // Protocol (slot 16) MUST be set to UDP (17) before LocalPorts / RemotePorts.
    rule.put_i32(16, spec.protocol, stage)?;
    rule.put_bstr(18, Some(&spec.local_ports), stage)?;
    rule.put_bstr(20, Some(&spec.remote_ports), stage)?;
    rule.put_bstr(22, Some(&spec.local_addresses), stage)?;
    rule.put_bstr(24, Some(&spec.remote_addresses), stage)?;
    rule.put_i32(28, spec.direction, stage)?;
    rule.put_bstr(32, Some(&spec.interface_types), stage)?;
    rule.put_i32(38, spec.profiles, stage)?;
    rule.put_i32(42, spec.action, stage)?;
    rule.put_bool(34, spec.enabled, stage)?;
    Ok(())
}

impl FirewallStore for ComFirewallStore {
    type RuleHandle = ComPtr;

    fn list_candidate_rules(&mut self) -> Result<Vec<(Self::RuleHandle, FirewallRuleSpec)>, FirewallRuleError> {
        unsafe {
            // INetFwRules::get__NewEnum is vtable slot 11.
            let mut unk_ptr = std::ptr::null_mut();
            let get_enum: unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> i32 =
                std::mem::transmute(self.rules.slot(11));
            let hr = get_enum(self.rules.0, &mut unk_ptr);
            if hr < 0 || unk_ptr.is_null() {
                return Err(FirewallRuleError::new(FirewallStage::RulesEnum, Some(hr)));
            }
            let unk = ComPtr(unk_ptr);
            let enum_var = unk.query_interface(&IID_IENUM_VARIANT, FirewallStage::RulesEnum)?;
            // IEnumVARIANT::Next is vtable slot 3.
            let next_fn: unsafe extern "system" fn(*mut c_void, u32, *mut Variant, *mut u32) -> i32 =
                std::mem::transmute(enum_var.slot(3));

            let mut out = Vec::new();
            loop {
                let mut vg = VariantGuard::new();
                let mut fetched: u32 = 0;
                let hr = next_fn(enum_var.0, 1, &mut vg.0, &mut fetched);
                if hr == S_FALSE || fetched == 0 {
                    break;
                }
                if hr < 0 {
                    return Err(FirewallRuleError::new(FirewallStage::RulesEnum, Some(hr)));
                }
                if (vg.0.vt == VT_DISPATCH || vg.0.vt == VT_UNKNOWN) && !vg.0.ptr.is_null() {
                    let disp = std::mem::ManuallyDrop::new(ComPtr(vg.0.ptr));
                    let rule = disp.query_interface(&IID_INET_FW_RULE, FirewallStage::RuleInspect)?;
                    let name = rule.get_bstr(7, FirewallStage::RuleInspect)?.unwrap_or_default();
                    if name == RULE_NAME {
                        let spec = read_rule_spec(&rule, FirewallStage::RuleInspect)?;
                        out.push((rule, spec));
                    }
                }
            }
            Ok(out)
        }
    }

    fn update_rule(&mut self, handle: &mut Self::RuleHandle, spec: &FirewallRuleSpec) -> Result<(), FirewallRuleError> {
        unsafe {
            apply_rule_spec(handle, spec)?;
            let actual = read_rule_spec(handle, FirewallStage::RuleVerify)?;
            if !spec.matches_readback(&actual) {
                return Err(FirewallRuleError::new(FirewallStage::RuleVerify, None));
            }
            Ok(())
        }
    }

    fn add_rule(&mut self, spec: &FirewallRuleSpec) -> Result<(), FirewallRuleError> {
        unsafe {
            let mut rule_ptr = std::ptr::null_mut();
            let hr = CoCreateInstance(
                &CLSID_NET_FW_RULE,
                std::ptr::null_mut(),
                CLSCTX_INPROC_SERVER,
                &IID_INET_FW_RULE,
                &mut rule_ptr,
            );
            if hr < 0 || rule_ptr.is_null() {
                return Err(FirewallRuleError::new(FirewallStage::RuleCreate, Some(hr)));
            }
            let rule = ComPtr(rule_ptr);
            apply_rule_spec(&rule, spec)?;
            // INetFwRules::Add is vtable slot 8.
            let add_fn: unsafe extern "system" fn(*mut c_void, *mut c_void) -> i32 =
                std::mem::transmute(self.rules.slot(8));
            let hr = add_fn(self.rules.0, rule.0);
            if hr < 0 {
                return Err(FirewallRuleError::new(FirewallStage::RuleAdd, Some(hr)));
            }
            let actual = read_rule_spec(&rule, FirewallStage::RuleVerify)?;
            if !spec.matches_readback(&actual) {
                return Err(FirewallRuleError::new(FirewallStage::RuleVerify, None));
            }
            Ok(())
        }
    }

    fn remove_by_name(&mut self, name: &str) -> Result<(), FirewallRuleError> {
        unsafe {
            let b = Bstr::new(name)?;
            // INetFwRules::Remove is vtable slot 9.
            let remove_fn: unsafe extern "system" fn(*mut c_void, *mut u16) -> i32 =
                std::mem::transmute(self.rules.slot(9));
            let hr = remove_fn(self.rules.0, b.0);
            if hr < 0 {
                return Err(FirewallRuleError::new(FirewallStage::RuleRemove, Some(hr)));
            }
            Ok(())
        }
    }
}

pub fn ensure_core_udp_inbound(install_root: &Path) -> Result<EnsureOutcome, FirewallRuleError> {
    let mut store = ComFirewallStore::open()?;
    ensure_with_store(&mut store, install_root)
}

pub fn remove_core_udp_inbound() -> Result<RemoveOutcome, FirewallRuleError> {
    let mut store = ComFirewallStore::open()?;
    remove_with_store(&mut store)
}
