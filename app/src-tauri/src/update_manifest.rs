//! Exact-byte, offline update authorization. No HTTP, paths, or installation side effects.
use ed25519_dalek::{Signature, VerifyingKey};
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{cmp::Ordering, collections::{BTreeMap, HashSet}, fmt};

pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;
pub const MAX_SIGNATURE_BYTES: usize = 130;
pub const MAX_CLIENT_BYTES: u64 = 1024 * 1024 * 1024;
pub const MAX_CORE_BYTES: u64 = 256 * 1024 * 1024;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UpdateKind { Client, Core }
impl UpdateKind {
    pub fn product(self) -> &'static str {
        match self { Self::Client => "kat-client", Self::Core => "kat-client-core" }
    }
    pub fn repo(self) -> &'static str {
        match self { Self::Client => "Kat-Client", Self::Core => "Kat-Server" }
    }
    pub fn manifest_name(self) -> &'static str {
        match self { Self::Client => "kat-client-update.json", Self::Core => "kat-client-core-update.json" }
    }
    pub fn signature_name(self) -> &'static str {
        match self { Self::Client => "kat-client-update.json.sig", Self::Core => "kat-client-core-update.json.sig" }
    }
    pub fn max_asset_bytes(self) -> u64 {
        match self { Self::Client => MAX_CLIENT_BYTES, Self::Core => MAX_CORE_BYTES }
    }
}
/// Supplied by protected installation metadata, NEVER by the download cache.
/// app_sha256 is the previously authorized SETUP asset hash, NOT the GUI image hash.
#[derive(Clone, Debug)]
pub struct CurrentVersions {
    pub app_version: String,
    pub core_version: String,
    pub app_sha256: Option<String>,
    pub core_sha256: String,
    pub app_sequence: u64,
    pub core_sequence: u64,
    pub supported_capabilities: Vec<String>,
}
#[derive(Clone, Debug)]
pub struct ExpectedRelease {
    pub kind: UpdateKind,
    pub release_id: u64,
    pub release_tag: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseBinding { pub id: u64, pub tag: String }
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetBinding {
    pub name: String,
    pub id: u64,
    pub bytes: u64,
    pub sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: u32,
    pub product: String,
    pub owner: String,
    pub repo: String,
    pub release: ReleaseBinding,
    pub version: String,
    pub sequence: u64,
    pub os: String,
    pub arch: String,
    pub asset: AssetBinding,
    pub gui_compatibility: String,
    pub stdio_protocol: u32,
    pub required_capabilities: Vec<String>,
    pub service_protocol: u32,
    pub record_schema: u32,
    pub workspace_read_compatibility: u32,
    pub workspace_write_compatibility: u32,
    pub source_revision: String,
    pub key_id: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VersionDisposition { Newer, Current }
/// Not deserializable or publicly constructible. Re-verify at every trust boundary.
#[derive(Clone, Debug)]
pub struct VerifiedManifest {
    manifest: Manifest,
    manifest_bytes: Vec<u8>,
    signature_hex: String,
    digest: String,
    disposition: VersionDisposition,
}
impl VerifiedManifest {
    pub fn manifest(&self) -> &Manifest { &self.manifest }
    pub fn manifest_bytes(&self) -> &[u8] { &self.manifest_bytes }
    pub fn signature_hex(&self) -> &str { &self.signature_hex }
    pub fn digest(&self) -> &str { &self.digest }
    pub fn disposition(&self) -> VersionDisposition { self.disposition }
    pub fn expected(&self) -> ExpectedRelease {
        ExpectedRelease {
            kind: if self.manifest.product == "kat-client" { UpdateKind::Client } else { UpdateKind::Core },
            release_id: self.manifest.release.id,
            release_tag: self.manifest.release.tag.clone(),
        }
    }
}
#[derive(Clone, Debug)]
pub struct UpdateError {
    pub code: &'static str,
    pub message: String,
    /// Display-only, bounded HTTP header. Never authorizes a retry or an update.
    pub retry_after: Option<String>,
}
impl UpdateError {
    pub(crate) fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self { code, message: message.into(), retry_after: None }
    }
}
impl fmt::Display for UpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}: {}", self.code, self.message) }
}
impl std::error::Error for UpdateError {}
fn require(ok: bool, code: &'static str, message: &'static str) -> Result<(), UpdateError> {
    if ok { Ok(()) } else { Err(UpdateError::new(code, message)) }
}
fn lower_hex(s: &str, bytes: usize) -> bool {
    s.len() == bytes * 2 && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn safe_atom(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.bytes().all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
        && s != "." && s != ".."
}
fn capabilities_valid(caps: &[String]) -> bool {
    let mut unique = HashSet::new();
    caps.len() <= 64 && caps.iter().all(|c| safe_atom(c, 80) && unique.insert(c.as_str()))
}
fn stable_version(value: &str) -> Result<Version, UpdateError> {
    require(!value.is_empty() && value.len() <= 128, "version", "语义版本长度无效")?;
    let version = Version::parse(value).map_err(|_| UpdateError::new("version", "版本必须是完整的语义版本"))?;
    require(version.pre.is_empty(), "version", "仅支持稳定语义版本")?;
    Ok(version)
}
fn verified_signature(bytes: &[u8], signature_hex: &[u8]) -> Result<(String, Vec<u8>), UpdateError> {
    require(!bytes.is_empty() && bytes.len() <= MAX_MANIFEST_BYTES,
        "manifest_size", "签名描述文件缺失或超过大小限制")?;
    require(signature_hex.len() <= MAX_SIGNATURE_BYTES, "signature", "签名长度无效")?;
    let text = signature_hex.strip_suffix(b"\r\n").or_else(|| signature_hex.strip_suffix(b"\n")).unwrap_or(signature_hex);
    let text = std::str::from_utf8(text).map_err(|_| UpdateError::new("signature", "签名必须为十六进制文本"))?;
    require(lower_hex(text, 64), "signature", "签名必须为 64 字节的十六进制文本")?;
    let decoded = hex::decode(text).map_err(|_| UpdateError::new("signature", "签名格式无效"))?;
    let sig = Signature::from_slice(&decoded).map_err(|_| UpdateError::new("signature", "签名长度无效"))?;
    let key = VerifyingKey::from_bytes(&crate::update_key::PUBLIC_KEY).map_err(|_| UpdateError::new("key", "内置更新公钥无效"))?;
    key.verify_strict(bytes, &sig).map_err(|_| UpdateError::new("signature", "发布者签名验证失败"))?;
    Ok((text.to_owned(), decoded))
}
/// JSON is never normalized/reserialized; unknown/duplicate fields fail.
/// Signature: 128 lowercase hex characters (64 bytes), optionally one LF or CRLF.
pub fn verify(bytes: &[u8], signature_hex: &[u8], expected: &ExpectedRelease, current: &CurrentVersions)
    -> Result<VerifiedManifest, UpdateError> {
    let (signature_hex, sig_bytes) = verified_signature(bytes, signature_hex)?;
    let manifest: Manifest = serde_json::from_slice(bytes)
        .map_err(|_| UpdateError::new("manifest_schema", "签名清单结构无效或存在未知/重复字段"))?;
    require(manifest.schema == 1 && manifest.key_id == crate::update_key::KEY_ID,
        "manifest_schema", "不支持的清单版本或签名密钥标识")?;
    require(manifest.product == expected.kind.product() && manifest.owner == "shui1iao" && manifest.repo == expected.kind.repo(),
        "source", "签名清单产品或固定仓库不匹配")?;
    require(expected.release_id > 0 && manifest.release.id == expected.release_id
        && manifest.release.tag == expected.release_tag && !manifest.release.tag.is_empty()
        && manifest.release.tag.len() <= 256 && !manifest.release.tag.chars().any(char::is_control),
        "release_binding", "签名清单与发现的 release ID/tag 不匹配")?;
    require(manifest.os == "windows" && manifest.arch == "amd64", "platform", "暂无 Windows AMD64 兼容更新")?;
    require(manifest.asset.id > 0 && safe_atom(&manifest.asset.name, 240) && manifest.asset.name.ends_with(".exe")
        && manifest.asset.bytes >= 64 && manifest.asset.bytes <= expected.kind.max_asset_bytes() && lower_hex(&manifest.asset.sha256, 32),
        "asset", "资产名称、大小、ID 或 SHA-256 无效（仅支持裸 exe）")?;
    require(match expected.kind {
        UpdateKind::Client => manifest.asset.name.to_ascii_lowercase().contains("setup"),
        UpdateKind::Core => manifest.asset.name.starts_with("kat-client-core") && manifest.asset.name.contains("windows-amd64"),
    }, "asset", "资产名称不符合 Setup/Windows core 产品约定")?;
    require(manifest.stdio_protocol == 1 && manifest.service_protocol == 1 && manifest.record_schema == 2
        && manifest.workspace_read_compatibility == 1 && manifest.workspace_write_compatibility == 1,
        "compatibility", "更新的协议、安装记录或 workspace 兼容版本不受支持")?;
    require(capabilities_valid(&manifest.required_capabilities) && capabilities_valid(&current.supported_capabilities),
        "capabilities", "能力标识无效或重复")?;
    require(manifest.required_capabilities.iter().all(|c| current.supported_capabilities.contains(c)),
        "capabilities", "需先更新客户端：当前 GUI/helper 不支持发布要求的能力")?;
    require(lower_hex(&manifest.source_revision, 20) || lower_hex(&manifest.source_revision, 32),
        "source_revision", "清单必须包含完整源码 revision")?;
    let next = stable_version(&manifest.version)?;
    let app = stable_version(&current.app_version)?;
    let core = stable_version(&current.core_version)?;
    let gui_requirement = VersionReq::parse(&manifest.gui_compatibility)
        .map_err(|_| UpdateError::new("compatibility", "GUI 兼容范围不是有效的 VersionReq"))?;
    require(!manifest.gui_compatibility.is_empty() && manifest.gui_compatibility.len() <= 256
        && gui_requirement.matches(match expected.kind { UpdateKind::Client => &next, UpdateKind::Core => &app }),
        "compatibility", "暂无兼容更新：GUI 版本不满足签名清单要求")?;
    let (installed, floor, installed_hash) = match expected.kind {
        UpdateKind::Client => (&app, current.app_sequence, current.app_sha256.as_deref()),
        UpdateKind::Core => (&core, current.core_sequence, Some(current.core_sha256.as_str())),
    };
    require(lower_hex(&current.core_sha256, 32) && current.app_sha256.as_deref().map(|h| lower_hex(h, 32)).unwrap_or(true),
        "installed_metadata", "受保护安装摘要无效，不能检查更新")?;
    require(manifest.sequence > 0 && manifest.sequence >= floor, "rollback", "拒绝低于受保护 sequence 下限的发布")?;
    let disposition = match next.cmp_precedence(installed) {
        Ordering::Less => return Err(UpdateError::new("rollback", "拒绝低于当前组件版本的发布")),
        Ordering::Equal => {
            require(installed_hash == Some(manifest.asset.sha256.as_str()),
                "same_version_hash", "拒绝同版本不同摘要，或当前同版本摘要未知的发布")?;
            VersionDisposition::Current
        }
        Ordering::Greater => {
            require(manifest.sequence > floor, "rollback", "新版本必须提高受保护 sequence")?;
            VersionDisposition::Newer
        }
    };
    let mut digest = Sha256::new();
    digest.update(b"kat-update-offer-v1\0"); digest.update(bytes); digest.update(&sig_bytes);
    Ok(VerifiedManifest { manifest, manifest_bytes: bytes.to_vec(), signature_hex,
        digest: hex::encode(digest.finalize()), disposition })
}
/// Inner Setup descriptor: no Setup self-hash. Caller binds peer identity and actual component bytes.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageAuth {
    pub schema: u32,
    pub product: String,
    pub key_id: String,
    pub os: String,
    pub arch: String,
    pub app_version: String,
    pub stdio_protocol: u32,
    pub service_protocol: u32,
    pub record_schema: u32,
    pub workspace_schema: u32,
    pub source_revision: String,
    #[serde(deserialize_with = "unique_components")]
    pub components: BTreeMap<String, String>,
}
// Five required executable roles plus the already-authorized optional watchdog.
const MAX_PACKAGE_COMPONENTS: usize = 6;
fn unique_components<'de, D>(deserializer: D) -> Result<BTreeMap<String, String>, D::Error>
where D: serde::Deserializer<'de> {
    struct Components;
    impl<'de> serde::de::Visitor<'de> for Components {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("unique component roles") }
        fn visit_map<M: serde::de::MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
            let mut result = BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<String, String>()? {
                if result.len() >= MAX_PACKAGE_COMPONENTS || result.insert(key, value).is_some() {
                    return Err(serde::de::Error::custom("duplicate or excessive component roles"));
                }
            }
            Ok(result)
        }
    }
    deserializer.deserialize_map(Components)
}
pub fn verify_package(bytes: &[u8], signature_hex: &[u8]) -> Result<PackageAuth, UpdateError> {
    verified_signature(bytes, signature_hex)?;
    let auth: PackageAuth = serde_json::from_slice(bytes)
        .map_err(|_| UpdateError::new("package_schema", "包身份描述符结构无效或存在未知/重复字段"))?;
    require(auth.schema == 1 && auth.product == "kat-client-package" && auth.key_id == crate::update_key::KEY_ID
        && auth.os == "windows" && auth.arch == "amd64", "package_schema", "包身份、平台或签名密钥标识不受支持")?;
    stable_version(&auth.app_version)?;
    require(auth.stdio_protocol == 1 && auth.service_protocol == 1 && auth.record_schema == 2 && auth.workspace_schema == 1,
        "compatibility", "包内协议或数据兼容版本不受支持")?;
    require(lower_hex(&auth.source_revision, 20) || lower_hex(&auth.source_revision, 32),
        "source_revision", "包身份必须包含完整源码 revision")?;
    const REQUIRED: [&str; 5] = ["kat-desktop.exe", "kat-install-helper.exe", "kat-network-service.exe", "kat-client-core.exe", "kat-elevate-helper.exe"];
    require(REQUIRED.iter().all(|name| auth.components.contains_key(*name)) && auth.components.iter().all(|(name, hash)|
        (REQUIRED.contains(&name.as_str()) || name == "kat-proxy-watchdog.exe") && lower_hex(hash, 32)),
        "package_components", "包身份缺少必需组件，或包含未知角色/无效 SHA-256")?;
    Ok(auth)
}

/// Validates forward/rollback package transitions against the protected metadata floor.
/// Higher-sequence full signed rollback packages must advance sequence and never lower version/floor.
#[allow(clippy::too_many_arguments)]
pub fn verify_forward_transition(
    old_gui_version: &str, old_gui_sequence: u64, old_gui_sha256: &str,
    old_core_version: &str, old_core_sequence: u64, old_core_sha256: &str,
    new_gui_version: &str, new_gui_sequence: u64, new_gui_sha256: &str,
    new_core_version: &str, new_core_sequence: u64, new_core_sha256: &str,
    strict_core: bool,
) -> Result<(), UpdateError> {
    let a = stable_version(old_gui_version)?;
    let b = stable_version(new_gui_version)?;
    if b < a || new_gui_sequence < old_gui_sequence || (b == a && new_gui_sha256 != old_gui_sha256) || (b > a && new_gui_sequence <= old_gui_sequence) {
        return Err(UpdateError::new("UPDATE_DOWNGRADE", "Older, replayed, or same-version different-hash client is not permitted"));
    }
    let o = stable_version(old_core_version)?;
    let n = stable_version(new_core_version)?;
    if n < o || new_core_sequence < old_core_sequence || (n == o && new_core_sha256 != old_core_sha256) || (strict_core && (n <= o || new_core_sequence <= old_core_sequence)) {
        return Err(UpdateError::new("UPDATE_DOWNGRADE", "Older, replayed, or same-version different-hash core is not permitted"));
    }
    Ok(())
}
