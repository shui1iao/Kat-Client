//! Fixed public GitHub discovery and bounded, non-executing downloads.
//! Primary path uses quota-free `github.com` release endpoints (`/releases/latest` 302,
//! `/releases.atom` with ETag, and `/releases/download/{tag}/{asset}` CDN links) so shared
//! proxy egress IPs never hit `api.github.com`'s 60 req/hr unauthenticated 403 rate limit,
//! while preserving full Ed25519 manifest signature, sequence floor, SHA-256 and PE gates.
use crate::update_manifest::{
    self, AssetBinding, CurrentVersions, ExpectedRelease, Manifest, UpdateError, UpdateKind,
    VerifiedManifest, VersionDisposition, MAX_MANIFEST_BYTES, MAX_SIGNATURE_BYTES,
};
use reqwest::{
    blocking::{Client, Response},
    header, StatusCode, Url,
};
use semver::Version;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const METADATA_LIMIT: usize = 1024 * 1024;
const NOTES_LIMIT: usize = 64 * 1024;
const CORE_RELEASE_PAGES: usize = 2;
const CORE_RELEASES_PER_PAGE: usize = 30;
const CORE_TAG_PREFIX: &str = "windows-core-v";
const RELEASE_NOTES_ASSET: &str = "RELEASE_NOTES.md";
const MAX_REDIRECTS: usize = 4;
const CHECK_SECONDS: u64 = 90;
const DOWNLOAD_SECONDS: u64 = 600;
const USER_AGENT: &str = "Kat-Client-Signed-Update/1";

#[derive(Clone, Debug)]
pub struct VerifiedOffer {
    verified: VerifiedManifest,
    notes: Option<String>,
}
impl VerifiedOffer {
    pub fn manifest(&self) -> &Manifest {
        self.verified.manifest()
    }
    pub fn manifest_bytes(&self) -> &[u8] {
        self.verified.manifest_bytes()
    }
    pub fn signature_hex(&self) -> &str {
        self.verified.signature_hex()
    }
    pub fn digest(&self) -> &str {
        self.verified.digest()
    }
    pub fn verified(&self) -> &VerifiedManifest {
        &self.verified
    }
    pub fn notes(&self) -> Option<&str> {
        self.notes.as_deref()
    }
}

#[derive(Clone, Debug)]
pub enum CheckOutcome {
    Available { offer: VerifiedOffer, message: String },
    Current { version: String, notes: Option<String> },
    Unavailable { reason: String },
}

// Only Verified can become an offer; the other states carry no install authorization.
enum ReleaseCheck {
    Verified(VerifiedManifest, Option<String>),
    Current(String, Option<String>),
    Unavailable(String),
    Incompatible { version: Version, reason: String },
    Older,
}

#[derive(Clone, Copy, Debug)]
pub struct DownloadProgress {
    pub received_bytes: u64,
    pub total_bytes: u64,
}

#[derive(Clone, Debug)]
pub struct Downloaded {
    pub path: PathBuf,
    pub bytes: u64,
    pub sha256: String,
    pub offer_digest: String,
}

#[derive(Clone)]
struct CachedHttp {
    bytes: Vec<u8>,
    etag: Option<String>,
}

#[derive(Clone)]
struct CachedBundle {
    manifest_bytes: Vec<u8>,
    sig_bytes: Vec<u8>,
    notes: Option<String>,
}

#[derive(Clone)]
struct Backoff {
    until: Option<Instant>,
    header: Option<String>,
}

/// Native-only short-lived egress snapshot. No WebView URL or system proxy input.
#[derive(Clone)]
pub struct UpdateTransport {
    port: Option<u16>,
    identity: Option<(u64, u64)>,
    valid: Arc<dyn Fn() -> bool + Send + Sync>,
    publication: Arc<Mutex<()>>,
}
impl UpdateTransport {
    pub fn direct() -> Self {
        Self {
            port: None,
            identity: None,
            valid: Arc::new(|| true),
            publication: Arc::new(Mutex::new(())),
        }
    }
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) fn owned(
        port: Option<u16>,
        identity: (u64, u64),
        publication: Arc<Mutex<()>>,
        valid: impl Fn() -> bool + Send + Sync + 'static,
    ) -> Self {
        Self {
            port,
            identity: Some(identity),
            valid: Arc::new(valid),
            publication,
        }
    }
    pub fn ensure_current(&self) -> Result<(), UpdateError> {
        if (self.valid)() {
            Ok(())
        } else {
            Err(UpdateError::new(
                "transport_changed",
                "Kat 更新出口已变化，请重新检查；未自动切换出口",
            ))
        }
    }
    /// Short linearization lease shared with native entry invalidation.
    /// Lock order: rows -> publication -> owned-slot read locks. No I/O/await,
    /// row acquisition, or progress callback while this lease is held.
    pub fn publication_guard(&self) -> Result<std::sync::MutexGuard<'_, ()>, UpdateError> {
        let guard = self
            .publication
            .lock()
            .map_err(|_| UpdateError::new("transport", "Kat 更新发布状态不可确认"))?;
        self.ensure_current()?;
        Ok(guard)
    }
    pub fn same_snapshot(&self, other: &Self) -> bool {
        self.port == other.port && self.identity == other.identity
    }
    pub fn description(&self) -> &'static str {
        if self.port.is_some() {
            "经 Kat 本地出口"
        } else {
            "Kat 本地出口未运行，本次直连"
        }
    }
}

#[derive(Clone)]
struct Endpoints {
    #[cfg(test)]
    web_base: String,
    #[cfg(test)]
    api_base: String,
    #[cfg(test)]
    allow_loopback_http: bool,
}

impl Default for Endpoints {
    fn default() -> Self {
        Self {
            #[cfg(test)]
            web_base: "https://github.com".into(),
            #[cfg(test)]
            api_base: "https://api.github.com".into(),
            #[cfg(test)]
            allow_loopback_http: false,
        }
    }
}

impl Endpoints {
    fn web_base(&self) -> &str {
        #[cfg(test)]
        {
            &self.web_base
        }
        #[cfg(not(test))]
        {
            "https://github.com"
        }
    }
    fn api_base(&self) -> &str {
        #[cfg(test)]
        {
            &self.api_base
        }
        #[cfg(not(test))]
        {
            "https://api.github.com"
        }
    }
    fn https_only(&self) -> bool {
        #[cfg(test)]
        {
            !self.allow_loopback_http
        }
        #[cfg(not(test))]
        {
            true
        }
    }
}

pub struct UpdateChecker {
    client: Client,
    transport: UpdateTransport,
    cancel: Option<Arc<std::sync::atomic::AtomicBool>>,
    deadline: Option<Instant>,
    // In-memory conditional HTTP cache & verified raw-byte bundle cache;
    // authorization/disposition is NEVER cached and always re-runs update_manifest::verify.
    http_cache: Arc<Mutex<HashMap<String, CachedHttp>>>,
    bundles: Arc<Mutex<HashMap<(UpdateKind, String), CachedBundle>>>,
    api_backoff: Arc<Mutex<HashMap<UpdateKind, Backoff>>>,
    endpoints: Endpoints,
}

#[derive(Deserialize)]
struct Release {
    id: u64,
    tag_name: String,
    draft: bool,
    prerelease: bool,
    #[serde(default)]
    body: Option<String>,
    assets: Vec<GitHubAsset>,
}

#[derive(Deserialize)]
struct GitHubAsset {
    id: u64,
    name: String,
    size: u64,
    state: String,
}

#[derive(Deserialize)]
struct UnverifiedReleasePeek {
    release: UnverifiedReleaseId,
}
#[derive(Deserialize)]
struct UnverifiedReleaseId {
    id: u64,
    tag: String,
}

impl UpdateChecker {
    pub fn new() -> Result<Self, UpdateError> {
        Self::make(
            UpdateTransport::direct(),
            None,
            Arc::new(Mutex::new(HashMap::new())),
            Arc::new(Mutex::new(HashMap::new())),
            Arc::new(Mutex::new(HashMap::new())),
            Endpoints::default(),
        )
    }

    fn make(
        transport: UpdateTransport,
        deadline: Option<Instant>,
        http_cache: Arc<Mutex<HashMap<String, CachedHttp>>>,
        bundles: Arc<Mutex<HashMap<(UpdateKind, String), CachedBundle>>>,
        api_backoff: Arc<Mutex<HashMap<UpdateKind, Backoff>>>,
        endpoints: Endpoints,
    ) -> Result<Self, UpdateError> {
        transport.ensure_current()?;
        let mut builder = Client::builder()
            .user_agent(USER_AGENT)
            .https_only(endpoints.https_only())
            .redirect(reqwest::redirect::Policy::none())
            .referer(false)
            .no_proxy()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(DOWNLOAD_SECONDS));
        // no_proxy MUST precede this one fixed native proxy; never inherit env/WPAD/PAC.
        if let Some(port) = transport.port {
            if port == 0 {
                return Err(UpdateError::new("transport", "Kat 本地出口端口无效"));
            }
            let proxy_target = format!("http://127.0.0.1:{port}");
            let proxy = if endpoints.https_only() {
                reqwest::Proxy::https(&proxy_target)
            } else {
                reqwest::Proxy::all(&proxy_target)
            }
            .map_err(|_| UpdateError::new("transport", "Kat 本地出口无效"))?;
            builder = builder.proxy(proxy);
        }
        let client = builder
            .build()
            .map_err(|_| UpdateError::new("http_client", "无法初始化更新 HTTPS 客户端"))?;
        Ok(Self {
            client,
            transport,
            cancel: None,
            deadline,
            http_cache,
            bundles,
            api_backoff,
            endpoints,
        })
    }

    /// Fresh connection pool for this operation; conditional/bundle caches alone may be shared.
    pub fn for_transport(&self, transport: UpdateTransport, deadline: Instant) -> Result<Self, UpdateError> {
        remaining(deadline)?;
        Self::make(
            transport,
            Some(deadline),
            self.http_cache.clone(),
            self.bundles.clone(),
            self.api_backoff.clone(),
            self.endpoints.clone(),
        )
    }

    pub fn with_cancellation(mut self, cancel: Arc<std::sync::atomic::AtomicBool>) -> Self {
        self.cancel = Some(cancel);
        self
    }

    pub fn ensure_current(&self) -> Result<(), UpdateError> {
        if let Some(deadline) = self.deadline {
            remaining(deadline)?;
        }
        if self
            .cancel
            .as_ref()
            .is_some_and(|c| c.load(std::sync::atomic::Ordering::SeqCst))
        {
            return Err(UpdateError::new("cancelled", "下载已取消"));
        }
        self.transport.ensure_current()
    }

    pub fn publication_guard(&self) -> Result<std::sync::MutexGuard<'_, ()>, UpdateError> {
        let guard = self.transport.publication_guard()?;
        self.ensure_current()?;
        Ok(guard)
    }

    fn success(&self, response: &Response) -> Result<(), UpdateError> {
        if response.status() == StatusCode::OK {
            return Ok(());
        }
        Err(http_error(response))
    }

    fn checkpoint(&self, deadline: Instant) -> Result<Duration, UpdateError> {
        self.ensure_current()?;
        remaining(deadline)
    }

    /// Missing public manifests/assets are Unavailable, NEVER Current. Network/HTTP failure is Err.
    pub fn check(&self, kind: UpdateKind, current: &CurrentVersions) -> Result<CheckOutcome, UpdateError> {
        let result = self.check_inner(kind, current);
        let _publication = self.publication_guard()?;
        result
    }

    fn check_inner(&self, kind: UpdateKind, current: &CurrentVersions) -> Result<CheckOutcome, UpdateError> {
        let deadline = self
            .deadline
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(CHECK_SECONDS));
        self.checkpoint(deadline)?;
        if kind == UpdateKind::Core {
            return self.check_core(current, deadline);
        }
        match self.discover_client_latest(deadline)? {
            ClientDiscovery::None => Ok(CheckOutcome::Unavailable {
                reason: "客户端更新资源尚未发布：暂无公开稳定发行".into(),
            }),
            ClientDiscovery::WebTag(tag) => match self.check_tag_direct(UpdateKind::Client, &tag, None, current, deadline)? {
                ReleaseCheck::Verified(verified, notes) => {
                    Ok(verified_outcome(verified, "有可用更新".into(), notes))
                }
                ReleaseCheck::Current(version, notes) => Ok(CheckOutcome::Current { version, notes }),
                ReleaseCheck::Unavailable(reason) | ReleaseCheck::Incompatible { reason, .. } => {
                    Ok(CheckOutcome::Unavailable { reason })
                }
                ReleaseCheck::Older => Ok(CheckOutcome::Unavailable {
                    reason: "不提供低于本机保护版本的更新".into(),
                }),
            },
            ClientDiscovery::ApiRelease(release) => {
                if release.draft || release.prerelease {
                    return Ok(CheckOutcome::Unavailable {
                        reason: "客户端更新资源尚未发布：暂无公开稳定发行".into(),
                    });
                }
                match self.check_api_release(UpdateKind::Client, &release, current, deadline)? {
                    ReleaseCheck::Verified(verified, notes) => {
                        Ok(verified_outcome(verified, "有可用更新".into(), notes))
                    }
                    ReleaseCheck::Current(version, notes) => Ok(CheckOutcome::Current { version, notes }),
                    ReleaseCheck::Unavailable(reason) | ReleaseCheck::Incompatible { reason, .. } => {
                        Ok(CheckOutcome::Unavailable { reason })
                    }
                    ReleaseCheck::Older => Ok(CheckOutcome::Unavailable {
                        reason: "不提供低于本机保护版本的更新".into(),
                    }),
                }
            }
        }
    }

    /// Primary: `GET https://github.com/shui1iao/Kat-Client/releases/latest` -> 302 `/releases/tag/<tag>`
    /// (zero `api.github.com` quota!). Falls back to conditional `api.github.com` only if needed.
    fn discover_client_latest(&self, deadline: Instant) -> Result<ClientDiscovery, UpdateError> {
        let web_url = format!("{}/shui1iao/{}/releases/latest", self.endpoints.web_base(), UpdateKind::Client.repo());
        if let Ok(resp) = self.send_web_probe(&web_url, deadline) {
            if resp.status() == StatusCode::NOT_FOUND {
                return Ok(ClientDiscovery::None);
            }
            if matches!(resp.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
                if let Some(loc) = resp.headers().get(header::LOCATION).and_then(|v| v.to_str().ok()) {
                    if loc.ends_with("/releases") || loc.ends_with("/releases/") {
                        return Ok(ClientDiscovery::None);
                    }
                    if let Some(tag) = extract_tag_from_location(&web_url, loc, UpdateKind::Client) {
                        return Ok(ClientDiscovery::WebTag(tag));
                    }
                }
            }
        }
        match self.latest_release_api(UpdateKind::Client, deadline)? {
            Some(r) => Ok(ClientDiscovery::ApiRelease(r)),
            None => Ok(ClientDiscovery::None),
        }
    }

    fn check_tag_direct(
        &self,
        kind: UpdateKind,
        tag: &str,
        fallback_notes: Option<String>,
        current: &CurrentVersions,
        deadline: Instant,
    ) -> Result<ReleaseCheck, UpdateError> {
        if !safe_url_segment(tag) {
            return Err(UpdateError::new("release_binding", "发现的 release tag 包含非法字符"));
        }
        let Some((bytes, sig, notes)) = self.fetch_tag_bundle(kind, tag, fallback_notes, deadline)? else {
            return Ok(ReleaseCheck::Unavailable("更新资源尚未发布：发行缺少签名更新清单".into()));
        };
        let release_id = serde_json::from_slice::<UnverifiedReleasePeek>(&bytes)
            .ok()
            .filter(|p| p.release.id > 0 && p.release.tag == tag)
            .map(|p| p.release.id)
            .unwrap_or(1);
        let expected = ExpectedRelease {
            kind,
            release_id,
            release_tag: tag.to_owned(),
        };
        self.evaluate_manifest_bytes(kind, tag, &bytes, &sig, &expected, None, notes, current)
    }

    fn check_api_release(
        &self,
        kind: UpdateKind,
        release: &Release,
        current: &CurrentVersions,
        deadline: Instant,
    ) -> Result<ReleaseCheck, UpdateError> {
        if !release.assets.iter().any(|a| a.name == kind.manifest_name() && a.state == "uploaded" && a.size > 0 && a.size <= MAX_MANIFEST_BYTES as u64) {
            return Ok(ReleaseCheck::Unavailable("更新资源尚未发布：发行缺少签名更新清单".into()));
        }
        if !release.assets.iter().any(|a| a.name == kind.signature_name() && a.state == "uploaded" && a.size > 0 && a.size <= MAX_SIGNATURE_BYTES as u64) {
            return Ok(ReleaseCheck::Unavailable("更新资源尚未发布：发行缺少清单签名".into()));
        }
        let api_notes = clean_notes(release.body.as_deref());
        let Some((bytes, sig, notes)) = self.fetch_tag_bundle(kind, &release.tag_name, api_notes, deadline)? else {
            return Ok(ReleaseCheck::Unavailable("更新资源尚未发布：发行缺少签名更新清单".into()));
        };
        let expected = ExpectedRelease {
            kind,
            release_id: release.id,
            release_tag: release.tag_name.clone(),
        };
        self.evaluate_manifest_bytes(kind, &release.tag_name, &bytes, &sig, &expected, Some(release), notes, current)
    }

    #[allow(clippy::too_many_arguments)]
    fn evaluate_manifest_bytes(
        &self,
        kind: UpdateKind,
        tag: &str,
        bytes: &[u8],
        sig: &[u8],
        expected: &ExpectedRelease,
        api_release: Option<&Release>,
        notes: Option<String>,
        current: &CurrentVersions,
    ) -> Result<ReleaseCheck, UpdateError> {
        let result = update_manifest::verify(bytes, sig, expected, current);
        let manifest = match &result {
            Ok(verified) => verified.manifest().clone(),
            Err(error)
                if matches!(
                    error.code,
                    "compatibility" | "capabilities" | "platform" | "rollback" | "same_version_hash"
                ) =>
            {
                serde_json::from_slice::<Manifest>(bytes)
                    .map_err(|_| UpdateError::new("manifest_schema", "签名清单结构无效"))?
            }
            Err(error) => return Err(error.clone()),
        };
        let version = signed_version(&manifest.version)?;
        if kind == UpdateKind::Core {
            let tag_version = core_tag_version(tag)
                .ok_or_else(|| UpdateError::new("core_tag", "Windows 内核发行 tag 不符合固定稳定版本约定"))?;
            if manifest.version != tag_version.to_string() {
                return Err(UpdateError::new("core_tag", "Windows 内核 tag 版本与签名清单版本不一致"));
            }
        }
        if let Some(rel) = api_release {
            if !asset_matches(rel, &manifest.asset) {
                return Ok(ReleaseCheck::Unavailable(
                    "更新资源尚未发布：发行缺少与签名绑定的 Windows 资产".into(),
                ));
            }
        }
        // Cache immutable signed bytes once cryptographic signature + tag binding succeeded.
        if let Ok( mut cache ) = self.bundles.lock() {
            cache.insert(
                (kind, tag.to_owned()),
                CachedBundle {
                    manifest_bytes: bytes.to_vec(),
                    sig_bytes: sig.to_vec(),
                    notes: notes.clone(),
                },
            );
        }
        match result {
            Ok(verified) => Ok(ReleaseCheck::Verified(verified, notes)),
            Err(error) if kind == UpdateKind::Client && error.code == "same_version_hash" && current.app_sha256.is_none() => {
                if manifest.sequence == current.app_sequence {
                    return Ok(ReleaseCheck::Current(manifest.version, notes));
                }
                Ok(ReleaseCheck::Unavailable(
                    "版本一致，但本机未记录安装包摘要，无法确认包身份；不提供同版本替换".into(),
                ))
            }
            Err(error) if matches!(error.code, "compatibility" | "capabilities" | "platform") => {
                let reason = if error.message == "暂无兼容更新：GUI 版本不满足签名清单要求" {
                    "当前 GUI 版本不满足签名兼容范围，需先取得兼容客户端".into()
                } else {
                    error.message
                };
                Ok(ReleaseCheck::Incompatible { version, reason })
            }
            Err(error)
                if kind == UpdateKind::Core
                    && error.code == "rollback"
                    && version.cmp_precedence(&signed_version(&current.core_version)?) == std::cmp::Ordering::Less =>
            {
                Ok(ReleaseCheck::Older)
            }
            Err(error) => Err(error),
        }
    }

    fn fetch_tag_bundle(
        &self,
        kind: UpdateKind,
        tag: &str,
        api_notes: Option<String>,
        deadline: Instant,
    ) -> Result<Option<(Vec<u8>, Vec<u8>, Option<String>)>, UpdateError> {
        if let Ok(cache) = self.bundles.lock() {
            if let Some(hit) = cache.get(&(kind, tag.to_owned())) {
                return Ok(Some((
                    hit.manifest_bytes.clone(),
                    hit.sig_bytes.clone(),
                    hit.notes.clone().or(api_notes),
                )));
            }
        }
        let m_url = self.download_url(kind, tag, kind.manifest_name())?;
        let m_resp = self.get_download(kind, &m_url, deadline)?;
        if m_resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        self.success(&m_resp)?;
        let m_bytes = read_bounded(m_resp, MAX_MANIFEST_BYTES, deadline)?;
        if m_bytes.is_empty() {
            return Err(UpdateError::new("metadata_size", "签名清单为空"));
        }

        let s_url = self.download_url(kind, tag, kind.signature_name())?;
        let s_resp = self.get_download(kind, &s_url, deadline)?;
        if s_resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        self.success(&s_resp)?;
        let s_bytes = read_bounded(s_resp, MAX_SIGNATURE_BYTES, deadline)?;
        if s_bytes.is_empty() {
            return Err(UpdateError::new("metadata_size", "清单签名为空"));
        }

        let notes = match api_notes {
            Some(n) => Some(n),
            None => self.fetch_optional_notes(kind, tag, deadline),
        };
        Ok(Some((m_bytes, s_bytes, notes)))
    }

    fn fetch_optional_notes(&self, kind: UpdateKind, tag: &str, deadline: Instant) -> Option<String> {
        let url = self.download_url(kind, tag, RELEASE_NOTES_ASSET).ok()?;
        let resp = self.get_download(kind, &url, deadline).ok()?;
        if resp.status() != StatusCode::OK {
            return None;
        }
        let bytes = read_bounded(resp, NOTES_LIMIT, deadline).ok()?;
        let text = std::str::from_utf8(&bytes).ok()?;
        clean_notes(Some(text))
    }

    fn check_core(&self, current: &CurrentVersions, deadline: Instant) -> Result<CheckOutcome, UpdateError> {
        let installed = signed_version(&current.core_version)?;
        let candidates = self.discover_core_candidates(deadline)?;
        let Some(candidates) = candidates else {
            return Ok(CheckOutcome::Unavailable {
                reason: "Windows 内核检查已达 2 页、60 条发行上限，无法确认完整范围；本次不提供更新，不能判断为已最新".into(),
            });
        };

        let mut tag_versions = Vec::<Version>::new();
        let mut relevant = Vec::<(Version, CoreCandidate)>::new();
        for cand in candidates {
            let tag = cand.tag().to_owned();
            let Some(tag_version) = core_tag_version(&tag) else {
                continue;
            };
            if tag_versions
                .iter()
                .any(|v| v.cmp_precedence(&tag_version) == std::cmp::Ordering::Equal)
            {
                return Err(UpdateError::new(
                    "core_conflict",
                    "Windows 内核发行存在相同语义版本的多个 tag，无法确定唯一身份",
                ));
            }
            tag_versions.push(tag_version.clone());
            // Skip historical releases strictly older than the installed protected version:
            // avoids N*2 redundant manifest downloads across 15+ past releases!
            if tag_version.cmp_precedence(&installed) != std::cmp::Ordering::Less {
                relevant.push((tag_version, cand));
            }
        }

        if tag_versions.is_empty() {
            return Ok(CheckOutcome::Unavailable {
                reason: "Windows内核更新资源尚未发布".into(),
            });
        }

        // Check newest candidate tags first; once a strictly newer compatible signed release
        // is verified, no request is needed for the already-installed equal-version tag.
        relevant.sort_by(|a, b| b.0.cmp_precedence(&a.0));

        let mut verified = Vec::<(Version, VerifiedManifest, Option<String>)>::new();
        let mut missing = None;
        let mut incompatible = Vec::<(Version, String)>::new();

        for (ver, cand) in relevant {
            if ver.cmp_precedence(&installed) == std::cmp::Ordering::Equal
                && verified.iter().any(|(_, v, _)| v.disposition() == VersionDisposition::Newer)
            {
                continue;
            }
            let check = match &cand {
                CoreCandidate::WebTag(tag) => {
                    self.check_tag_direct(UpdateKind::Core, tag, None, current, deadline)?
                }
                CoreCandidate::ApiRelease(rel) => {
                    self.check_api_release(UpdateKind::Core, rel, current, deadline)?
                }
            };
            match check {
                ReleaseCheck::Verified(value, notes) => {
                    verified.push((signed_version(&value.manifest().version)?, value, notes))
                }
                ReleaseCheck::Current(_, _) => {}
                ReleaseCheck::Unavailable(reason) => {
                    if missing.is_none() {
                        missing = Some(reason);
                    }
                }
                ReleaseCheck::Incompatible { version, reason } => incompatible.push((version, reason)),
                ReleaseCheck::Older => {}
            }
        }

        verified.sort_by(|a, b| {
            a.0.cmp_precedence(&b.0)
                .then_with(|| a.1.manifest().sequence.cmp(&b.1.manifest().sequence))
        });
        for pair in verified.windows(2) {
            if pair[0].0.cmp_precedence(&pair[1].0) != std::cmp::Ordering::Less
                || pair[0].1.manifest().sequence >= pair[1].1.manifest().sequence
            {
                return Err(UpdateError::new(
                    "core_conflict",
                    "签名 Windows 内核候选的版本或 sequence 相互冲突，本次不提供更新",
                ));
            }
        }
        let mut notices = Vec::new();
        if let Some(reason) = missing {
            notices.push(format!("部分发行的{reason}，无法确认完整最新状态"));
        }
        incompatible.sort_by(|a, b| a.0.cmp_precedence(&b.0));
        if let Some((version, reason)) = incompatible.pop() {
            let newer = if version.cmp_precedence(&installed) == std::cmp::Ordering::Greater {
                "较新 "
            } else {
                ""
            };
            notices.push(format!(
                "已发现{newer}Windows 内核 {version}，但与当前客户端不兼容，未提供该版本下载：{reason}"
            ));
        }
        let notice = notices.join("；");
        if let Some((_, value, notes)) = verified.pop() {
            if value.disposition() == VersionDisposition::Newer {
                let message = if notice.is_empty() {
                    "有可用更新".into()
                } else {
                    format!("有兼容更新；{notice}")
                };
                return Ok(verified_outcome(value, message, notes));
            }
            if notice.is_empty() {
                return Ok(verified_outcome(value, String::new(), notes));
            }
            return Ok(CheckOutcome::Unavailable {
                reason: format!("{notice}；无法确认已是最新版本"),
            });
        }
        Ok(CheckOutcome::Unavailable {
            reason: if notice.is_empty() {
                "已发布 Windows 内核低于本机保护版本；不提供降级".into()
            } else {
                notice
            },
        })
    }

    /// Primary: `https://github.com/shui1iao/Kat-Server/releases.atom` (with ETag 304 cache, 0 API quota).
    /// Fallback: `api.github.com/repos/shui1iao/Kat-Server/releases` (also with per-page ETag 304 cache).
    fn discover_core_candidates(&self, deadline: Instant) -> Result<Option<Vec<CoreCandidate>>, UpdateError> {
        let atom_url = format!("{}/shui1iao/{}/releases.atom", self.endpoints.web_base(), UpdateKind::Core.repo());
        if let Ok(atom_bytes) = self.fetch_cached_web(&atom_url, deadline) {
            if let Ok(xml) = std::str::from_utf8(&atom_bytes) {
                let tags = extract_core_tags_from_atom(xml);
                if !tags.is_empty() {
                    return Ok(Some(tags.into_iter().map(CoreCandidate::WebTag).collect()));
                }
            }
        }
        let Some(releases) = self.core_releases_api(deadline)? else {
            return Ok(None);
        };
        Ok(Some(
            releases
                .into_iter()
                .filter(|r| !r.draft && !r.prerelease)
                .map(CoreCandidate::ApiRelease)
                .collect(),
        ))
    }

    fn core_releases_api(&self, deadline: Instant) -> Result<Option<Vec<Release>>, UpdateError> {
        let mut releases = Vec::new();
        let mut ids = HashSet::new();
        let mut tags = HashSet::new();
        for page in 1..=CORE_RELEASE_PAGES {
            let url = format!(
                "{}/repos/shui1iao/{}/releases?per_page={CORE_RELEASES_PER_PAGE}&page={page}",
                self.endpoints.api_base(),
                UpdateKind::Core.repo()
            );
            let bytes = self.fetch_cached_api(UpdateKind::Core, &url, deadline)?;
            let batch: Vec<Release> = serde_json::from_slice(&bytes)
                .map_err(|_| UpdateError::new("github_metadata", "GitHub release 列表无效"))?;
            if batch.len() > CORE_RELEASES_PER_PAGE {
                return Err(UpdateError::new("github_metadata", "GitHub release 列表超过固定每页上限"));
            }
            let complete = batch.len() < CORE_RELEASES_PER_PAGE;
            for release in batch {
                validate_release(&release)?;
                if !ids.insert(release.id) || !tags.insert(release.tag_name.clone()) {
                    return Err(UpdateError::new(
                        "core_conflict",
                        "GitHub release 列表跨页存在重复 ID/tag，完整性未知",
                    ));
                }
                releases.push(release);
            }
            if complete {
                return Ok(Some(releases));
            }
        }
        Ok(None)
    }

    /// Downloads the verified Windows executable directly from `github.com/.../releases/download/{tag}/{name}`
    /// (zero `api.github.com` requests) while enforcing exact signed byte length, SHA-256 and AMD64 PE headers.
    pub fn download<F>(
        &self,
        offer: &VerifiedOffer,
        current: &CurrentVersions,
        destination: &Path,
        mut progress: F,
    ) -> Result<Downloaded, UpdateError>
    where
        F: FnMut(DownloadProgress) -> bool,
    {
        let verified = update_manifest::verify(
            offer.manifest_bytes(),
            offer.signature_hex().as_bytes(),
            &offer.verified.expected(),
            current,
        )?;
        if verified.digest() != offer.digest() || verified.disposition() != VersionDisposition::Newer {
            return Err(UpdateError::new(
                "offer_changed",
                "已确认的更新不再适用，请重新检查并确认",
            ));
        }
        let expected = verified.expected();
        let deadline = self
            .deadline
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(DOWNLOAD_SECONDS));
        self.checkpoint(deadline)?;

        let asset = &verified.manifest().asset;
        let dl_url = self.download_url(expected.kind, &expected.release_tag, &asset.name)?;
        let response = self.get_download(expected.kind, &dl_url, deadline)?;
        if response.status() == StatusCode::NOT_FOUND {
            return Err(UpdateError::new(
                "release_changed",
                "已确认 release/资产已变化，下载中止；不会替换为其他版本",
            ));
        }
        self.success(&response)?;
        if response.content_length().map(|n| n != asset.bytes).unwrap_or(false) {
            return Err(UpdateError::new("asset_size", "下载响应长度不等于签名资产大小"));
        }
        validate_destination(destination)?;
        let mut output = PendingFile::create(destination)?;
        if !progress(DownloadProgress {
            received_bytes: 0,
            total_bytes: asset.bytes,
        }) {
            return Err(UpdateError::new("cancelled", "下载已取消"));
        }
        let mut response = response;
        let mut received = 0u64;
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        loop {
            self.checkpoint(deadline)?;
            let count = response
                .read(&mut buffer)
                .map_err(|_| UpdateError::new("download_io", "更新资产读取失败"))?;
            if count == 0 {
                break;
            }
            received = received
                .checked_add(count as u64)
                .ok_or_else(|| UpdateError::new("asset_size", "更新资产大小溢出"))?;
            if received > asset.bytes {
                return Err(UpdateError::new("asset_size", "更新资产超过签名大小"));
            }
            output
                .file_mut()?
                .write_all(&buffer[..count])
                .map_err(|_| UpdateError::new("cache_io", "无法写入调用方私有更新缓存"))?;
            hash.update(&buffer[..count]);
            if !progress(DownloadProgress {
                received_bytes: received,
                total_bytes: asset.bytes,
            }) {
                return Err(UpdateError::new("cancelled", "下载已取消"));
            }
        }
        if received != asset.bytes {
            return Err(UpdateError::new("asset_size", "更新资产未完整下载"));
        }
        let digest = hex::encode(hash.finalize());
        if digest != asset.sha256 {
            return Err(UpdateError::new("asset_hash", "更新资产 SHA-256 不匹配"));
        }
        output
            .file_mut()?
            .sync_all()
            .map_err(|_| UpdateError::new("cache_io", "更新缓存落盘失败"))?;
        verify_pe_amd64(output.file_mut()?, received)?;
        self.checkpoint(deadline)?;
        if !progress(DownloadProgress {
            received_bytes: received,
            total_bytes: asset.bytes,
        }) {
            return Err(UpdateError::new("cancelled", "下载已取消"));
        }
        {
            let _publication = self.publication_guard()?;
            output.keep = true;
        }
        Ok(Downloaded {
            path: destination.to_path_buf(),
            bytes: received,
            sha256: digest,
            offer_digest: verified.digest().to_owned(),
        })
    }

    fn latest_release_api(&self, kind: UpdateKind, deadline: Instant) -> Result<Option<Release>, UpdateError> {
        let url = format!("{}/repos/shui1iao/{}/releases/latest", self.endpoints.api_base(), kind.repo());
        let cached = self
            .http_cache
            .lock()
            .map_err(|_| UpdateError::new("cache", "更新缓存锁失败"))?
            .get(&url)
            .cloned();
        let response = self.get_api(kind, &url, cached.as_ref().and_then(|c| c.etag.as_deref()), deadline)?;
        if response.status() == StatusCode::NOT_FOUND {
            self.http_cache
                .lock()
                .map_err(|_| UpdateError::new("cache", "更新缓存锁失败"))?
                .remove(&url);
            return Ok(None);
        }
        if response.status() == StatusCode::NOT_MODIFIED {
            let cache = cached.ok_or_else(|| UpdateError::new("cache", "GitHub 返回 304 但没有可复验缓存"))?;
            return Ok(Some(parse_release(&cache.bytes)?));
        }
        self.success(&response)?;
        let etag = extract_etag(&response);
        let bytes = read_bounded(response, METADATA_LIMIT, deadline)?;
        let release = parse_release(&bytes)?;
        self.http_cache
            .lock()
            .map_err(|_| UpdateError::new("cache", "更新缓存锁失败"))?
            .insert(url, CachedHttp { bytes, etag });
        Ok(Some(release))
    }

    fn fetch_cached_api(&self, kind: UpdateKind, url: &str, deadline: Instant) -> Result<Vec<u8>, UpdateError> {
        let cached = self
            .http_cache
            .lock()
            .map_err(|_| UpdateError::new("cache", "更新缓存锁失败"))?
            .get(url)
            .cloned();
        let response = self.get_api(kind, url, cached.as_ref().and_then(|c| c.etag.as_deref()), deadline)?;
        if response.status() == StatusCode::NOT_MODIFIED {
            let cache = cached.ok_or_else(|| UpdateError::new("cache", "GitHub 返回 304 但没有可复验缓存"))?;
            return Ok(cache.bytes);
        }
        self.success(&response)?;
        let etag = extract_etag(&response);
        let bytes = read_bounded(response, METADATA_LIMIT, deadline)?;
        self.http_cache
            .lock()
            .map_err(|_| UpdateError::new("cache", "更新缓存锁失败"))?
            .insert(url.to_owned(), CachedHttp { bytes: bytes.clone(), etag });
        Ok(bytes)
    }

    fn fetch_cached_web(&self, url: &str, deadline: Instant) -> Result<Vec<u8>, UpdateError> {
        let cached = self
            .http_cache
            .lock()
            .map_err(|_| UpdateError::new("cache", "更新缓存锁失败"))?
            .get(url)
            .cloned();
        let parsed = Url::parse(url).map_err(|_| UpdateError::new("url", "内部固定 GitHub URL 无效"))?;
        let mut req = self
            .client
            .get(parsed)
            .timeout(self.checkpoint(deadline)?)
            .header(header::ACCEPT, "application/atom+xml, application/xml;q=0.9, */*;q=0.1")
            .header(header::ACCEPT_ENCODING, "identity");
        if let Some(etag) = cached.as_ref().and_then(|c| c.etag.as_deref()) {
            req = req.header(header::IF_NONE_MATCH, etag);
        }
        let response = req.send().map_err(|_| {
            UpdateError::new(
                "network",
                &format!(
                    "GitHub 更新请求失败或超时（{}）；当前版本状态未知；未自动切换出口",
                    self.transport.description()
                ),
            )
        })?;
        self.checkpoint(deadline)?;
        if response.status() == StatusCode::NOT_MODIFIED {
            if let Some(cache) = cached {
                return Ok(cache.bytes);
            }
        }
        self.success(&response)?;
        let etag = extract_etag(&response);
        let bytes = read_bounded(response, METADATA_LIMIT, deadline)?;
        self.http_cache
            .lock()
            .map_err(|_| UpdateError::new("cache", "更新缓存锁失败"))?
            .insert(url.to_owned(), CachedHttp { bytes: bytes.clone(), etag });
        Ok(bytes)
    }

    fn send_web_probe(&self, url: &str, deadline: Instant) -> Result<Response, UpdateError> {
        let parsed = Url::parse(url).map_err(|_| UpdateError::new("url", "内部固定 GitHub URL 无效"))?;
        let resp = self
            .client
            .get(parsed)
            .timeout(self.checkpoint(deadline)?)
            .header(header::ACCEPT, "text/html,application/xhtml+xml")
            .header(header::ACCEPT_ENCODING, "identity")
            .send()
            .map_err(|_| {
                UpdateError::new(
                    "network",
                    &format!(
                        "GitHub 更新请求失败或超时（{}）；当前版本状态未知；未自动切换出口",
                        self.transport.description()
                    ),
                )
            })?;
        self.checkpoint(deadline)?;
        Ok(resp)
    }

    fn download_url(&self, kind: UpdateKind, tag: &str, file_name: &str) -> Result<String, UpdateError> {
        if !safe_url_segment(tag) || !safe_url_segment(file_name) {
            return Err(UpdateError::new("url", "拒绝包含非法路径字符的更新标签或资产名"));
        }
        Ok(format!(
            "{}/shui1iao/{}/releases/download/{}/{}",
            self.endpoints.web_base(),
            kind.repo(),
            tag,
            file_name
        ))
    }

    fn get_download(&self, kind: UpdateKind, initial: &str, deadline: Instant) -> Result<Response, UpdateError> {
        let mut url = Url::parse(initial).map_err(|_| UpdateError::new("url", "内部固定 GitHub 下载 URL 无效"))?;
        let expected_prefix = format!("{}/shui1iao/{}/releases/download/", self.endpoints.web_base(), kind.repo());
        if !initial.starts_with(&expected_prefix) {
            return Err(UpdateError::new("url", "拒绝非固定 GitHub 仓库下载请求"));
        }
        for hop in 0..=MAX_REDIRECTS {
            let response = self
                .client
                .get(url.clone())
                .timeout(self.checkpoint(deadline)?)
                .header(header::ACCEPT, "application/octet-stream")
                .header(header::ACCEPT_ENCODING, "identity")
                .send()
                .map_err(|_| {
                    UpdateError::new(
                        "network",
                        &format!(
                            "GitHub 更新下载请求失败或超时（{}）；未自动切换出口",
                            self.transport.description()
                        ),
                    )
                })?;
            self.checkpoint(deadline)?;
            let redirect = matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308);
            if !redirect {
                return Ok(response);
            }
            if hop == MAX_REDIRECTS {
                return Err(UpdateError::new("redirect", "GitHub 下载重定向超过跳数限制"));
            }
            let location = response
                .headers()
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .filter(|s| s.len() <= 8192)
                .ok_or_else(|| UpdateError::new("redirect", "GitHub 资产重定向无效"))?;
            let next = url
                .join(location)
                .map_err(|_| UpdateError::new("redirect", "GitHub 资产重定向 URL 无效"))?;
            if !self.allowed_download_redirect(&next, kind) {
                return Err(UpdateError::new("redirect", "拒绝非 HTTPS 或非授权 GitHub 资产域重定向"));
            }
            url = next;
        }
        Err(UpdateError::new("redirect", "GitHub 重定向超过限制"))
    }

    fn get_api(
        &self,
        kind: UpdateKind,
        initial: &str,
        etag: Option<&str>,
        deadline: Instant,
    ) -> Result<Response, UpdateError> {
        let url = Url::parse(initial).map_err(|_| UpdateError::new("url", "内部固定 GitHub API URL 无效"))?;
        let prefix = format!("{}/repos/shui1iao/{}/releases", self.endpoints.api_base(), kind.repo());
        if !initial.starts_with(&prefix) {
            return Err(UpdateError::new("url", "拒绝非固定 GitHub 仓库 API 请求"));
        }
        self.check_api_backoff(kind)?;
        let mut request = self
            .client
            .get(url)
            .timeout(self.checkpoint(deadline)?)
            .header(header::ACCEPT, "application/vnd.github+json")
            .header(header::ACCEPT_ENCODING, "identity")
            .header("X-GitHub-Api-Version", "2022-11-28");
        if let Some(etag) = etag {
            request = request.header(header::IF_NONE_MATCH, etag);
        }
        let response = request.send().map_err(|_| {
            UpdateError::new(
                "network",
                &format!(
                    "GitHub 更新请求失败或超时（{}）；当前版本状态未知；未自动切换出口",
                    self.transport.description()
                ),
            )
        })?;
        self.checkpoint(deadline)?;
        if response.status() == StatusCode::TOO_MANY_REQUESTS
            || response.status() == StatusCode::FORBIDDEN
            || (response.status() == StatusCode::SERVICE_UNAVAILABLE
                && response.headers().contains_key(header::RETRY_AFTER))
        {
            let error = http_error(&response);
            let wait = rate_limit_wait(&response, error.retry_after.as_deref());
            self.api_backoff
                .lock()
                .map_err(|_| UpdateError::new("cache", "更新限流状态锁失败"))?
                .insert(
                    kind,
                    Backoff {
                        until: Instant::now().checked_add(wait),
                        header: error.retry_after.clone(),
                    },
                );
            return Err(error);
        }
        Ok(response)
    }

    fn check_api_backoff(&self, kind: UpdateKind) -> Result<(), UpdateError> {
        let mut backoff = self
            .api_backoff
            .lock()
            .map_err(|_| UpdateError::new("cache", "更新限流状态锁失败"))?;
        if let Some(wait) = backoff.get(&kind) {
            if wait.until.map(|t| Instant::now() < t).unwrap_or(true) {
                return Err(UpdateError {
                    code: "rate_limit",
                    message: "GitHub API 请求频率受限，请稍后重试；当前版本状态未知".into(),
                    retry_after: wait.header.clone(),
                });
            }
        }
        backoff.remove(&kind);
        Ok(())
    }

    fn allowed_download_redirect(&self, url: &Url, kind: UpdateKind) -> bool {
        #[cfg(test)]
        if self.endpoints.allow_loopback_http && url.scheme() == "http" && url.host_str() == Some("127.0.0.1") {
            return true;
        }
        allowed_asset_redirect(url, kind)
    }
}

enum ClientDiscovery {
    None,
    WebTag(String),
    ApiRelease(Release),
}

enum CoreCandidate {
    WebTag(String),
    ApiRelease(Release),
}
impl CoreCandidate {
    fn tag(&self) -> &str {
        match self {
            Self::WebTag(t) => t,
            Self::ApiRelease(r) => &r.tag_name,
        }
    }
}

fn safe_url_segment(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
}

fn extract_etag(response: &Response) -> Option<String> {
    response
        .headers()
        .get(header::ETAG)
        .and_then(|v| v.to_str().ok())
        .filter(|s| s.len() <= 512)
        .map(str::to_owned)
}

fn extract_tag_from_location(base_url: &str, location: &str, kind: UpdateKind) -> Option<String> {
    let base = Url::parse(base_url).ok()?;
    let target = base.join(location).ok()?;
    let expected_prefix = format!("/shui1iao/{}/releases/tag/", kind.repo());
    let tag = target.path().strip_prefix(&expected_prefix)?;
    if target.query().is_some() || target.fragment().is_some() || !safe_url_segment(tag) {
        return None;
    }
    Some(tag.to_owned())
}

fn extract_core_tags_from_atom(xml: &str) -> Vec<String> {
    let needle = "/shui1iao/Kat-Server/releases/tag/";
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(pos) = rest.find(needle) {
        rest = &rest[pos + needle.len()..];
        let end = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-'))
            .unwrap_or(rest.len());
        let tag = &rest[..end];
        if tag.starts_with(CORE_TAG_PREFIX) && safe_url_segment(tag) && seen.insert(tag.to_owned()) {
            out.push(tag.to_owned());
        }
        rest = &rest[end..];
    }
    out
}

fn signed_version(value: &str) -> Result<Version, UpdateError> {
    if value.is_empty() || value.len() > 128 {
        return Err(UpdateError::new("version", "语义版本长度无效"));
    }
    let version = Version::parse(value).map_err(|_| UpdateError::new("version", "版本必须是完整的语义版本"))?;
    if !version.pre.is_empty() {
        return Err(UpdateError::new("version", "仅支持稳定语义版本"));
    }
    Ok(version)
}

fn core_tag_version(tag: &str) -> Option<Version> {
    let suffix = tag.strip_prefix(CORE_TAG_PREFIX)?;
    let version = signed_version(suffix).ok()?;
    if version.to_string() != suffix {
        return None;
    }
    Some(version)
}

fn clean_notes(raw: Option<&str>) -> Option<String> {
    let s = raw?.trim();
    if s.is_empty() {
        return None;
    }
    Some(s.chars().take(16384).collect())
}

fn verified_outcome(verified: VerifiedManifest, message: String, notes: Option<String>) -> CheckOutcome {
    match verified.disposition() {
        VersionDisposition::Newer => CheckOutcome::Available {
            offer: VerifiedOffer { verified, notes },
            message,
        },
        VersionDisposition::Current => CheckOutcome::Current {
            version: verified.manifest().version.clone(),
            notes,
        },
    }
}

fn allowed_asset_redirect(url: &Url, kind: UpdateKind) -> bool {
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port_or_known_default() != Some(443)
        || url.fragment().is_some()
    {
        return false;
    }
    match url.host_str() {
        Some("release-assets.githubusercontent.com" | "objects.githubusercontent.com") => true,
        Some("github.com") => url
            .path()
            .starts_with(&format!("/shui1iao/{}/releases/download/", kind.repo())),
        _ => false,
    }
}

fn remaining(deadline: Instant) -> Result<Duration, UpdateError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|v| !v.is_zero())
        .ok_or_else(|| UpdateError::new("timeout", "更新请求超过总时限"))
}

fn read_bounded(mut response: Response, limit: usize, deadline: Instant) -> Result<Vec<u8>, UpdateError> {
    if response.content_length().map(|n| n > limit as u64).unwrap_or(false) {
        return Err(UpdateError::new("metadata_size", "GitHub 响应超过大小限制"));
    }
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        remaining(deadline)?;
        let count = response
            .read(&mut buffer)
            .map_err(|_| UpdateError::new("network", "GitHub 响应读取失败或超时"))?;
        if count == 0 {
            break;
        }
        if bytes.len() + count > limit {
            return Err(UpdateError::new("metadata_size", "GitHub 响应超过大小限制"));
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    Ok(bytes)
}

fn parse_release(bytes: &[u8]) -> Result<Release, UpdateError> {
    let release: Release =
        serde_json::from_slice(bytes).map_err(|_| UpdateError::new("github_metadata", "GitHub release metadata 无效"))?;
    validate_release(&release)?;
    Ok(release)
}

fn validate_release(release: &Release) -> Result<(), UpdateError> {
    let mut names = HashSet::new();
    let mut ids = HashSet::new();
    if release.id == 0
        || release.tag_name.is_empty()
        || release.tag_name.len() > 256
        || release.tag_name.chars().any(char::is_control)
        || release.assets.len() > 1024
        || !release
            .assets
            .iter()
            .all(|a| a.id > 0 && names.insert(a.name.as_str()) && ids.insert(a.id))
    {
        return Err(UpdateError::new("github_metadata", "GitHub release/资产绑定缺失或重复"));
    }
    Ok(())
}

fn asset_matches(release: &Release, signed: &AssetBinding) -> bool {
    release
        .assets
        .iter()
        .any(|a| a.id == signed.id && a.name == signed.name && a.size == signed.bytes && a.state == "uploaded")
}

fn rate_limit_wait(response: &Response, retry_after: Option<&str>) -> Duration {
    if let Some(d) = retry_after.and_then(retry_delay) {
        return d.min(Duration::from_secs(3600));
    }
    if let Some(reset_epoch) = response
        .headers()
        .get("x-ratelimit-reset")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
    {
        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if reset_epoch > now_sec {
            return Duration::from_secs((reset_epoch - now_sec).min(900));
        }
    }
    Duration::from_secs(30)
}

fn http_error(response: &Response) -> UpdateError {
    let retry_after = response
        .headers()
        .get(header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .filter(|s| s.len() <= 128 && s.bytes().all(|b| (0x20..=0x7e).contains(&b)))
        .map(str::to_owned);
    let status = response.status().as_u16();
    let message = if status == 403 || status == 429 {
        format!("GitHub API 请求配额暂时受限（HTTP {status}）；请稍后重试，不能判断为已最新")
    } else {
        format!("GitHub 返回 HTTP {status}；检查未完成，不能判断为已最新")
    };
    UpdateError {
        code: if status == 403 || status == 429 {
            "rate_limit"
        } else {
            "http_status"
        },
        message,
        retry_after,
    }
}

/// Retry-After supports delta-seconds and the current HTTP-date (IMF-fixdate) format.
fn retry_delay(value: &str) -> Option<Duration> {
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds.max(1)));
    }
    let p: Vec<_> = value.split_ascii_whitespace().collect();
    if p.len() != 6 || !p[0].ends_with(',') || p[5] != "GMT" {
        return None;
    }
    let day = p[1].parse::<u64>().ok()?;
    let month = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ]
    .iter()
    .position(|m| *m == p[2])?;
    let year = p[3].parse::<u64>().ok()?;
    if !(1970..=9999).contains(&year) {
        return None;
    }
    let leap = |y: u64| y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let mut lengths = [31u64, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if leap(year) {
        lengths[1] = 29;
    }
    if day == 0 || day > lengths[month] {
        return None;
    }
    let hms: Vec<_> = p[4]
        .split(':')
        .map(str::parse::<u64>)
        .collect::<Result<_, _>>()
        .ok()?;
    if hms.len() != 3 || hms[0] > 23 || hms[1] > 59 || hms[2] > 59 {
        return None;
    }
    let days: u64 = (1970..year)
        .map(|y| if leap(y) { 366 } else { 365 })
        .sum::<u64>()
        + lengths[..month].iter().sum::<u64>()
        + day
        - 1;
    let target = UNIX_EPOCH.checked_add(Duration::from_secs(days * 86400 + hms[0] * 3600 + hms[1] * 60 + hms[2]))?;
    Some(target.duration_since(SystemTime::now()).unwrap_or(Duration::from_secs(1)))
}

fn validate_destination(path: &Path) -> Result<(), UpdateError> {
    if !path.is_absolute()
        || path.file_name().is_none()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(UpdateError::new(
            "cache_path",
            "缓存目标必须是私有本地目录下的绝对新文件路径",
        ));
    }
    #[cfg(windows)]
    {
        use std::path::Prefix;
        if !matches!(path.components().next(), Some(Component::Prefix(p))
            if matches!(p.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)))
        {
            return Err(UpdateError::new("cache_path", "更新缓存不接受 UNC 或设备路径"));
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| UpdateError::new("cache_path", "缓存文件名无效"))?;
        let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
        if name.contains(':')
            || name.ends_with('.')
            || name.ends_with(' ')
            || ["CON", "PRN", "AUX", "NUL"].contains(&stem.as_str())
            || (stem.len() == 4
                && (stem.starts_with("COM") || stem.starts_with("LPT"))
                && stem.as_bytes()[3].is_ascii_digit())
        {
            return Err(UpdateError::new("cache_path", "缓存文件名包含设备或别名语义"));
        }
    }
    let parent = path
        .parent()
        .ok_or_else(|| UpdateError::new("cache_path", "缓存父目录缺失"))?;
    for dir in parent.ancestors() {
        let meta =
            fs::symlink_metadata(dir).map_err(|_| UpdateError::new("cache_path", "私有缓存目录不存在或无法读取"))?;
        let unsafe_link = meta.file_type().is_symlink();
        #[cfg(windows)]
        let unsafe_link = {
            use std::os::windows::fs::MetadataExt;
            unsafe_link || meta.file_attributes() & 0x400 != 0
        };
        if !meta.is_dir() || unsafe_link {
            return Err(UpdateError::new("cache_path", "缓存目录链包含链接/reparse point 或非目录"));
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::metadata(parent).map_err(|_| UpdateError::new("cache_path", "无法读取缓存目录权限"))?;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(UpdateError::new("cache_path", "缓存父目录必须是调用方私有目录（0700）"));
        }
    }
    Ok(())
}

struct PendingFile {
    path: PathBuf,
    file: Option<File>,
    keep: bool,
}
impl PendingFile {
    fn create(path: &Path) -> Result<Self, UpdateError> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.share_mode(0).custom_flags(0x00200000);
        }
        let file = options
            .open(path)
            .map_err(|_| UpdateError::new("cache_create", "无法创建新的缓存文件（已存在的文件不会覆盖）"))?;
        Ok(Self {
            path: path.to_path_buf(),
            file: Some(file),
            keep: false,
        })
    }
    fn file_mut(&mut self) -> Result<&mut File, UpdateError> {
        self.file
            .as_mut()
            .ok_or_else(|| UpdateError::new("cache_io", "缓存文件已关闭"))
    }
}
impl Drop for PendingFile {
    fn drop(&mut self) {
        drop(self.file.take());
        if !self.keep {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn verify_pe_amd64(file: &mut File, bytes: u64) -> Result<(), UpdateError> {
    let invalid = || UpdateError::new("pe_arch", "资产不是 Windows AMD64 可执行 PE（拒绝 Linux/其他架构/库文件）");
    file.seek(SeekFrom::Start(0)).map_err(|_| invalid())?;
    let mut dos = [0u8; 64];
    file.read_exact(&mut dos).map_err(|_| invalid())?;
    if &dos[..2] != b"MZ" {
        return Err(invalid());
    }
    let offset = u32::from_le_bytes([dos[60], dos[61], dos[62], dos[63]]) as u64;
    if offset < 64 || offset > 1024 * 1024 || offset + 26 > bytes {
        return Err(invalid());
    }
    file.seek(SeekFrom::Start(offset)).map_err(|_| invalid())?;
    let mut pe = [0u8; 26];
    file.read_exact(&mut pe).map_err(|_| invalid())?;
    let u16_at = |i| u16::from_le_bytes([pe[i], pe[i + 1]]);
    let sections = u16_at(6);
    let optional_bytes = u16_at(20);
    let flags = u16_at(22);
    if &pe[..4] != b"PE\0\0"
        || u16_at(4) != 0x8664
        || !(1..=96).contains(&sections)
        || optional_bytes < 112
        || offset + 24 + optional_bytes as u64 > bytes
        || flags & 0x2 == 0
        || flags & 0x2000 != 0
        || u16_at(24) != 0x20b
    {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod quota_free_update_tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn fake_amd64_pe(size: usize) -> Vec<u8> {
        let mut b = vec![0u8; size.max(256)];
        b[0] = b'M';
        b[1] = b'Z';
        let pe_off = 64u32;
        b[60..64].copy_from_slice(&pe_off.to_le_bytes());
        let p = pe_off as usize;
        b[p..p + 4].copy_from_slice(b"PE\0\0");
        b[p + 4..p + 6].copy_from_slice(&0x8664u16.to_le_bytes()); // AMD64
        b[p + 6..p + 8].copy_from_slice(&1u16.to_le_bytes()); // 1 section
        b[p + 20..p + 22].copy_from_slice(&112u16.to_le_bytes()); // optional header size
        b[p + 22..p + 24].copy_from_slice(&0x0002u16.to_le_bytes()); // executable, not DLL
        b[p + 24..p + 26].copy_from_slice(&0x020bu16.to_le_bytes()); // PE32+
        b
    }

    #[test]
    fn extract_helpers_reject_traversal_and_parse_atom_tags_cleanly() {
        assert_eq!(
            extract_tag_from_location(
                "https://github.com/shui1iao/Kat-Client/releases/latest",
                "https://github.com/shui1iao/Kat-Client/releases/tag/v0.2.22",
                UpdateKind::Client
            ),
            Some("v0.2.22".into())
        );
        assert_eq!(
            extract_tag_from_location(
                "https://github.com/shui1iao/Kat-Client/releases/latest",
                "https://github.com/shui1iao/Kat-Client/releases/tag/../v0.2.22",
                UpdateKind::Client
            ),
            None
        );
        assert_eq!(
            extract_tag_from_location(
                "https://github.com/shui1iao/Kat-Client/releases/latest",
                "https://github.com/shui1iao/Kat-Client/releases/tag/v0.2.22?foo=1",
                UpdateKind::Client
            ),
            None
        );

        let atom = r#"<?xml version="1.0" encoding="UTF-8"?>
        <feed xmlns="http://www.w3.org/2005/Atom">
          <entry><link rel="alternate" href="https://github.com/shui1iao/Kat-Server/releases/tag/v0.8.1"/></entry>
          <entry><link rel="alternate" href="https://github.com/shui1iao/Kat-Server/releases/tag/windows-core-v0.8.15"/></entry>
          <entry><link rel="alternate" href="https://github.com/shui1iao/Kat-Server/releases/tag/windows-core-v0.8.14"/></entry>
          <entry><link rel="alternate" href="https://github.com/shui1iao/Kat-Server/releases/tag/windows-core-v0.8.15"/></entry>
        </feed>"#;
        assert_eq!(
            extract_core_tags_from_atom(atom),
            vec!["windows-core-v0.8.15".to_string(), "windows-core-v0.8.14".to_string()]
        );
    }

    #[test]
    fn check_and_download_succeed_with_zero_api_quota_even_when_api_returns_403_and_skip_18_old_core_tags() {
        // Use real signed manifests from v0.2.21 release dir if present, or verify transport & skipping with real Ed25519 signature!
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let base = format!("http://127.0.0.1:{}", addr.port());

        let api_hits = Arc::new(AtomicUsize::new(0));
        let old_core_hits = Arc::new(AtomicUsize::new(0));
        let atom_304_hits = Arc::new(AtomicUsize::new(0));

        let client_json = "{\n  \"schema\": 1,\n  \"product\": \"kat-client\",\n  \"owner\": \"shui1iao\",\n  \"repo\": \"Kat-Client\",\n  \"release\": {\n    \"id\": 448934535,\n    \"tag\": \"v0.2.21\"\n  },\n  \"version\": \"0.2.21\",\n  \"sequence\": 1794902000,\n  \"os\": \"windows\",\n  \"arch\": \"amd64\",\n  \"asset\": {\n    \"id\": 759873421,\n    \"bytes\": 31010003,\n    \"sha256\": \"5609a6356f8f597e308385de10a58d614e4242b0a4b02fc79d870f4fafbc1367\",\n    \"name\": \"Kat-Setup-x64.exe\"\n  },\n  \"gui_compatibility\": \">=0.1.0, <0.3.0\",\n  \"stdio_protocol\": 1,\n  \"required_capabilities\": [\n    \"host.prepare-update.v1\",\n    \"host.handover.v1\",\n    \"host.elevated.v1\",\n    \"network.tun-core.v1\"\n  ],\n  \"service_protocol\": 1,\n  \"record_schema\": 2,\n  \"workspace_read_compatibility\": 1,\n  \"workspace_write_compatibility\": 1,\n  \"source_revision\": \"7de838bec396c13f3bd89a173ddbba38d0ee9c34\",\n  \"key_id\": \"0afa646ee76f17d8\"\n}\n".as_bytes();
        let client_sig = "d2427badaffb34dfca9e57b18648e1e8080c565dc36d91ba192f8dbac845d96dbca6fea6c4d39c56f93621e33a4f517ac21c9677add116e5ff27aa7ececcb203\n".as_bytes();
        let core_json = "{\n  \"schema\": 1,\n  \"product\": \"kat-client-core\",\n  \"owner\": \"shui1iao\",\n  \"repo\": \"Kat-Server\",\n  \"release\": {\n    \"id\": 448934542,\n    \"tag\": \"windows-core-v0.8.15\"\n  },\n  \"version\": \"0.8.15\",\n  \"sequence\": 1794902000,\n  \"os\": \"windows\",\n  \"arch\": \"amd64\",\n  \"asset\": {\n    \"id\": 759873613,\n    \"bytes\": 17570304,\n    \"sha256\": \"ce44c30e612c68d7c13bd379280f4e95c401f411ded85d1087eb9a5c7aed7699\",\n    \"name\": \"kat-client-core-0.8.15-windows-amd64.exe\"\n  },\n  \"gui_compatibility\": \">=0.1.32, <0.3.0\",\n  \"stdio_protocol\": 1,\n  \"required_capabilities\": [\n    \"host.prepare-update.v1\",\n    \"host.handover.v1\",\n    \"host.elevated.v1\",\n    \"network.tun-core.v1\"\n  ],\n  \"service_protocol\": 1,\n  \"record_schema\": 2,\n  \"workspace_read_compatibility\": 1,\n  \"workspace_write_compatibility\": 1,\n  \"source_revision\": \"04a81276f5f663a48f9cfb4fac548cf4950f207d0c9df3893e0069736d3f7a8e\",\n  \"key_id\": \"0afa646ee76f17d8\"\n}\n".as_bytes();
        let core_sig = "3c47b70dc8d4ad364a6839bb6386d3225e4e73bd5052ffa99f49ed999c5c78d48501f52a049845c40a31ab335c37dff9e77db5313154ca949574277aa05ed402\n".as_bytes();

        let api_hits_srv = api_hits.clone();
        let old_core_srv = old_core_hits.clone();
        let atom_304_srv = atom_304_hits.clone();
        let base_srv = base.clone();

        let server = std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut reader = BufReader::new(&stream);
                let mut req_line = String::new();
                if reader.read_line(&mut req_line).unwrap_or(0) == 0 {
                    continue;
                }
                let path = req_line.split_whitespace().nth(1).unwrap_or("");
                let mut if_none_match = String::new();
                loop {
                    let mut h = String::new();
                    if reader.read_line(&mut h).unwrap_or(0) == 0 || h == "\r\n" {
                        break;
                    }
                    if let Some((k, v)) = h.split_once(':') {
                        if k.trim().eq_ignore_ascii_case("if-none-match") {
                            if_none_match = v.trim().to_owned();
                        }
                    }
                }
                let mut out = &stream;
                if path == "/__stop" {
                    let _ = out.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    break;
                }
                // Simulate shared proxy IP where EVERY api.github.com call returns 403 rate limit!
                if path.starts_with("/repos/") {
                    api_hits_srv.fetch_add(1, Ordering::SeqCst);
                    let body = b"{\"message\":\"API rate limit exceeded\"}";
                    let hdr = format!(
                        "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = out.write_all(hdr.as_bytes());
                    let _ = out.write_all(body);
                    continue;
                }
                if path == "/shui1iao/Kat-Client/releases/latest" {
                    let loc = format!("{base_srv}/shui1iao/Kat-Client/releases/tag/v0.2.21");
                    let hdr = format!("HTTP/1.1 302 Found\r\nLocation: {loc}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    let _ = out.write_all(hdr.as_bytes());
                    continue;
                }
                if path == "/shui1iao/Kat-Server/releases.atom" {
                    if if_none_match == "\"atom-v1\"" {
                        atom_304_srv.fetch_add(1, Ordering::SeqCst);
                        let _ = out.write_all(b"HTTP/1.1 304 Not Modified\r\nETag: \"atom-v1\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                        continue;
                    }
                    // Include 15 historical windows-core-v0.8.0..0.8.14 PLUS latest 0.8.15!
                    let mut xml = String::from("<?xml version=\"1.0\"?><feed>");
                    xml.push_str("<entry><link href=\"https://github.com/shui1iao/Kat-Server/releases/tag/windows-core-v0.8.15\"/></entry>");
                    for minor in (0..=14).rev() {
                        xml.push_str(&format!(
                            "<entry><link href=\"https://github.com/shui1iao/Kat-Server/releases/tag/windows-core-v0.8.{minor}\"/></entry>"
                        ));
                    }
                    xml.push_str("</feed>");
                    let hdr = format!(
                        "HTTP/1.1 200 OK\r\nETag: \"atom-v1\"\r\nContent-Type: application/atom+xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        xml.len()
                    );
                    let _ = out.write_all(hdr.as_bytes());
                    let _ = out.write_all(xml.as_bytes());
                    continue;
                }
                if path.contains("/windows-core-v0.8.") && !path.contains("/windows-core-v0.8.15/") {
                    old_core_srv.fetch_add(1, Ordering::SeqCst);
                    let _ = out.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    continue;
                }
                let body: Option<&[u8]> = match path {
                    "/shui1iao/Kat-Client/releases/download/v0.2.21/kat-client-update.json" => Some(&client_json),
                    "/shui1iao/Kat-Client/releases/download/v0.2.21/kat-client-update.json.sig" => Some(&client_sig),
                    "/shui1iao/Kat-Client/releases/download/v0.2.21/RELEASE_NOTES.md" => Some(b"# Client 0.2.21 Notes"),
                    "/shui1iao/Kat-Server/releases/download/windows-core-v0.8.15/kat-client-core-update.json" => Some(&core_json),
                    "/shui1iao/Kat-Server/releases/download/windows-core-v0.8.15/kat-client-core-update.json.sig" => Some(&core_sig),
                    "/shui1iao/Kat-Server/releases/download/windows-core-v0.8.15/RELEASE_NOTES.md" => Some(b"# Core 0.8.15 Notes"),
                    _ => None,
                };
                if let Some(b) = body {
                    let hdr = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        b.len()
                    );
                    let _ = out.write_all(hdr.as_bytes());
                    let _ = out.write_all(b);
                } else {
                    let _ = out.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                }
            }
        });

        let checker = UpdateChecker::make(
            UpdateTransport::direct(),
            Some(Instant::now() + Duration::from_secs(15)),
            Arc::new(Mutex::new(HashMap::new())),
            Arc::new(Mutex::new(HashMap::new())),
            Arc::new(Mutex::new(HashMap::new())),
            Endpoints {
                web_base: base.clone(),
                api_base: base.clone(),
                allow_loopback_http: true,
            },
        )
        .unwrap();

        let current = CurrentVersions {
            app_version: "0.2.20".into(),
            core_version: "0.8.14".into(),
            app_sha256: None,
            core_sha256: "ad3b90d8349f520014f00992fde07e7fe1d1fc860cd1e332cc07b46b0f98f2c3".into(),
            app_sequence: 1794901000,
            core_sequence: 1794901000,
            supported_capabilities: vec![
                "host.prepare-update.v1".into(),
                "host.handover.v1".into(),
                "host.elevated.v1".into(),
                "network.tun-core.v1".into(),
            ],
        };

        // Run 3 consecutive full Client + Core update checks!
        for round in 0..3 {
            match checker.check(UpdateKind::Client, &current).unwrap() {
                CheckOutcome::Available { offer, .. } => {
                    assert_eq!(offer.manifest().version, "0.2.21");
                    assert_eq!(offer.notes(), Some("# Client 0.2.21 Notes"));
                }
                other => panic!("round {round}: unexpected client outcome: {other:?}"),
            }
            match checker.check(UpdateKind::Core, &current).unwrap() {
                CheckOutcome::Available { offer, .. } => {
                    assert_eq!(offer.manifest().version, "0.8.15");
                    assert_eq!(offer.notes(), Some("# Core 0.8.15 Notes"));
                }
                other => panic!("round {round}: unexpected core outcome: {other:?}"),
            }
        }

        // Verify ZERO api.github.com calls, ZERO historical (< 0.8.14) core tag fetches, and Atom ETag 304 reuse!
        assert_eq!(api_hits.load(Ordering::SeqCst), 0, "must never hit rate-limited api.github.com on primary path");
        assert_eq!(old_core_hits.load(Ordering::SeqCst), 0, "must skip all historical core tags below installed version");
        assert_eq!(atom_304_hits.load(Ordering::SeqCst), 2, "rounds 2 and 3 must hit Atom ETag 304 cache");

        // Verify tampered signature or mismatched tag is strictly rejected even on direct web path:
        let bad_sig = vec![b'0'; 128];
        let exp = ExpectedRelease { kind: UpdateKind::Client, release_id: 448934535, release_tag: "v0.2.21".into() };
        assert!(checker.evaluate_manifest_bytes(UpdateKind::Client, "v0.2.21", &client_json, &bad_sig, &exp, None, None, &current).is_err());
        let wrong_tag = ExpectedRelease { kind: UpdateKind::Client, release_id: 448934535, release_tag: "v0.2.99".into() };
        assert!(checker.evaluate_manifest_bytes(UpdateKind::Client, "v0.2.99", &client_json, &client_sig, &wrong_tag, None, None, &current).is_err());

        let _ = Client::new().get(format!("{base}/__stop")).send();
        let _ = server.join();
        let _ = fake_amd64_pe(256);
    }
}
