//! Fixed public GitHub discovery and bounded, non-executing downloads.
//! Blocking API: call on a worker. The caller owns scheduling and a private cache directory.
use crate::update_manifest::{self, AssetBinding, CurrentVersions, ExpectedRelease, Manifest,
    UpdateError, UpdateKind, VerifiedManifest, VersionDisposition, MAX_MANIFEST_BYTES, MAX_SIGNATURE_BYTES};
use reqwest::{blocking::{Client, Response}, header, StatusCode, Url};
use serde::Deserialize;
use semver::Version;
use sha2::{Digest, Sha256};
use std::{collections::{HashMap, HashSet}, fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write}, path::{Component, Path, PathBuf}, sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH}};

const METADATA_LIMIT: usize = 1024 * 1024;
const CORE_RELEASE_PAGES: usize = 2;
const CORE_RELEASES_PER_PAGE: usize = 30;
const CORE_TAG_PREFIX: &str = "windows-core-v";
const MAX_REDIRECTS: usize = 4;
const CHECK_SECONDS: u64 = 90;
const DOWNLOAD_SECONDS: u64 = 600;
const USER_AGENT: &str = "Kat-Client-Signed-Update/1";

#[derive(Clone, Debug)]
pub struct VerifiedOffer { verified: VerifiedManifest }
impl VerifiedOffer {
    pub fn manifest(&self) -> &Manifest { self.verified.manifest() }
    pub fn manifest_bytes(&self) -> &[u8] { self.verified.manifest_bytes() }
    pub fn signature_hex(&self) -> &str { self.verified.signature_hex() }
    pub fn digest(&self) -> &str { self.verified.digest() }
    pub fn verified(&self) -> &VerifiedManifest { &self.verified }
}
#[derive(Clone, Debug)]
pub enum CheckOutcome {
    Available { offer: VerifiedOffer, message: String },
    Current { version: String },
    Unavailable { reason: String },
}
// Only Verified can become an offer; the other states carry no install authorization.
enum ReleaseCheck {
    Verified(VerifiedManifest),
    Current(String),
    Unavailable(String),
    Incompatible { version: Version, reason: String },
    Older,
}
#[derive(Clone, Copy, Debug)]
pub struct DownloadProgress { pub received_bytes: u64, pub total_bytes: u64 }
#[derive(Clone, Debug)]
pub struct Downloaded {
    pub path: PathBuf,
    pub bytes: u64,
    pub sha256: String,
    pub offer_digest: String,
}
#[derive(Clone)]
struct CachedLatest { bytes: Vec<u8>, etag: Option<String> }
#[derive(Clone)]
struct Backoff { until: Option<Instant>, header: Option<String> }
/// Native-only short-lived egress snapshot. No WebView URL or system proxy input.
#[derive(Clone)]
pub struct UpdateTransport {
    port: Option<u16>,
    identity: Option<(u64, u64)>,
    valid: Arc<dyn Fn() -> bool + Send + Sync>,
    publication: Arc<Mutex<()>>,
}
impl UpdateTransport {
    pub fn direct() -> Self { Self { port: None, identity: None, valid: Arc::new(|| true), publication: Arc::new(Mutex::new(())) } }
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) fn owned(port: Option<u16>, identity: (u64,u64), publication: Arc<Mutex<()>>, valid: impl Fn() -> bool + Send + Sync + 'static) -> Self {
        Self { port, identity: Some(identity), valid: Arc::new(valid), publication }
    }
    pub fn ensure_current(&self) -> Result<(), UpdateError> {
        if (self.valid)() { Ok(()) } else { Err(UpdateError::new("transport_changed", "Kat 更新出口已变化，请重新检查；未自动切换出口")) }
    }
    /// Short linearization lease shared with native entry invalidation.
    /// Lock order: rows -> publication -> owned-slot read locks. No I/O/await,
    /// row acquisition, or progress callback while this lease is held.
    pub fn publication_guard(&self) -> Result<std::sync::MutexGuard<'_, ()>, UpdateError> {
        let guard = self.publication.lock().map_err(|_| UpdateError::new("transport", "Kat 更新发布状态不可确认"))?;
        self.ensure_current()?;
        Ok(guard)
    }
    pub fn same_snapshot(&self, other: &Self) -> bool {
        self.port == other.port && self.identity == other.identity
    }
    pub fn description(&self) -> &'static str {
        if self.port.is_some() { "经 Kat 本地出口" } else { "Kat 本地出口未运行，本次直连" }
    }
}
pub struct UpdateChecker {
    client: Client,
    transport: UpdateTransport,
    cancel: Option<Arc<std::sync::atomic::AtomicBool>>,
    deadline: Option<Instant>,
    // In-memory conditional metadata cache, never a persisted authorization or version floor.
    latest: Arc<Mutex<HashMap<UpdateKind, CachedLatest>>>,
    backoff: Arc<Mutex<HashMap<UpdateKind, Backoff>>>,
}
#[derive(Deserialize)]
struct Release {
    id: u64,
    tag_name: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<GitHubAsset>,
}
#[derive(Deserialize)]
struct GitHubAsset { id: u64, name: String, size: u64, state: String }

impl UpdateChecker {
    pub fn new() -> Result<Self, UpdateError> {
        Self::make(UpdateTransport::direct(), None, Arc::new(Mutex::new(HashMap::new())), Arc::new(Mutex::new(HashMap::new())))
    }
    fn make(transport: UpdateTransport, deadline: Option<Instant>,
        latest: Arc<Mutex<HashMap<UpdateKind, CachedLatest>>>, backoff: Arc<Mutex<HashMap<UpdateKind, Backoff>>>) -> Result<Self, UpdateError> {
        transport.ensure_current()?;
        let mut builder = Client::builder().user_agent(USER_AGENT).https_only(true)
            .redirect(reqwest::redirect::Policy::none()).referer(false).no_proxy()
            .no_gzip().no_brotli().no_deflate().no_zstd()
            .connect_timeout(Duration::from_secs(10)).timeout(Duration::from_secs(DOWNLOAD_SECONDS));
        // no_proxy MUST precede this one fixed native proxy; never inherit env/WPAD/PAC.
        if let Some(port) = transport.port {
            if port == 0 { return Err(UpdateError::new("transport", "Kat 本地出口端口无效")); }
            builder = builder.proxy(reqwest::Proxy::https(format!("http://127.0.0.1:{port}"))
                .map_err(|_| UpdateError::new("transport", "Kat 本地出口无效"))?);
        }
        let client = builder.build().map_err(|_| UpdateError::new("http_client", "无法初始化更新 HTTPS 客户端"))?;
        Ok(Self { client, transport, cancel: None, deadline, latest, backoff })
    }
    /// Fresh connection pool for this operation; metadata/backoff alone may be shared.
    pub fn for_transport(&self, transport: UpdateTransport, deadline: Instant) -> Result<Self, UpdateError> {
        remaining(deadline)?;
        Self::make(transport, Some(deadline), self.latest.clone(), self.backoff.clone())
    }
    pub fn with_cancellation(mut self, cancel: Arc<std::sync::atomic::AtomicBool>) -> Self { self.cancel = Some(cancel); self }
    pub fn ensure_current(&self) -> Result<(), UpdateError> {
        if let Some(deadline) = self.deadline { remaining(deadline)?; }
        if self.cancel.as_ref().is_some_and(|c|c.load(std::sync::atomic::Ordering::SeqCst)) { return Err(UpdateError::new("cancelled", "下载已取消")); }
        self.transport.ensure_current()
    }
    pub fn publication_guard(&self) -> Result<std::sync::MutexGuard<'_, ()>, UpdateError> {
        let guard = self.transport.publication_guard()?;
        self.ensure_current()?; // cancellation/deadline as well as the guarded generation
        Ok(guard)
    }
    fn checkpoint(&self, deadline: Instant) -> Result<Duration, UpdateError> {
        self.ensure_current()?; remaining(deadline)
    }
    /// Missing public manifests/assets are Unavailable, NEVER Current. Network/HTTP failure is Err.
    pub fn check(&self, kind: UpdateKind, current: &CurrentVersions) -> Result<CheckOutcome, UpdateError> {
        let result = self.check_inner(kind, current);
        let _publication = self.publication_guard()?;
        result
    }
    fn check_inner(&self, kind: UpdateKind, current: &CurrentVersions) -> Result<CheckOutcome, UpdateError> {
        let deadline = self.deadline.unwrap_or_else(|| Instant::now() + Duration::from_secs(CHECK_SECONDS));
        self.checkpoint(deadline)?;
        if kind == UpdateKind::Core { return self.check_core(current, deadline); }
        let Some(release) = self.latest_release(kind, deadline)? else {
            return Ok(CheckOutcome::Unavailable { reason: "客户端更新资源尚未发布：暂无公开稳定发行".into() });
        };
        if release.draft || release.prerelease {
            return Ok(CheckOutcome::Unavailable { reason: "客户端更新资源尚未发布：暂无公开稳定发行".into() });
        }
        match self.check_release(kind, &release, current, deadline)? {
            ReleaseCheck::Verified(verified) => Ok(verified_outcome(verified, "有可用更新".into())),
            ReleaseCheck::Current(version) => Ok(CheckOutcome::Current { version }),
            ReleaseCheck::Unavailable(reason) | ReleaseCheck::Incompatible { reason, .. } => {
                Ok(CheckOutcome::Unavailable { reason })
            }
            ReleaseCheck::Older => Ok(CheckOutcome::Unavailable { reason: "不提供低于本机保护版本的更新".into() }),
        }
    }
    fn check_release(&self, kind: UpdateKind, release: &Release, current: &CurrentVersions,
        deadline: Instant) -> Result<ReleaseCheck, UpdateError> {
        let Some(manifest_asset) = release.assets.iter().find(|a| a.name == kind.manifest_name()) else {
            return Ok(ReleaseCheck::Unavailable("更新资源尚未发布：发行缺少签名更新清单".into()));
        };
        let Some(signature_asset) = release.assets.iter().find(|a| a.name == kind.signature_name()) else {
            return Ok(ReleaseCheck::Unavailable("更新资源尚未发布：发行缺少清单签名".into()));
        };
        let bytes = self.small_asset(kind, manifest_asset, MAX_MANIFEST_BYTES, deadline)?;
        let sig = self.small_asset(kind, signature_asset, MAX_SIGNATURE_BYTES, deadline)?;
        let expected = ExpectedRelease { kind, release_id: release.id, release_tag: release.tag_name.clone() };
        let result = update_manifest::verify(&bytes, &sig, &expected, current);
        // These specific errors occur AFTER exact-byte signature, schema, product/repo and
        // release binding verification. Re-reading the same signed JSON is for tag/diagnostic
        // classification only: failed verification NEVER creates a VerifiedManifest or offer.
        let manifest = match &result {
            Ok(verified) => verified.manifest().clone(),
            Err(error) if matches!(error.code, "compatibility" | "capabilities" | "platform" | "rollback" | "same_version_hash") => {
                serde_json::from_slice::<Manifest>(&bytes)
                    .map_err(|_| UpdateError::new("manifest_schema", "签名清单结构无效"))?
            }
            Err(error) => return Err(error.clone()),
        };
        let version = signed_version(&manifest.version)?;
        if kind == UpdateKind::Core {
            let tag_version = core_tag_version(&release.tag_name)
                .ok_or_else(|| UpdateError::new("core_tag", "Windows 内核发行 tag 不符合固定稳定版本约定"))?;
            if manifest.version != tag_version.to_string() {
                return Err(UpdateError::new("core_tag", "Windows 内核 tag 版本与签名清单版本不一致"));
            }
        }
        if !asset_matches(release, &manifest.asset) {
            return Ok(ReleaseCheck::Unavailable("更新资源尚未发布：发行缺少与签名绑定的 Windows 资产".into()));
        }
        match result {
            Ok(verified) => Ok(ReleaseCheck::Verified(verified)),
            Err(error) if kind == UpdateKind::Client && error.code == "same_version_hash" && current.app_sha256.is_none() => {
                if manifest.sequence == current.app_sequence {
                    return Ok(ReleaseCheck::Current(manifest.version));
                }
                Ok(ReleaseCheck::Unavailable("版本一致，但本机未记录安装包摘要，无法确认包身份；不提供同版本替换".into()))
            }
            Err(error) if matches!(error.code, "compatibility" | "capabilities" | "platform") => {
                let reason = if error.message == "暂无兼容更新：GUI 版本不满足签名清单要求" {
                    "当前 GUI 版本不满足签名兼容范围，需先取得兼容客户端".into()
                } else { error.message };
                Ok(ReleaseCheck::Incompatible { version, reason })
            }
            // Historical signed releases are not installable and do not mean Current.
            // A same/newer release that fails its sequence floor remains a hard error.
            Err(error) if kind == UpdateKind::Core && error.code == "rollback"
                && version.cmp_precedence(&signed_version(&current.core_version)?) == std::cmp::Ordering::Less => {
                Ok(ReleaseCheck::Older)
            }
            Err(error) => Err(error),
        }
    }
    fn check_core(&self, current: &CurrentVersions, deadline: Instant) -> Result<CheckOutcome, UpdateError> {
        let Some(releases) = self.core_releases(deadline)? else {
            return Ok(CheckOutcome::Unavailable { reason: "Windows 内核检查已达 2 页、60 条发行上限，无法确认完整范围；本次不提供更新，不能判断为已最新".into() });
        };
        let installed = signed_version(&current.core_version)?;
        let mut tag_versions = Vec::<Version>::new();
        let mut verified = Vec::<(Version, VerifiedManifest)>::new();
        let mut missing = None;
        let mut incompatible = Vec::<(Version, String)>::new();
        for release in releases {
            if release.draft || release.prerelease { continue; }
            let Some(tag_version) = core_tag_version(&release.tag_name) else { continue; };
            // Build metadata cannot turn one SemVer precedence into multiple identities.
            // Tags only filter/identify ambiguity; NEVER choose or authorize a payload.
            if tag_versions.iter().any(|v| v.cmp_precedence(&tag_version) == std::cmp::Ordering::Equal) {
                return Err(UpdateError::new("core_conflict", "Windows 内核发行存在相同语义版本的多个 tag，无法确定唯一身份"));
            }
            tag_versions.push(tag_version);
            match self.check_release(UpdateKind::Core, &release, current, deadline)? {
                ReleaseCheck::Verified(value) => verified.push((signed_version(&value.manifest().version)?, value)),
                ReleaseCheck::Current(_) => {}
                ReleaseCheck::Unavailable(reason) => { if missing.is_none() { missing = Some(reason); } }
                ReleaseCheck::Incompatible { version, reason } => incompatible.push((version, reason)),
                ReleaseCheck::Older => {}
            }
        }
        if tag_versions.is_empty() {
            return Ok(CheckOutcome::Unavailable { reason: "Windows内核更新资源尚未发布".into() });
        }
        // Rank only manifests that passed ALL original compatibility/forward/hash gates.
        // A higher version must also have a strictly higher sequence than lower candidates.
        verified.sort_by(|a, b| a.0.cmp_precedence(&b.0).then_with(|| a.1.manifest().sequence.cmp(&b.1.manifest().sequence)));
        for pair in verified.windows(2) {
            if pair[0].0.cmp_precedence(&pair[1].0) != std::cmp::Ordering::Less
                || pair[0].1.manifest().sequence >= pair[1].1.manifest().sequence {
                return Err(UpdateError::new("core_conflict", "签名 Windows 内核候选的版本或 sequence 相互冲突，本次不提供更新"));
            }
        }
        let mut notices = Vec::new();
        if let Some(reason) = missing { notices.push(format!("部分发行的{reason}，无法确认完整最新状态")); }
        incompatible.sort_by(|a, b| a.0.cmp_precedence(&b.0));
        if let Some((version, reason)) = incompatible.pop() {
            let newer = if version.cmp_precedence(&installed) == std::cmp::Ordering::Greater { "较新 " } else { "" };
            notices.push(format!("已发现{newer}Windows 内核 {version}，但与当前客户端不兼容，未提供该版本下载：{reason}"));
        }
        let notice = notices.join("；");
        if let Some((_, value)) = verified.pop() {
            if value.disposition() == VersionDisposition::Newer {
                let message = if notice.is_empty() { "有可用更新".into() } else { format!("有兼容更新；{notice}") };
                return Ok(verified_outcome(value, message));
            }
            if notice.is_empty() { return Ok(verified_outcome(value, String::new())); }
            return Ok(CheckOutcome::Unavailable { reason: format!("{notice}；无法确认已是最新版本") });
        }
        Ok(CheckOutcome::Unavailable { reason: if notice.is_empty() {
            "已发布 Windows 内核低于本机保护版本；不提供降级".into()
        } else { notice } })
    }
    // At most two fixed pages, 30 records each, <=1 MiB/page, one shared check deadline.
    // A full second page is conservatively incomplete, even if there are exactly 60 releases.
    fn core_releases(&self, deadline: Instant) -> Result<Option<Vec<Release>>, UpdateError> {
        let mut releases = Vec::new();
        let mut ids = HashSet::new();
        let mut tags = HashSet::new();
        for page in 1..=CORE_RELEASE_PAGES {
            let response = self.get(UpdateKind::Core, &core_releases_api(page), false, None, deadline)?;
            self.success(&response)?;
            let batch: Vec<Release> = serde_json::from_slice(&read_bounded(response, METADATA_LIMIT, deadline)?)
                .map_err(|_| UpdateError::new("github_metadata", "GitHub release 列表无效"))?;
            if batch.len() > CORE_RELEASES_PER_PAGE {
                return Err(UpdateError::new("github_metadata", "GitHub release 列表超过固定每页上限"));
            }
            let complete = batch.len() < CORE_RELEASES_PER_PAGE;
            for release in batch {
                validate_release(&release)?;
                if !ids.insert(release.id) || !tags.insert(release.tag_name.clone()) {
                    return Err(UpdateError::new("core_conflict", "GitHub release 列表跨页存在重复 ID/tag，完整性未知"));
                }
                releases.push(release);
            }
            if complete { return Ok(Some(releases)); }
        }
        Ok(None)
    }
    /// No execution, overwrite, resume, or URL/path from a manifest. destination must be a NEW
    /// absolute filename in a caller-created private local directory (Windows: protected user DACL).
    /// The protected helper must re-verify a protected staged copy; this user cache is not trusted.
    /// Callback false cancels; bytes are real bytes written, total is the signed exact byte count.
    pub fn download<F>(&self, offer: &VerifiedOffer, current: &CurrentVersions,
        destination: &Path, mut progress: F) -> Result<Downloaded, UpdateError>
    where F: FnMut(DownloadProgress) -> bool {
        let verified = update_manifest::verify(offer.manifest_bytes(), offer.signature_hex().as_bytes(),
            &offer.verified.expected(), current)?;
        if verified.digest() != offer.digest() || verified.disposition() != VersionDisposition::Newer {
            return Err(UpdateError::new("offer_changed", "已确认的更新不再适用，请重新检查并确认"));
        }
        let expected = verified.expected();
        let deadline = self.deadline.unwrap_or_else(|| Instant::now() + Duration::from_secs(DOWNLOAD_SECONDS));
        self.checkpoint(deadline)?;
        // Pin to the CONFIRMED release ID, never silently re-check latest and substitute an offer.
        let url = format!("{}/releases/{}", repo_api(expected.kind), expected.release_id);
        let response = self.get(expected.kind, &url, false, None, deadline)?;
        self.success(&response)?;
        let release = parse_release(&read_bounded(response, METADATA_LIMIT, deadline)?)?;
        if release.id != expected.release_id || release.tag_name != expected.release_tag
            || release.draft || release.prerelease || !asset_matches(&release, &verified.manifest().asset) {
            return Err(UpdateError::new("release_changed", "已确认 release/资产已变化，下载中止；不会替换为其他版本"));
        }
        let asset = &verified.manifest().asset;
        let response = self.get(expected.kind, &asset_api(expected.kind, asset.id), true, None, deadline)?;
        self.success(&response)?;
        if response.content_length().map(|n| n != asset.bytes).unwrap_or(false) {
            return Err(UpdateError::new("asset_size", "下载响应长度不等于签名资产大小"));
        }
        validate_destination(destination)?;
        let mut output = PendingFile::create(destination)?;
        if !progress(DownloadProgress { received_bytes: 0, total_bytes: asset.bytes }) {
            return Err(UpdateError::new("cancelled", "下载已取消"));
        }
        let mut response = response;
        let mut received = 0u64;
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        loop {
            self.checkpoint(deadline)?;
            let count = response.read(&mut buffer).map_err(|_| UpdateError::new("download_io", "更新资产读取失败"))?;
            if count == 0 { break; }
            received = received.checked_add(count as u64)
                .ok_or_else(|| UpdateError::new("asset_size", "更新资产大小溢出"))?;
            if received > asset.bytes { return Err(UpdateError::new("asset_size", "更新资产超过签名大小")); }
            output.file_mut()?.write_all(&buffer[..count])
                .map_err(|_| UpdateError::new("cache_io", "无法写入调用方私有更新缓存"))?;
            hash.update(&buffer[..count]);
            if !progress(DownloadProgress { received_bytes: received, total_bytes: asset.bytes }) {
                return Err(UpdateError::new("cancelled", "下载已取消"));
            }
        }
        if received != asset.bytes { return Err(UpdateError::new("asset_size", "更新资产未完整下载")); }
        let digest = hex::encode(hash.finalize());
        if digest != asset.sha256 { return Err(UpdateError::new("asset_hash", "更新资产 SHA-256 不匹配")); }
        output.file_mut()?.sync_all().map_err(|_| UpdateError::new("cache_io", "更新缓存落盘失败"))?;
        verify_pe_amd64(output.file_mut()?, received)?;
        self.checkpoint(deadline)?;
        // Last cancellation/transport fence is AFTER fsync/PE, before keeping any file.
        if !progress(DownloadProgress { received_bytes: received, total_bytes: asset.bytes }) {
            return Err(UpdateError::new("cancelled", "下载已取消"));
        }
        {
            // fsync/PE and progress are staging, outside the shared lease.
            let _publication = self.publication_guard()?;
            output.keep = true;
        }
        Ok(Downloaded { path: destination.to_path_buf(), bytes: received, sha256: digest,
            offer_digest: verified.digest().to_owned() })
    }
    fn latest_release(&self, kind: UpdateKind, deadline: Instant) -> Result<Option<Release>, UpdateError> {
        let cached = self.latest.lock().map_err(|_| UpdateError::new("cache", "更新缓存锁失败"))?
            .get(&kind).cloned();
        let url = format!("{}/releases/latest", repo_api(kind));
        let response = self.get(kind, &url, false, cached.as_ref().and_then(|c| c.etag.as_deref()), deadline)?;
        if response.status() == StatusCode::NOT_FOUND {
            self.latest.lock().map_err(|_| UpdateError::new("cache", "更新缓存锁失败"))?.remove(&kind);
            return Ok(None);
        }
        if response.status() == StatusCode::NOT_MODIFIED {
            let cache = cached.ok_or_else(|| UpdateError::new("cache", "GitHub 返回 304 但没有可复验缓存"))?;
            // Only metadata is reused; signed manifests are ALWAYS fetched and verified again.
            return Ok(Some(parse_release(&cache.bytes)?));
        }
        self.success(&response)?;
        let etag = response.headers().get(header::ETAG).and_then(|v| v.to_str().ok())
            .filter(|s| s.len() <= 512).map(str::to_owned);
        let bytes = read_bounded(response, METADATA_LIMIT, deadline)?;
        let release = parse_release(&bytes)?;
        self.latest.lock().map_err(|_| UpdateError::new("cache", "更新缓存锁失败"))?
            .insert(kind, CachedLatest { bytes, etag });
        Ok(Some(release))
    }
    fn small_asset(&self, kind: UpdateKind, asset: &GitHubAsset, limit: usize, deadline: Instant)
        -> Result<Vec<u8>, UpdateError> {
        if asset.state != "uploaded" || asset.size == 0 || asset.size > limit as u64 {
            return Err(UpdateError::new("metadata_size", "签名清单/签名资产大小或状态不合法"));
        }
        let response = self.get(kind, &asset_api(kind, asset.id), true, None, deadline)?;
        self.success(&response)?;
        let bytes = read_bounded(response, limit, deadline)?;
        if bytes.len() as u64 != asset.size { return Err(UpdateError::new("metadata_size", "签名描述文件与发现的大小不符")); }
        Ok(bytes)
    }
    fn success(&self, response: &Response) -> Result<(), UpdateError> {
        if response.status() == StatusCode::OK { return Ok(()); }
        Err(http_error(response))
    }
    /// No implicit redirects, system proxies, credentials, arbitrary API paths, or body logging.
    fn get(&self, kind: UpdateKind, initial: &str, asset: bool, etag: Option<&str>, deadline: Instant)
        -> Result<Response, UpdateError> {
        let mut url = Url::parse(initial).map_err(|_| UpdateError::new("url", "内部固定 GitHub URL 无效"))?;
        // Initial URLs are internal: fixed repo/IDs, or exactly the two Core list pages.
        // Do not widen the metadata/asset redirect, proxy or host policy for list discovery.
        let base = format!("{}/releases/", repo_api(kind));
        let core_page = kind == UpdateKind::Core
            && (1..=CORE_RELEASE_PAGES).any(|page| initial == core_releases_api(page));
        if (!initial.starts_with(&base) && !core_page) || url.host_str() != Some("api.github.com") {
            return Err(UpdateError::new("url", "拒绝非固定 GitHub 仓库请求"));
        }
        for hop in 0..=MAX_REDIRECTS {
            self.check_backoff(kind)?;
            let mut request = self.client.get(url.clone()).timeout(self.checkpoint(deadline)?)
                .header(header::ACCEPT, if asset { "application/octet-stream" } else { "application/vnd.github+json" })
                .header(header::ACCEPT_ENCODING, "identity");
            if hop == 0 {
                request = request.header("X-GitHub-Api-Version", "2022-11-28");
                if let Some(etag) = etag { request = request.header(header::IF_NONE_MATCH, etag); }
            }
            let response = request.send().map_err(|_| UpdateError::new("network", &format!("GitHub 更新请求失败或超时（{}）；当前版本状态未知；未自动切换出口", self.transport.description())))?;
            self.checkpoint(deadline)?;
            if response.status() == StatusCode::TOO_MANY_REQUESTS || response.status() == StatusCode::FORBIDDEN
                || (response.status() == StatusCode::SERVICE_UNAVAILABLE && response.headers().contains_key(header::RETRY_AFTER)) {
                let error = http_error(&response);
                let wait = error.retry_after.as_deref().and_then(retry_delay).unwrap_or(Duration::from_secs(60));
                self.backoff.lock().map_err(|_| UpdateError::new("cache", "更新限流状态锁失败"))?
                    .insert(kind, Backoff { until: Instant::now().checked_add(wait), header: error.retry_after.clone() });
                return Err(error);
            }
            let redirect = matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308);
            if !redirect { return Ok(response); }
            if !asset || hop == MAX_REDIRECTS { return Err(UpdateError::new("redirect", "GitHub 重定向被拒绝或超过跳数限制")); }
            let location = response.headers().get(header::LOCATION).and_then(|v| v.to_str().ok())
                .filter(|s| s.len() <= 8192).ok_or_else(|| UpdateError::new("redirect", "GitHub 资产重定向无效"))?;
            let next = url.join(location).map_err(|_| UpdateError::new("redirect", "GitHub 资产重定向 URL 无效"))?;
            if !allowed_asset_redirect(&next, kind) {
                return Err(UpdateError::new("redirect", "拒绝非 HTTPS 或非授权 GitHub 资产域重定向"));
            }
            url = next;
        }
        Err(UpdateError::new("redirect", "GitHub 重定向超过限制"))
    }
    fn check_backoff(&self, kind: UpdateKind) -> Result<(), UpdateError> {
        let mut backoff = self.backoff.lock().map_err(|_| UpdateError::new("cache", "更新限流状态锁失败"))?;
        if let Some(wait) = backoff.get(&kind) {
            if wait.until.map(|t| Instant::now() < t).unwrap_or(true) {
                return Err(UpdateError { code: "rate_limit", message: "GitHub 要求稍后重试；当前版本状态未知".into(),
                    retry_after: wait.header.clone() });
            }
        }
        backoff.remove(&kind);
        Ok(())
    }
}
fn repo_api(kind: UpdateKind) -> String { format!("https://api.github.com/repos/shui1iao/{}", kind.repo()) }
fn core_releases_api(page: usize) -> String {
    format!("{}/releases?per_page={CORE_RELEASES_PER_PAGE}&page={page}", repo_api(UpdateKind::Core))
}
fn signed_version(value: &str) -> Result<Version, UpdateError> {
    if value.is_empty() || value.len() > 128 { return Err(UpdateError::new("version", "语义版本长度无效")); }
    let version = Version::parse(value).map_err(|_| UpdateError::new("version", "版本必须是完整的语义版本"))?;
    if !version.pre.is_empty() { return Err(UpdateError::new("version", "仅支持稳定语义版本")); }
    Ok(version)
}
fn core_tag_version(tag: &str) -> Option<Version> {
    let suffix = tag.strip_prefix(CORE_TAG_PREFIX)?;
    let version = signed_version(suffix).ok()?;
    if version.to_string() != suffix { return None; }
    Some(version)
}
fn verified_outcome(verified: VerifiedManifest, message: String) -> CheckOutcome {
    match verified.disposition() {
        VersionDisposition::Newer => CheckOutcome::Available { offer: VerifiedOffer { verified }, message },
        VersionDisposition::Current => CheckOutcome::Current { version: verified.manifest().version.clone() },
    }
}
fn asset_api(kind: UpdateKind, id: u64) -> String { format!("{}/releases/assets/{}", repo_api(kind), id) }
fn allowed_asset_redirect(url: &Url, kind: UpdateKind) -> bool {
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some()
        || url.port_or_known_default() != Some(443) || url.fragment().is_some() { return false; }
    match url.host_str() {
        Some("release-assets.githubusercontent.com" | "objects.githubusercontent.com") => true,
        Some("github.com") => url.path().starts_with(&format!("/shui1iao/{}/releases/download/", kind.repo())),
        _ => false,
    }
}
fn remaining(deadline: Instant) -> Result<Duration, UpdateError> {
    deadline.checked_duration_since(Instant::now()).filter(|v| !v.is_zero())
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
        let count = response.read(&mut buffer).map_err(|_| UpdateError::new("network", "GitHub 响应读取失败或超时"))?;
        if count == 0 { break; }
        if bytes.len() + count > limit { return Err(UpdateError::new("metadata_size", "GitHub 响应超过大小限制")); }
        bytes.extend_from_slice(&buffer[..count]);
    }
    Ok(bytes)
}
fn parse_release(bytes: &[u8]) -> Result<Release, UpdateError> {
    let release: Release = serde_json::from_slice(bytes).map_err(|_| UpdateError::new("github_metadata", "GitHub release metadata 无效"))?;
    validate_release(&release)?;
    Ok(release)
}
fn validate_release(release: &Release) -> Result<(), UpdateError> {
    let mut names = HashSet::new(); let mut ids = HashSet::new();
    if release.id == 0 || release.tag_name.is_empty() || release.tag_name.len() > 256
        || release.tag_name.chars().any(char::is_control) || release.assets.len() > 1024
        || !release.assets.iter().all(|a| a.id > 0 && names.insert(a.name.as_str()) && ids.insert(a.id)) {
        return Err(UpdateError::new("github_metadata", "GitHub release/资产绑定缺失或重复"));
    }
    Ok(())
}
fn asset_matches(release: &Release, signed: &AssetBinding) -> bool {
    release.assets.iter().any(|a| a.id == signed.id && a.name == signed.name && a.size == signed.bytes && a.state == "uploaded")
}
fn http_error(response: &Response) -> UpdateError {
    let retry_after = response.headers().get(header::RETRY_AFTER).and_then(|v| v.to_str().ok())
        .filter(|s| s.len() <= 128 && s.bytes().all(|b| (0x20..=0x7e).contains(&b))).map(str::to_owned);
    let status = response.status().as_u16();
    UpdateError { code: if status == 403 || status == 429 { "rate_limit" } else { "http_status" },
        message: format!("GitHub 返回 HTTP {status}；检查未完成，不能判断为已最新"), retry_after }
}
/// Retry-After supports delta-seconds and the current HTTP-date (IMF-fixdate) format.
fn retry_delay(value: &str) -> Option<Duration> {
    if let Ok(seconds) = value.parse::<u64>() { return Some(Duration::from_secs(seconds.max(1))); }
    let p: Vec<_> = value.split_ascii_whitespace().collect();
    if p.len() != 6 || !p[0].ends_with(',') || p[5] != "GMT" { return None; }
    let day = p[1].parse::<u64>().ok()?;
    let month = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"].iter().position(|m| *m == p[2])?;
    let year = p[3].parse::<u64>().ok()?;
    if !(1970..=9999).contains(&year) { return None; }
    let leap = |y: u64| y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let mut lengths = [31u64, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if leap(year) { lengths[1] = 29; }
    if day == 0 || day > lengths[month] { return None; }
    let hms: Vec<_> = p[4].split(':').map(str::parse::<u64>).collect::<Result<_, _>>().ok()?;
    if hms.len() != 3 || hms[0] > 23 || hms[1] > 59 || hms[2] > 59 { return None; }
    let days: u64 = (1970..year).map(|y| if leap(y) { 366 } else { 365 }).sum::<u64>()
        + lengths[..month].iter().sum::<u64>() + day - 1;
    let target = UNIX_EPOCH.checked_add(Duration::from_secs(days * 86400 + hms[0] * 3600 + hms[1] * 60 + hms[2]))?;
    Some(target.duration_since(SystemTime::now()).unwrap_or(Duration::from_secs(1)))
}
fn validate_destination(path: &Path) -> Result<(), UpdateError> {
    if !path.is_absolute() || path.file_name().is_none()
        || path.components().any(|c| matches!(c, Component::ParentDir | Component::CurDir)) {
        return Err(UpdateError::new("cache_path", "缓存目标必须是私有本地目录下的绝对新文件路径"));
    }
    #[cfg(windows)] {
        use std::path::Prefix;
        if !matches!(path.components().next(), Some(Component::Prefix(p))
            if matches!(p.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))) {
            return Err(UpdateError::new("cache_path", "更新缓存不接受 UNC 或设备路径"));
        }
        // No alternate data stream or Win32 alias names, even though this path is caller-owned.
        let name = path.file_name().and_then(|n| n.to_str()).ok_or_else(|| UpdateError::new("cache_path", "缓存文件名无效"))?;
        let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
        if name.contains(':') || name.ends_with('.') || name.ends_with(' ') || ["CON", "PRN", "AUX", "NUL"].contains(&stem.as_str())
            || (stem.len() == 4 && (stem.starts_with("COM") || stem.starts_with("LPT")) && stem.as_bytes()[3].is_ascii_digit()) {
            return Err(UpdateError::new("cache_path", "缓存文件名包含设备或别名语义"));
        }
    }
    let parent = path.parent().ok_or_else(|| UpdateError::new("cache_path", "缓存父目录缺失"))?;
    for dir in parent.ancestors() {
        let meta = fs::symlink_metadata(dir).map_err(|_| UpdateError::new("cache_path", "私有缓存目录不存在或无法读取"))?;
        let unsafe_link = meta.file_type().is_symlink();
        #[cfg(windows)] let unsafe_link = {
            use std::os::windows::fs::MetadataExt;
            unsafe_link || meta.file_attributes() & 0x400 != 0
        };
        if !meta.is_dir() || unsafe_link { return Err(UpdateError::new("cache_path", "缓存目录链包含链接/reparse point 或非目录")); }
    }
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::metadata(parent).map_err(|_| UpdateError::new("cache_path", "无法读取缓存目录权限"))?;
        if meta.permissions().mode() & 0o077 != 0 { return Err(UpdateError::new("cache_path", "缓存父目录必须是调用方私有目录（0700）")); }
    }
    Ok(())
}
struct PendingFile { path: PathBuf, file: Option<File>, keep: bool }
impl PendingFile {
    fn create(path: &Path) -> Result<Self, UpdateError> {
        let mut options = OpenOptions::new(); options.read(true).write(true).create_new(true);
        #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
        #[cfg(windows)] { use std::os::windows::fs::OpenOptionsExt; options.share_mode(0).custom_flags(0x00200000); }
        let file = options.open(path).map_err(|_| UpdateError::new("cache_create", "无法创建新的缓存文件（已存在的文件不会覆盖）"))?;
        Ok(Self { path: path.to_path_buf(), file: Some(file), keep: false })
    }
    fn file_mut(&mut self) -> Result<&mut File, UpdateError> {
        self.file.as_mut().ok_or_else(|| UpdateError::new("cache_io", "缓存文件已关闭"))
    }
}
impl Drop for PendingFile {
    fn drop(&mut self) { drop(self.file.take()); if !self.keep { let _ = fs::remove_file(&self.path); } }
}
fn verify_pe_amd64(file: &mut File, bytes: u64) -> Result<(), UpdateError> {
    let invalid = || UpdateError::new("pe_arch", "资产不是 Windows AMD64 可执行 PE（拒绝 Linux/其他架构/库文件）");
    file.seek(SeekFrom::Start(0)).map_err(|_| invalid())?;
    let mut dos = [0u8; 64]; file.read_exact(&mut dos).map_err(|_| invalid())?;
    if &dos[..2] != b"MZ" { return Err(invalid()); }
    let offset = u32::from_le_bytes([dos[60], dos[61], dos[62], dos[63]]) as u64;
    if offset < 64 || offset > 1024 * 1024 || offset + 26 > bytes { return Err(invalid()); }
    file.seek(SeekFrom::Start(offset)).map_err(|_| invalid())?;
    let mut pe = [0u8; 26]; file.read_exact(&mut pe).map_err(|_| invalid())?;
    let u16_at = |i| u16::from_le_bytes([pe[i], pe[i + 1]]);
    let sections = u16_at(6); let optional_bytes = u16_at(20); let flags = u16_at(22);
    if &pe[..4] != b"PE\0\0" || u16_at(4) != 0x8664 || !(1..=96).contains(&sections)
        || optional_bytes < 112 || offset + 24 + optional_bytes as u64 > bytes
        || flags & 0x2 == 0 || flags & 0x2000 != 0 || u16_at(24) != 0x20b { return Err(invalid()); }
    Ok(())
}
