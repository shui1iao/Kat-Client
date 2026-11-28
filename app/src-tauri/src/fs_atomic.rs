//! Unified symlink/reparse-safe atomic file persistence with CSPRNG temporary names.
use crate::error::{Error, Result};
use std::{
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(1);

fn random_hex_16(err_code: &str) -> Result<String> {
    let mut bytes = [0u8; 16];
    #[cfg(windows)]
    {
        #[link(name = "bcrypt")]
        extern "system" {
            fn BCryptGenRandom(
                alg: *mut core::ffi::c_void,
                buf: *mut u8,
                len: u32,
                flags: u32,
            ) -> i32;
        }
        if unsafe { BCryptGenRandom(std::ptr::null_mut(), bytes.as_mut_ptr(), 16, 2) } < 0 {
            return Err(Error::new(err_code, "无法生成安全随机临时文件名"));
        }
    }
    #[cfg(not(windows))]
    {
        use std::io::Read;
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut bytes))
            .map_err(|e| Error::io(err_code, &e))?;
    }
    Ok(hex::encode(bytes))
}

pub fn ensure_target_not_reparse(path: &Path, reparse_code: &str, type_code: &str) -> Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{
            GetFileAttributesW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
            INVALID_FILE_ATTRIBUTES,
        };
        let w: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let attr = unsafe { GetFileAttributesW(w.as_ptr()) };
        if attr != INVALID_FILE_ATTRIBUTES {
            if attr & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(Error::new(reparse_code, "拒绝写入符号链接或重解析点"));
            }
            if attr & FILE_ATTRIBUTE_DIRECTORY != 0 {
                return Err(Error::new(type_code, "目标路径不能是目录"));
            }
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        match std::fs::symlink_metadata(path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(Error::new(reparse_code, "拒绝写入符号链接"));
                }
                if meta.is_dir() {
                    return Err(Error::new(type_code, "目标路径不能是目录"));
                }
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::io(reparse_code, &e)),
        }
    }
}

fn parse_atomic_temp_leaf(name: &str) -> Option<&str> {
    let (before_rand, rand) = name.rsplit_once('-')?;
    if rand.len() != 32 || !rand.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let (before_seq, seq) = before_rand.rsplit_once('-')?;
    if seq.is_empty()
        || !seq.bytes().all(|b| b.is_ascii_digit())
        || !seq.parse::<u64>().is_ok_and(|v| v > 0)
    {
        return None;
    }
    let (prefix, pid) = before_seq.rsplit_once(".tmp-")?;
    if pid.is_empty()
        || !pid.bytes().all(|b| b.is_ascii_digit())
        || pid.parse::<u32>().is_err()
    {
        return None;
    }
    let leaf = prefix.strip_prefix('.')?;
    if leaf.is_empty()
        || leaf == "."
        || leaf == ".."
        || leaf.contains('/')
        || leaf.contains('\\')
    {
        return None;
    }
    Some(leaf)
}

pub fn is_atomic_temp_name(name: &str) -> bool {
    parse_atomic_temp_leaf(name).is_some()
}

pub fn is_atomic_temp_for(name: &str, leaf: &str) -> bool {
    !leaf.is_empty() && parse_atomic_temp_leaf(name) == Some(leaf)
}

fn build_temp_path(path: &Path, write_code: &str) -> Result<(PathBuf, PathBuf)> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| Error::new(write_code, "缺少父目录路径"))?
        .to_path_buf();
    let leaf = path
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| !n.is_empty())
        .ok_or_else(|| Error::new(write_code, "无效的目标文件名"))?;
    let seq = NEXT.fetch_add(1, Ordering::Relaxed);
    let rand = random_hex_16(write_code)?;
    let tmp = parent.join(format!(".{leaf}.tmp-{}-{seq}-{rand}", std::process::id()));
    Ok((parent, tmp))
}

pub fn replace_durable(
    tmp: &Path,
    path: &Path,
    parent: &Path,
    replace_code: &str,
    sync_code: &str,
) -> Result<()> {
    #[cfg(windows)]
    {
        let _ = (parent, sync_code);
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::{
            Foundation::GetLastError,
            Storage::FileSystem::{
                MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
            },
        };
        let a: Vec<u16> = tmp.as_os_str().encode_wide().chain(Some(0)).collect();
        let z: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        if unsafe {
            MoveFileExW(
                a.as_ptr(),
                z.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(Error::new(replace_code, "无法原子提交文件")
                .native(unsafe { GetLastError() }));
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        std::fs::rename(tmp, path).map_err(|e| Error::io(replace_code, &e))?;
        std::fs::File::open(parent)
            .and_then(|f| f.sync_all())
            .map_err(|e| Error::io(sync_code, &e))?;
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub fn write_atomic_with_codes(
    path: &Path,
    bytes: &[u8],
    limit: usize,
    limit_code: &str,
    reparse_code: &str,
    type_code: &str,
    write_code: &str,
    replace_code: &str,
    sync_code: &str,
) -> Result<()> {
    if bytes.len() > limit {
        return Err(Error::new(limit_code, "写入内容超过大小限制"));
    }
    ensure_target_not_reparse(path, reparse_code, type_code)?;
    let (parent, tmp) = build_temp_path(path, write_code)?;
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            // FILE_FLAG_OPEN_REPARSE_POINT (0x00200000) + exclusive share_mode(0)
            options.share_mode(0).custom_flags(0x00200000);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
            #[cfg(target_os = "linux")]
            options.custom_flags(0x20000); // O_NOFOLLOW
        }
        let mut f = options
            .open(&tmp)
            .map_err(|e| Error::io(write_code, &e))?;
        f.write_all(bytes)
            .and_then(|_| f.sync_all())
            .map_err(|e| Error::io(write_code, &e))?;
        drop(f);
        ensure_target_not_reparse(path, reparse_code, type_code)?;
        replace_durable(&tmp, path, &parent, replace_code, sync_code)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

pub fn write_atomic_io(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    write_atomic_with_codes(
        path,
        bytes,
        64 * 1024 * 1024,
        "FILE_LIMIT",
        "UNTRUSTED_PATH",
        "FILE_TYPE",
        "LOCAL_FILE_WRITE",
        "LOCAL_FILE_COMMIT",
        "LOCAL_FILE_COMMIT",
    )
    .map_err(|e| {
        e.os_error
            .map(|c| std::io::Error::from_raw_os_error(c as i32))
            .unwrap_or_else(|| std::io::Error::other(e.message))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_roundtrip_and_leaves_no_temp_files() {
        let dir = std::env::temp_dir().join(format!(
            "kat-fs-atomic-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("sample.json");
        write_atomic_with_codes(
            &target,
            b"{\"ok\":true}",
            1024,
            "FILE_LIMIT",
            "FILE_REPARSE",
            "FILE_TYPE",
            "JOURNAL_WRITE",
            "JOURNAL_REPLACE",
            "JOURNAL_SYNC",
        )
        .unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"{\"ok\":true}");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn atomic_temp_name_matchers_are_exact() {
        let (_, generated) = build_temp_path(Path::new("/tmp/network-last-error.json"), "WRITE").unwrap();
        let gen_name = generated.file_name().unwrap().to_str().unwrap();
        assert!(is_atomic_temp_name(gen_name));
        assert!(is_atomic_temp_for(gen_name, "network-last-error.json"));
        assert!(!is_atomic_temp_for(gen_name, "diagnostic-retention.json"));

        let tricky = ".foo.tmp-bar.json.tmp-4242-9-0123456789abcdef0123456789abcdef";
        assert!(is_atomic_temp_name(tricky));
        assert!(is_atomic_temp_for(tricky, "foo.tmp-bar.json"));

        for invalid in [
            "prefs.json",
            "network-last-error.next",
            "prefs.json.tmp-123-1-0123456789abcdef0123456789abcdef",
            ".tmp-123-1-0123456789abcdef0123456789abcdef",
            "..tmp-123-1-0123456789abcdef0123456789abcdef",
            "...tmp-123-1-0123456789abcdef0123456789abcdef",
            ".prefs.json.tmp-123-0-0123456789abcdef0123456789abcdef",
            ".prefs.json.tmp-999999999999-1-0123456789abcdef0123456789abcdef",
            ".prefs.json.tmp-123-1-0123456789ABCDEF0123456789abcdef",
            ".prefs.json.tmp-123-1-0123456789abcdef",
            ".a/b.tmp-123-1-0123456789abcdef0123456789abcdef",
        ] {
            assert!(!is_atomic_temp_name(invalid), "unexpected match for {invalid}");
            assert!(!is_atomic_temp_for(invalid, "prefs.json"));
        }
    }
}
