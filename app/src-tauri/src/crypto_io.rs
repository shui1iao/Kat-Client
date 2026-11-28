//! Unified 64 KiB streaming SHA-256 verification without whole-file heap allocations.
use crate::error::{Error, Result};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

pub const STREAM_BUF_BYTES: usize = 64 * 1024;

pub fn open_regular_readonly(
    path: &Path,
    single_link: bool,
    open_code: &str,
    reparse_code: &str,
) -> Result<(File, u64)> {
    #[cfg(windows)]
    {
        use std::os::windows::{ffi::OsStrExt, io::FromRawHandle};
        use windows_sys::Win32::{
            Foundation::INVALID_HANDLE_VALUE,
            Storage::FileSystem::{
                CreateFileW, GetFileInformationByHandle, GetFileType, BY_HANDLE_FILE_INFORMATION,
                FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
                FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_READ_DATA,
                FILE_SHARE_READ, FILE_TYPE_DISK, OPEN_EXISTING, READ_CONTROL,
            },
        };
        unsafe {
            let w: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            let h = CreateFileW(
                w.as_ptr(),
                FILE_READ_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL,
                FILE_SHARE_READ,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            );
            if h == INVALID_HANDLE_VALUE {
                return Err(Error::io(open_code, &std::io::Error::last_os_error()));
            }
            let file = File::from_raw_handle(h);
            let mut info = BY_HANDLE_FILE_INFORMATION::default();
            if GetFileType(h) != FILE_TYPE_DISK
                || GetFileInformationByHandle(h, &mut info) == 0
                || info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
                    != 0
                || (single_link && info.nNumberOfLinks != 1)
            {
                return Err(Error::new(
                    reparse_code,
                    "目标文件不是单一普通磁盘文件或包含重解析点",
                ));
            }
            let size = (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow);
            Ok((file, size))
        }
    }
    #[cfg(not(windows))]
    {
        let meta = std::fs::symlink_metadata(path).map_err(|e| Error::io(open_code, &e))?;
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err(Error::new(
                reparse_code,
                "目标文件不是普通磁盘文件或为符号链接",
            ));
        }
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true);
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.custom_flags(0x20000); // O_NOFOLLOW
        }
        let file = opts.open(path).map_err(|e| Error::io(open_code, &e))?;
        let fmeta = file.metadata().map_err(|e| Error::io(open_code, &e))?;
        if fmeta.file_type().is_symlink() || !fmeta.is_file() {
            return Err(Error::new(reparse_code, "目标文件不是普通磁盘文件"));
        }
        #[cfg(unix)]
        if single_link {
            use std::os::unix::fs::MetadataExt;
            if fmeta.nlink() != 1 {
                return Err(Error::new(reparse_code, "拒绝包含多硬链接的目标文件"));
            }
        }
        Ok((file, fmeta.len()))
    }
}

pub fn sha256_reader(
    reader: &mut impl Read,
    max_bytes: u64,
    read_code: &str,
    limit_code: &str,
) -> Result<(String, u64)> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; STREAM_BUF_BYTES];
    let mut total = 0u64;
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| Error::io(read_code, &e))?;
        if n == 0 {
            break;
        }
        total = total
            .checked_add(n as u64)
            .filter(|&t| t <= max_bytes)
            .ok_or_else(|| Error::new(limit_code, "文件大小超出安全上限"))?;
        hasher.update(&buf[..n]);
    }
    Ok((hex::encode(hasher.finalize()), total))
}

pub fn sha256_path(
    path: &Path,
    max_bytes: u64,
    single_link: bool,
    read_code: &str,
    reparse_code: &str,
    limit_code: &str,
) -> Result<(String, u64)> {
    let (mut file, size) = open_regular_readonly(path, single_link, read_code, reparse_code)?;
    if size > max_bytes {
        return Err(Error::new(limit_code, "文件大小超出安全上限"));
    }
    sha256_reader(&mut file, max_bytes, read_code, limit_code)
}

pub fn verify_path_sha256(
    path: &Path,
    max_bytes: u64,
    expected_hex: &str,
    single_link: bool,
    read_code: &str,
    mismatch_code: &str,
    mismatch_msg: &str,
) -> Result<()> {
    let (digest, _) = sha256_path(
        path,
        max_bytes,
        single_link,
        read_code,
        mismatch_code,
        mismatch_code,
    )?;
    if !digest.eq_ignore_ascii_case(expected_hex) || digest != expected_hex {
        return Err(Error::new(mismatch_code, mismatch_msg));
    }
    Ok(())
}

pub fn pin_verified_file(
    path: &Path,
    expected_bytes: Option<u64>,
    max_bytes: u64,
    expected_hex: &str,
    single_link: bool,
    code: &str,
    msg: &str,
) -> Result<File> {
    let (mut file, size) =
        open_regular_readonly(path, single_link, code, code).map_err(|_| Error::new(code, msg))?;
    if size > max_bytes || expected_bytes.is_some_and(|b| b != size) {
        return Err(Error::new(code, msg));
    }
    let (digest, read_total) =
        sha256_reader(&mut file, max_bytes, code, code).map_err(|_| Error::new(code, msg))?;
    if expected_bytes.is_some_and(|b| b != read_total) || digest != expected_hex {
        return Err(Error::new(code, msg));
    }
    Ok(file)
}

/// Stream-copies `input` into `output` using a fixed 64 KiB stack buffer while computing SHA-256.
/// Truncates `output` back to 0 bytes immediately if size or digest fails verification.
pub fn copy_verified_stream(
    mut input: impl Read,
    expected_size: u64,
    max_bytes: u64,
    expected_hex: &str,
    output: &mut File,
    io_code: &str,
    mismatch_code: &str,
    mismatch_msg: &str,
) -> Result<()> {
    let bad = || Error::new(mismatch_code, mismatch_msg);
    if expected_size == 0 || expected_size > max_bytes {
        let _ = output.set_len(0);
        return Err(bad());
    }
    let mut hasher = Sha256::new();
    let mut buf = [0u8; STREAM_BUF_BYTES];
    let mut total = 0u64;
    loop {
        let n = match input.read(&mut buf) {
            Ok(n) => n,
            Err(e) => {
                let _ = output.set_len(0);
                return Err(Error::io(io_code, &e));
            }
        };
        if n == 0 {
            break;
        }
        total = match total.checked_add(n as u64) {
            Some(t) if t <= expected_size => t,
            _ => {
                let _ = output.set_len(0);
                return Err(bad());
            }
        };
        hasher.update(&buf[..n]);
        if let Err(e) = output.write_all(&buf[..n]) {
            let _ = output.set_len(0);
            return Err(Error::io(io_code, &e));
        }
    }
    if total != expected_size || hex::encode(hasher.finalize()) != expected_hex {
        let _ = output.set_len(0);
        return Err(bad());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streaming_sha256_matches_multi_chunk_payload_and_enforces_limits() {
        let payload: Vec<u8> = (0..(STREAM_BUF_BYTES * 2 + 321))
            .map(|i| (i % 251) as u8)
            .collect();
        let expected = hex::encode(Sha256::digest(&payload));
        let (actual, total) = sha256_reader(
            &mut std::io::Cursor::new(&payload),
            1024 * 1024,
            "FILE_READ",
            "FILE_LIMIT",
        )
        .unwrap();
        assert_eq!(actual, expected);
        assert_eq!(total, payload.len() as u64);

        let err = sha256_reader(
            &mut std::io::Cursor::new(&payload),
            1024,
            "FILE_READ",
            "FILE_LIMIT",
        )
        .unwrap_err();
        assert_eq!(err.code, "FILE_LIMIT");
    }
}
