//! Fixed bridge image only; no generic path normalization or relaxed identity.
use std::path::{Path, PathBuf};

pub(crate) fn bridge_image_path(root: &Path) -> PathBuf {
    root.join("network").join("tun2socks.exe")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_image_path_spawn_and_attach_use_the_same_production_helper() {
        let job = include_str!("job.rs");
        let attach = include_str!("flow_channel.rs");
        let engine = include_str!("engine.rs");
        assert!(!attach.contains("root.join(\"network/tun2socks.exe\")"), "old attach keeps an embedded slash, unlike the spawned Windows image");
        assert!(job.contains("mod bridge_image;"));
        assert!(job.contains("pub(super) use bridge_image::bridge_image_path;"));
        assert!(job.contains("let executable=bridge_image_path(root);"));
        assert!(attach.contains("security::same_path(&security::image(process.0)?,&super::job::bridge_image_path(root))"));
        assert!(engine.contains("job::spawn_bridge(&self.root,&name,port,&pipes)?"));
        assert!(job.contains("CreateProcessW(app.as_ptr()"));
        assert!(job.contains("executable.as_os_str().encode_wide()"));
        assert!(job.contains("let network=root.join(\"network\");"));
        assert!(job.contains("let dir:Vec<u16>=network.as_os_str().encode_wide()"));
    }

    #[test]
    fn bridge_image_path_has_fixed_segments_and_exact_windows_spelling() {
        // Execute the very same production helper, then render its fixed
        // components as Windows spells them. This is not a Linux equality of
        // two POSIX paths and is not claimed to execute Windows std::path.
        let path = bridge_image_path(Path::new("root"));
        let parts: Vec<_> = path.strip_prefix("root").unwrap().components()
            .map(|part| part.as_os_str().to_str().unwrap()).collect();
        assert_eq!(parts, ["network", "tun2socks.exe"]);
        let windows = format!(r"C:\Program Files\Kat Client\{}", parts.join(r"\"));
        assert_eq!(windows, r"C:\Program Files\Kat Client\network\tun2socks.exe");
        let old_attach = r"C:\Program Files\Kat Client\network/tun2socks.exe";
        assert!(!windows.eq_ignore_ascii_case(old_attach));
        println!("FIXED_COMPONENT_WINDOWS_SPELLING={windows}; OLD_MIXED_SEPARATOR_MISMATCH=true");
    }

    #[test]
    fn bridge_image_path_preserves_attach_identity_and_strict_comparator() {
        let attach = include_str!("flow_channel.rs");
        for guard in ["OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|0x00100000,0,pid)",
            "sid:\"S-1-5-18\".into(),session:0", "identity::process_stamp(process.0)?",
            "version==1&&s==session", "tcp_owner(&flow.control_source,&flow.control_destination)==Some(pid)"] {
            assert!(attach.contains(guard), "retained guard: {guard}");
        }
        let security = include_str!("security.rs");
        assert!(security.contains("pub fn same_path(a:&Path,b:&Path)->bool{a.to_string_lossy().trim_start_matches(r\"\\\\?\\\").eq_ignore_ascii_case(b.to_string_lossy().trim_start_matches(r\"\\\\?\\\"))}"));
    }

    #[cfg(windows)]
    #[test]
    fn bridge_image_path_windows_std_path_is_exact_and_strict_image_check_matches() {
        // Compiled against the Windows std library. Actual Windows execution is
        // controller-owned; the Linux rendered-component test above is separate.
        for root in [r"C:\Program Files\Kat Client", r"D:\应用\Kat"] {
            let path = bridge_image_path(Path::new(root));
            let expected = format!(r"{root}\network\tun2socks.exe");
            assert_eq!(path.as_os_str(), std::ffi::OsStr::new(&expected));
            assert!(!path.as_os_str().to_string_lossy().contains('/'));
            assert!(crate::windows::security::same_path(&path, Path::new(&expected)));
            assert!(crate::windows::security::same_path(Path::new(&format!(r"\\?\{}", expected.to_uppercase())), &path));
            assert!(!crate::windows::security::same_path(Path::new(&format!(r"{root}\network/tun2socks.exe")), &path));
            assert!(!crate::windows::security::same_path(Path::new(&format!(r"{root}\other\tun2socks.exe")), &path));
        }
    }
}
