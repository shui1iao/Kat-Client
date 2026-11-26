# Validation: Kat-Client v0.2.35 (Windows Core v0.8.21)

- Client sequence: `1795640000`
- Windows Core sequence: `1795629000` (unchanged Core v0.8.21, `git diff v0.2.34 -- core/` empty)
- Core source fingerprint: `624ff4ff10f4aa83f86ec85145945aacb02d460c245a5d2fd420e19ab6ece93f`
- Companion Linux Server: `v0.8.3`

## Automated Gates Passed
1. **Frontend (`app/`)**: `tsc --noEmit` (0 errors) and `node build.mjs` (Vite production bundle) succeeded; verified default 4:3 (`1080x810`) layout & wide-screen anti-stretch CSS in Chromium with 0 console errors.
2. **Rust Host (`app/src-tauri/`)**: `cargo test --offline --locked` passed all 326 tests (0 failed, including updated `window_geometry::tests::corrupt_state_falls_back_and_no_minimized_field` covering 96/120/144 DPI 4:3 default sizing and saved window restoration, plus `control_contract::r1_r2_display_version_production_wiring_contract`), `build-windows.sh` cross-compiled all 5 Windows x64 host binaries pinned to unchanged Core v0.8.21 + verified Wintun DLL.
3. **Packaging & Signing Gate**: pinned NSIS 3.11 uninstaller capture + Ed25519 (`0afa646ee76f17d8`) offline dual-signature product verification gate (schema 1 + schema 2, 22 files) passed; online update manifest verified with product `update_manifest::verify` (`0.2.34 -> 0.2.35 Newer`, `0.2.35 -> Current`).
