# Validation: Kat-Client v0.2.32 / Windows Core v0.8.19

- Client version: `0.2.32` (`client_sequence`: `1795535000`, previous `0.2.31` / `1795525000`)
- Windows Core version: `0.8.19` (`core_sequence`: `1795524000`, unchanged from v0.2.31; `gui_compatibility >=0.2.29, <0.3.0`)
- Core source fingerprint: `6a72464eba0bfbd8e568b474696ce6162f4ebe8ccc6b12308693dbdc50d763ea`

## Automated Gates Passed
1. **Frontend (`app/`)**: `npm run typecheck` (0 errors), `npm test` (152 passed, 0 failed), `npm run build` (verified `.modal` standard `backdrop-filter: blur(28px)` and `kat-mask-in` `background-color` animation in compiled CSS), and headless Chromium light/dark visual verification of modal glass clarity.
2. **Windows Go Core (`core/`)**: Unchanged byte-for-byte from verified v0.8.19 (`6a72464eba0bfbd8e568b474696ce6162f4ebe8ccc6b12308693dbdc50d763ea`).
3. **Rust Host (`app/src-tauri/`)**: `cargo test --offline --locked` (324 passed, 0 failed, 2 ignored), `build-windows.sh` (all 5 Windows x64 binaries built + Wintun verified), pinned NSIS 3.11 uninstaller capture + final `Kat-Setup-x64.exe` offline dual-signature product verification gate (schema 1 + schema 2, 22 files) passed.
4. **Online Update Gate**: Product `update_manifest::verify` verifies `0.2.31 -> 0.2.32` (`Newer`), `0.2.32 -> 0.2.32` (`Current`), and Core v0.8.19 compatibility (`Current`).
