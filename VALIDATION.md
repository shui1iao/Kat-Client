# Validation: Kat-Client v0.2.30 / Windows Core v0.8.18

- Client version: `0.2.30` (`client_sequence`: `1795500000`, previous `0.2.29` / `1795421000`)
- Windows Core version: `0.8.18` (`core_sequence`: `1795420000`, unchanged from v0.2.29; `gui_compatibility >=0.2.29, <0.3.0`)
- Core source fingerprint: `12c468ff8e8d19723bf3d3f2e0595ed0ae025f9d5abd6bf600dd2ffd84d8e282`

## Automated Gates Passed
1. **Frontend (`app/`)**: `npm run typecheck` (0 errors), `npm test` (152 passed, 0 failed — including `dns-input.test.ts` covering URL/IDN/IP parsing & LightningCSS standard `backdrop-filter` / `mask-image` preservation), `npm run build` (compiled production CSS verified for standard `backdrop-filter` and `mask-image`), and headless Chromium visual verification across light/dark themes, Rules judge frosted popover, DNS top-center frosted toast, and Policies/Rules/DNS soft gradient fade edges.
2. **Windows Go Core (`core/`)**: Unchanged byte-for-byte from verified v0.8.18 (`12c468ff8e8d19723bf3d3f2e0595ed0ae025f9d5abd6bf600dd2ffd84d8e282`).
3. **Rust Host (`app/src-tauri/`)**: `cargo test --offline --locked` (324 passed, 0 failed, 2 ignored), `test-package-inputs.py` (2/2), `build-windows.sh` (all 5 Windows x64 binaries built + Wintun vendor verification passed), pinned NSIS 3.11 uninstaller capture + final `Kat-Setup-x64.exe` offline dual-signature product verification gate (schema 1 + schema 2, all 22 installed files) passed.
4. **Online Update Gate**: Product `update_manifest::verify` verifies `0.2.29 -> 0.2.30` (`Newer`) and `0.2.30 -> 0.2.30` (`Current`).
