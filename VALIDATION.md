# Validation: Kat-Client v0.2.37 (Windows Core v0.8.22)

- Client sequence: `1795793000`
- Windows Core sequence: `1795722000` (unchanged Core v0.8.22, `git diff v0.2.36 -- core/` empty)
- Core source fingerprint: `940bdd151404c4ecf8fbdc3b3fd6101bb063a12c0042e3594e9fdc6555ed8726`
- Companion Linux Server: `v0.8.3`

## Automated Gates Passed
1. **Frontend Static, Unit & Multi-Viewport Geometry Gate (`app/npm run verify`)**:
   - `tsc --noEmit` (with `noUnusedLocals` + `noUnusedParameters`, 0 errors) and `node build.mjs` (Vite production bundle) succeeded;
   - `node tests-ui/run-unit.mjs`: all **150/150** unit & `architecture-gate.test.ts` invariants passed (`main.tsx` 100% reachability, 0 zombie exports, 0 unused CSS custom properties, 0 duplicate top-level selectors, 0 orphan CSS classes, 0 business `!important`, singleton `errorText`/`DateTimeFormat`/`Icon`);
   - `node tests-ui/geometry-gate.mjs`: headless Chromium verified 4 viewports (`1080x810`, `900x600`, `880x600`, `1440x900`) × dark/light themes × 20 sub-views × self-drawn tray menu (`?view=tray-menu`) × all modals & popovers with `0` horizontal overflows, exact `34x28` (`6px` radius) caption buttons, `30px` toolbar controls, `34px` modal controls, and `0` console errors/warnings.
2. **Rust Host (`app/src-tauri/`)**: `cargo test --offline --locked` passed all **327** tests (`0` failed, including `r1_r2_display_version_production_wiring_contract` for `0.2.37`); `build-windows.sh` cross-compiled all 5 Windows x64 host binaries pinned to unchanged Core v0.8.22 + verified official Wintun DLL.
3. **Packaging & Signing Gate**: pinned NSIS 3.11 uninstaller capture + Ed25519 (`0afa646ee76f17d8`) offline dual-signature product verification gate (schema 1 + schema 2, 22 files) passed; online update manifest verified with product `update_manifest::verify` (`0.2.36 -> 0.2.37 Newer`, `0.2.37 -> Current`, existing `windows-core-v0.8.22` compatible with `0.2.37 -> Current`).
