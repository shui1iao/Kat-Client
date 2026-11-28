# Validation: Kat-Client v0.2.38 (Windows Core v0.8.23)

- Client sequence: `1795859000`
- Windows Core sequence: `1795858000`
- Core source fingerprint: `7d92dba98d7133990b51b134e1fd509b7e9e2645041ac0c4549f7f4951a04720`
- Companion Linux Server: `v0.8.4` / Kat-Manager: `v0.1.4`

## Automated Gates Passed
1. **Frontend Static, Unit & Multi-Viewport Geometry Gate (`app/npm run verify`)**:
   - `tsc --noEmit` (with `noUnusedLocals` + `noUnusedParameters`, 0 errors) and `node build.mjs` (Vite production bundle) succeeded;
   - `node tests-ui/run-unit.mjs`: all **166 / 166** unit, fuzz, virtual-scroll, large-integer span preservation, and `architecture-gate.test.ts` invariants passed;
   - `node tests-ui/geometry-gate.mjs`: headless Chromium verified 4 viewports (`1080x810`, `900x600`, `880x600`, `1440x900`) × dark/light themes × 20 sub-views × self-drawn tray menu × virtualized 5,000 rules / 2,000 connections × rapid Esc modal transitions with `0` horizontal overflows, `0` height mismatches, and `0` console errors.
2. **Windows Go Core (`core/`, v0.8.23)**:
   - Linux `go vet ./...` (0 issues), Windows amd64 `go vet -tags desktop ./...` (0 issues), and full `go test -race -count=1 ./...` across all **27** Go packages passed (`0` failed, `0` data race);
   - Shared packages `internal/{ss,anytls,udpmmsg}` verified `0 diff` byte-identical with `Kat-Server v0.8.4`.
3. **Rust Host & Packaging (`app/src-tauri/`)**:
   - `RUSTFLAGS="-D warnings" cargo test --offline --locked` passed all **319** tests (`0` failed, `0` warnings);
   - `build-windows.sh` cross-compiled all 5 Windows x64 host binaries pinned to Core v0.8.23 + verified official Wintun DLL;
   - Pinned NSIS 3.11 uninstaller capture + Ed25519 (`0afa646ee76f17d8`) offline dual-signature product verification gate (schema 1 + schema 2, 22 files) passed; online update manifests verified with product `update_manifest::verify`.
