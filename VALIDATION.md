# Validation: Kat-Client v0.2.36 (Windows Core v0.8.22)

- Client sequence: `1795723000`
- Windows Core sequence: `1795722000`
- Core source fingerprint: `940bdd151404c4ecf8fbdc3b3fd6101bb063a12c0042e3594e9fdc6555ed8726`
- Companion Linux Server: `v0.8.3`

## Automated Gates Passed
1. **Frontend (`app/`)**: `tsc --noEmit -p .` (0 errors), `node tests-ui/run-unit.mjs` (152 / 152 unit & contract tests passed, 0 failed), production bundle `node build.mjs` succeeded, and Playwright headless Chromium visual & interaction audit across all 9 pages, popovers, modals, tray view, scroll edge-fade states, and sidebar glide (0 intermediate chart relayouts) passed with 0 console/page errors.
2. **Windows Go Core (`core/`, v0.8.22)**: Linux `go vet ./...` (0 issues), Windows amd64 `go vet -tags desktop ./...` (0 issues), full `go test -race -p 2 -parallel 2 -count=1 ./...` across all 25 Go packages (0 failed, 0 data race, including `TestSubscriptionValidationPromotesAndReusesMmap` and `TestBackgroundUpdateSwitchesToMmap`), and Windows amd64 `go build -tags desktop` succeeded (`15,458,304 B`, `WINDOWS_GUI` subsystem).
3. **Rust Host (`app/src-tauri/`)**: `cargo test --offline --locked` (326 / 326 unit + contract + diagnostic allowlist + supervisor tests passed, 0 failed), `build-windows.sh` (all 5 Windows x64 host binaries pinned to Core v0.8.22 + official Wintun verified), pinned NSIS 3.11 uninstaller capture + final `Kat-Setup-x64.exe` offline dual-signature product verification gate (schema 1 + schema 2, 22 files) passed.
