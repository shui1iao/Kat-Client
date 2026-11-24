# Validation: Kat-Client v0.2.31 / Windows Core v0.8.19

- Client version: `0.2.31` (`client_sequence`: `1795525000`, previous `0.2.30` / `1795500000`)
- Windows Core version: `0.8.19` (`core_sequence`: `1795524000`, previous `0.8.18` / `1795420000`)
- Core source fingerprint: `6a72464eba0bfbd8e568b474696ce6162f4ebe8ccc6b12308693dbdc50d763ea`

## Automated Gates Passed
1. **Frontend (`app/`)**: `npm run typecheck` (0 errors), `npm test` (152 passed, 0 failed), `npm run build` (standard `backdrop-filter` and `mask-image` verified), and headless Chromium visual verification of upper-center multi-IP floating toast and `+N` frosted popover in light/dark themes.
2. **Windows Go Core (`core/`)**: Linux `go vet ./...` (0 issues), Windows amd64 `go vet -tags desktop ./...` (0 issues), full `go test -race -count=1 ./...` across all 22 test packages (0 failed, 0 data race, including `TestDomainSetCompactParityAndMemoryReduction`), and Windows amd64 `go build -tags desktop` succeeded.
3. **Rust Host (`app/src-tauri/`)**: `cargo test --offline --locked` (324 passed, 0 failed, 2 ignored), `build-windows.sh` (all 5 Windows x64 binaries pinned to Core v0.8.19 + Wintun verified), pinned NSIS 3.11 uninstaller capture + final `Kat-Setup-x64.exe` offline dual-signature product verification gate (schema 1 + schema 2, 22 files) passed.
4. **Online Update Gate**: Product `update_manifest::verify` verifies `0.2.30 -> 0.2.31` (`Newer`), `0.2.31 -> 0.2.31` (`Current`), `0.8.18 -> 0.8.19` (`Newer`), and `0.8.19 -> 0.8.19` (`Current`).
