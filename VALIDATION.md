# Validation: Kat-Client v0.2.33 / Windows Core v0.8.20

- Client version: `0.2.33` (`client_sequence`: `1795550000`, previous `0.2.32` / `1795535000`)
- Windows Core version: `0.8.20` (`core_sequence`: `1795549000`, previous `0.8.19` / `1795524000`)
- Core source fingerprint: `39587687863267dbd2a86b38e25f315530fec46b4b159132e0dc18bfd56d15f5`

## Automated Gates Passed
1. **Windows Go Core (`core/`)**: Linux `go vet ./...` (0 issues), Windows amd64 `go vet -tags desktop ./...` (0 issues), full `go test -race -count=1` across all Go packages + `gvisor.dev/gvisor/pkg/buffer` (0 failed, 0 data race, including `TestMMDBTableCoalesceAndBoundaries`, `TestParseGeoIPAndGeositePruned`, `TestCopyAdaptiveDemotesAndPromotes`), and Windows amd64 `go build -tags desktop` succeeded.
2. **Rust Host (`app/src-tauri/`)**: `cargo test --offline --locked` (325 passed, 0 failed, 2 ignored, including `core_memory_breakdown_keeps_only_numeric_fields`), `build-windows.sh` (all 5 Windows x64 binaries pinned to Core v0.8.20 + Wintun verified), pinned NSIS 3.11 uninstaller capture + final `Kat-Setup-x64.exe` offline dual-signature product verification gate (schema 1 + schema 2, 22 files) passed.
3. **Frontend (`app/`)**: Unchanged from verified v0.2.32 production bundle (`app/src/` diff empty).
4. **Online Update Gate**: Product `update_manifest::verify` verifies `0.2.32 -> 0.2.33` (`Newer`), `0.2.33 -> 0.2.33` (`Current`), `0.8.19 -> 0.8.20` (`Newer`), and `0.8.20 -> 0.8.20` (`Current`).
