# Validation: Kat-Client v0.2.34 (Windows Core v0.8.21)

- Client sequence: `1795630000`
- Windows Core sequence: `1795629000`
- Core source fingerprint: `624ff4ff10f4aa83f86ec85145945aacb02d460c245a5d2fd420e19ab6ece93f`
- Companion Linux Server: `v0.8.3`

## Automated Gates Passed
1. **Windows Go Core (`core/`, zero gVisor)**: Linux `go vet ./...` (0 issues), Windows amd64 `go vet -tags desktop ./...` (0 issues), full `go test -race -count=1 ./...` across all 25 Go packages (0 failed, 0 data race, including `TestSystemStackNATRFC1624AndAdmissionRST`, `TestUDPPathMTUDiscoveryIPv4AndIPv6`, `TestMmapIndexHotLoadAndInvalidation`, `TestUDPGSOAndGRORoundTrip`), and Windows amd64 `go build -tags desktop` succeeded (`15,430,656 B`).
2. **Rust Host (`app/src-tauri/`)**: `cargo test --offline --locked` (all unit + contract + supervisor tests passed, 0 failed, including `tun_tcp_rule_matches_windows_com_canonical_readback_and_lifecycle`), `build-windows.sh` (all 5 Windows x64 host binaries pinned to Core v0.8.21 + Wintun verified), pinned NSIS 3.11 uninstaller capture + final `Kat-Setup-x64.exe` offline dual-signature product verification gate (schema 1 + schema 2, 22 files) passed.
3. **Real Hardware Benchmarks (3-round alternating medians)**:
   - Win11 181ms Wintun TUN: AnyTLS 4-stream download 1,702.7 Mbps (peak 1,747.7 Mbps, 1.76 s/GB), upload 994.8 Mbps (peak 1,001.0 Mbps), UDP 99.7%, idle 30s WorkingSet 2.7 MiB; SS2022 4-stream download 1,082.4 Mbps (peak 1,360.2 Mbps), upload 549.5 Mbps (peak 779.0 Mbps), UDP 99.4%, idle 30s WorkingSet 0.7 MiB.
   - 29,203 rules + 3 Geo DBs warm mmap startup: 18.0 ms, steady RSS 19.4 MiB (Go heap 4.4 MiB).
   - Linux UDP GSO/GRO (4-flow): SS2022 463.3 Mbps (48,716 pps, 100.0% delivery), AnyTLS UoT 440.6 Mbps (100.0% delivery); direct TCP `splice(2)` 23.3 / 35.2 Gbps.
