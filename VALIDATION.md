# Validation: Kat-Client 0.2.25 / Windows Core 0.8.16

- Sequence: `1794906000` (client `1794906000`, core `1794906000`)
- Core source fingerprint: `1ddd03e186b08e6d094c7b512be745c94deb601f23f005f9d7ada26e78af7697`
- Independent review: GPT-6.2 Sol two-round independent review passed with zero release blockers.
- Go Core tests: `go test ./internal/kernel/... ./internal/route/... ./internal/clientcore/... -count=1` passed (including `TestSniffOverridePublicIPDirectGroupAndProxyZeroExtraDNS` verifying 0 extra DNS on direct rule, strategy group -> `direct` leaf, and proxy outbound with sniff override).
- Rust Host tests: `r1_r2_regression_tests` (6 passed) and `control-contract` (`DISPLAY_VERSION == "0.2.25"`) passed.
- Frontend build: `tsc --noEmit -p . && node build.mjs` passed.
- Package gate: offline Ed25519 signature (`0afa646ee76f17d8`) verified by product `update_manifest::verify_package` before NSIS packaging.
- Real-machine Windows WebView2 runtime check was not executed on this Linux build host.
