# Validation: Kat-Client 0.2.26 / Windows Core 0.8.17

- Sequence: `1794907000` (client `1794907000`, core `1794907000`)
- Core source fingerprint: `e50829b80230520a3566e15992e98e9a995d4899be7e5239ace568a7541229b5`
- Go Core tests: `provider`, `outbound/group`, `route`, `kernel`, `clientcore` all passed (including `TestAirportClashLargeSubscriptionImport` covering 80-member groups, 1500 inline rules, duplicate members, `fallback` tolerance, `select` probe hints, `REJECT-DROP`, and emoji node names).
- Rust Host tests: `r1_r2_regression_tests` (6 passed) and `control-contract` (12 passed, `DISPLAY_VERSION == "0.2.26"`).
- Frontend build: `tsc --noEmit -p . && node build.mjs` passed; 1200x860 Light & Dark Chromium renders visually verified.
- Package gate: offline Ed25519 signature (`0afa646ee76f17d8`) verified by product `update_manifest::verify_package` before NSIS packaging.
- Real-machine Windows WebView2 runtime check was not executed on this Linux build host.
