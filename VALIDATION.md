# Validation: Kat-Client 0.2.27 (Built-in Windows Core 0.8.17)

- Client sequence: `1794908000`; Windows Core sequence: `1794907000` (Core v0.8.17 unchanged, bit-identical SHA256 `9e4109a9ef400e2ee602879f76e3bc67f51b01b58c3fa0c3ae055667719c6bfa`).
- Core source fingerprint: `e50829b80230520a3566e15992e98e9a995d4899be7e5239ace568a7541229b5`
- Independent review: GPT-6.2-Astra review passed (`通过（可发布）`) after resolving all P1/P2 layout, select-width, forced-colors, reduced-transparency, and 4K active-connections row-height findings.
- Rust Host tests: `r1_r2_regression_tests` (6 passed) and `control-contract` (12 passed, `DISPLAY_VERSION == "0.2.27"`).
- Frontend build: `tsc --noEmit -p . && node build.mjs` passed cleanly.
- Package gate: offline Ed25519 signature (`0afa646ee76f17d8`) verified by product `update_manifest::verify_package` before NSIS packaging.
- Real-machine Windows WebView2 native acrylic backdrop check was not executed on this Linux build host.
