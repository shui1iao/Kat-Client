# Validation: Kat-Client v0.2.24 / Windows Core v0.8.15

- Sequence: `1794905000` (client) / `1794902000` (core)
- Core source fingerprint: `04a81276f5f663a48f9cfb4fac548cf4950f207d0c9df3893e0069736d3f7a8e` (matches Windows Core v0.8.15 byte-for-byte)
- Frontend: `npx tsc --noEmit` & `npm run build` passed (0 errors)
- Rust host tests: `cargo test --offline --locked --lib` (`276 passed; 0 failed; 1 ignored`) and `--test control-contract` (`12 passed; 0 failed`)
- Offline UI visual & layout checks: Chromium Playwright verified `1040×680` & `1180×800` (light/dark) with 0 runtime errors, 0 vertical overflow on overview, `0.00px` label shift on top-bar switches, and equal-height subscription cards
- Offline package gate: `kat-package-validator` (`update_manifest::verify_package`, key `0afa646ee76f17d8`) passed prior to NSIS 3.11 packaging
