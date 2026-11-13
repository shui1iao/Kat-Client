# Validation: Kat-Client v0.2.4 / Windows Core v0.8.3

## Release gate

Final same-source native Go regression on Linux passed across internal/clientdiag, internal/route, internal/kernel, internal/clientcore, internal/procattr and internal/tunstack: 487 top-level tests passed, 0 failed, 31 existing optional/private-input/platform/E2E tests skipped. Skipped cases are not counted as passed.

Rust native library tests: 276 passed, 0 failed, 1 ignored. Native control contract tests: 11 passed. Portable NSIS completion/name policy: 7 passed; read-line policy: 8 passed.

Frontend TypeScript/Vite release build, Windows cross-compilation of all six roles, peer SHA binding, actual Rust product verify_package gate, Ed25519 package/online-manifest signatures, NSIS assembly and public download hashes are recorded in build identities and release receipts.

## Windows runtime benchmark & acceptance

The exact candidate logic was also installed and validated on a controlled Windows 11 x64 environment via the real desktop NSIS Setup wizard and real Session 1 UAC confirmation:
- Both local HTTP system proxy (7890, direct in-process kernel routing) and TUN (198.18.0.1, gVisor + Wintun) passed health and 60-cell multi-protocol TCP/UDP verification (SOCKS5, SS2017, SS2022, Trojan, AnyTLS) with 100% UDP burst delivery and preserved 15-day traffic history and ACLs.
- Anonymous media service unlock signals reflect only public entry responses and do not guarantee account login, playback, conversation or payment availability. Production Linux server nodes remain on v0.8.1 and are not modified by this release.

Versions: Client0.2.4 / WindowsCore0.8.3; online sequence1794300038. Exact core source fingerprint and binary hashes are in BUILD-IDENTITY.json and SOURCE-MANIFEST.json.
