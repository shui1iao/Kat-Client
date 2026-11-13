# Validation: Kat-Client v0.2.7 / Windows Core v0.8.5

## Release gate

Final same-source native Go regression on Linux passed across internal/clientdiag, internal/route, internal/kernel, internal/clientcore, internal/procattr and internal/tunstack: 489 top-level tests passed, 0 failed, 31 existing optional/private-input/platform/E2E tests skipped. Skipped cases are not counted as passed.

Rust native library tests: 276 passed, 0 failed, 1 ignored. Native control contract tests: 11 passed. Portable NSIS completion/name policy: 7 passed; read-line policy: 8 passed.

Frontend TypeScript/Vite release build, Windows cross-compilation of all six roles, peer SHA binding, actual Rust product verify_package gate, Ed25519 package/online-manifest signatures, NSIS assembly and public download hashes are recorded in build identities and release receipts.

## Scope & runtime boundaries

- Retains the validated Windows 11 data-plane architecture (direct in-process HTTP proxy routing on 7890, gVisor + Wintun TUN stack, UDP tuple lease cache, AnyTLS/SS2022 buffer alignment) while adding parallel route resource loading, parallel startup before WebView2 creation, `--autostart` tray-only silent startup fix, and the redesigned `3:2` (`1080×720`) translucent Acrylic UI.
- Anonymous media service unlock signals reflect only public entry responses and do not guarantee account login, playback, conversation or payment availability. Production Linux server nodes remain on v0.8.1 and are not modified by this release.

Versions: Client0.2.7 / WindowsCore0.8.5; online sequence1794580000. Exact core source fingerprint and binary hashes are in BUILD-IDENTITY.json and SOURCE-MANIFEST.json.
