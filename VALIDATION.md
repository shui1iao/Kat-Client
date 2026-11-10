# Validation: Kat-Client v0.2.3 / Windows Core v0.8.2

## Release gate

Final same-source native Go regression on Linux passed for internal/clientdiag, internal/route, internal/kernel and internal/clientcore: 477 top-level tests passed, 0 failed, 31 existing optional/private-input/platform/E2E tests skipped. Skipped cases are not counted as passed and no new skip was added to hide the discovered UDP failure.

The existing 0.2.2 SOCKS5 native UDP output dead branch was reproduced before the fix and corrected by deleting one redundant else-if line; the three original failing wire/DNS/relay regressions and a new closed-socket / oversized-datagram boundary test passed after the fix. TCP and tun_udp.go paths were not modified. Historical fixture/assertion migrations preserved cancellation, pending-cache lifetime, cursor and non-disclosure checks; no additional product behavior changes were introduced for those migrations.

Rust native library tests: 259 passed, 0 failed, 1 ignored. Native control contract tests: 11 passed. Portable NSIS completion/name policy: 7 passed; read-line policy: 8 passed. These portable/source-contract tests are not Windows installer execution.

Frontend TypeScript/Vite release build, Windows cross-compilation of all six roles, peer SHA binding, actual Rust product verify_package gate, Ed25519 package/online-manifest signatures, NSIS assembly and public download hashes are recorded separately in build identities and release receipts. A compiler or signature success is not described as runtime test success.

## Runtime boundary

The candidate was also measured through an isolated same-source Linux core and real proxy nodes, with the actual frontend rendered through a loopback IPC bridge. The media results were NOT seven successes: one available result, region-denial signals, a challenge, an unknown redirect, and two items blocked before target access by Linux process-attribution limitations. Detailed private configuration, node names, URLs and private screenshots are deliberately not included in public source or attachments.

No native Windows installation, UAC, finish-page launch, TUN/data-plane performance or native acrylic visual acceptance was performed in this release task. Bero and production Linux nodes were not upgraded by it. Anonymous service signals do not guarantee account, conversation, purchase or playback functionality.

Versions: Client0.2.3 / WindowsCore0.8.2; online sequence1794300003. Exact core source fingerprint and binary hashes are in BUILD-IDENTITY.json and SOURCE-MANIFEST.json.
