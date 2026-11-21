# Validation: Kat-Client v0.2.28 / Windows Core v0.8.17

- Client version: `0.2.28` (`client_sequence`: `1794909000`, previous `0.2.27` / `1794908000`)
- Windows Core version: `0.8.17` (`core_sequence`: `1794907000`, bit-identical SHA256 `9e4109a9ef400e2ee602879f76e3bc67f51b01b58c3fa0c3ae055667719c6bfa`, `core/` unchanged)

## Automated Checks
1. **Frontend Build & CSS Verification**: `npm run build` (`tsc --noEmit -p . && node build.mjs`) passed cleanly. Compiled `dist/assets/*.css` inspected directly: all 6 blur declarations retain standard unprefixed `backdrop-filter` (fixing the LightningCSS prefix-order stripping bug).
2. **Rust Host & Contract Tests**: `cargo test --offline --locked` full suite passed (279 lib tests + 12 `control_contract` + 1 `elevation_launch` + 23 `supervisor`, 0 failures), including real-process ordering tests covering both `planned_close_then_eof_suppresses_false_transport_error` and `unexpected_eof_before_terminate_retains_transport_error_evidence`.
3. **Windows x64 Cross-Build & Signing Gate**: All 6 Windows x64 binaries built cleanly (`cargo xwin build --offline --release --locked --target x86_64-pc-windows-msvc --features desktop`), signed with Ed25519 key `0afa646ee76f17d8`, and verified by product `kat-package-validator` (`update_manifest::verify_package`).
4. **Independent Review**: Reviewed by GPT-6.2-Astra across Rust DWM ABI (`acrylic.rs`), supervisor EOF ordering (`supervisor.rs` / `supervisor_pipe.rs`), handover waiting (`core_process.rs` / `safe_log.rs`), compiled CSS, popover layout alignment (`SideControls.tsx` / `shell.css`), and release metadata consistency. Note: Win11 desktop DWM compositing was statically and ABI-verified on Linux; visual previews were rendered in Chromium.
