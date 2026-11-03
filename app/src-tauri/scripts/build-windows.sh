#!/bin/sh
set -eu
. /opt/kat-windows-toolchain-20261027/env.sh
cd /opt/kat-windows-client-20261028/app/src-tauri
python3 scripts/verify-vendor.py
python3 "$KAT_WINDOWS_TOOLCHAIN/tools/run-guard.py" "kat-host-build-$(date +%s)" cargo xwin build --release --locked --target x86_64-pc-windows-msvc --features desktop --bin kat-desktop --bin kat-network-service --bin kat-proxy-watchdog -j2
