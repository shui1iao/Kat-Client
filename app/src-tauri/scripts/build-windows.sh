#!/bin/sh
# Issuer-selected release inputs. Build only; never sign or deploy.
set -eu
src=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
# env.sh sets shared defaults. Preserve the caller's isolated release locations.
requested_target=${CARGO_TARGET_DIR:?absolute release-specific Cargo target required}
requested_tmp=${TMPDIR:-}
case "$requested_target" in /*) ;; *) exit 2;; esac
. "${KAT_TOOLCHAIN_ENV:-/opt/kat-windows-toolchain-20261027/env.sh}"
cd "$src"
: "${KAT_CORE_EXE:?absolute final controller-supplied core}" "${KAT_CORE_SHA256:?expected release core SHA-256}"
: "${KAT_BUILD_BIN_DIR:?absolute NEW output directory}" "${KAT_INSTALL_CORE_VERSION:?approved core version}"
: "${KAT_INSTALL_CORE_SEQUENCE:?approved core sequence}" "${KAT_INSTALL_CLIENT_SEQUENCE:?approved client sequence}"
export CARGO_TARGET_DIR="$requested_target"
if [ -n "$requested_tmp" ]; then export TMPDIR="$requested_tmp"; fi
export KAT_INSTALL_CORE_VERSION KAT_INSTALL_CORE_SEQUENCE KAT_INSTALL_CLIENT_SEQUENCE
case "$KAT_BUILD_BIN_DIR" in /*) ;; *) exit 2;; esac
case "$KAT_CORE_EXE" in /*) ;; *) exit 2;; esac
hash() { sha256sum -- "$1" | cut -d' ' -f1; }
[ "$(hash "$KAT_CORE_EXE")" = "$KAT_CORE_SHA256" ]
python3 - <<'CHECK'
import os, re, runpy
version = runpy.run_path('scripts/sign-update-manifest.py')['version']
if not version(os.environ['KAT_INSTALL_CORE_VERSION']):
    raise SystemExit('stable release core version required')
for key in ('KAT_INSTALL_CORE_SEQUENCE', 'KAT_INSTALL_CLIENT_SEQUENCE'):
    seq = os.environ[key]
    if not re.fullmatch(r'[1-9][0-9]{0,19}', seq) or int(seq) >= 2**64:
        raise SystemExit('positive u64 sequence required: ' + key)
CHECK
mkdir -m 700 -- "$KAT_BUILD_BIN_DIR"
python3 scripts/verify-vendor.py
build() {
 python3 "$KAT_WINDOWS_TOOLCHAIN/tools/run-guard.py" "kat-host-build-$(date +%s)" cargo xwin build --release --locked --target x86_64-pc-windows-msvc --features desktop -j2 "$@"
}
# Preserve the exact first-pass binaries; never package by scanning a shared target/ directory.
unset KAT_INSTALL_APPROVED_SERVICE_SHA256 KAT_INSTALL_APPROVED_CLIENTS_SHA256
target=$CARGO_TARGET_DIR/x86_64-pc-windows-msvc/release
build --bin kat-desktop --bin kat-network-service --bin kat-proxy-watchdog --bin kat-elevate-helper
for n in kat-desktop kat-network-service kat-proxy-watchdog kat-elevate-helper; do cp -- "$target/$n.exe" "$KAT_BUILD_BIN_DIR/$n.exe"; done
KAT_INSTALL_APPROVED_SERVICE_SHA256=$(hash "$KAT_BUILD_BIN_DIR/kat-network-service.exe")
KAT_INSTALL_APPROVED_CLIENTS_SHA256=$(hash "$KAT_BUILD_BIN_DIR/kat-desktop.exe"):$KAT_CORE_SHA256:$(hash "$KAT_BUILD_BIN_DIR/kat-proxy-watchdog.exe"):$(hash "$KAT_BUILD_BIN_DIR/kat-elevate-helper.exe")
export KAT_INSTALL_APPROVED_SERVICE_SHA256 KAT_INSTALL_APPROVED_CLIENTS_SHA256 KAT_INSTALL_CORE_VERSION KAT_INSTALL_CORE_SEQUENCE KAT_INSTALL_CLIENT_SEQUENCE
build --bin kat-install-helper
cp -- "$target/kat-install-helper.exe" "$KAT_BUILD_BIN_DIR/kat-install-helper.exe"
# Staging checks these final bytes, including the actual helper and the controller-supplied core.
(cd "$KAT_BUILD_BIN_DIR" && sha256sum -- kat-*.exe && printf '%s  kat-client-core.exe\n' "$KAT_CORE_SHA256") > "$KAT_BUILD_BIN_DIR/role-hashes.txt"
