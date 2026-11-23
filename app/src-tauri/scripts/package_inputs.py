"""Shared fixed build inventory. No recursive discovery of executable inputs."""
from pathlib import Path
import hashlib
import json
import os
import re
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def require(ok, message):
    if not ok:
        raise ValueError(message)


def inventory(filename, name):
    text = (ROOT / 'src' / filename).read_text().split('pub const ' + name + ':', 1)[1].split('];', 1)[0]
    names = tuple(re.findall(r'"([A-Za-z0-9./_-]+)"', text))
    require(names and len(set(names)) == len(names), 'invalid fixed installer inventory: ' + name)
    return names


AUTH = inventory('update_manifest.rs', 'BRIDGE_AUTH_FILES')
SETUP_AUTH = inventory('update_manifest.rs', 'SETUP_AUTH_FILES')
FILES = inventory('installer_files.rs', 'FILES')
INPUTS = FILES + SETUP_AUTH
require(len(set(INPUTS)) == len(INPUTS), 'Setup authority must not be installed')
APP = inventory('installer_files.rs', 'APP_FILES')
RUNTIME = inventory('installer_files.rs', 'RUNTIME_FILES')
ROLES = inventory('update_manifest.rs', 'PACKAGE_ROLES')
ASSETS = inventory('update_manifest.rs', 'PACKAGE_ASSETS')
require(sorted(APP + RUNTIME) == sorted(FILES) == sorted(ROLES + ASSETS + AUTH), 'inconsistent installer inventories')


def limit(name):
    return {AUTH[0]: 65536, SETUP_AUTH[0]: 65536, AUTH[1]: 130, SETUP_AUTH[1]: 130}.get(name, (128 if name in ROLES else 256) * 1024**2)


def transfer(src, dest=None, maximum=256 * 1024**2):
    """Read only one open regular file; copy/hash the same chunks, enforce the bound."""
    h = hashlib.sha256()
    with os.fdopen(os.open(src, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as f:
        info = os.fstat(f.fileno())
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= maximum, 'invalid build input: ' + str(src))
        size = 0
        while chunk := f.read(256 * 1024):
            size += len(chunk)
            require(size <= info.st_size, 'build input changed size')
            h.update(chunk)
            if dest is not None:
                dest.write(chunk)
        require(size == info.st_size, 'short build input')
    return h.hexdigest(), size


def snapshot(payload, dest):
    require(payload.is_dir() and not payload.is_symlink() and not (payload/'network').is_symlink(), 'invalid build payload root')
    dest.mkdir(mode=0o700)
    (dest/'network').mkdir()
    rows = []
    for name in INPUTS:
        with (dest/name).open('xb') as f:
            digest, size = transfer(payload/name, f, limit(name))
        rows.append({'path': name, 'sha256': digest, 'bytes': size})
    require(sum(row['bytes'] for row in rows) <= 1024**3, 'payload exceeds installer bound')
    return rows


def gate(payload, receipt):
    subprocess.run([sys.executable, str(ROOT/'scripts/verify-package.py'), '--manifest', str(payload/AUTH[0]),
                    '--signature', str(payload/AUTH[1]), '--receipt', str(receipt)], check=True)


def app_version():
    version = json.loads((ROOT/'tauri.conf.json').read_bytes())['version']
    cargo = re.search(r'^version\s*=\s*"([^"\n]+)"', (ROOT/'Cargo.toml').read_text().split('[lib]', 1)[0], re.M)
    require(cargo and cargo[1] == version, 'Cargo and Tauri release versions differ')
    return version
