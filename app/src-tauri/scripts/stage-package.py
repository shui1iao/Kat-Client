#!/usr/bin/env python3
"""Prepare an unsigned fixed payload, or archive an already signed and validated payload. No key access."""
import argparse
import hashlib
import importlib.util
import io
import runpy
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import zipfile
from package_inputs import ASSETS, AUTH, SETUP_AUTH, ROLES, ROOT, app_version, gate, limit, require, snapshot, transfer


def bridge_descriptor(revision, hashes):
    # Keep the exact v0.2.28 wire format. No full-Setup-only fields here.
    return {'schema': 1, 'product': 'kat-client-package', 'key_id': '0afa646ee76f17d8', 'os': 'windows', 'arch': 'amd64',
            'app_version': app_version(), 'stdio_protocol': 1, 'service_protocol': 1, 'record_schema': 2, 'workspace_schema': 1,
            'source_revision': revision, 'components': {n: hashes[n] for n in ROLES}}


def prepare(a):
    require(re.fullmatch(r'(?:[0-9a-f]{40}|[0-9a-f]{64})', a.source_revision), 'full release source revision required')
    receipt = {}
    for line in (a.bin_dir/'role-hashes.txt').read_text().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([a-z-]+\.exe)', line)
        require(match and match[2] not in receipt, 'invalid build role receipt')
        receipt[match[2]] = match[1]
    require(set(receipt) == set(ROLES), 'incomplete build role receipt')
    a.payload.mkdir(mode=0o700)  # New directory only; never overlay a prior signed package.
    (a.payload/'network').mkdir()
    inputs = {name: ROOT/'distribution'/name for name in ASSETS}
    inputs.update({name: ROOT/'vendor'/name for name in ASSETS if name.startswith('network/')})
    inputs.update({name: a.bin_dir/name for name in ROLES})
    inputs.update({'kat-client-core.exe': a.core, 'Kat-Uninstall.exe': a.uninstaller, 'BUILD-IDENTITY.json': a.build_identity,
                   'YAML-README.md': a.docs_dir/'YAML.md', 'kat-client.example.yaml': a.docs_dir/'kat-client.example.yaml'})
    spec = importlib.util.spec_from_file_location('pe', ROOT/'scripts/inspect-pe.py')
    pe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pe)
    hashes = {}
    for name in ROLES + ASSETS:
        with (a.payload/name).open('xb') as out:
            hashes[name], _ = transfer(inputs[name], out, limit(name))
        if name in ROLES or name == 'Kat-Uninstall.exe':
            info = pe.inspect(a.payload/name)
            require(info['machine'] == 'AMD64' and (name == 'kat-client-core.exe' or info['subsystem'] == 'WINDOWS_GUI'), 'wrong PE role: ' + name)
        if name in receipt:
            require(receipt[name] == hashes[name], 'role differs from pinned build inputs: ' + name)
    build_id = json.loads((a.payload/'BUILD-IDENTITY.json').read_bytes())
    for name in ('kat-desktop.exe', 'kat-client-core.exe'):
        require(build_id['executables'][name] == hashes[name], 'build identity differs from final bytes: ' + name)
    auth = bridge_descriptor(a.source_revision, hashes)
    (a.payload/AUTH[0]).write_text(json.dumps(auth, indent=2) + '\n')
    print('Unsigned descriptor prepared. Issuer must sign its exact bytes and supply kat-package-auth.sig.')


def describe_setup(a):
    # The first signature is itself an installed file, so its exact bytes must exist
    # BEFORE we describe/sign Setup. Never regenerate it after this point.
    raw = io.BytesIO(); sig = io.BytesIO()
    ipc_hash, _ = transfer(a.payload/AUTH[0], raw, limit(AUTH[0]))
    sig_hash, _ = transfer(a.payload/AUTH[1], sig, limit(AUTH[1]))
    issuer_schema = runpy.run_path(str(ROOT/'scripts/sign-update-manifest.py'))['validate']
    issuer_schema(raw.getvalue(), 'package')
    require(re.fullmatch(rb'[0-9a-f]{128}(?:\r?\n)?', sig.getvalue()), 'invalid detached IPC signature format')
    bridge = json.loads(raw.getvalue())
    require(bridge['app_version'] == app_version(), 'wrong IPC release version')
    for name in ROLES:
        require(transfer(a.payload/name, maximum=limit(name))[0] == bridge['components'][name], 'role changed: ' + name)
    assets = {name: transfer(a.payload/name, maximum=limit(name))[0] for name in ASSETS}
    assets.update({AUTH[0]: ipc_hash, AUTH[1]: sig_hash})
    setup = {'schema': 2, 'product': 'kat-client-setup', 'bridge': bridge, 'assets': assets}
    data = (json.dumps(setup, indent=2) + '\n').encode()
    issuer_schema(data, 'setup')
    with (a.payload/SETUP_AUTH[0]).open('xb') as out:
        out.write(data)
    print('Unsigned full Setup authorization prepared. Both signatures remain mandatory at the build and installer gates.')


def archive(a):
    with tempfile.TemporaryDirectory(prefix='.kat-archive-', dir=a.output.absolute().parent) as tmp:
        tmp = Path(tmp)
        stage = tmp/'Kat-Client-Windows-x64'
        rows = snapshot(a.payload, stage)
        gate(stage, tmp/'validator.json')
        # Archive-only license/source inputs are never installed or selected by Setup.
        for source, dest in ((ROOT/'distribution/licenses-rust', 'licenses-rust'), (ROOT/'distribution/corresponding-source', 'corresponding-source'),
                             (ROOT/'vendor/network/licenses', 'network/licenses')):
            for f in sorted(source.rglob('*')):
                require(not f.is_symlink(), 'unexpected link in license/source tree')
                if f.is_file():
                    n = str(Path(dest)/f.relative_to(source)); path = stage/n; path.parent.mkdir(exist_ok=True, parents=True)
                    shutil.copyfile(f, path)
                    rows.append({'path': n, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'bytes': path.stat().st_size})
        (stage/'PACKAGE-SHA256.json').write_text(json.dumps(sorted(rows, key=lambda row: row['path']), indent=2) + '\n')
        with zipfile.ZipFile(tmp/'package.zip', 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as z:
            for p in sorted(stage.rglob('*')):
                if p.is_file():
                    z.write(p, Path(stage.name)/p.relative_to(stage))
        os.link(tmp/'package.zip', a.output)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    p = sub.add_parser('prepare')
    for name in ('bin-dir', 'core', 'uninstaller', 'docs-dir', 'build-identity', 'payload'):
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--source-revision', required=True)
    p = sub.add_parser('describe-setup'); p.add_argument('--payload', type=Path, required=True)
    p = sub.add_parser('archive'); p.add_argument('--payload', type=Path, required=True); p.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    {'prepare': prepare, 'describe-setup': describe_setup, 'archive': archive}[args.action](args)
