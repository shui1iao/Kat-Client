#!/usr/bin/env python3
"""Offline, two independent NSIS compilations: capture once BEFORE signing; embed the signed bytes without regeneration."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from package_inputs import ROOT, FILES, INPUTS, APP, RUNTIME, app_version, gate, require, snapshot, transfer

DEBS = {'nsis_3.11-1_amd64.deb': 'e6eb6ffb70f0df09e95dedb2d2cf55ad3c2679f7c2ae357d0c00cc4c83178690',
        'nsis-common_3.11-1_all.deb': '103a3284c1a5356efa0aba90fdfc391c3cde8e7df8726377cef0f98471584047'}


def build(args, tmp):
    tree = tmp/'toolchain'
    for name, expected in DEBS.items():
        with (tmp/name).open('xb') as out:
            actual, _ = transfer(args.nsis_debs/name, out)
        require(actual == expected, 'unapproved NSIS toolchain: ' + name)
        subprocess.run(['dpkg-deb', '-x', str(tmp/name), str(tree)], check=True)
    env = dict(os.environ, NSISDIR=str(tree/'usr/share/nsis'), SOURCE_DATE_EPOCH='1793232000')
    version = app_version() + '.0'
    shutil.copyfile(ROOT/'scripts/Kat-Setup.nsi', tmp/'Kat-Setup.nsi')
    shutil.copyfile(ROOT/'icons/icon.ico', tmp/'icon.ico')
    cmd = [str(tree/'usr/bin/makensis'), '-NOCD', '-V3', '-DOUTPUT=Setup.exe', '-DICON=icon.ico',
           '-XVIProductVersion ' + version, '-XVIAddVersionKey /LANG=2052 "ProductName" "Kat"',
           '-XVIAddVersionKey /LANG=2052 "ProductVersion" "' + version + '"',
           '-XVIAddVersionKey /LANG=2052 "FileVersion" "' + version + '"']
    capture = args.action == 'capture'
    if capture:
        shutil.copyfile(ROOT/'scripts/capture-uninstaller.py', tmp/'capture-uninstaller.py')
        cmd += ['-DCAPTURE_ONLY', '-DPAYLOAD_SIZE_KIB=0', '-DCAPTURE_SCRIPT=capture-uninstaller.py', '-DUNINSTALLER_TEMPLATE=Kat-Uninstall.exe']
    else:
        rows = snapshot(args.payload, tmp/'payload')
        gate(tmp/'payload', tmp/'gate.json')
        lines = []
        for name in INPUTS:
            parent, _, leaf = name.rpartition('/')
            out = '$PLUGINSDIR\\payload' + ('\\' + parent if parent else '')
            lines += ['SetOutPath "' + out + '"', 'File /oname=' + leaf + ' "payload/' + name + '"']
        (tmp/'payload.nsh').write_text('\n'.join(lines) + '\n')
        kib = sum((r['bytes'] + 1023)//1024 for r in rows if r['path'] in FILES)
        cmd += ['-DPAYLOAD_INCLUDE=payload.nsh', '-DPAYLOAD_SIZE_KIB=' + str(kib)]
    subprocess.run(cmd + ['Kat-Setup.nsi'], env=env, cwd=tmp, check=True)
    src = tmp/('Kat-Uninstall.exe' if capture else 'Setup.exe')
    require(src.is_file() and src.stat().st_size > 0, 'missing NSIS output')
    if not capture:
        report = {'technology': 'NSIS 3.11 offline', 'sha256': transfer(src, maximum=1024**3)[0], 'bytes': src.stat().st_size,
                  'payload': rows, 'installed_payload_count': len(FILES), 'app_file_count': len(APP), 'runtime_file_count': len(RUNTIME),
                  'required_space_kib': kib, 'toolchain_debs': DEBS, 'validator': json.loads((tmp/'gate.json').read_bytes())}
        with Path(str(args.output)+'.build.json').open('x') as f:
            json.dump(report, f, indent=2)
    # Build in the output filesystem; publish only a completed artifact, without overwriting.
    os.link(src, args.output)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    for mode in ('capture', 'pack'):
        p = sub.add_parser(mode)
        p.add_argument('--nsis-debs', type=Path, required=True)
        p.add_argument('--output', type=Path, required=True, help='new artifact in trusted build directory')
        if mode == 'pack':
            p.add_argument('--payload', type=Path, required=True, help='fully staged and signed package')
    args = parser.parse_args()
    args.output = args.output.absolute()
    args.output.parent.mkdir(exist_ok=True, parents=True)
    with tempfile.TemporaryDirectory(prefix='.kat-nsis-', dir=args.output.parent) as tmp:
        build(args, Path(tmp))
