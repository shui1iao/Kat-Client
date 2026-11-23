#!/usr/bin/env python3
"""NSIS !uninstfinalize hook: capture exact bytes in the private seed build, never execute."""
from pathlib import Path
import shutil
import sys

source, target = map(Path, sys.argv[1:])
with source.open('rb') as f, target.open('xb') as out:
    if f.read(2) != b'MZ':
        raise ValueError('expected NSIS uninstaller image')
    out.write(b'MZ')
    shutil.copyfileobj(f, out)
