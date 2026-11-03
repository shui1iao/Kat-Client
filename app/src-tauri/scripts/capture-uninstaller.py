#!/usr/bin/env python3
"""NSIS !uninstfinalize hook: retain the exact generated uninstall image, do not execute it."""
from pathlib import Path
import sys,shutil
source,target=map(Path,sys.argv[1:]);assert source.is_file() and source.read_bytes()[:2]==b'MZ';target.parent.mkdir(exist_ok=True,parents=True);shutil.copy2(source,target)
