#!/usr/bin/env python3
"""Assemble only an explicit, controller-supplied actual core. No mock/fallback binary."""
from pathlib import Path
import sys,shutil,json,hashlib,zipfile,importlib.util
root=Path(__file__).resolve().parents[1]
if len(sys.argv)!=2:raise SystemExit("usage: stage-package.py /absolute/controller/actual/kat-client-core.exe")
core=Path(sys.argv[1]);assert core.is_absolute() and core.is_file()
spec=importlib.util.spec_from_file_location("pe",root/"scripts/inspect-pe.py");pe=importlib.util.module_from_spec(spec);spec.loader.exec_module(pe)
assert pe.inspect(core)["machine"]=="AMD64"
target=Path("/opt/kat-windows-toolchain-20261027/cache/target/x86_64-pc-windows-msvc/release")
stage=root/"distribution/Kat-Client-Windows-x64";stage.mkdir(exist_ok=True)
for n in ["kat-desktop.exe","kat-network-service.exe","kat-proxy-watchdog.exe","kat-install-helper.exe"]:
 src=target/n;assert pe.inspect(src)["subsystem"]=="WINDOWS_GUI";shutil.copy2(src,stage/n)
shutil.copy2(core,stage/"kat-client-core.exe")
for n in ["kat-package-auth.json","kat-package-auth.sig"]:
 src=root/"distribution"/n
 assert src.is_file(), "Signed package identity must be generated from final component bytes first"
 shutil.copy2(src,stage/n)
network=stage/"network";network.mkdir(exist_ok=True)
for n in ["tun2socks.exe","wintun.dll","WINTUN-LICENSE.txt","TUN2SOCKS-LICENSE.txt","THIRD-PARTY-NOTICES.txt","manifest.json","tun2socks-buildinfo.txt"]:shutil.copy2(root/"vendor/network"/n,network/n)
for n in ["README-WINDOWS.txt","Restore-User-Proxy.cmd","RUST-THIRD-PARTY-NOTICES.txt","THIRD-PARTY-SOURCE.zip","GO-THIRD-PARTY-NOTICES.txt"]:shutil.copy2(root/"distribution"/n,stage/n)
for src,name in [(root.parents[1]/"core/docs/client/YAML.md","YAML-README.md"),(root.parents[1]/"core/docs/client/kat-client.example.yaml","kat-client.example.yaml"),(root/"distribution/FRONTEND-THIRD-PARTY-NOTICES.txt","FRONTEND-THIRD-PARTY-NOTICES.txt"),(root/"distribution/BUILD-IDENTITY.json","BUILD-IDENTITY.json")]:
 assert src.is_file();shutil.copy2(src,stage/name)
for n in ["licenses-rust","corresponding-source"]:shutil.copytree(root/"distribution"/n,stage/n,dirs_exist_ok=True)
shutil.copytree(root/"vendor/network/licenses",network/"licenses",dirs_exist_ok=True)
manifest=[]
for p in sorted(stage.rglob("*")):
 if p.is_file() and p.name!="PACKAGE-SHA256.json":manifest.append({"path":str(p.relative_to(stage)),"sha256":hashlib.sha256(p.read_bytes()).hexdigest(),"bytes":p.stat().st_size})
(stage/"PACKAGE-SHA256.json").write_text(json.dumps(manifest,indent=2))
archive=root/"distribution/Kat-Client-Windows-x64.zip"
with zipfile.ZipFile(archive,"w",compression=zipfile.ZIP_DEFLATED,compresslevel=6)as z:
 for p in sorted(stage.rglob("*")):
  if p.is_file():z.write(p,Path(stage.name)/p.relative_to(stage))
print(json.dumps({"package":str(archive),"sha256":hashlib.sha256(archive.read_bytes()).hexdigest(),"bytes":archive.stat().st_size,"files":len(manifest)},indent=2))
