#!/usr/bin/env python3
import hashlib,json,struct
from pathlib import Path
root=Path(__file__).resolve().parents[1]/"vendor/network"
m=json.loads((root/"manifest.json").read_text())
for file,key in [("wintun-0.14.1.zip","wintun_zip_sha256"),("wintun.dll","wintun_dll_sha256"),("tun2socks-windows-amd64.zip","tun2socks_zip_sha256"),("tun2socks.exe","tun2socks_exe_sha256")]:
 b=(root/file).read_bytes();assert hashlib.sha256(b).hexdigest()==m[key],file
 if file.endswith((".exe",".dll")):
  offset=struct.unpack_from("<I",b,0x3c)[0];assert b[offset:offset+4]==b"PE\0\0";assert struct.unpack_from("<H",b,offset+4)[0]==0x8664
  if file=="wintun.dll":
   optional=offset+24;assert struct.unpack_from("<H",b,optional)[0]==0x20b
   cert,sz=struct.unpack_from("<II",b,optional+112+4*8);assert cert and sz and b[cert+8:cert+9]==b"\x30", "Supplier Authenticode certificate table missing"
for n in ["WINTUN-LICENSE.txt","TUN2SOCKS-LICENSE.txt","THIRD-PARTY-NOTICES.txt","licenses/manifest.json"]:assert (root/n).stat().st_size>0
if "kat_patch_sha256" in m:
 assert hashlib.sha256((root/m["kat_patch"]).read_bytes()).hexdigest()==m["kat_patch_sha256"]
 assert hashlib.sha256((root/m["rollback"]/"tun2socks.exe").read_bytes()).hexdigest()==m["tun2socks_upstream_exe_sha256"]
print("PASS: pinned vendor/controlled Kat patch SHA256, upstream rollback, x64 PE, Wintun certificate table and licenses")
print("Certificate-table presence is NOT WinVerifyTrust runtime validation; Windows chain verification remains pending.")
