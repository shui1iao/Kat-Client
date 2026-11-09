#!/usr/bin/env python3
from pathlib import Path
import json,hashlib,struct
root=Path(__file__).resolve().parents[1]/'vendor/network'
m=json.loads((root/'manifest.json').read_text())
for n,k in [('wintun-0.14.1.zip','wintun_zip_sha256'),('wintun.dll','wintun_dll_sha256')]:assert hashlib.sha256((root/n).read_bytes()).hexdigest()==m[k],n
b=(root/'wintun.dll').read_bytes();p=struct.unpack_from('<I',b,0x3c)[0];assert b[p:p+4]==b'PE\0\0'and struct.unpack_from('<H',b,p+4)[0]==0x8664 and struct.unpack_from('<H',b,p+24)[0]==0x20b
cert_offset,cert_bytes=struct.unpack_from('<II',b,p+24+112+4*8);assert cert_offset>0 and cert_bytes>0 and cert_offset+cert_bytes<=len(b)
assert (root/'WINTUN-LICENSE.txt').stat().st_size>0 and (root/'THIRD-PARTY-NOTICES.txt').stat().st_size>0
assert not(root/'tun2socks.exe').exists()
print('PASS: unchanged official Wintun zip/DLL SHA256, AMD64 PE32+, certificate table, license; external bridge absent')
print('Certificate table is not Windows WinVerifyTrust runtime validation; no Windows execution.')
