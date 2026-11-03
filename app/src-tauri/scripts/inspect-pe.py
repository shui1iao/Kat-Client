#!/usr/bin/env python3
import struct,json,hashlib,sys
from pathlib import Path
def inspect(p):
 b=p.read_bytes();pe=struct.unpack_from("<I",b,0x3c)[0];assert b[pe:pe+4]==b"PE\0\0"
 machine,n=struct.unpack_from("<HH",b,pe+4);size=struct.unpack_from("<H",b,pe+20)[0];opt=pe+24;assert machine==0x8664;assert struct.unpack_from("<H",b,opt)[0]==0x20b
 subsystem=struct.unpack_from("<H",b,opt+68)[0];sections=[]
 for i in range(n):
  pos=opt+size+i*40;virtual_size,virtual,raw_size,raw=struct.unpack_from("<IIII",b,pos+8);sections.append((virtual,max(virtual_size,raw_size),raw))
 def at(rva):
  for virtual,size,raw in sections:
   if virtual<=rva<virtual+size:return raw+rva-virtual
  raise ValueError("invalid RVA")
 imports=[];rva,_=struct.unpack_from("<II",b,opt+112+8)
 if rva:
  pos=at(rva)
  while any(b[pos:pos+20]):
   name_rva=struct.unpack_from("<I",b,pos+12)[0];start=at(name_rva);imports.append(b[start:b.index(b"\0",start)].decode("ascii"));pos+=20
 return {"file":p.name,"sha256":hashlib.sha256(b).hexdigest(),"bytes":len(b),"machine":"AMD64","subsystem":{2:"WINDOWS_GUI",3:"WINDOWS_CUI"}.get(subsystem,subsystem),"imports":imports}
if __name__=="__main__":print(json.dumps([inspect(Path(p))for p in sys.argv[1:]],indent=2))
