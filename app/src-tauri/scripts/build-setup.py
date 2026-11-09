#!/usr/bin/env python3
"""Build the real offline x64 wizard with task-isolated, hash-pinned NSIS 3.11.
No install/deploy, global package manager, signing, publishing or network here.
"""
from pathlib import Path
import argparse,hashlib,json,os,re,subprocess,sys
R=Path(__file__).resolve().parents[3]
S=R/'app/src-tauri';E=R/'integration-evidence/comprehensive-20261029/native/setup-installer'
p=argparse.ArgumentParser();p.add_argument('--payload',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--uninstaller',type=Path,required=True);a=p.parse_args()
assert a.payload.is_absolute() and a.output.is_absolute() and a.uninstaller.is_absolute()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
# Final signed bytes must pass the product validator before any NSIS output.
subprocess.run([sys.executable,str(S/'scripts/verify-package.py'),'--manifest',str(a.payload/'kat-package-auth.json'),'--signature',str(a.payload/'kat-package-auth.sig'),'--receipt',str(a.output.parent/'REAL-VALIDATOR-GATE.json')],check=True)
T=E/'toolchain/nsis';expected={'nsis_3.11-1_amd64.deb':'e6eb6ffb70f0df09e95dedb2d2cf55ad3c2679f7c2ae357d0c00cc4c83178690','nsis-common_3.11-1_all.deb':'103a3284c1a5356efa0aba90fdfc391c3cde8e7df8726377cef0f98471584047'}
for n,h in expected.items():assert sha(T/n)==h,n
names=re.findall(r'"([^"]+)"',(S/'src/installer_files.rs').read_text().split('pub const FILES:')[1].split('];',1)[0])
assert len(names)==len(set(names)) and 'Kat-Uninstall.exe' in names
app_names=re.findall(r'"([^"]+)"',(S/'src/installer_files.rs').read_text().split('pub const APP_FILES:')[1].split('];',1)[0])
runtime_names=re.findall(r'"([^"]+)"',(S/'src/installer_files.rs').read_text().split('pub const RUNTIME_FILES:')[1].split('];',1)[0])
assert set(app_names).isdisjoint(runtime_names) and set(app_names)|set(runtime_names)==set(names)
rows=[];lines=[]
for name in names:
 if name=='Kat-Uninstall.exe':continue
 source=a.payload/name;assert source.is_file() and not source.is_symlink(),name
 rows.append({'path':name,'sha256':sha(source),'bytes':source.stat().st_size})
 parent=Path(name).parent
 out='$PLUGINSDIR\\payload'+(''if str(parent)=='.'else'\\'+str(parent).replace('/','\\'))
 lines+=['SetOutPath "'+out+'"','File /oname='+Path(name).name+' "'+str(source)+'"']
assert next(r for r in rows if r['path']=='kat-client-core.exe')['sha256']=='1271016b470f604da2ab3c99fbcbb8fcf13fbb72c40d4470210c525bee235a20'
E.mkdir(exist_ok=True);a.output.parent.mkdir(exist_ok=True,parents=True);a.uninstaller.parent.mkdir(exist_ok=True,parents=True)
inc=E/'payload.nsh';inc.write_text('\n'.join(lines)+'\n')
cmd=[str(T/'root/usr/bin/makensis'),'-V3','-DOUTPUT='+str(a.output),'-DICON='+str(S/'icons/icon.ico'),'-DPAYLOAD_INCLUDE='+str(inc),'-DCAPTURE_SCRIPT='+str(S/'scripts/capture-uninstaller.py'),'-DUNINSTALLER_TEMPLATE='+str(a.uninstaller),str(S/'scripts/Kat-Setup.nsi')]
app_version=json.loads((S/'tauri.conf.json').read_text())['version']
cmd[2:2]=['-XVIProductVersion '+app_version+'.0','-XVIAddVersionKey /LANG=2052 "ProductName" "Kat"','-XVIAddVersionKey /LANG=2052 "ProductVersion" "'+app_version+'.0"','-XVIAddVersionKey /LANG=2052 "FileVersion" "'+app_version+'.0"']
env=dict(os.environ,NSISDIR=str(T/'root/usr/share/nsis'),SOURCE_DATE_EPOCH='1793232000')
# Files are extracted in .onInit, outside the install section. Account for
# every installed app+Runtime file explicitly, including the protected
# future-update helper and signed package identity. Pass 1 captures the actual generated uninstaller size, pass 2 adds
# that exact size to the section shown on the directory page.
def payload_kib(uninstaller_bytes):
 return sum((r['bytes']+1023)//1024 for r in rows if r['path'] in names)+(uninstaller_bytes+1023)//1024
subprocess.run(cmd[:-1]+['-DPAYLOAD_SIZE_KIB='+str(payload_kib(0)),cmd[-1]],check=True,env=env)
first_uninstaller_bytes=a.uninstaller.stat().st_size
required_kib=payload_kib(first_uninstaller_bytes)
subprocess.run(cmd[:-1]+['-DPAYLOAD_SIZE_KIB='+str(required_kib),cmd[-1]],check=True,env=env)
assert a.output.is_file() and a.uninstaller.is_file()
assert a.uninstaller.stat().st_size==first_uninstaller_bytes, 'section sizing changed uninstaller bytes'
result={'technology':'NSIS 3.11-1 Debian amd64-unicode; ordinary-user UI, explicit fixed-helper UAC','installer':str(a.output),'sha256':sha(a.output),'bytes':a.output.stat().st_size,'uninstaller_template':{'path':str(a.uninstaller),'sha256':sha(a.uninstaller),'bytes':a.uninstaller.stat().st_size},'required_space_kib':required_kib,'required_space_basis':'per-file ceil KiB of actual installer_files App+Runtime roles, including helpers and package auth','installed_payload_count':len(names),'app_file_count':len(app_names),'runtime_file_count':len(runtime_names),'embedded_source_file_count':len(rows),'installed_update_helper':'kat-install-helper.exe','payload':rows,'toolchain_debs':expected,'source_date_epoch':env['SOURCE_DATE_EPOCH']}
(a.output.parent/(a.output.name+'.build.json')).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
