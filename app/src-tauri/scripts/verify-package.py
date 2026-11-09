#!/usr/bin/env python3
"""Fail-closed offline build gate invoking the product's actual Rust verify_package."""
from pathlib import Path
import argparse,subprocess,os,json,hashlib,fcntl,sys,time
p=argparse.ArgumentParser();p.add_argument('--manifest',type=Path,required=True);p.add_argument('--signature',type=Path,required=True);p.add_argument('--receipt',type=Path,required=True);a=p.parse_args()
S=Path(__file__).resolve().parents[1];tool=S/'tools/package-validator/Cargo.toml'
target=Path(os.environ.get('CARGO_TARGET_DIR',str(S/'target'))).resolve();target.mkdir(parents=True,exist_ok=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
env=dict(os.environ,CARGO_NET_OFFLINE='true',CARGO_BUILD_JOBS='2')
host=next(l.split(': ',1)[1]for l in subprocess.check_output(['rustc','-vV'],text=True).splitlines()if l.startswith('host: '))
with (target/'.candidate-build.lock').open('a')as lock:
 fcntl.flock(lock,fcntl.LOCK_EX)
 subprocess.run(['cargo','build','--offline','--locked','--release','--manifest-path',str(tool),'--target',host,'-j2'],check=True,env=env)
 binary=target/host/'release/kat-package-validator';cmd=[str(binary),str(a.manifest.resolve()),str(a.signature.resolve())]
 start=time.time_ns();r=subprocess.run(cmd,check=True,text=True,capture_output=True,env=env);result=json.loads(r.stdout)
 assert result['result']=='passed'and result['validator']=='product update_manifest::verify_package'
 assert result['manifest_sha256']==sha(a.manifest)and result['signature_sha256']==sha(a.signature)
 assert result['validator_source_sha256']==sha(S/'src/update_manifest.rs')
 result.update({'command':cmd,'exit_code':r.returncode,'validator_binary_sha256':sha(binary),'passed_at_unix_ns':time.time_ns(),'started_at_unix_ns':start,'tool_cargo_lock_sha256':sha(tool.parent/'Cargo.lock'),'offline':True,'target_flock':str(target/'.candidate-build.lock'),'before_nsis':True})
 a.receipt.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n');print(json.dumps(result,ensure_ascii=False))
