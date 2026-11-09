"""Small complete-app functional tests, never a performance/load matrix."""
from local_harness import *
import importlib.util,struct,time,concurrent.futures,hashlib
spec=importlib.util.spec_from_file_location('apps',ROOT/'tools/app-matrix.py');apps=importlib.util.module_from_spec(spec);spec.loader.exec_module(apps)
ART=pathlib.Path(os.environ.get('SNELL_FUNCTION_ARTIFACT_DIR',str(ROOT/'docs/snell-opt-20261018')));prefix=os.environ.get('SNELL_FUNCTION_PREFIX','candidate');results=[]
class HalfCloseReply(socketserver.BaseRequestHandler):
 def handle(self):
  self.request.settimeout(5);got=b''
  while True:
   x=self.request.recv(4096)
   if not x:break
   got+=x
   if len(got)>16384:raise RuntimeError('unbounded input')
  if got!=HALF_INPUT:raise RuntimeError('target half-close bytes differ')
  self.request.sendall(HALF_REPLY)
HALF_INPUT=bytes(range(256))*17;HALF_REPLY=b'after-real-EOF:'+hashlib.sha256(HALF_INPUT).digest()+bytes(range(256))*1024
@contextlib.contextmanager
def half_target():
 s=TCP(('127.0.0.1',0),HalfCloseReply);th=threading.Thread(target=s.serve_forever);th.start()
 try:yield '127.0.0.1:'+str(s.server_address[1])
 finally:s.shutdown();s.server_close();th.join()
with tempfile.TemporaryDirectory(dir=ROOT/'.tmp') as temp:
 directory=pathlib.Path(temp);cert=directory/'fixture-ca.crt';key=directory/'fixture-ca.key'
 subprocess.run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1','-addext','basicConstraints=critical,CA:TRUE'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 for app in ['sing-box','mihomo']:
  for version in [4,5]:
   for obfs in ['none','http']:
    row={'app':app,'server_config_version':version,'client_wire_version':4,'obfs':obfs,'reuse':True,'client_class':'complete pinned application, not library peer'};d=directory/f'{app}-{version}-{obfs}';d.mkdir()
    try:
     inbound,secret=apps.spec('snell',obfs=obfs);inbound['snell']['version']=version
     with tcp() as target1,tcp() as target2,tcp('snell-server-first:') as first,half_target() as half,udp() as udp_target,core(inbound) as actual,apps.counting_bridge(actual) as (server,count):
      port=apps.chooseport();cfg=apps.appcfg(app,'snell',server,secret,port,cert,obfs=obfs)
      with apps.client(app,cfg,d) as (proc,log):
       apps.ready(port,proc);apps.tcpcheck(port,target1);time.sleep(.08);a=count();apps.tcpcheck(port,target2);time.sleep(.08);b=count();row['two_distinct_target_reuse_physical_TCP']=[a,b];assert a==b==1,('not physical reuse',a,b)
       row['TCP_two_targets']='PASS exact 2056 bytes each';apps.udpcheck(port,udp_target);row['UDP']='PASS 3x131 exact payload plus source address'
       c,_=apps.socks(port,first)
       try:
        assert apps.readn(c,len(b'snell-server-first:'))==b'snell-server-first:'
        large=bytes(range(256))*768;c.sendall(large);assert apps.readn(c,len(large))==large
       finally:c.close()
       row['server_first_large_response']='PASS initial 19 byte banner, then exact 196608-byte echo'
       c,_=apps.socks(port,half)
       try:
        c.sendall(HALF_INPUT);c.shutdown(socket.SHUT_WR);got=b''
        while True:
         x=c.recv(65536)
         if not x:break
         got+=x
         assert len(got)<=len(HALF_REPLY),'unexpected tail'
        assert got==HALF_REPLY,('half-close response mismatch',len(got),len(HALF_REPLY))
       finally:c.close()
       row['real_half_close_large_response']='PASS target waited for EOF then exact '+str(len(HALF_REPLY))+' response bytes'
       apps.tcpcheck(port,target1);row['post_halfclose_new_target']='PASS exact bytes, no stale tail'
     row['status']='PASS'
    except Exception as e:
     row['status']='FAIL';row['error']=repr(e)
     log=d/'client.log'
     if log.exists():row['app_log']=log.read_text()[-2500:]
    results.append(row);print(json.dumps(row,ensure_ascii=False),flush=True);(ART/f'{prefix}-Snell-complete-apps.json').write_text(json.dumps(results,indent=2,ensure_ascii=False)+'\n')
failed=[x for x in results if x['status']!='PASS'];print('SNELL_COMPLETE_APP_TUPLES',len(results),'FAILURES',len(failed),flush=True)
raise SystemExit(bool(failed))
