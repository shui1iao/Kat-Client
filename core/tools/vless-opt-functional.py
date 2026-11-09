"""Bounded functional checks, not Vision/REALITY/HTTP throughput benchmarking."""
from local_harness import *
import importlib.util,ssl,time
spec=importlib.util.spec_from_file_location('b4',ROOT/'tools/batch4-matrix.py');b4=importlib.util.module_from_spec(spec);spec.loader.exec_module(b4);apps=b4.apps
# Smaller valid payload for HTTP/HTTPS integrity and an actual inner TLS handshake.
b4.PAYLOAD=bytes(range(256))*768
ART=pathlib.Path(os.environ.get('VLESS_FUNCTION_ARTIFACT_DIR',str(ROOT/'docs/vless-opt-20261018')));PREFIX=os.environ.get('VLESS_FUNCTION_PREFIX','candidate');rows=[];ORD='31004faa-7f59-47a6-8cbe-012345678901'
def cfg_uuid(cfg,app,value):
 if app=='sing-box':cfg['outbounds'][0]['uuid']=value
 elif app=='mihomo':cfg['proxies'][0]['uuid']=value
 else:cfg['outbounds'][0]['settings']['vnext'][0]['users'][0]['id']=value

def two_udp(port,a,b):
 c,bound=apps.socks(port,'0.0.0.0:0',3);u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.bind(('127.0.0.1',0));u.settimeout(4)
 try:
  if bound[0]=='0.0.0.0':bound=('127.0.0.1',bound[1])
  for i,dst in enumerate([a,b,a]):
   payload=b'ordinary-two-target-'+bytes([i])*79;u.sendto(b'\0\0\0'+apps.addrwire(dst)+payload,bound);got,_=u.recvfrom(2048);assert got[4:10]==apps.addrwire(dst)[1:] and got[10:]==payload,('target',dst,'actual_source',got[4:10].hex(),'expected',apps.addrwire(dst)[1:].hex(),'payload_equal',got[10:]==payload)
 finally:u.close();c.close()

def record(row):
 print(json.dumps(row,ensure_ascii=False),flush=True);rows.append(row);(ART/f'{PREFIX}-VLESS-targets.json').write_text(json.dumps(rows,indent=2,ensure_ascii=False)+'\n')
with tempfile.TemporaryDirectory(dir=ROOT/'.tmp') as td:
 d=pathlib.Path(td);cert=d/'ca.crt';key=d/'ca.key'
 subprocess.run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1','-addext','basicConstraints=critical,CA:TRUE'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 kp=subprocess.check_output([str(ROOT/'.interop/xray'),'x25519'],text=True);private=kp.split('PrivateKey: ')[1].splitlines()[0];public=kp.split('Password (PublicKey): ')[1].splitlines()[0]
 with b4.http_target(cert,key) as http,b4.http_target(cert,key,ssl.TLSVersion.TLSv1_3) as https13,b4.http_target(cert,key,ssl.TLSVersion.TLSv1_2) as https12,b4.http_target(cert,key,ssl.TLSVersion.TLSv1_3,True) as decoy,udp() as u1,udp() as u2:
  for app in ['sing-box','mihomo','xray']:
   if os.environ.get('ONLY_CMD2'):continue
   row={'case':'ordinary-only','app':app,'security':'trusted TLS1.3','flow':'','client':'complete application, no library codec'};dd=d/('plain-'+app);dd.mkdir();inbound={'protocol':'vless','users':[{'uuid':b4.UUID}],'tls':{'cert':str(cert),'key':str(key)}}
   try:
    with b4.kernel(inbound,row) as front:
     port=apps.chooseport();cfg=b4.nodecfg(app,front,port,cert,'tls',public,'','raw')
     # Pin outer TLS13 where app has a version setting (server supports12 too).
     if app=='sing-box':cfg['outbounds'][0]['tls'].update(min_version='1.3',max_version='1.3')
     if app=='xray':cfg['outbounds'][0]['streamSettings']['tlsSettings'].update(minVersion='1.3',maxVersion='1.3')
     with apps.client(app,cfg,dd,cone_disabled=False) as (proc,log):
      apps.ready(port,proc);two_udp(port,u1,u2);row['default_XUDP_two_targets_same_control']='PASS exact 3 payloads/source'
      for dst,version,name in [(http,None,'HTTP'),(https13,ssl.TLSVersion.TLSv1_3,'HTTPS13'),(https12,ssl.TLSVersion.TLSv1_2,'HTTPS12')]:b4.httpcheck(port,dst,cert,version);row[name]='PASS 196608 exact bytes upload+download'
      with tcp('server-first:') as greeting:
       c,_=apps.socks(port,greeting);assert apps.readn(c,13)==b'server-first:';c.sendall(b'proof');assert apps.readn(c,5)==b'proof';c.close()
      row['server_first']='PASS'
    row['status']='PASS'
   except Exception as e:
    row.update(status='FAIL',error=repr(e))
    if (dd/'client.log').exists():row['app_log']=(dd/'client.log').read_text()[-2000:]
   record(row)
  # Explicit command2 vs default XUDP, TLS12 outer compatibility, complete SB.
  for case in ['explicit-cmd2','outer-TLS12']:
   row={'case':case,'app':'sing-box','listener':'ordinary-only'};dd=d/case;dd.mkdir()
   try:
    with b4.kernel({'protocol':'vless','users':[{'uuid':b4.UUID}],'tls':{'cert':str(cert),'key':str(key)}},row) as front:
     port=apps.chooseport();cfg=apps.appcfg('sing-box','vless',front,b4.UUID,port,cert,tlsmode=True)
     if case=='outer-TLS12':cfg['outbounds'][0]['tls'].update(min_version='1.2',max_version='1.2')
     with apps.client('sing-box',cfg,dd) as (proc,log):apps.ready(port,proc);b4.httpcheck(port,http,cert,None);apps.udpcheck(port,u1);apps.udpcheck(port,u2)
    row.update(status='PASS',TCP='196608-byte HTTP upload+download exact',UDP='cmd2 fixed target: two separate associations/destinations, exact 3 packets each')
   except Exception as e:row.update(status='FAIL',error=repr(e))
   record(row)
  # Only a few correctness probes, no Vision throughput table. Mixed listener
  # MUST retain old gate for BOTH users before knowing the authenticated flow.
  for case,mode,flows in [('vision-only','tls',['xtls-rprx-vision']),('mixed','tls',['','xtls-rprx-vision']),('REALITY-ordinary','reality',['']),('REALITY-Vision','reality',['xtls-rprx-vision'])]:
   if os.environ.get('ONLY_CMD2'):continue
   row={'case':case,'app':'xray','mode':mode,'flows':flows};dd=d/case;dd.mkdir()
   users=[{'uuid':b4.UUID,'flow':'xtls-rprx-vision' if 'Vision' in case or case=='vision-only' else ''}]
   if case=='mixed':users=[{'uuid':ORD,'flow':''},{'uuid':b4.UUID,'flow':'xtls-rprx-vision'}]
   inbound={'protocol':'vless','users':users}
   if mode=='tls':inbound['tls']={'cert':str(cert),'key':str(key)}
   else:inbound['reality']={'private_key':private,'short_ids':['0100000000000000'],'server_names':['localhost'],'local_decoy':decoy,'decoy_ca':str(cert)}
   try:
    with b4.kernel(inbound,row) as front:
     for i,flow in enumerate(flows):
      sub=dd/str(i);sub.mkdir();port=apps.chooseport();cfg=b4.nodecfg('xray',front,port,cert,mode,public,flow,'raw')
      if case=='mixed' and flow=='':cfg_uuid(cfg,'xray',ORD)
      with apps.client('xray',cfg,sub,cone_disabled=False) as (proc,log):apps.ready(port,proc);b4.httpcheck(port,https13,cert,ssl.TLSVersion.TLSv1_3);two_udp(port,u1,u2)
    if any(flows):assert row.get('diagnostics',{}).get('vision_read_direct',0)>0 and row['diagnostics'].get('vision_write_direct',0)>0,('no bidirectional innerTLS direct',row)
    row.update(status='PASS',functional_bytes='196608 per flow, actual innerTLS13',gate='retained; direct proof only for Vision flow')
   except Exception as e:row.update(status='FAIL',error=repr(e))
   record(row)
 # Complete application trust/identity rejection for the new ordinary path.
 wrong=d/'wrong-ca.crt';wrongkey=d/'wrong-ca.key'
 subprocess.run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-keyout',str(wrongkey),'-out',str(wrong),'-days','1','-subj','/CN=wrong-ca','-addext','basicConstraints=critical,CA:TRUE'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 class NoTarget(socketserver.BaseRequestHandler):
  def handle(self):self.server.count+=1
 target=TCP(('127.0.0.1',0),NoTarget);target.count=0;worker=threading.Thread(target=target.serve_forever);worker.start();address='127.0.0.1:'+str(target.server_address[1])
 try:
  for bad in ['bad-ca','bad-sni','bad-uuid']:
   row={'case':'ordinary-'+bad,'app':'sing-box','listener':'ordinary-only'};dd=d/bad;dd.mkdir();before=target.count
   try:
    with b4.kernel({'protocol':'vless','users':[{'uuid':b4.UUID}],'tls':{'cert':str(cert),'key':str(key)}},row) as front:
     port=apps.chooseport();cfg=b4.nodecfg('sing-box',front,port,cert,'tls',public,'','raw');node=cfg['outbounds'][0]
     if bad=='bad-ca':node['tls']['certificate_path']=str(wrong)
     if bad=='bad-sni':node['tls']['server_name']='wrong.invalid'
     if bad=='bad-uuid':node['uuid']='11111111-1111-4111-8111-111111111111'
     with apps.client('sing-box',cfg,dd) as (proc,log):
      apps.ready(port,proc);rejected=False
      try:apps.tcpcheck(port,address)
      except Exception:rejected=True
      assert rejected,'invalid trust/identity unexpectedly succeeded'
    assert target.count==before,('invalid trust/identity dialed target',target.count-before)
    row.update(status='PASS',target_accepts=target.count-before,result='REJECTED_NO_TARGET')
   except Exception as e:row.update(status='FAIL',error=repr(e))
   record(row)
 finally:target.shutdown();target.server_close();worker.join()
fail=[r for r in rows if r['status']!='PASS'];print('VLESS_FOCUSED_FUNCTIONAL',len(rows),'FAILURES',len(fail),flush=True);raise SystemExit(bool(fail))
