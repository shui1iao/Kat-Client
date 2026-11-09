from local_harness import *
import importlib.util,time,ssl,json,socketserver,threading
spec=importlib.util.spec_from_file_location('b4',ROOT/'tools/batch4-matrix.py');b4=importlib.util.module_from_spec(spec);spec.loader.exec_module(b4);apps=b4.apps
class NoTarget(socketserver.BaseRequestHandler):
    def handle(self):
        self.server.count+=1;self.request.settimeout(2)
        try:self.request.recv(1024)
        except OSError:pass
@contextlib.contextmanager
def delayed_hello(upstream):
    listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen();listener.settimeout(.1);stop=threading.Event();active=[];threads=[]
    def one(a,b):
        def up():
            try:
                first=a.recv(65536);time.sleep(2.2);b.sendall(first)
                while True:
                    data=a.recv(65536)
                    if not data:break
                    b.sendall(data)
            except OSError:pass
            finally:
                try:b.shutdown(socket.SHUT_WR)
                except OSError:pass
        t=threading.Thread(target=up);t.start()
        try:
            while True:
                data=b.recv(65536)
                if not data:break
                a.sendall(data)
        except OSError:pass
        finally:
            try:a.shutdown(socket.SHUT_RDWR)
            except OSError:pass
            a.close();b.close();t.join()
    def run():
        while not stop.is_set():
            try:a,_=listener.accept()
            except TimeoutError:continue
            except OSError:break
            b=socket.create_connection((upstream.rsplit(':',1)[0],int(upstream.rsplit(':',1)[1])),2);active.extend([a,b]);t=threading.Thread(target=one,args=(a,b));threads.append(t);t.start()
    t=threading.Thread(target=run);t.start()
    try:yield '127.0.0.1:'+str(listener.getsockname()[1])
    finally:
        stop.set();listener.close();t.join()
        for c in active:
            try:c.shutdown(socket.SHUT_RDWR)
            except OSError:pass
            c.close()
        for t in threads:t.join(timeout=4);assert not t.is_alive()
def main():
    results=[]
    with tempfile.TemporaryDirectory(dir=ROOT/'.tmp') as td:
        d=pathlib.Path(td);cert=d/'ca.crt';key=d/'ca.key';subprocess.run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1','-addext','basicConstraints=critical,CA:TRUE'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        kp=subprocess.check_output([str(ROOT/'.interop/xray'),'x25519'],text=True);private=kp.split('PrivateKey: ')[1].splitlines()[0];public=kp.split('Password (PublicKey): ')[1].splitlines()[0]
        target=TCP(('127.0.0.1',0),NoTarget);target.count=0;th=threading.Thread(target=target.serve_forever);th.start();address='127.0.0.1:'+str(target.server_address[1])
        try:
            with b4.http_target(cert,key,ssl.TLSVersion.TLSv1_3,True) as decoy:
                for name in ['bad-uuid','empty-flow-tcp-for-vision','bad-public-key','bad-sni','bad-shortid','stale-time','bad-client-version','ws-wrong-path','ws-wrong-host','grpc-wrong-service']:
                    mode='reality' if name in ('bad-public-key','bad-sni','bad-shortid','stale-time','bad-client-version') else 'tls';kind='ws' if name.startswith('ws-') else 'grpc' if name.startswith('grpc-') else 'raw';flow='xtls-rprx-vision' if kind=='raw' else ''
                    inbound={'protocol':'vless','users':[{'uuid':b4.UUID,'flow':flow}]};record={'case':name}
                    if mode=='reality':inbound['reality']={'private_key':private,'short_ids':['0100000000000000'],'server_names':['localhost'],'local_decoy':decoy,'decoy_ca':str(cert),'max_time_diff':'1s' if name=='stale-time' else '1m'}
                    else:inbound['tls']={'cert':str(cert),'key':str(key)}
                    if kind!='raw':inbound['transport']={'type':kind,'path':'/tunnel','host':'localhost','service_name':'vt' if kind=='grpc' else ''}
                    if name=='bad-client-version':inbound['reality']['min_client_version']='/v7+' # 254.254.254
                    dd=d/name;dd.mkdir();before=target.count
                    with b4.kernel(inbound,record) as front:
                        with (delayed_hello(front) if name=='stale-time' else contextlib.nullcontext(front)) as endpoint:
                            port=apps.chooseport();cfg=b4.nodecfg('xray',endpoint,port,cert,mode,public,flow,kind)
                            user=cfg['outbounds'][0]['settings']['vnext'][0]['users'][0];st=cfg['outbounds'][0]['streamSettings']
                            if name=='bad-uuid':user['id']='11111111-1111-4111-8111-111111111111'
                            if name=='empty-flow-tcp-for-vision':user['flow']=''
                            if name=='bad-public-key':st['realitySettings']['publicKey']=base64.urlsafe_b64encode(b'\x42'*32).decode().rstrip('=')
                            if name=='bad-sni':st['realitySettings']['serverName']='wrong.invalid'
                            if name=='bad-shortid':st['realitySettings']['shortId']='02'
                            if name=='ws-wrong-path':st['wsSettings']['path']='/wrong'
                            if name=='ws-wrong-host':st['wsSettings']['host']='wrong.invalid'
                            if name=='grpc-wrong-service':st['grpcSettings']['serviceName']='wrong'
                            with apps.client('xray',cfg,dd) as (proc,log):
                                apps.ready(port,proc)
                                rejected=False
                                try:apps.tcpcheck(port,address)
                                except Exception:rejected=True
                                assert rejected,(name,'unexpected success')
                    time.sleep(.03);assert target.count==before,(name,'unauthenticated target dial',target.count-before);record['status']='REJECTED_NO_TARGET';results.append(record);print(json.dumps(record),flush=True)
        finally:target.shutdown();target.server_close();th.join()
    (ROOT/'docs/batch4-negatives.json').write_text(json.dumps(results,indent=2)+'\n')
if __name__=='__main__':main()
