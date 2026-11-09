from local_harness import *
import importlib.util,sys,time
spec=importlib.util.spec_from_file_location('b4',ROOT/'tools/batch4-matrix.py');b4=importlib.util.module_from_spec(spec);spec.loader.exec_module(b4);apps=b4.apps
class CountEcho(socketserver.BaseRequestHandler):
    def handle(self):
        self.server.count+=1;self.request.settimeout(4)
        try:
            while True:
                data=self.request.recv(65536)
                if not data:break
                self.request.sendall(data)
        except OSError:pass
@contextlib.contextmanager
def target():
    s=TCP(('127.0.0.1',0),CountEcho);s.count=0;t=threading.Thread(target=s.serve_forever);t.start()
    try:yield s,'127.0.0.1:'+str(s.server_address[1])
    finally:s.shutdown();s.server_close();t.join()
def main():
    rows=[]
    with tempfile.TemporaryDirectory(dir=ROOT/'.tmp') as tmp:
        d=pathlib.Path(tmp);cert=d/'ca.crt';key=d/'ca.key';badcert=d/'wrong.crt';badkey=d/'wrong.key'
        for c,k in [(cert,key),(badcert,badkey)]:subprocess.run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-keyout',str(k),'-out',str(c),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1','-addext','basicConstraints=critical,CA:TRUE'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        for app in ['sing-box','mihomo']:
            for mode in ['default-empty','explicit','wrong-password','wrong-ca']:
                row={'app':app,'metadata_profile':mode};inbound={'protocol':'anytls','anytls':{'password':'fixture-password','max_streams':16},'tls':{'cert':str(cert),'key':str(key)}};dd=d/str(len(rows));dd.mkdir()
                with target() as (echo,dst),b4.kernel(inbound,row) as front:
                    port=apps.chooseport();cfg=apps.appcfg(app,'anytls',front,'wrong-fixture-password' if mode=='wrong-password' else 'fixture-password',port,badcert if mode=='wrong-ca' else cert,tlsmode=True)
                    n=cfg['outbounds'][0] if app=='sing-box' else cfg['proxies'][0];field='client_metadata' if app=='sing-box' else 'client-metadata';assert field not in n
                    if mode=='explicit':n[field]=f'{app}/explicit-test-version'
                    with apps.client(app,cfg,dd) as (proc,log):
                        apps.ready(port,proc);success=False
                        try:
                            c,_=apps.socks(port,dst)
                            try:payload=bytes(range(256))*256;c.sendall(payload);success=apps.readn(c,len(payload))==payload
                            finally:c.close()
                        except Exception:pass
                    if mode in ['default-empty','explicit']:assert success and echo.count==1,(row,'expected success',echo.count)
                    else:assert not success and echo.count==0,(row,'unauthenticated dial',echo.count)
                row['status']='PASS';row['target_accepts']=echo.count;row['client_metadata_configured']=mode=='explicit';rows.append(row);print(json.dumps(row),flush=True)
    (ROOT/'docs/batch5-anytls-metadata.json').write_text(json.dumps(rows,indent=2)+'\n')
if __name__=='__main__':main()
