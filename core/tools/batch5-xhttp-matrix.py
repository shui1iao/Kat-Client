"""Fixed complete Xray/mihomo XHTTP -> CLI -> real local HTTP/HTTPS/UDP.
No VLESSX stage reads and no REALITY/Vision assertion in this batch."""
from local_harness import *
import importlib.util,sys,ssl
spec=importlib.util.spec_from_file_location('b4',ROOT/'tools/batch4-matrix.py');b4=importlib.util.module_from_spec(spec);spec.loader.exec_module(b4);apps=b4.apps
PROFILES=['packet-up','stream-up','stream-one','auto','packet-up-no-sse','stream-up-no-grpc','packet-up-split','stream-up-split']
def node(app,front,port,cert,alpn,mode,profile):
    cfg=apps.appcfg(app,'vless',front,b4.UUID,port,cert,tlsmode=True)
    if app=="xray":cfg["log"]["loglevel"]="debug"
    if app=='xray':
        out=cfg['outbounds'][0];out.pop('mux',None);st=out['streamSettings'];st['network']='xhttp';st['tlsSettings'].update(alpn=[alpn],minVersion='1.3')
        x={'path':'/xh','host':'localhost','mode':mode,'noSSEHeader':profile=='packet-up-no-sse','noGRPCHeader':profile=='stream-up-no-grpc','xmux':{'maxConnections':1}}
        st['xhttpSettings']=x
        if profile.endswith('-split'):
            h,p=front.rsplit(':',1);x['downloadSettings']={'address':h,'port':int(p),'network':'xhttp','security':'tls','tlsSettings':st['tlsSettings'],'xhttpSettings':{'path':'/xh','host':'localhost','xmux':{'maxConnections':1}}}
    else:
        n=cfg['proxies'][0];n.update(network='xhttp',alpn=[alpn]);x={'path':'/xh','host':'localhost','mode':mode,'reuse-settings':{'max-connections':'1'},'session-table':'uuid','no-grpc-header':profile=='stream-up-no-grpc'};n['xhttp-opts']=x
        if profile.endswith('-split'):
            h,p=front.rsplit(':',1);x['download-settings']={'server':h,'port':int(p),'tls':True,'servername':'localhost','alpn':[alpn],'path':'/xh','host':'localhost','reuse-settings':{'max-connections':'1'}}
    return cfg
def main():
    rows=[]
    with tempfile.TemporaryDirectory(dir=ROOT/'.tmp') as tmp:
        d=pathlib.Path(tmp);cert=d/'ca.crt';key=d/'ca.key';subprocess.run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1','-addext','basicConstraints=critical,CA:TRUE'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        with b4.http_target(cert,key) as http1,b4.http_target(cert,key,ssl.TLSVersion.TLSv1_3) as https13,udp() as u1,udp() as u2:
            for app in ['xray','mihomo']:
                for alpn in ['http/1.1','h2']:
                    for profile in PROFILES:
                        mode=profile.split('-no-')[0].removesuffix('-split');row={'app':app,'alpn':alpn,'profile':profile};label=f'{app}/{alpn}/{profile}'
                        if len(sys.argv)>1 and sys.argv[1] not in label:continue
                        inbound={'protocol':'vless','users':[{'uuid':b4.UUID}],'tls':{'cert':str(cert),'key':str(key)},'transport':{'type':'xhttp','path':'/xh/','host':'localhost','max_streams':16,'xhttp':{'alpn':[alpn],'mode':'auto','no_sse_header':profile=='packet-up-no-sse','pair_timeout':'5s','io_timeout':'8s'}}}
                        dd=d/str(len(rows));dd.mkdir()
                        try:
                            with b4.kernel(inbound,row) as front:
                                port=apps.chooseport();cfg=node(app,front,port,cert,alpn,mode,profile)
                                with apps.client(app,cfg,dd,cone_disabled=False) as (proc,log):
                                    apps.ready(port,proc)
                                    for target,version,name in [(http1,None,'HTTP'),(https13,ssl.TLSVersion.TLSv1_3,'HTTPS13')]:b4.httpcheck(port,target,cert,version);row[name]='PASS 1179648B upload+download'
                                    apps.udpcheck(port,u1);apps.udpcheck(port,u2);row['default_xudp']='PASS two destinations'
                                    with tcp('welcome') as target:
                                        c,_=apps.socks(port,target);assert apps.readn(c,7)==b'welcome';payload=bytes(range(251))*1195
                                        # Concurrent upload/download exercises full duplex, not request buffering.
                                        err=[]
                                        def send():
                                            try:c.sendall(payload)
                                            except Exception as e:err.append(str(e))
                                        th=threading.Thread(target=send);th.start();got=apps.readn(c,len(payload));th.join();assert not err and got==payload;c.close();row['server_first']='PASS 299945B duplex'
                            diag=row.get('diagnostics',{});assert diag.get('xhttp_h2' if alpn=='h2' else 'xhttp_h1',0)>0,('wrong HTTP version',diag)
                            selected='packet_up' if mode=='auto' else mode.replace('-','_');assert diag.get('xhttp_'+selected,0)>0,('wrong mode',diag);row['observed_mode']=selected;row['status']='PASS'
                        except Exception as e:
                            row['status']='FAIL';row['error']=str(e)
                            if (dd/'client.log').exists():row['app_log']=(dd/'client.log').read_text()[-2000:]
                        print(label,json.dumps(row,ensure_ascii=False),flush=True);rows.append(row)
        rows.append({'app':'sing-box','status':'NOT_SUPPORTED_BY_APP','reason':'fixed v1.14.3 V2Ray transport config has no xhttp outbound; not substituted with a library peer'})
        (ROOT/'docs/batch5-xhttp-app-matrix.json').write_text(json.dumps(rows,indent=2,ensure_ascii=False)+'\n');print('XHTTP_MATRIX',len(rows),'FAILURES',sum(r['status']=='FAIL' for r in rows),flush=True)
        return any(r['status']=='FAIL' for r in rows)
if __name__=='__main__':sys.exit(main())
