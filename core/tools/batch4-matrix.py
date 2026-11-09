"""Fixed complete apps -> CLI: local RAW/Vision/REALITY, default XUDP and HTTP transports.
Functional bounded tests, no kernel/peer codec import, no outside network."""
from local_harness import *
import importlib.util,struct,ssl,time,http.server,sys,hashlib
spec=importlib.util.spec_from_file_location('apps',ROOT/'tools/app-matrix.py');apps=importlib.util.module_from_spec(spec);spec.loader.exec_module(apps)
UUID='4a86ae32-2235-4dc3-b103-42a2d162d73c'
PAYLOAD=bytes(range(256))*4608 # 1,179,648 bytes each direction
class HTTPEcho(http.server.BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def do_POST(self):
        body=self.rfile.read(int(self.headers['Content-Length']));assert body==PAYLOAD,'target upload differs'
        self.send_response(200);self.send_header('Content-Length',str(len(body)));self.send_header('Connection','close');self.end_headers();self.wfile.write(body)
    def do_GET(self):
        self.send_response(200);self.send_header('Content-Length','7');self.send_header('Connection','close');self.end_headers();self.wfile.write(b'welcome')
    def log_message(self,*a):pass
@contextlib.contextmanager
def http_target(cert,key,version=None,decoy=False):
    h=http.server.ThreadingHTTPServer(('127.0.0.1',0),HTTPEcho);h.daemon_threads=True
    if version:
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(cert,key);ctx.minimum_version=version;ctx.maximum_version=version
        if decoy:ctx.set_alpn_protocols(['h2','http/1.1'])
        h.socket=ctx.wrap_socket(h.socket,server_side=True)
    t=threading.Thread(target=h.serve_forever);t.start()
    try:yield '127.0.0.1:'+str(h.server_port)
    finally:h.shutdown();h.server_close();t.join()
@contextlib.contextmanager
def kernel(inbound,record):
    with tempfile.TemporaryDirectory(dir=ROOT/'.tmp') as tmp:
        d=pathlib.Path(tmp);p=d/'core.json';p.write_text(json.dumps({'inbounds':[dict(inbound,listen='127.0.0.1:0')],'udp_bind_ipv4':'127.0.0.1','udp_bind_ipv6':'::1','limits':{'connections':32,'logical_streams':32,'handshakes':8,'dials':8,'udp_associations':8,'udp_queue':8,'udp_targets':8,'pool_buffers':8,'handshake_timeout':'10s','dial_timeout':'3s','drain_timeout':'3s','udp_idle':'3s'}}));p.chmod(0o600)
        exe=str(ROOT/'bin/proxy-kernel');check=subprocess.run([exe,'check',str(p)],capture_output=True,text=True);assert check.returncode==0,check.stderr
        c=subprocess.Popen([exe,'run',str(p)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=dict(os.environ,GOMAXPROCS='2',PROXY_KERNEL_TEST_DIAGNOSTICS='1'))
        try:
            assert select.select([c.stderr],[],[],25)[0],'CLI preflight timeout';line=c.stderr.readline().strip();assert line.startswith('listening '),line
            yield line.split()[1]
        finally:
            c.terminate()
            try:_,err=c.communicate(timeout=5)
            except subprocess.TimeoutExpired:c.kill();_,err=c.communicate(timeout=3)
            record['cli_exit']=c.returncode
            other_logs=[line for line in err.splitlines() if not line.startswith('{')]
            if other_logs:record['cli_error_log']='\n'.join(other_logs)[-2000:]
            for line in err.splitlines():
                try:
                    parsed=json.loads(line)
                    if 'vision_read_direct' in parsed:record['diagnostics']=parsed
                except ValueError:pass
            assert c.returncode==0,('core exit',c.returncode,err)
def nodecfg(app,server,port,cert,mode,public,flow,kind,ed=False,multi=False):
    cfg=apps.appcfg(app,'vless',server,UUID,port,cert,tlsmode=(mode!='plain'))
    if app=='sing-box':
        node=cfg['outbounds'][0];node['flow']=flow;node.pop('packet_encoding',None) # app default XUDP, not cmd2 override
        if mode=='reality':node['tls']={'enabled':True,'server_name':'localhost','utls':{'enabled':True,'fingerprint':'chrome'},'reality':{'enabled':True,'public_key':public,'short_id':'01'}}
        if kind!='raw':
            node['transport']={'type':kind,'path':'/tunnel','headers':{'Host':'localhost'}}
            if kind=='httpupgrade':node['transport']['host']='localhost'
            if kind=='grpc':node['transport']={'type':'grpc','service_name':'vt'}
            if kind=='ws' and ed:node['transport'].update(max_early_data=1024,early_data_header_name='Sec-WebSocket-Protocol')
        return cfg
    if app=='mihomo':
        node=cfg['proxies'][0];node['flow']=flow
        if mode=='reality':node.update(tls=True,servername='localhost',**{'client-fingerprint':'chrome','reality-opts':{'public-key':public,'short-id':'01'}})
        if kind!='raw':
            node['network']=kind
            if kind=='ws':node['ws-opts']={'path':'/tunnel','headers':{'Host':'localhost'}}
            elif kind=='httpupgrade':node['network']='ws';node['ws-opts']={'path':'/tunnel','headers':{'Host':'localhost'},'v2ray-http-upgrade':True}
            else:node['grpc-opts']={'grpc-service-name':'vt'}
            if kind=='ws' and ed:node['ws-opts'].update(**{'max-early-data':1024,'early-data-header-name':'Sec-WebSocket-Protocol'})
        return cfg
    out=cfg['outbounds'][0];out['settings']['vnext'][0]['users'][0]['flow']=flow;st=out['streamSettings']
    if mode=='reality':st.update(security='reality',realitySettings={'serverName':'localhost','fingerprint':'chrome','publicKey':public,'shortId':'01','spiderX':'/'});st.pop('tlsSettings',None)
    cfg['outbounds'][0].pop('mux',None)
    if kind!='raw':
        st['network']=kind
        if kind=='ws':st['wsSettings']={'path':'/tunnel'+('?ed=1024' if ed else ''),'host':'localhost'}
        elif kind=='httpupgrade':st['httpupgradeSettings']={'path':'/tunnel'+('?ed=1024' if ed else ''),'host':'localhost'}
        else:st['grpcSettings']={'serviceName':'vt','multiMode':multi}
    return cfg
def httpcheck(port,target,roots,version=None):
    c,_=apps.socks(port,target)
    try:
        if version:
            ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);ctx.load_verify_locations(roots);ctx.minimum_version=version;ctx.maximum_version=version
            c=ctx.wrap_socket(c,server_hostname='localhost');c.settimeout(8)
        # Give server/client handshake parsers actual TLS1.2/1.3 before bulk transfer.
        request=(f'POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: {len(PAYLOAD)}\r\nConnection: close\r\n\r\n').encode()
        c.sendall(request)
        if version==ssl.TLSVersion.TLSv1_3:
            time.sleep(.02);c.sendall(PAYLOAD[:1024]);time.sleep(.02);start=1024
        else:start=0
        for i in range(start,len(PAYLOAD),4096):c.sendall(PAYLOAD[i:i+4096])
        f=c.makefile('rb');status=f.readline();assert b' 200 ' in status,status
        while f.readline()!=b'\r\n':pass
        got=f.read(len(PAYLOAD));assert got==PAYLOAD,('download differs',len(got));f.close()
    finally:c.close()
def run():
    rows=[]
    with tempfile.TemporaryDirectory(dir=ROOT/'.tmp') as tmp:
        d=pathlib.Path(tmp);cert=d/'ca.crt';key=d/'ca.key'
        subprocess.run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1','-addext','basicConstraints=critical,CA:TRUE'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        kp=subprocess.check_output([str(ROOT/'.interop/xray'),'x25519'],text=True);private=kp.split('PrivateKey: ')[1].splitlines()[0];public=kp.split('Password (PublicKey): ')[1].splitlines()[0]
        combos=[('tls','raw',True,False,False),('reality','raw',False,False,False),('reality','raw',True,False,False),('tls','raw',False,False,False),('plain','ws',False,False,False),('plain','httpupgrade',False,False,False),('tls','ws',False,False,False),('tls','ws',False,True,False),('tls','httpupgrade',False,False,False),('tls','httpupgrade',False,True,False),('tls','grpc',False,False,False),('tls','grpc',False,False,True)]
        with http_target(cert,key,ssl.TLSVersion.TLSv1_3,decoy=True) as decoy,http_target(cert,key) as http1,http_target(cert,key,ssl.TLSVersion.TLSv1_3) as https13,http_target(cert,key,ssl.TLSVersion.TLSv1_2) as https12,udp() as u1,udp() as u2:
            for app in ['xray','sing-box','mihomo']:
                for mode,kind,vision,ed,multi in combos:
                    if app!='xray' and (multi or kind=='httpupgrade' and ed):continue
                    flow='xtls-rprx-vision' if vision else '';label=f'{app}/{mode}/{kind}/vision={vision}/ed={ed}/multi={multi}'
                    if len(sys.argv)>1 and sys.argv[1] not in label:continue
                    row={'app':app,'security':mode,'transport':kind,'vision':vision,'ed':ed,'multi':multi};inbound={'protocol':'vless','users':[{'uuid':UUID,'flow':flow}]}
                    if mode=='reality':inbound['reality']={'private_key':private,'short_ids':['0100000000000000'],'server_names':['localhost'],'local_decoy':decoy,'decoy_ca':str(cert)}
                    elif mode=='tls':inbound['tls']={'cert':str(cert),'key':str(key)}
                    if kind!='raw':inbound['transport']={'type':kind,'path':'/tunnel','host':'localhost','service_name':'vt' if kind=='grpc' else '', 'max_early_data':2048 if kind=='ws' and ed else 0}
                    dd=d/str(len(rows));dd.mkdir()
                    try:
                        with kernel(inbound,row) as front:
                            port=apps.chooseport();cfg=nodecfg(app,front,port,cert,mode,public,flow,kind,ed,multi)
                            with apps.client(app,cfg,dd,cone_disabled=False) as (proc,log):
                                apps.ready(port,proc)
                                # app default encoding, same client source -> 2 destinations
                                apps.udpcheck(port,u1);apps.udpcheck(port,u2);row['default_xudp_two_destinations']='PASS'
                                control,bound=apps.socks(port,'0.0.0.0:0',3);native=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);native.bind(('127.0.0.1',0));native.settimeout(4)
                                try:
                                    if bound[0]=='0.0.0.0':bound=('127.0.0.1',bound[1])
                                    for dst in [u1,u2,u1]:
                                        payload=b'same-association-two-targets';native.sendto(b'\0\0\0'+apps.addrwire(dst)+payload,bound);data,_=native.recvfrom(2048);assert data[4:10]==apps.addrwire(dst)[1:] and data[10:]==payload
                                    row['same_control_two_destinations']='PASS'
                                finally:native.close();control.close()
                                for target,version,name in [(http1,None,'HTTP'),(https13,ssl.TLSVersion.TLSv1_3,'HTTPS13'),(https12,ssl.TLSVersion.TLSv1_2,'HTTPS12')]:httpcheck(port,target,cert,version);row[name]='PASS 1179648B upload+download'
                                with tcp('welcome') as greeting:
                                    c,_=apps.socks(port,greeting);assert apps.readn(c,7)==b'welcome';c.sendall(b'first');assert apps.readn(c,5)==b'first';c.close()
                                row['server_first']='PASS'
                        if vision:assert row.get('diagnostics',{}).get('vision_read_direct',0)>0 and row['diagnostics'].get('vision_write_direct',0)>0,('Vision did not switch both directions',row)
                        if ed and kind=='ws':assert row.get('diagnostics',{}).get('http_early_data',0)>0,('no observed client ED',row)
                        row['status']='PASS'
                    except Exception as e:
                        row['status']='FAIL';row['error']=str(e)
                        if (dd/'client.log').exists():row['app_log']=(dd/'client.log').read_text()[-2500:]
                    rows.append(row);print(label,json.dumps(row,ensure_ascii=False),flush=True)
        (ROOT/'docs/batch4-app-matrix.json').write_text(json.dumps(rows,indent=2,ensure_ascii=False)+'\n');print('BATCH4_MATRIX',len(rows),'FAILURES',sum(r['status']=='FAIL' for r in rows),flush=True)
        return any(r['status']=='FAIL' for r in rows)
if __name__=='__main__':sys.exit(run())
