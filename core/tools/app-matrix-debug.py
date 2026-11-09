"""Complete pinned app -> built CLI -> real loopback TCP/UDP targets. No kernel imports."""
from local_harness import *
import struct,ssl,time,concurrent.futures,sys
METHODS=['aes-128-gcm','aes-256-gcm','chacha20-ietf-poly1305','2022-blake3-aes-128-gcm','2022-blake3-aes-256-gcm','2022-blake3-chacha20-poly1305']
def readn(c,n):
    b=b''
    while len(b)<n:
        v=c.recv(n-len(b))
        if not v:raise RuntimeError('unexpected EOF')
        b+=v
    return b
def addrwire(target):
    h,p=target.rsplit(':',1);return b'\x01'+socket.inet_aton(h)+struct.pack('!H',int(p))
def readaddr(c):
    typ=readn(c,1)[0]
    if typ==1:h=socket.inet_ntop(socket.AF_INET,readn(c,4))
    elif typ==4:h=socket.inet_ntop(socket.AF_INET6,readn(c,16))
    elif typ==3:h=readn(c,readn(c,1)[0]).decode()
    else:raise RuntimeError('bad address')
    return h,struct.unpack('!H',readn(c,2))[0]
def socks(port,target,cmd=1):
    c=socket.create_connection(('127.0.0.1',port),3);c.settimeout(4);c.sendall(b'\x05\x01\x00');assert readn(c,2)==b'\x05\x00'
    c.sendall(bytes([5,cmd,0])+addrwire(target));h=readn(c,3);assert h==b'\x05\x00\x00',('SOCKS reply',h);bound=readaddr(c);return c,bound
def tcpcheck(port,target):
    c,_=socks(port,target)
    try:
        p=b'app-tcp-'+b'x'*2048;c.sendall(p);assert readn(c,len(p))==p
    finally:c.close()
def udpcheck(port,target):
    c,b=socks(port,'0.0.0.0:0',3);u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.bind(('127.0.0.1',0));u.settimeout(4)
    try:
        if b[0]=='0.0.0.0':b=('127.0.0.1',b[1])
        for i in range(3):
            payload=b'app-udp-'+bytes([i])*123;u.sendto(b'\0\0\0'+addrwire(target)+payload,b);data,_=u.recvfrom(65535)
            # all chosen targets are IPv4, replies carry source and exact payload
            assert data[:4]==b'\0\0\0\1' and data[4:10]==addrwire(target)[1:] and data[10:]==payload,('UDP mismatch',data[:20])
    finally:u.close();c.close()
def chooseport():
    p=socket.socket();p.bind(('127.0.0.1',0));n=p.getsockname()[1];p.close();return n
def spec(proto,method=None,tlsmode=False,obfs='none'):
    if proto=='socks5':return {'protocol':proto,'users':[{'username':'appuser','password':'app-pass'}]},'app-pass'
    if proto=='shadowsocks':
        secret='app-ss-password';opts={'method':method,'password':secret}
        if method.startswith('2022-'):
            secret=base64.b64encode(bytes(range(16 if '128' in method else 32))).decode();opts={'method':method,'key':secret}
        return {'protocol':proto,'ss':opts},secret
    if proto=='trojan':return {'protocol':proto,'users':[{'password':'app-pass'}]},'app-pass'
    if proto=='vless':return {'protocol':proto,'users':[{'uuid':'4a86ae32-2235-4dc3-b103-42a2d162d73c'}]},'4a86ae32-2235-4dc3-b103-42a2d162d73c'
    if proto=='anytls':return {'protocol':proto,'anytls':{'password':'fixture-password','max_streams':16,'session_streams':8}},'fixture-password'
    if proto=='snell':return {'protocol':proto,'snell':{'version':4,'psk':'snell-core-fixture-psk','obfs':obfs}},'snell-core-fixture-psk'
def appcfg(app,proto,server,secret,port,cert,method=None,tlsmode=False,obfs='none'):
    host,p=server.rsplit(':',1);p=int(p)
    if app=='sing-box':
        node={'type':proto if proto!='socks5' else 'socks','tag':'node','server':host,'server_port':p}
        if proto=='socks5':node.update(version='5',username='appuser',password=secret)
        elif proto=='shadowsocks':node.update(method=method,password=secret)
        elif proto=='trojan' or proto=='anytls':node['password']=secret
        elif proto=='vless':node.update(uuid=secret,flow='',packet_encoding='')
        elif proto=='snell':node.update(version=4,psk=secret,reuse=True,obfs_mode='' if obfs=='none' else obfs,obfs_host='localhost')
        if tlsmode:node['tls']={'enabled':True,'server_name':'localhost','certificate_path':str(cert)}
        if proto=='anytls':node.update(min_idle_session=1,client_metadata='sing-box/1.14.3')
        return {'log':{'level':'error'},'inbounds':[{'type':'socks','tag':'local','listen':'127.0.0.1','listen_port':port}], 'outbounds':[node],'route':{'final':'node'}}
    if app=='mihomo':
        node={'name':'node','type':{'socks5':'socks5','shadowsocks':'ss'}.get(proto,proto),'server':host,'port':p,'udp':True}
        if proto=='socks5':node.update(username='appuser',password=secret)
        elif proto=='shadowsocks':node.update(cipher=method,password=secret)
        elif proto in ('trojan','anytls'):node.update(password=secret,sni='localhost')
        elif proto=='vless':node.update(uuid=secret,flow='',tls=tlsmode,servername='localhost')
        elif proto=='snell':node.update(psk=secret,version=4,reuse=True,**{'obfs-opts':{'mode':'' if obfs=='none' else obfs,'host':'localhost'}})
        if proto=='anytls':node['client-metadata']='mihomo/1.19.32';node['min-idle-session']=1
        if tlsmode:node['skip-cert-verify']=False
        return {'socks-port':port,'bind-address':'127.0.0.1','allow-lan':False,'mode':'rule','log-level':'error','ipv6':True,'geodata-mode':False,'geo-auto-update':False,'dns':{'enable':False},'profile':{'store-selected':False,'store-fake-ip':False},'tls':{'custom-certifactes':[cert.read_text()]},'proxies':[node],'rules':['MATCH,node']}
    stream={'network':'tcp','security':'none'}
    if tlsmode:stream.update(security='tls',tlsSettings={'serverName':'localhost','allowInsecure':False,'disableSystemRoot':True,'certificates':[{'certificateFile':str(cert),'usage':'verify'}]})
    if proto=='socks5':settings={'servers':[{'address':host,'port':p,'users':[{'user':'appuser','pass':secret}]}]};typ='socks'
    elif proto=='shadowsocks':settings={'servers':[{'address':host,'port':p,'method':method,'password':secret}]};typ='shadowsocks'
    elif proto=='trojan':settings={'servers':[{'address':host,'port':p,'password':secret}]};typ='trojan'
    else:settings={'vnext':[{'address':host,'port':p,'users':[{'id':secret,'encryption':'none','flow':''}]}]};typ='vless'
    return {'log':{'loglevel':'none'},'inbounds':[{'protocol':'socks','listen':'127.0.0.1','port':port,'settings':{'auth':'noauth','udp':True,'ip':'127.0.0.1'}}],'outbounds':[{'protocol':typ,'settings':settings,'streamSettings':stream,'mux':{'enabled':False}}]}
@contextlib.contextmanager
def client(app,cfg,d):
    path=d/'client.json';path.write_text(json.dumps(cfg));path.chmod(0o600);log=open(d/'client.log','w+')
    args=[str(ROOT/'.interop'/app)]
    if app=='sing-box':args+=['run','-c',str(path)]
    elif app=='mihomo':args+=['-d',str(d),'-f',str(path)]
    else:args+=['run','-config',str(path)]
    env=dict(os.environ,GOMAXPROCS='2',XRAY_CONE_DISABLED='true',DISABLE_SYSTEM_CA='true',DISABLE_EMBED_CA='true');env['xray.cone.disabled']='true'
    c=subprocess.Popen(args,stdout=log,stderr=log,env=env)
    try:
        yield c,log
    finally:
        c.terminate()
        try:c.wait(timeout=4)
        except subprocess.TimeoutExpired:c.kill();c.wait(timeout=2)
        log.close()
def ready(port,c):
    for _ in range(150):
        if c.poll() is not None:raise RuntimeError('app exited early')
        try:s=socket.create_connection(('127.0.0.1',port),.1);s.settimeout(.3);s.sendall(b'\x05\x01\x00');assert readn(s,2)==b'\x05\x00';s.close();return
        except OSError:time.sleep(.01)
    raise RuntimeError('app did not bind')
def main():
    results=[]
    with tempfile.TemporaryDirectory(dir=ROOT/'.tmp') as directory:
        directory=pathlib.Path(directory);cert=directory/'ca.crt';key=directory/'ca.key'
        subprocess.run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1','-addext','basicConstraints=critical,CA:TRUE'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        combos=[('socks5',None,False,'none')]+[('shadowsocks',m,False,'none') for m in METHODS]+[('trojan',None,True,'none'),('vless',None,False,'none'),('vless',None,True,'none'),('anytls',None,True,'none'),('snell',None,False,'none'),('snell',None,False,'http')]
        for app in ['sing-box','mihomo','xray']:
            for proto,method,tlsmode,obfs in combos:
                if app=='xray' and proto in ('anytls','snell'):
                    results.append({'app':app,'protocol':proto,'obfs':obfs,'status':'NOT_SUPPORTED_BY_APP'});continue
                label=f'{app}/{proto}/{method or ""}/tls={tlsmode}/obfs={obfs}'
                if len(sys.argv)>1 and sys.argv[1] not in label:continue
                inbound,secret=spec(proto,method,tlsmode,obfs)
                if tlsmode:inbound['tls']={'cert':str(cert),'key':str(key)}
                d=directory/str(len(results));d.mkdir()
                row={'app':app,'protocol':proto,'method':method,'tls':tlsmode,'obfs':obfs}
                try:
                    with tcp() as target,udp() as udp_target,core(inbound) as server:
                        port=chooseport();cfg=appcfg(app,proto,server,secret,port,cert,method,tlsmode,obfs)
                        with client(app,cfg,d) as (proc,log):
                            ready(port,proc);tcpcheck(port,target);row['tcp']='PASS'
                            if app=='mihomo' and proto=='vless':row['udp']='NOT_CONFIGURABLE_AS_CMD2: fixed app forces XUDP/packetaddr'
                            else:udpcheck(port,udp_target);row['udp']='PASS'
                            if proto=='anytls':
                                tcpcheck(port,target);row['sequential_streams']='PASS'
                                with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:list(ex.map(lambda _:tcpcheck(port,target),range(4)))
                                row['concurrent_streams']='PASS (app may use multiple TLS sessions)'
                            if proto=='snell':tcpcheck(port,target);row['sequential_requests']='PASS (physical reuse separately proven by library peer)'
                    row['status']='PASS'
                except Exception as e:
                    row['status']='FAIL';row['error']=str(e)
                    logpath=d/'client.log'
                    if logpath.exists():row['app_log']=logpath.read_text()[-2500:]
                print(label,json.dumps(row,ensure_ascii=False),flush=True);results.append(row)
        (ROOT/'docs/batch3-app-matrix.json').write_text(json.dumps(results,indent=2,ensure_ascii=False)+'\n')
        failures=[r for r in results if r['status']=='FAIL'];print('APP_MATRIX',len(results),'FAILURES',len(failures),flush=True)
        return bool(failures)
if __name__=='__main__':sys.exit(main())
