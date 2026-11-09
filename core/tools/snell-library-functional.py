"""Loopback/random-port functional tests. Independent peers run as subprocesses.
No production codecs imported, no proxy traffic outside loopback."""
import os
os.environ["GOMAXPROCS"]="1"
import base64,contextlib,hashlib,json,pathlib,select,socket,socketserver,subprocess,tempfile,threading
ROOT=pathlib.Path('/opt/proxy-kernel')
class TCP(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True
class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(6)
        if self.server.banner is True:self.request.sendall(('hello:'+self.server.address+':').encode())
        elif self.server.banner:self.request.sendall(self.server.banner.encode())
        try:
            while True:
                b=self.request.recv(65536)
                if not b:break
                self.request.sendall(b)
        except (OSError,TimeoutError):pass
@contextlib.contextmanager
def tcp(banner=False):
    s=TCP(('127.0.0.1',0),Echo);s.banner=banner;s.address='127.0.0.1:'+str(s.server_address[1]);th=threading.Thread(target=s.serve_forever);th.start()
    try:yield s.address
    finally:s.shutdown();s.server_close();th.join()
@contextlib.contextmanager
def udp():
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',0));s.settimeout(.1);stop=threading.Event()
    def loop():
        while not stop.is_set():
            try:b,a=s.recvfrom(65535);s.sendto(b,a)
            except TimeoutError:pass
            except OSError:break
    th=threading.Thread(target=loop);th.start()
    try:yield '127.0.0.1:'+str(s.getsockname()[1])
    finally:stop.set();th.join();s.close()
@contextlib.contextmanager
def core(inbound):
    with tempfile.TemporaryDirectory(dir=ROOT/'.tmp') as d:
        p=pathlib.Path(d)/'config.json';p.write_text(json.dumps({'inbounds':[dict(inbound,listen='127.0.0.1:0')],'udp_bind_ipv4':'127.0.0.1','udp_bind_ipv6':'::1','limits':{'connections':16,'handshakes':8,'dials':8,'udp_associations':8,'udp_queue':4,'udp_targets':4,'pool_buffers':4,'drain_timeout':'2s','udp_idle':'2s','tcp_idle':'5s'}}));p.chmod(0o600)
        exe=str(ROOT/'bin/proxy-kernel');check=subprocess.run([exe,'check',str(p)],capture_output=True,text=True);assert check.returncode==0,check.stderr
        c=subprocess.Popen([exe,'run',str(p)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            assert select.select([c.stderr],[],[],3)[0],'startup timeout'
            line=c.stderr.readline().strip();assert line.startswith('listening '),line
            yield line.split()[1]
        finally:
            c.terminate()
            try:c.communicate(timeout=4)
            except subprocess.TimeoutExpired:c.kill();c.communicate(timeout=2)
            assert c.returncode==0,('CLI did not exit cleanly',c.returncode)
def run(args):
    p=subprocess.run(args,capture_output=True,text=True,timeout=12);assert p.returncode==0,(args[0],p.stdout,p.stderr);print(p.stdout.strip(),flush=True)
for version in [4,5]:
    for obfs in ['none','http']:
        with tcp(True) as target1,tcp(True) as target2,udp() as datagram,core({'protocol':'snell','snell':{'version':version,'psk':'snell-core-fixture-psk','obfs':obfs}}) as server:
            run([str(ROOT/'.interop/snell-peer'),'-server',server,'-obfs',obfs,'-target1',target1,'-target2',target2,'-udp',datagram])
            print('CLI SNELL PASS',version,obfs,flush=True)
print('SNELL v4/v5 none/http library TCP/UDP/two-target physical reuse/half-close/server-first PASS',flush=True)
