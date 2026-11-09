import http.server,json,pathlib,select,subprocess,tempfile,threading
ROOT=pathlib.Path('/opt/proxy-kernel')
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200);self.send_header('Content-Length','9');self.end_headers();self.wfile.write(b'cli-smoke')
    def log_message(self,*a):pass
http=http.server.HTTPServer(('127.0.0.1',0),Handler)
th=threading.Thread(target=http.serve_forever);th.start()
try:
    with tempfile.TemporaryDirectory(dir=ROOT/'.tmp') as d:
        p=pathlib.Path(d)/'config.json'
        p.write_text(json.dumps({'inbounds':[{'protocol':'socks5','listen':'127.0.0.1:0'}],'udp_bind_ipv4':'127.0.0.1','udp_bind_ipv6':'::1','limits':{'connections':8,'handshakes':4,'dials':4,'drain_timeout':'1s'}}));p.chmod(0o600)
        exe=str(ROOT/'bin/proxy-kernel')
        assert subprocess.run([exe,'check',str(p)],capture_output=True).returncode==0
        proc=subprocess.Popen([exe,'run',str(p)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            if not select.select([proc.stderr],[],[],3)[0]:raise RuntimeError('CLI did not start')
            line=proc.stderr.readline().strip();assert line.startswith('listening '),line
            address=line.split()[1]
            out=subprocess.run(['curl','--fail','--silent','--show-error','--noproxy','','--max-time','3','--socks5-hostname',address,f'http://127.0.0.1:{http.server_port}/'],capture_output=True,timeout=5)
            assert out.returncode==0 and out.stdout==b'cli-smoke',(out.returncode,out.stdout,out.stderr)
            proc.terminate();proc.communicate(timeout=3);assert proc.returncode==0
            print('PASS: built CLI check/run -> independent curl -> loopback HTTP -> SIGTERM graceful exit')
        finally:
            if proc.poll() is None:proc.kill();proc.communicate(timeout=3)
        p.write_text(json.dumps({'inbounds':[],'password':'never-print-this-test-sentinel'}))
        result=subprocess.run([exe,'check',str(p)],capture_output=True,text=True)
        assert result.returncode!=0 and 'never-print-this-test-sentinel' not in result.stderr
        print('PASS: CLI rejects bad configuration without credential-value disclosure')
finally:
    http.shutdown();th.join();http.server_close()
