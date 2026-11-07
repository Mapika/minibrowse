# Test server: static files plus /slow?ms=N, which answers after N milliseconds.
import http.server, socketserver, time, urllib.parse, json, os, sys
os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'site'))
class H(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path == '/slow':
            time.sleep(int(urllib.parse.parse_qs(u.query).get('ms', ['1000'])[0]) / 1000)
            body = json.dumps({'results': 42}).encode()
            self.send_response(200); self.send_header('Content-Type', 'application/json'); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
        elif u.path == '/file':
            body = b'report contents\n'
            self.send_response(200); self.send_header('Content-Type', 'text/plain'); self.send_header('Content-Disposition', 'attachment; filename="report.txt"'); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
        else: super().do_GET()
class S(socketserver.ThreadingMixIn, http.server.HTTPServer): daemon_threads = True
S(('0.0.0.0', int(sys.argv[1]) if len(sys.argv) > 1 else 8766), H).serve_forever()
