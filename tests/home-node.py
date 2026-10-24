"""Start the actual standalone node plus a fixture-only loopback HTTP bridge."""
import http.client
import http.server
import os
import signal
import socket
import subprocess


class Bridge(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def forward(self):
        length = int(self.headers.get('Content-Length', 0))
        if length > 8192:
            self.send_error(413)
            return
        connection = http.client.HTTPConnection('127.0.0.1', 3744, timeout=20)
        try:
            connection.request(self.command, self.path, self.rfile.read(length),
                               {key: value for key, value in self.headers.items() if key.lower() not in ('host', 'connection')})
            response = connection.getresponse()
            body = response.read(65537)
            assert len(body) <= 65536
            self.send_response(response.status)
            for key, value in response.getheaders():
                if key.lower() not in ('transfer-encoding', 'connection', 'content-length'):
                    self.send_header(key, value)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (OSError, AssertionError):
            self.send_error(503)
        finally:
            connection.close()

    do_GET = forward
    do_POST = forward


if __name__ == '__main__':
    environment = dict(os.environ, SPRY_RELAY_IP=socket.gethostbyname(socket.gethostname()))
    child = subprocess.Popen(['/fixture/spry-node'], env=environment)
    def terminate(*_):
        raise SystemExit()
    signal.signal(signal.SIGTERM, terminate)
    try:
        with http.server.ThreadingHTTPServer(('0.0.0.0', 3844), Bridge) as server:
            server.serve_forever()
    finally:
        child.terminate()
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=3)
