"""Bounded, synthetic Nostr TLS relay for the isolated home-node fixture only."""
import base64
import hashlib
import json
import os
import socket
import socketserver
import ssl
import struct
import threading

LOCK = threading.RLock()
CLIENTS = set()
EVENTS = {}


def matches(event, filters):
    for query in filters:
        if 'kinds' in query and event.get('kind') not in query['kinds']:
            continue
        if any(name in query and not any(event.get(field, '').startswith(prefix) for prefix in query[name])
               for name, field in [('ids', 'id'), ('authors', 'pubkey')]):
            continue
        if event.get('created_at', 0) < query.get('since', 0) or event.get('created_at', 0) > query.get('until', 2**53):
            continue
        if any(not any(tag[0] == name[1:] and len(tag) > 1 and tag[1] in values for tag in event.get('tags', []))
               for name, values in query.items() if name.startswith('#')):
            continue
        return True
    return False


class Handler(socketserver.BaseRequestHandler):
    def exact(self, size):
        data = b''
        while len(data) < size:
            part = self.request.recv(size - len(data))
            if not part:
                raise EOFError()
            data += part
        return data

    def send(self, value):
        body = json.dumps(value, separators=(',', ':')).encode()
        header = bytes([0x81, len(body)]) if len(body) < 126 else bytes([0x81, 126]) + struct.pack('!H', len(body)) if len(body) <= 65535 else bytes([0x81, 127]) + struct.pack('!Q', len(body))
        with self.writer:
            self.request.sendall(header + body)

    def handle(self):
        self.writer = threading.Lock()
        self.subscriptions = {}
        try:
            self.request.settimeout(60)
            headers = b''
            while not headers.endswith(b'\r\n\r\n'):
                headers += self.exact(1)
                if len(headers) > 16384:
                    raise ValueError()
            fields = dict(line.split(':', 1) for line in headers.decode().split('\r\n')[1:] if ':' in line)
            key = next(value.strip() for name, value in fields.items() if name.lower() == 'sec-websocket-key')
            accept = base64.b64encode(hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
            self.request.sendall(f'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n'.encode())
            with LOCK:
                if len(CLIENTS) >= 64:
                    return
                CLIENTS.add(self)
            while True:
                header = self.exact(2)
                opcode, length = header[0] & 15, header[1] & 127
                if header[0] & 0x70 or not header[0] & 0x80 or not header[1] & 0x80:
                    return
                if length == 126:
                    length = struct.unpack('!H', self.exact(2))[0]
                if length == 127:
                    length = struct.unpack('!Q', self.exact(8))[0]
                if length > 131072:
                    return
                mask = self.exact(4)
                body = bytes(value ^ mask[index % 4] for index, value in enumerate(self.exact(length)))
                if opcode == 8:
                    return
                if opcode == 9:
                    with self.writer:
                        self.request.sendall(bytes([0x8a, len(body)]) + body)
                    continue
                if opcode != 1:
                    continue
                value = json.loads(body)
                with LOCK:
                    if value[0] == 'REQ' and len(self.subscriptions) < 128:
                        self.subscriptions[value[1]] = value[2:]
                        for event in sorted(EVENTS.values(), key=lambda event: event['created_at'], reverse=True)[:1000]:
                            if matches(event, value[2:]):
                                self.send(['EVENT', value[1], event])
                        self.send(['EOSE', value[1]])
                    elif value[0] == 'CLOSE':
                        self.subscriptions.pop(value[1], None)
                    elif value[0] == 'AUTH':
                        self.send(['OK', value[1]['id'], True, ''])
                    elif value[0] == 'EVENT':
                        event = value[1]
                        if not 20000 <= event['kind'] < 30000:
                            EVENTS[event['id']] = event
                            while len(EVENTS) > 2048:
                                EVENTS.pop(next(iter(EVENTS)))
                        self.send(['OK', event['id'], True, ''])
                        for client in list(CLIENTS):
                            for subscription, filters in client.subscriptions.items():
                                if matches(event, filters):
                                    try:
                                        client.send(['EVENT', subscription, event])
                                    except OSError:
                                        pass
        except (OSError, EOFError, ValueError, KeyError, StopIteration, TypeError):
            pass
        finally:
            with LOCK:
                CLIENTS.discard(self)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == '__main__':
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('/fixture/tls/server.pem', '/fixture/tls/server.key')
    with Server(('0.0.0.0', int(os.environ['FIXTURE_RELAY_PORT'])), Handler) as server:
        server.socket = context.wrap_socket(server.socket, server_side=True)
        print('fixture relay ready', flush=True)
        server.serve_forever()
