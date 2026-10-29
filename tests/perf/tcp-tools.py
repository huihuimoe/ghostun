#!/usr/bin/env python3
"""Real terminating relay and content-checking traffic fixtures for isolated netns tests."""
import argparse
import json
import selectors
import socket
import threading
import time


def family(address):
    return socket.AF_INET6 if ':' in address else socket.AF_INET


def relay(listen, backend, port):
    selector = selectors.DefaultSelector()
    server = socket.socket(family(listen))
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family(listen) == socket.AF_INET6:
        server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    server.bind((listen, port))
    server.listen(256)
    server.setblocking(False)
    selector.register(server, selectors.EVENT_READ)
    peers, buffers = {}, {}
    source_port = 40000

    def close(sock):
        other = peers.pop(sock, None)
        for s in (sock, other):
            if s is not None:
                peers.pop(s, None)
                buffers.pop(s, None)
                try:
                    selector.unregister(s)
                except KeyError:
                    pass
                s.close()

    while True:
        for key, events in selector.select(0.1):
            sock = key.fileobj
            if sock is server:
                client, _ = server.accept()
                upstream = socket.socket(family(backend))
                # Every backend source port has the same modulo-2 class. This defeats
                # source-port worker dispatch while leaving authenticated IDs intact.
                for _ in range(1000):
                    source_port = 40000 + (source_port + 2 - 40000) % 20000
                    try:
                        upstream.bind(('::' if family(backend) == socket.AF_INET6 else '0.0.0.0', source_port))
                        break
                    except OSError:
                        continue
                try:
                    upstream.settimeout(1)
                    upstream.connect((backend, 443))
                except OSError:
                    client.close()
                    upstream.close()
                    continue
                for s, peer in ((client, upstream), (upstream, client)):
                    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    s.setblocking(False)
                    peers[s] = peer
                    buffers[s] = bytearray()
                    selector.register(s, selectors.EVENT_READ)
                continue
            if sock not in peers:
                continue
            try:
                if events & selectors.EVENT_WRITE:
                    n = sock.send(buffers[sock])
                    del buffers[sock][:n]
                if events & selectors.EVENT_READ and len(buffers[peers[sock]]) < 65536:
                    data = sock.recv(65536 - len(buffers[peers[sock]]))
                    if not data:
                        close(sock)
                        continue
                    buffers[peers[sock]].extend(data)
                for s in (sock, peers[sock]):
                    mask = (selectors.EVENT_READ if len(buffers[peers[s]]) < 65536 else 0)
                    if buffers[s]:
                        mask |= selectors.EVENT_WRITE
                    # A full outbound buffer always gives the opposite fd write readiness.
                    try:
                        selector.get_key(s)
                        registered = True
                    except KeyError:
                        registered = False
                    if mask and registered:
                        selector.modify(s, mask)
                    elif mask:
                        selector.register(s, mask)
                    elif registered:
                        selector.unregister(s)
            except (ConnectionError, OSError):
                close(sock)


def serve(address, port):
    def tcp():
        s = socket.socket(family(address))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family(address) == socket.AF_INET6:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        s.bind((address, port))
        s.listen(128)
        def handle(c):
            with c:
                c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                try:
                    while data := c.recv(8192):
                        c.sendall(data)
                except OSError:
                    pass
        while True:
            c, _ = s.accept()
            threading.Thread(target=handle, args=(c,), daemon=True).start()
    threading.Thread(target=tcp, daemon=True).start()
    s = socket.socket(family(address), socket.SOCK_DGRAM)
    s.bind((address, port))
    while True:
        data, peer = s.recvfrom(8192)
        s.sendto(data, peer)


def check(address, udp=False, count=16, duration=0, port=7000):
    latencies = []
    s = socket.socket(family(address), socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
    s.settimeout(3)
    if not udp:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.connect((address, port))
    start = time.monotonic()
    i = 0
    while i < count or time.monotonic() - start < duration:
        data = (f'{i:08d}:'.encode() + bytes(range(251))) * (1 if duration else 4)
        before = time.monotonic()
        s.sendall(data)
        got = b''
        while len(got) < len(data):
            part = s.recv(len(data)-len(got))
            if not part:
                raise RuntimeError('premature EOF')
            got += part
        assert got == data, 'payload corruption'
        latencies.append((time.monotonic()-before)*1000)
        i += 1
        if duration:
            time.sleep(0.01)
    s.close()
    values = sorted(latencies)
    return {'samples':len(values), 'p95_ms':values[min(len(values)-1, int(len(values)*.95))],
            'p99_ms':values[min(len(values)-1, int(len(values)*.99))]}


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest='cmd', required=True)
    r = sub.add_parser('relay'); r.add_argument('listen'); r.add_argument('backend'); r.add_argument('--port',type=int,default=8443)
    s = sub.add_parser('serve'); s.add_argument('address'); s.add_argument('--port', type=int, default=7000)
    c = sub.add_parser('check'); c.add_argument('address'); c.add_argument('--udp',action='store_true'); c.add_argument('--duration',type=float,default=0); c.add_argument('--port',type=int,default=7000)
    args = p.parse_args()
    if args.cmd == 'relay':
        relay(args.listen,args.backend,args.port)
    elif args.cmd == 'serve':
        serve(args.address,args.port)
    else:
        print(json.dumps(check(args.address,args.udp,duration=args.duration,port=args.port)))
