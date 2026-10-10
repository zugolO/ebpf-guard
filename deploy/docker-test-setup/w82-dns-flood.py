#!/usr/bin/env python3
"""Wave 8.2 B3 smoke: DNS flood from ONE process via connected UDP socket.

The DNS collector hooks connect()/send*()/write() on fds connected to :53
(bpf/dns.bpf.c), not packets, so the load must come from a process that
connect()s and sends. Phases: (rate pps, seconds); rate 0 = unthrottled.
Prints one line per phase: phase rate secs sent. A listener on 127.0.0.1:53
drains the datagrams so send() never fails with ECONNREFUSED.
"""
import os, random, socket, string, struct, sys, time

PHASES = [(2000, 20), (20000, 20), (0, 10)]
if len(sys.argv) > 1:
    PHASES = [tuple(int(x) for x in p.split(':')) for p in sys.argv[1].split(',')]

lst = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
lst.bind(('127.0.0.1', 53))
lst.setblocking(False)
cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
cli.connect(('127.0.0.1', 53))

def label(n):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n)).encode()

def query():
    q = b''.join(bytes([len(l)]) + l for l in (label(40), label(30), b'w82flood', b'invalid')) + b'\0'
    return struct.pack('!HHHHHH', random.randrange(65536), 0x0100, 1, 0, 0, 0) + q + struct.pack('!HH', 1, 1)

pool = [query() for _ in range(4096)]
for i, (rate, secs) in enumerate(PHASES):
    sent, t0 = 0, time.time()
    end = t0 + secs
    while True:
        now = time.time()
        if now >= end:
            break
        if rate and sent >= (now - t0) * rate:
            time.sleep(0.0005)
            continue
        try:
            cli.send(pool[sent & 4095])
            sent += 1
        except OSError:
            pass
        if sent & 255 == 0:
            try:
                while True:
                    lst.recv(2048)
            except BlockingIOError:
                pass
    print(f'phase {i} rate {rate} secs {secs} sent {sent}', flush=True)
