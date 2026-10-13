#!/usr/bin/env python3
"""w85-o1-ctl.py <режим> — положительные контроли O1 СЫРЫМ syscall (libc.syscall с c_long-аргументами, не обёртки):
  sock-c2     root: socket(AF_INET=2, SOCK_RAW=3, 255)                   → c2_raw_socket_shell (comm python3)
  sock-exfil  uid 65534 (raw setuid): socket(2, SOCK_RAW|SOCK_CLOEXEC, 1) → exfil_raw_socket_by_non_root (EPERM — событие есть)
  sock-arp    root: socket(AF_PACKET=17, SOCK_RAW=3, htons(3))            → mitre_arp_spoof_raw_socket
  clone       uid 65534: raw clone(SIGCHLD) × N, ребёнок сразу exit_group → impact_fork_bomb_pattern (nr 56)
  sock-plain  root: 200 × socket(AF_INET, SOCK_STREAM) — «обычные» вызовы того же номера (ни одно правило не должно сработать)
Номера x86_64: socket 41, clone 56, exit_group 231, close 3, setuid 105."""
import ctypes, os, sys
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
L = ctypes.c_long
def sc(nr, *a):
    return libc.syscall(L(nr), *[L(x) for x in a])
mode = sys.argv[1]
n = int(sys.argv[2]) if len(sys.argv) > 2 else 5
def sock(dom, typ, proto, count=n):
    for _ in range(count):
        fd = sc(41, dom, typ, proto)
        if fd >= 0:
            sc(3, fd)
if mode == 'sock-c2':
    sock(2, 3, 255)
elif mode == 'sock-exfil':
    assert sc(105, 65534) == 0, 'setuid'
    sock(2, 3 | 0o2000000, 1)
elif mode == 'sock-arp':
    sock(17, 3, 0x0300)
elif mode == 'sock-plain':
    sock(2, 1, 0, 200)
elif mode == 'clone':
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 12
    assert sc(105, 65534) == 0, 'setuid'
    for _ in range(n):
        pid = sc(56, 17, 0, 0, 0, 0)  # SIGCHLD, без CLONE_*: форк
        if pid == 0:
            sc(231, 0)
        elif pid > 0:
            os.waitpid(pid, 0)
else:
    sys.exit('режим?')
print('ok', mode)
