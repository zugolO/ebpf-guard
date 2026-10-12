#!/usr/bin/env python3
# w85-f3-ctl.py <go-файл> <N> — процесс контроля F3: ждёт файл-сигнал, затем N служебных bpf()
# (cmd 1,2,4,24 поровну), затем BPF_PROG_LOAD (cmd 5) с NULL-аттрибутами — вызов падает с EFAULT/EINVAL,
# но событие enter/exit эмитируется. Сырой syscall: libc-обёртка подменила бы номер.
import ctypes, os, sys, time
libc = ctypes.CDLL(None, use_errno=True)
sc = libc.syscall
sc.restype = ctypes.c_long
L = ctypes.c_long
go, n = sys.argv[1], int(sys.argv[2])
while not os.path.exists(go):
    time.sleep(0.05)
cmds = [1, 2, 4, 24]
for i in range(n):
    sc(L(321), L(cmds[i % 4]), L(0), L(0))
sc(L(321), L(5), L(0), L(0))
print("w85-f3-ctl done n=%d pid=%d" % (n, os.getpid()))
