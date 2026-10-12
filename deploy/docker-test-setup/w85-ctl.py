#!/usr/bin/env python3
# Волна 8.5, F1: положительные контроли трёх номеров СЫРЫМ syscall (libc-обёртка
# подменила бы номер) + «обычные» вызовы того же номера, которые предикат обязан
# отбросить и посчитать.
import ctypes, sys
libc = ctypes.CDLL(None, use_errno=True)
sc = libc.syscall
sc.restype = ctypes.c_long
L = ctypes.c_long
MAP_ANON_PRIV = 0x22

def raw(nr, *a):
    return sc(L(nr), *[L(x) for x in a])

attack = int(sys.argv[1]) if len(sys.argv) > 1 else 5
benign = int(sys.argv[2]) if len(sys.argv) > 2 else 3000

for _ in range(attack):
    # mmap(NULL, 4096, PROT_READ|WRITE|EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
    raw(9, 0, 4096, 7, MAP_ANON_PRIV, -1, 0)
    # mprotect(addr, 4096, PROT_READ|WRITE|EXEC)
    addr = raw(9, 0, 4096, 3, MAP_ANON_PRIV, -1, 0)
    raw(10, addr, 4096, 7)
    # arch_prctl(ARCH_GET_CPUID, 0)
    raw(158, 0x1011, 0)

for _ in range(benign):
    addr = raw(9, 0, 4096, 3, MAP_ANON_PRIV, -1, 0)   # RW анонимная: не атака
    raw(10, addr, 4096, 1)                             # mprotect PROT_READ: не атака
    raw(158, 0x1003, 0)                                # ARCH_GET_FS: не cpuid
    raw(11, addr, 4096)                                # munmap (не отбирается)
print("w85-ctl done attack=%d benign=%d" % (attack, benign))
