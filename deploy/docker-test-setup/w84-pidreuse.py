#!/usr/bin/env python3
"""w84-pidreuse.py <скрипт> — воспроизводит реюз pid родителя (X5 w84-controls.sh).

P (форк) запускает S = <скрипт> (путь /var/lib/dpkg/info/*.prerm), S ждёт и зовёт `systemctl stop`; P тут же
выходит, и его pid освобождается. Через ns_last_pid следующий форк получает ТОТ ЖЕ pid и исполняет
/usr/bin/dpkg --version: теперь под pid P числится dpkg, запущенный ПОЗЖЕ S. Цепочка S → «P» → … не должна
давать исключение: родитель моложе потомка. Печатает «REUSED pid=…» только если реюз удался (класс предъявлен).
"""
import os, sys, time

script = sys.argv[1]
r, w = os.pipe()
p = os.fork()
if p == 0:  # P
    os.close(r)
    s = os.fork()
    if s == 0:  # S: исполняет скрипт после паузы — к этому моменту pid P уже занят
        os.close(w)
        time.sleep(4)
        os.execv(script, [script])
    os.write(w, str(os.getpid()).encode())
    os._exit(0)
os.close(w)
ppid = int(os.read(r, 32) or b"0")
os.waitpid(p, 0)
time.sleep(0.3)
try:
    with open("/proc/sys/kernel/ns_last_pid", "w") as f:
        f.write(str(ppid - 1))
except OSError as e:
    print("NO-REUSE: ns_last_pid не записан:", e)
    sys.exit(0)
n = os.fork()
if n == 0:
    os.execv("/usr/bin/dpkg", ["/usr/bin/dpkg", "--version"])
print(f"P={ppid} new={n}")
os.waitpid(n, 0)
print("REUSED pid=%d" % ppid if n == ppid else "NO-REUSE: новый pid %d != %d" % (n, ppid))
time.sleep(8)  # дождаться S
