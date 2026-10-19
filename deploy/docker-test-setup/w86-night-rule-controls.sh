#!/bin/bash
# Волна 8.6, заход B, шаг 1: живые контроли трёх правил, исправленных ПРЕДИКАТОМ (owasp_path_traversal — после слияния Д18 бывший web_path_traversal_process,
# container_escape_cgroup_v1_release_agent, privesc_cgroup_notify_on_release). Положительный контроль — настоящий процесс
# с настоящим comm (копия /bin/cat под именем nginx, копия tee, python3 с сырым openat), НЕ шебанг-скрипт; перед каждым
# контролем в журнал пишется /proc/self/comm процесса. Отрицательный — штатный читатель того же пути.
# Атрибуция — по окну времени контроля (timestamp ≥ t0 сценария), comm и правилу.
# НОЧНОЙ вариант (волна 8.6 C): контроли идут против РАБОЧЕГО агента ночи (API/TOKEN), второго агента нет;
# вызывается пайплайном в окне атак (после пакета и гейта, после паузы на сброс лимитера).
#   w86-night-rule-controls.sh <OUT>     окружение: API (http://localhost:19090), TOKEN
set -u
OUT=${1:?OUT}; API=${API:?API}; TOKEN=${TOKEN:?TOKEN}
rm -rf "$OUT"; mkdir -p "$OUT"; exec > "$OUT/driver.log" 2>&1
die() { echo "die: $*" > "$OUT/DONE"; echo "DIE: $*"; exit 1; }
[ "$(ps -eo cmd | grep -c '[e]bpf-guard --config')" -eq 1 ] || die "ожидался ровно один (рабочий) агент до запуска"
SA_API=$API; SA_TOKEN=$TOKEN
W=/var/lib/w86nightctl; rm -rf $W; mkdir -p $W/bin $W/www/html $W/opt/nginx $W/cgrp
cp /bin/cat $W/bin/nginx; cp /bin/cat $W/bin/cat; cp /usr/bin/tee $W/bin/tee
echo "reader data" > $W/cgrp/release_agent; echo "reader data" > $W/cgrp/notify_on_release; echo x > $W/cgrp/release_agent.txt
echo "[$(date -u +%FT%TZ)] рабочий агент ночи $API"
alerts() { curl -s --max-time 30 -H "Authorization: Bearer $SA_TOKEN" "$SA_API/api/v1/alerts?limit=5000"; }
CTLS=()
run() { # <имя> <ожидание: <rule>:<comm>:<yes|no> ...> -- команда...
    local name=$1; shift
    local exp=(); while [ "$1" != "--" ]; do exp+=("$1"); shift; done; shift
    local t0 t1; t0=$(date +%s); sleep 1
    "$@" > "$OUT/ctl-$name.out" 2>&1; echo "rc=$?" >> "$OUT/ctl-$name.out"
    sleep 14; t1=$(date +%s)
    CTLS+=("$name|$t0|$t1|${exp[*]}")
}
# comm процесса печатается самим процессом (шебанг-сторож: ноль без предъявленного comm не читается как провал)
showcomm() { "$@"; }
# --- положительные -------------------------------------------------------------------------------
run P1_nginx_traversal  owasp_path_traversal:nginx:yes -- $W/bin/nginx $W/www/html/../../../../etc/hostname
run P1b_python_traversal owasp_path_traversal:python3:yes -- python3 - <<PY
import ctypes
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
open("/proc/self/comm") and print("comm=" + open("/proc/self/comm").read().strip())
fd = libc.syscall(ctypes.c_long(257), ctypes.c_long(-100), ctypes.c_char_p(b"$W/www/html/../../../../etc/hostname"), ctypes.c_long(0), ctypes.c_long(0))
print("fd", fd)
PY
run P2_tee_release_agent container_escape_cgroup_v1_release_agent:tee:yes privesc_cgroup_notify_on_release:tee:yes -- sh -c "echo x | $W/bin/tee $W/cgrp/release_agent"
run P3_tee_notify privesc_cgroup_notify_on_release:tee:yes container_escape_cgroup_v1_release_agent:tee:no -- sh -c "echo 1 | $W/bin/tee $W/cgrp/notify_on_release"
run P4_python_rdwr_release_agent container_escape_cgroup_v1_release_agent:python3:yes -- python3 - <<PY
import ctypes
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
print("comm=" + open("/proc/self/comm").read().strip())
fd = libc.syscall(ctypes.c_long(257), ctypes.c_long(-100), ctypes.c_char_p(b"$W/cgrp/release_agent"), ctypes.c_long(2), ctypes.c_long(0))
print("fd", fd)
PY
# --- отрицательные -------------------------------------------------------------------------------
run N1_cat_server_name_in_path owasp_path_traversal:cat:no -- $W/bin/cat $W/opt/nginx/../../../../etc/hostname
run N2_cat_reads_release_agent container_escape_cgroup_v1_release_agent:cat:no privesc_cgroup_notify_on_release:cat:no -- $W/bin/cat $W/cgrp/release_agent
run N3_cat_reads_notify privesc_cgroup_notify_on_release:cat:no -- $W/bin/cat $W/cgrp/notify_on_release
run N4_python_reads_dist_packages owasp_path_traversal:python3:no -- python3 -c "print('comm=' + open('/proc/self/comm').read().strip()); open('/usr/lib/python3/dist-packages/apt/__init__.py').read(); print('read ok')"
run N5_tee_neighbour_name container_escape_cgroup_v1_release_agent:tee:no privesc_cgroup_notify_on_release:tee:no -- sh -c "echo x | $W/bin/tee $W/cgrp/release_agent.txt"
alerts > "$OUT/alerts.json"
python3 - "$OUT" "${CTLS[@]}" <<'PY'
import json, sys, datetime
out = sys.argv[1]
d = json.load(open(out + "/alerts.json"))
al = d if isinstance(d, list) else d.get("alerts", [])
def ts(a):
    s = a.get("timestamp") or a.get("Timestamp") or "1970-01-01T00:00:00Z"
    s = s.split(".")[0].rstrip("Z")
    return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.timezone.utc).timestamp()
ok = 0; bad = 0
for c in sys.argv[2:]:
    name, t0, t1, exp = c.split("|", 3)
    t0, t1 = float(t0), float(t1)
    got = {}
    for a in al:
        if t0 <= ts(a) <= t1 + 5:
            k = ((a.get("rule_id") or a.get("RuleID")), (a.get("comm") or a.get("Comm") or ""))
            got[k] = got.get(k, 0) + 1
    for e in exp.split():
        rule, comm, want = e.split(":")
        n = got.get((rule, comm), 0)
        verdict = "OK" if ((n > 0) == (want == "yes")) else "FAIL"
        ok += verdict == "OK"; bad += verdict == "FAIL"
        print("%-4s %-34s %-48s comm=%-8s ждали=%-3s получено=%d" % (verdict, name, rule, comm, want, n))
print("ИТОГ: %d OK, %d FAIL" % (ok, bad))
PY
echo "done $(date -u +%FT%TZ)" > "$OUT/DONE"
