#!/bin/bash
# w85-e1-smoke.sh <SRC> <OUT> — волна 8.5, E1 живьём: exe_path по dev/ino образа из таблицы процессов.
# Два ВТОРЫХ агента одного бинаря друг за другом (рабочий ebpf-guard-test не трогается):
#   до   — SA_PROC_TABLE=off (таблицы нет: образ только readlink /proc/<pid>/exe);
#   после — таблица включена (E1: образ по dev/ino).
# Нагрузка в обеих фазах — N запусков настоящего systemd-detect-virt (мс-процесс, читает DMI: кейс virt-detect-self).
# В фазе «после» — спуф-контроли оси exe_path: копия бинаря под тем же именем, exec -a, comm-спуф (prctl) —
# каждый в своём окне (лимитер 10 алертов/правило/60 с), правило обязано сработать.
# Результат: $OUT/{before,after}/{m0,m1}.txt, $OUT/spoof-*.txt, затем эмиттер w85-e1-report.sh.
# Запуск отсоединённо (скрипт — файлом, без pkill -f).
set -u
SRC=${1:?SRC}; OUT=${2:?OUT}; N=${N:-300}; HERE=$(cd "$(dirname "$0")" && pwd)
source "$HERE/w85-second-agent-lib.sh"
rm -rf "$OUT"; mkdir -p "$OUT/before" "$OUT/after"; exec > "$OUT/driver.log" 2>&1
trap 'sa_stop 2> /dev/null; echo "агентов после: $(ps -eo cmd | grep -c "[e]bpf-guard --config")"' EXIT
die() { echo "die: $*" > "$OUT/DONE"; echo "DIE: $*"; exit 1; }
RULE=mitre_vm_detect_dmi_read
echo "[$(date -u +%FT%TZ)] w85-e1-smoke git $(cat "$SRC/GIT-HEAD" 2>/dev/null) N=$N"
[ "$(ps -eo cmd | grep -c '[e]bpf-guard --config')" -eq 1 ] || die "ожидался ровно один (рабочий) агент до запуска"
ls /sys/class/dmi/id/product_name > /dev/null 2>&1 || die "на узле нет DMI: класс «systemd-detect-virt читает DMI» не предъявить"

alerts_since() { # <t0 epoch> — число алертов правила RULE с comm systemd-detect-* и timestamp ≥ t0 (сек); «none» — снимок не разобран
    curl -s --max-time 30 -H "Authorization: Bearer $SA_TOKEN" "$SA_API/api/v1/alerts?limit=5000" \
      | jq -r --argjson t0 "$1" --arg r "$RULE" '[(if type == "array" then . else .alerts // [] end)[]
          | select((.rule_id // .RuleID) == $r)
          | select(((.timestamp // .Timestamp // "1970-01-01T00:00:00Z") | sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601) >= $t0)
          | select((.comm // "") | test("^systemd-detect"))] | length' 2> /dev/null || echo none
}
phase() { # <before|after> <порт>
    local ph=$1 port=$2 d="$OUT/$1"
    if [ "$ph" = before ]; then export SA_PROC_TABLE=off; else unset SA_PROC_TABLE; fi
    sa_start "$SRC" /root/w85-run-e1-$ph "$port" || die "второй агент ($ph) не поднялся"
    local st; st=$(sa_metrics | grep -a '^ebpf_guard_proc_table_state' | grep -a ' 1$' | sed 's/.*state="\([^"]*\)".*/\1/')
    echo "$ph: состояние таблицы $st, агент pid $SA_PID"; echo "$st" > "$d/proc_table_state.txt"
    [ "$ph" = before ] && [ "$st" = active ] && die "до: таблица active"
    [ "$ph" = after ] && [ "$st" != active ] && die "после: таблица $st"
    sleep 20
    sa_metrics > "$d/m0.txt"; local t0; t0=$(date +%s); echo "$t0" > "$d/t0.txt"
    local i
    for i in $(seq 1 "$N"); do systemd-detect-virt > /dev/null 2>&1; sleep 0.05; done
    sleep 5
    sa_metrics > "$d/m1.txt"
    alerts_since "$t0" > "$d/alerts.txt"; echo "$ph: алертов $RULE от systemd-detect-* за окно: $(cat "$d/alerts.txt")"
    if [ "$ph" = after ]; then
        mkdir -p /var/tmp/w85e1; cp /usr/bin/systemd-detect-virt /var/tmp/w85e1/systemd-detect-virt; cp /usr/bin/systemd-detect-virt /var/tmp/w85e1/dv2
        # контроль 1: копия под тем же именем в другом каталоге
        spoof() { # <имя> <команда…>
            local n=$1; shift; sleep 62; local t; t=$(date +%s)
            "$@" > /dev/null 2>&1; sleep 6
            echo "$n $(alerts_since "$t")" | tee -a "$OUT/spoof.txt"
        }
        : > "$OUT/spoof.txt"
        spoof copy-same-name /var/tmp/w85e1/systemd-detect-virt
        spoof exec-a bash -c 'exec -a /usr/bin/systemd-detect-virt /var/tmp/w85e1/dv2'
        # comm-спуф сырым syscall: PR_SET_NAME + openat(AT_FDCWD, DMI, O_RDONLY|O_CLOEXEC); образ — python3
        cat > /var/tmp/w85e1/commspoof.py <<'PY'
import ctypes
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
libc.prctl(ctypes.c_int(15), ctypes.c_char_p(b"systemd-detect-"), ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0))
for p in (b"/sys/class/dmi/id/sys_vendor", b"/sys/class/dmi/id/product_name", b"/sys/class/dmi/id/product_uuid"):
    fd = libc.syscall(ctypes.c_long(257), ctypes.c_long(-100), ctypes.c_char_p(p), ctypes.c_long(0o2000000), ctypes.c_long(0))
    if fd >= 0:
        libc.syscall(ctypes.c_long(3), ctypes.c_long(fd))
PY
        spoof comm-spoof python3 /var/tmp/w85e1/commspoof.py
        # положительный контроль самой оси: настоящий образ ещё раз, исключение обязано примениться (счётчик ниже)
        sa_metrics > "$d/m2.txt"
    fi
    sa_stop; sleep 3
}
phase before 19211
phase after 19212
rm -rf /var/tmp/w85e1
echo "== E1"
OUT=$OUT bash "$HERE/w85-e1-report.sh" | tee "$OUT/report.txt"
echo "done $(date -u +%FT%TZ)" > "$OUT/DONE"
