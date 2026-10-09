#!/bin/bash
# w81-h4-smoke.sh — смок долгов 8.1 (09.10.2026): man-db (М), apt-daily (A),
# systemd-detect-virt (V), положительные контроли (P) — одной выдачей, фазы
# выбираются PHASES="M A V P".
#
# Общая схема фазы (как w549-smoke.sh): окно C без события, окно E той же длины
# с событием от транзиентного таймера (AccuracySec=1s, взведён до t0 —
# [[forced-node-event-costs-the-same]]). В E живёт свидетель bpftrace, запущенный
# ДО события: ВСЕ открытия (флаги, путь) и execve (pid → образ) — по ним отчёт
# сопоставляет правила с образом и объектом ([[bpftrace-is-the-second-witness]]).
# Предикат bpftrace короткий ([[bpftrace-014-rejects-long-predicate-and-begin]]).
#
# A: штампы apt сдвигаются на 2 суток и ВОЗВРАЩАЮТСЯ к исходным mtime после
#    окна ([[apt-timers-are-stamp-gated]]); apt-daily-upgrade не форсируется.
# V: ExecStart транзиентного юнита — настоящий /usr/bin/systemd-detect-virt,
#    не процесс шелла измерителя.
# P: копии образов из /var/tmp с теми же именами comm выполняют ту же работу —
#    правила обязаны сработать, исключения не должны считаться.
# В окнах скрипт только спит ([[waiting-loop-must-not-ssh-into-window]]).
set -u
OUT=${OUT:-/var/tmp/w81-h4-smoke}
PHASES=${PHASES:-"M A V P"}
WARM=${WARM:-300}
W=${W:-300}
WV=${WV:-120}
LEAD=20
REPO=/opt/ebpf-guard
UNIT=ebpf-guard-test.service
BIN=$REPO/build/ebpf-guard
API=http://localhost:19090
TOKEN=$(grep '^admin=' /var/lib/ebpf-guard/token | cut -d= -f2)
STAMPS=(/var/lib/apt/periodic/update-stamp /var/lib/apt/periodic/update-success-stamp)
M() { curl -s --max-time 30 -H "Authorization: Bearer $TOKEN" "$API/metrics"; }
A() { curl -s --max-time 60 -H "Authorization: Bearer $TOKEN" "$API/api/v1/alerts?since=$1s&limit=20000"; }
die() { echo "DIE: $*"; echo "die: $*" > "$OUT/DONE"; exit 1; }
has() { case " $PHASES " in *" $1 "*) return 0;; esac; return 1; }

rm -rf "$OUT"; mkdir -p "$OUT"
exec > "$OUT/driver.log" 2>&1
echo "[$(date -u +%FT%TZ)] w81-h4-smoke: фазы $PHASES"

[ "$(ps -eo cmd | grep -c '[e]bpf-guard --config')" -eq 1 ] || die "агентов не 1"
"$BIN" version > "$OUT/binary-version.txt" 2>&1
grep -q 'rego=true' "$OUT/binary-version.txt" || die "бинарь без тега rego"
command -v bpftrace > /dev/null || die "нет bpftrace — свидетель"
for u in man-db.service apt-daily.service; do systemctl cat "$u" > /dev/null 2>&1 || die "нет юнита $u"; done
[ -x /usr/bin/systemd-detect-virt ] || die "нет systemd-detect-virt"
for s in "${STAMPS[@]}"; do [ -e "$s" ] || die "нет штампа $s"; done
{ for s in "${STAMPS[@]}"; do echo "$s $(stat -c %Y "$s")"; done; } > "$OUT/stamps-orig.txt"
{ for u in man-db apt-daily; do echo "== $u"; systemctl cat $u.service | grep -E '^(ExecStart|Type|User)'; done; } > "$OUT/units.txt"
readlink -f /usr/bin/mandb /usr/bin/systemd-detect-virt /usr/lib/apt/methods/http /usr/lib/apt/methods/https /usr/lib/apt/methods/gpgv > "$OUT/readlink.txt"
dpkg -S /usr/bin/mandb /usr/bin/systemd-detect-virt /usr/lib/apt/methods/http /usr/lib/apt/methods/https /usr/lib/apt/methods/gpgv >> "$OUT/readlink.txt" 2>&1

systemctl stop $UNIT
rm -f /var/lib/ebpf-guard/test-events.db*
date +%s > "$OUT/t-start"
systemctl start $UNIT
for i in $(seq 1 60); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 $API/health)" = 200 ] && break; sleep 2
done
PID=$(systemctl show -p MainPID --value $UNIT)
sf=$(sha256sum "$BIN" | cut -d' ' -f1); sp=$(sha256sum /proc/$PID/exe | cut -d' ' -f1)
{ echo "path=$BIN"; echo "sha256=$sf"; echo "sha256_proc=$sp"; echo "pid=$PID"; cat "$OUT/binary-version.txt"; } > "$OUT/binary-identity.txt"
[ "$sf" = "$sp" ] || die "sha процесса ≠ sha файла"
echo "[$(date -u +%FT%TZ)] агент pid $PID sha ${sf:0:12}, прогрев $WARM с"
sleep "$WARM"

WITNESS='tracepoint:syscalls:sys_enter_openat /comm != "ebpf-guard"/ { printf("O %d %s %d %s\n", pid, comm, args->flags, str(args->filename)); } tracepoint:syscalls:sys_enter_execve { printf("X %d %s %s\n", pid, comm, str(args->filename)); }'

# _phase <каталог> <имя> <окно> <команда события...> — C, затем E с событием.
_phase() {
    local D="$1" name="$2" win="$3"; shift 3
    local fu="w81h4-force-$name" err
    mkdir -p "$D"; echo "$name" > "$D/target"; echo "$win" > "$D/window"; echo "$*" > "$D/command"
    systemctl stop "$fu.timer" "$fu.service" > /dev/null 2>&1
    systemctl reset-failed "$fu.timer" "$fu.service" > /dev/null 2>&1
    sleep 60
    M > "$D/mC0.txt"; date +%s > "$D/tC0"
    sleep "$win"
    M > "$D/mC1.txt"; date +%s > "$D/tC1"
    [ -n "${PRE_E:-}" ] && eval "$PRE_E"
    setsid bpftrace -e "$WITNESS" > "$D/bpf.txt" 2> "$D/bpf.err" < /dev/null &
    echo $! > "$D/bpf.pid"; sleep 5
    err=$(systemd-run --quiet --on-active=$((LEAD + 1))s --timer-property=AccuracySec=1s \
          --property=RemainAfterExit=yes --unit="$fu" "$@" 2>&1) \
        || { echo "systemd-run отказал: $err" > "$D/skipped"; return 1; }
    M > "$D/mE0.txt"; date +%s > "$D/tE0"
    sleep "$win"
    M > "$D/mE1.txt"; date +%s > "$D/tE1"
    kill "$(cat "$D/bpf.pid")" 2>/dev/null
    A $(( $(date +%s) - $(cat "$D/tC0") + 5 )) > "$D/alerts-CE.json"
    curl -s --max-time 60 -H "Authorization: Bearer $TOKEN" "$API/api/v1/incidents?limit=1000" > "$D/incidents.json"
    systemctl show "$fu.service" -p ActiveState -p Result -p ExecMainStartTimestamp -p ExecMainExitTimestamp -p ExecMainStatus -p ExecMainPID > "$D/force-unit.txt"
    journalctl -u "$fu.service" --since "@$(cat "$D/tE0")" -o short-iso --no-pager > "$D/unit-journal.txt" 2>&1
    systemctl stop "$fu.timer" "$fu.service" > /dev/null 2>&1
    systemctl reset-failed "$fu.timer" "$fu.service" > /dev/null 2>&1
    echo "[$(date -u +%FT%TZ)] $name: C [$(cat "$D/tC0"),$(cat "$D/tC1")] E [$(cat "$D/tE0"),$(cat "$D/tE1")]"
}

if has M; then
    _phase "$OUT/M" man-db "$W" /usr/bin/systemctl start man-db.service
    sleep 30
fi

if has V; then
    _phase "$OUT/V" virt "$WV" /usr/bin/systemd-detect-virt
    sleep 30
fi

if has A; then
    PRE_E='for s in "${STAMPS[@]}"; do touch -d "2 days ago" "$s"; done
           { for s in "${STAMPS[@]}"; do echo "$s $(stat -c %Y "$s")"; done; } > "$D/stamps-before.txt"'
    _phase "$OUT/A" apt-daily "$W" /usr/bin/systemctl start apt-daily.service
    PRE_E=
    { for s in "${STAMPS[@]}"; do echo "$s $(stat -c %Y "$s")"; done; } > "$OUT/A/stamps-after.txt"
    while read -r s t; do touch -d "@$t" "$s"; done < "$OUT/stamps-orig.txt"
    { for s in "${STAMPS[@]}"; do echo "$s $(stat -c %Y "$s")"; done; } > "$OUT/A/stamps-restored.txt"
    journalctl -u apt-daily.service --since "@$(cat "$OUT/A/tE0")" -o short-iso --no-pager > "$OUT/A/apt-daily-journal.txt" 2>&1
    sleep 30
fi

# ── P ── положительные контроли: копии образов из /var/tmp, имя comm то же.
if has P; then
    mkdir -p "$OUT/P" /var/tmp/w81h4p
    P=/var/tmp/w81h4p
    cp /bin/cat "$P/systemd-detect-virt"; cp /bin/cat "$P/mandb"
    M > "$OUT/P/m0.txt"; date +%s > "$OUT/P/t0"
    # копия detect-virt читает DMI (mitre_vm_detect_dmi_read)
    "$P/systemd-detect-virt" /sys/class/dmi/id/product_name /sys/class/dmi/id/sys_vendor > /dev/null 2>&1; echo "detect-virt-copy dmi rc=$?" >> "$OUT/P/reads.txt"
    # копия mandb с теми же операциями, что у настоящего (список — PCTL_MANDB_READS)
    for f in ${PCTL_MANDB_READS:-/etc/ld.so.preload /etc/passwd /etc/group}; do "$P/mandb" "$f" > /dev/null 2>&1; echo "mandb-copy read $f rc=$?" >> "$OUT/P/reads.txt"; done
    # копия curl под именем метода APT (comm=http): сетевые эвристики обязаны сработать
    cp /usr/bin/curl "$P/http"
    "$P/http" -s -m 10 -o /dev/null https://archive.ubuntu.com/ > /dev/null 2>&1; echo "http-copy curl rc=$?" >> "$OUT/P/reads.txt"
    "$P/http" -s -m 10 -o /dev/null http://archive.ubuntu.com/ > /dev/null 2>&1; echo "http-copy curl(80) rc=$?" >> "$OUT/P/reads.txt"
    sleep 30
    M > "$OUT/P/m1.txt"; date +%s > "$OUT/P/t1"
    A $(( $(date +%s) - $(cat "$OUT/P/t0") + 5 )) > "$OUT/P/alerts.json"
    rm -rf "$P"
fi

journalctl -u $UNIT --since "@$(cat "$OUT/t-start")" -o cat --no-pager -a > "$OUT/journal.txt"
echo "[$(date -u +%FT%TZ)] done"
echo "done $(date -u +%FT%TZ)" > "$OUT/DONE"
