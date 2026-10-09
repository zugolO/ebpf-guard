#!/bin/bash
# w549-smoke.sh — смок долгов №549 (б)/(в) после правки правил 09.10.2026.
#
# Фаза F — fwupd: демон fwupd остановлен ДО прогрева, fwupd-refresh стартует
#   от транзиентного таймера (AccuracySec=1s, взведён до t0 —
#   [[forced-node-event-costs-the-same]]), D-Bus поднимает демон с холодного
#   старта, как в 23:02 ночи H2. Окно C той же длины без события — для E − C.
#   Ожидание: инцидент дерева fwupd не attack; семь read-only правил подавлены
#   исключением fwupd-hardware-probe по трём слоям.
# Фаза P — положительный контроль: копия cat под именем fwupd из /var/tmp
#   читает /sys/class/dmi/id/product_uuid, /proc/modules, /proc/version —
#   правила обязаны сработать (exe_path не тот).
# Фаза A — натуральная цена apt-daily (решение владельца 08.10, вариант (в)):
#   update-stamp и update-success-stamp сдвинуты на 2 суток назад, форсируется
#   ТОЛЬКО apt-daily.service (apt-get update, без установки). В окне E живёт
#   свидетель bpftrace, запущенный ДО окна: открытия на запись (O_WRONLY/O_RDWR)
#   и execve — пути временных файлов apt и корни дерева. Исходные mtime
#   штампов возвращаются после окна: натуральный тик apt-daily ночи H3 не
#   должен уйти в пропуск по штампу ([[apt-timers-are-stamp-gated]]).
#
# Инциденты с корнем измерителя (sh/systemctl/systemd форсирования) отчёт судит
# отдельно и в вердикт события не включает. В окнах скрипт только спит.
set -u
OUT=${OUT:-/var/tmp/w549-smoke}
WARM=${WARM:-300}
W=${W:-300}
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

rm -rf "$OUT"; mkdir -p "$OUT"
exec > "$OUT/driver.log" 2>&1
echo "[$(date -u +%FT%TZ)] w549-smoke: F (fwupd-refresh) + P (спуф) + A (apt-daily натурально)"

[ "$(ps -eo cmd | grep -c '[e]bpf-guard --config')" -eq 1 ] || die "агентов не 1"
"$BIN" version > "$OUT/binary-version.txt" 2>&1
grep -q 'rego=true' "$OUT/binary-version.txt" || die "бинарь без тега rego"
command -v bpftrace > /dev/null || die "нет bpftrace — свидетель путей фазы A"
for u in fwupd-refresh.service fwupd.service apt-daily.service; do systemctl cat "$u" > /dev/null 2>&1 || die "нет юнита $u"; done
for s in "${STAMPS[@]}"; do [ -e "$s" ] || die "нет штампа $s"; done
{ for s in "${STAMPS[@]}"; do echo "$s $(stat -c %Y "$s")"; done; } > "$OUT/stamps-orig.txt"

systemctl stop fwupd.service
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
echo "[$(date -u +%FT%TZ)] агент pid $PID sha ${sf:0:12}, прогрев $WARM с; fwupd.service: $(systemctl is-active fwupd.service)"
sleep "$WARM"

# _phase <каталог> <юнит> — окна C и E, событие от транзиентного таймера в E.
_phase() {
    local D="$1" u="$2" fu="w549s-force-${2%.service}" err
    mkdir -p "$D"; echo "$u" > "$D/target"; echo "$W" > "$D/window"
    systemctl stop "$fu.timer" "$fu.service" > /dev/null 2>&1
    systemctl reset-failed "$fu.timer" "$fu.service" > /dev/null 2>&1
    sleep 60
    M > "$D/mC0.txt"; date +%s > "$D/tC0"
    sleep "$W"
    M > "$D/mC1.txt"; date +%s > "$D/tC1"
    [ -n "${PRE_E:-}" ] && eval "$PRE_E"
    err=$(systemd-run --quiet --on-active=$((LEAD + 1))s --timer-property=AccuracySec=1s \
          --property=RemainAfterExit=yes --unit="$fu" /usr/bin/systemctl start "$u" 2>&1) \
        || { echo "systemd-run отказал: $err" > "$D/skipped"; return 1; }
    M > "$D/mE0.txt"; date +%s > "$D/tE0"
    sleep "$W"
    M > "$D/mE1.txt"; date +%s > "$D/tE1"
    A $(( $(date +%s) - $(cat "$D/tC0") + 5 )) > "$D/alerts-CE.json"
    curl -s --max-time 60 -H "Authorization: Bearer $TOKEN" "$API/api/v1/incidents?limit=1000" > "$D/incidents.json"
    systemctl show "$u" -p ActiveState -p Result -p ExecMainStartTimestamp -p ExecMainExitTimestamp -p ExecMainStatus > "$D/unit.txt"
    systemctl show "$fu.service" -p ExecMainPID -p ExecMainStartTimestamp > "$D/force-unit.txt"
    systemctl stop "$fu.timer" "$fu.service" > /dev/null 2>&1
    systemctl reset-failed "$fu.timer" "$fu.service" > /dev/null 2>&1
    echo "[$(date -u +%FT%TZ)] $u: C [$(cat "$D/tC0"),$(cat "$D/tC1")] E [$(cat "$D/tE0"),$(cat "$D/tE1")]"
}

# ── F ──
_phase "$OUT/F" fwupd-refresh.service
systemctl show fwupd.service -p ExecMainStartTimestamp -p MainPID -p ActiveState > "$OUT/F/fwupd-unit.txt"
fp=$(systemctl show -p MainPID --value fwupd.service)
[ -n "$fp" ] && [ "$fp" != 0 ] && readlink "/proc/$fp/exe" > "$OUT/F/fwupd-exe.txt" 2>&1

# ── P ── (после окна E фазы F, вне его)
sleep 60
mkdir -p "$OUT/P" /var/tmp/w549s
cp /bin/cat /var/tmp/w549s/fwupd
M > "$OUT/P/m0.txt"; date +%s > "$OUT/P/t0"
for f in /sys/class/dmi/id/product_uuid /proc/modules /proc/version; do
    /var/tmp/w549s/fwupd "$f" > /dev/null 2>&1
    echo "$f rc=$?" >> "$OUT/P/reads.txt"
done
sleep 30
M > "$OUT/P/m1.txt"; date +%s > "$OUT/P/t1"
A $(( $(date +%s) - $(cat "$OUT/P/t0") + 5 )) > "$OUT/P/alerts.json"
rm -rf /var/tmp/w549s

# ── A ──
PRE_E='for s in "${STAMPS[@]}"; do touch -d "2 days ago" "$s"; done
       { for s in "${STAMPS[@]}"; do echo "$s $(stat -c %Y "$s")"; done; } > "$D/stamps-before.txt"
       setsid bpftrace -e "tracepoint:syscalls:sys_enter_openat /(args->flags & 3) != 0/ { printf(\"O %d %s %d %s\n\", pid, comm, args->flags, str(args->filename)); } tracepoint:syscalls:sys_enter_execve { printf(\"X %d %s %s\n\", pid, comm, str(args->filename)); }" > "$D/bpf.txt" 2> "$D/bpf.err" < /dev/null &
       echo $! > "$D/bpf.pid"; sleep 5'
_phase "$OUT/A" apt-daily.service
kill "$(cat "$OUT/A/bpf.pid")" 2>/dev/null; sleep 1
{ for s in "${STAMPS[@]}"; do echo "$s $(stat -c %Y "$s")"; done; } > "$OUT/A/stamps-after.txt"
# Исходные mtime назад: натуральный тик ночи H3 обязан решать по прежнему штампу.
while read -r s t; do touch -d "@$t" "$s"; done < "$OUT/stamps-orig.txt"
{ for s in "${STAMPS[@]}"; do echo "$s $(stat -c %Y "$s")"; done; } > "$OUT/A/stamps-restored.txt"
journalctl -u apt-daily.service --since "@$(cat "$OUT/A/tE0")" -o short-iso --no-pager > "$OUT/A/apt-daily-journal.txt" 2>&1

journalctl -u $UNIT --since "@$(cat "$OUT/t-start")" -o cat --no-pager -a > "$OUT/journal.txt"
echo "[$(date -u +%FT%TZ)] done"
echo "done $(date -u +%FT%TZ)" > "$OUT/DONE"
