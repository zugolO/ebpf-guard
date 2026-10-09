#!/bin/bash
# w549-node-price.sh — долг №549 (вне 8.1): цена ОДНОГО события ноды по каждому
# системному таймеру, поднимавшему 3.ATTACK ночей H/H2. Только измерение —
# правила не меняются (решение за владельцем).
#
# На каждую цель: окно C (контроль, без события) и сразу за ним окно E той же
# длины, в котором цель стартует от ТРАНЗИЕНТНОГО таймера systemd-run,
# взведённого ДО окна (AccuracySec=1s, RemainAfterExit=yes, уникальное имя,
# снимается после) — [[forced-node-event-costs-the-same]]: прямой systemctl
# start из окна сделал бы корнем дерева измеритель. Снимки /metrics на
# границах обоих окон (три слоя по правилам, E − C), стор окна E (цена по
# корню дерева, process_tree[0]), инциденты, тайминг юнита. В окнах скрипт
# только спит — ни exec, ни curl ([[waiting-loop-must-not-ssh-into-window]]).
#
# apt-daily-upgrade (unattended-upgrades) СТАВИТ пакеты: если среди ожидающих
# обновлений есть linux-image/linux-modules, цель пропускается с причиной —
# смена ядра на стенде без решения владельца не делается.
set -u
OUT=${OUT:-/var/lib/w549-price}
WARM=${WARM:-300}
TARGETS=${TARGETS:-"apt-daily.service:300 fwupd-refresh.service:300 apt-daily-upgrade.service:600"}
LEAD=20   # событие на t0+LEAD
SETUP=/opt/ebpf-guard/deploy/docker-test-setup
REPO=/opt/ebpf-guard
UNIT=ebpf-guard-test.service
BIN=$REPO/build/ebpf-guard
API=http://localhost:19090
TOKEN=$(grep '^admin=' /var/lib/ebpf-guard/token | cut -d= -f2)
M() { curl -s --max-time 30 -H "Authorization: Bearer $TOKEN" "$API/metrics"; }
die() { echo "DIE: $*" | tee "$OUT/DIE"; echo "die: $*" > "$OUT/DONE"; exit 1; }

rm -rf "$OUT"; mkdir -p "$OUT"
exec > "$OUT/driver.log" 2>&1
echo "[$(date -u +%FT%TZ)] w549-node-price targets: $TARGETS"

[ "$(ps -eo cmd | grep -c '[e]bpf-guard --config')" -eq 1 ] || die "агентов не 1"
"$BIN" version > "$OUT/binary-version.txt" 2>&1
grep -q 'rego=true' "$OUT/binary-version.txt" || die "бинарь без тега rego"
for t in $TARGETS; do
    u=${t%%:*}; systemctl cat "$u" > /dev/null 2>&1 || die "нет юнита $u"
done

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

n=0
for t in $TARGETS; do
    n=$((n+1)); u=${t%%:*}; W=${t##*:}; D=$OUT/$n-${u%.service}; mkdir -p "$D"
    echo "$u" > "$D/target"; echo "$W" > "$D/window"
    if [ "$u" = apt-daily-upgrade.service ]; then
        apt list --upgradable 2>/dev/null > "$D/upgradable.txt"
        if grep -qE '^linux-(image|modules|headers)' "$D/upgradable.txt"; then
            echo "skipped=ожидает обновление ядра (см. upgradable.txt) — смена ядра без решения владельца не делается" > "$D/skipped"
            echo "[$(date -u +%FT%TZ)] $u пропущен: ядро в очереди"; continue
        fi
    fi
    fu="w549-force-${u%.service}"
    systemctl stop "$fu.timer" "$fu.service" > /dev/null 2>&1
    systemctl reset-failed "$fu.timer" "$fu.service" > /dev/null 2>&1
    sleep 60   # осадка после прошлой цели и минуты лимитера

    # окно C — без события
    M > "$D/mC0.txt"; date +%s > "$D/tC0"
    sleep "$W"
    M > "$D/mC1.txt"; date +%s > "$D/tC1"

    # окно E — событие на t0+LEAD; таймер взводится ДО t0
    err=$(systemd-run --quiet --on-active=$((LEAD + 1))s --timer-property=AccuracySec=1s \
          --property=RemainAfterExit=yes --unit="$fu" /usr/bin/systemctl start "$u" 2>&1) \
        || { echo "systemd-run отказал: $err" > "$D/skipped"; continue; }
    systemctl show -p NextElapseUSecMonotonic --value "$fu.timer" > "$D/timer-next.txt" 2>&1
    M > "$D/mE0.txt"; date +%s > "$D/tE0"
    sleep "$W"
    M > "$D/mE1.txt"; date +%s > "$D/tE1"

    curl -s --max-time 60 -H "Authorization: Bearer $TOKEN" \
        "$API/api/v1/alerts?since=$(( $(cat "$D/tE1") - $(cat "$D/tE0") + 5 ))s&limit=20000" > "$D/alerts-E.json"
    curl -s --max-time 60 -H "Authorization: Bearer $TOKEN" \
        "$API/api/v1/alerts?since=$(( $(date +%s) - $(cat "$D/tC0") + 5 ))s&limit=20000" > "$D/alerts-CE.json"
    curl -s --max-time 60 -H "Authorization: Bearer $TOKEN" "$API/api/v1/incidents?limit=1000" > "$D/incidents.json"
    systemctl show "$u" -p ActiveState -p Result -p ExecMainStartTimestampMonotonic -p ExecMainExitTimestampMonotonic \
        -p ExecMainStartTimestamp -p ExecMainExitTimestamp -p ExecMainStatus -p MainPID > "$D/unit.txt"
    systemctl show "$fu.service" -p ExecMainPID -p ExecMainStartTimestamp > "$D/force-unit.txt"
    cat /proc/uptime > "$D/uptime-after.txt"
    systemctl stop "$fu.timer" "$fu.service" > /dev/null 2>&1
    systemctl reset-failed "$fu.timer" "$fu.service" > /dev/null 2>&1
    [ "$u" = apt-daily-upgrade.service ] && tail -60 /var/log/unattended-upgrades/unattended-upgrades.log > "$D/uu-log-tail.txt" 2>/dev/null
    echo "[$(date -u +%FT%TZ)] $u: окна C [$(cat "$D/tC0"),$(cat "$D/tC1")] E [$(cat "$D/tE0"),$(cat "$D/tE1")]"
done

journalctl -u $UNIT --since "@$(cat "$OUT/t-start")" -o cat --no-pager -a > "$OUT/journal.txt"
echo "[$(date -u +%FT%TZ)] done"
echo "done $(date -u +%FT%TZ)" > "$OUT/DONE"
