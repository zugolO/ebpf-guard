#!/bin/bash
# w81-h5-smoke.sh — смок остатка №549 (10.10.2026): после ночи H4 3.ATTACK
# держали два инцидента натурального тика apt-daily 03:17 — apt-daily.service
# (score 59) и esm-cache.service (score 50). Правки:
#   * impact_systemd_service_disabled — предикат stop/disable/mask/kill/isolate
#     (или пустой proc.args), а не «root исполнил systemctl»;
#   * container_escape_init_proc — исключения apt-method-init-cgroup (образ) и
#     node-timer-detect-virt (юнит system.slice по cgroup_id, proc.systemd_unit);
#   * trusted_units стенда += apt-news.service, esm-cache.service.
# Фазы (PHASES="A E F P"):
#   A — форсированный apt-daily со сдвигом штампов (настоящий apt-get update,
#       его хук сам стартует apt-news/esm-cache — форма H4);
#   E — прямой `systemctl start esm-cache.service apt-news.service` — та же
#       команда, что в H4 отдал apt.systemd.daily;
#   F — форсированный fwupd-refresh (его исключение в H4 не тикало);
#   P — положительные контроли: systemctl stop, systemctl под exec -a,
#       systemd-detect-virt в НЕдоверенном юните, копия метода APT из /var/tmp.
# Вердикт каждой фазы — дельта ebpf_guard_incidents_total{verdict="attack"}
# в окне E против окна C той же длины без события. В окнах скрипт только спит
# ([[waiting-loop-must-not-ssh-into-window]]). Штампы apt возвращаются к
# исходным mtime ([[apt-timers-are-stamp-gated]]).
set -u
OUT=${OUT:-/var/tmp/w81-h5-smoke}
PHASES=${PHASES:-"A E F P"}
WARM=${WARM:-300}
W=${W:-240}
LEAD=20
REPO=/opt/ebpf-guard
UNIT=ebpf-guard-test.service
BIN=$REPO/build/ebpf-guard
API=http://localhost:19090
TOKEN=$(grep '^admin=' /var/lib/ebpf-guard/token | cut -d= -f2)
STAMPS=(/var/lib/apt/periodic/update-stamp /var/lib/apt/periodic/update-success-stamp)
M() { curl -s --max-time 30 -H "Authorization: Bearer $TOKEN" "$API/metrics"; }
A() { curl -s --max-time 60 -H "Authorization: Bearer $TOKEN" "$API/api/v1/alerts?since=$1s&limit=20000"; }
I() { curl -s --max-time 60 -H "Authorization: Bearer $TOKEN" "$API/api/v1/incidents?limit=1000"; }
die() { echo "DIE: $*"; echo "die: $*" > "$OUT/DONE"; exit 1; }
has() { case " $PHASES " in *" $1 "*) return 0;; esac; return 1; }

rm -rf "$OUT"; mkdir -p "$OUT"
exec > "$OUT/driver.log" 2>&1
echo "[$(date -u +%FT%TZ)] w81-h5-smoke: фазы $PHASES"

[ "$(ps -eo cmd | grep -c '[e]bpf-guard --config')" -eq 1 ] || die "агентов не 1"
"$BIN" version > "$OUT/binary-version.txt" 2>&1
grep -q 'rego=true' "$OUT/binary-version.txt" || die "бинарь без тега rego"
for u in apt-daily.service esm-cache.service apt-news.service fwupd-refresh.service; do
    systemctl cat "$u" > /dev/null 2>&1 || die "нет юнита $u"
done
[ -d /sys/fs/cgroup/system.slice ] || die "нет /sys/fs/cgroup/system.slice — ось юнита неизмерима"
for s in "${STAMPS[@]}"; do [ -e "$s" ] || die "нет штампа $s"; done
{ for s in "${STAMPS[@]}"; do echo "$s $(stat -c %Y "$s")"; done; } > "$OUT/stamps-orig.txt"
CFG=$(ps -eo cmd | sed -n 's/.*[e]bpf-guard --config[= ]\([^ ]*\).*/\1/p' | head -1)
[ -f "$CFG" ] || die "конфиг агента не найден по командной строке ($CFG)"
echo "$CFG" > "$OUT/config-path.txt"
awk '/^[[:space:]]*trusted_units:/{f=1;next} f&&/^[[:space:]]*(#|$)/{next} f&&/^[[:space:]]*-/{print;next} f{exit}' "$CFG" > "$OUT/trusted-units.txt"
grep -q 'esm-cache.service' "$OUT/trusted-units.txt" || die "esm-cache.service нет в trusted_units ($CFG)"
grep -q 'name: node-timer-detect-virt' $REPO/rules/container-escape.yaml || die "правила на диске без node-timer-detect-virt"

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
M | grep -q '^ebpf_guard_systemd_unit_lookups_total{' || die "бинарь без ebpf_guard_systemd_unit_lookups_total"
echo "[$(date -u +%FT%TZ)] агент pid $PID sha ${sf:0:12}, прогрев $WARM с"
sleep "$WARM"

# _phase <каталог> <имя> <окно> <команда события...> — C, затем E с событием.
_phase() {
    local D="$1" name="$2" win="$3"; shift 3
    local fu="w81h5-force-$name" err
    mkdir -p "$D"; echo "$name" > "$D/target"; echo "$win" > "$D/window"; echo "$*" > "$D/command"
    systemctl stop "$fu.timer" "$fu.service" > /dev/null 2>&1
    systemctl reset-failed "$fu.timer" "$fu.service" > /dev/null 2>&1
    sleep 60
    M > "$D/mC0.txt"; date +%s > "$D/tC0"
    sleep "$win"
    M > "$D/mC1.txt"; date +%s > "$D/tC1"
    [ -n "${PRE_E:-}" ] && eval "$PRE_E"
    err=$(systemd-run --quiet --on-active=$((LEAD + 1))s --timer-property=AccuracySec=1s \
          --property=RemainAfterExit=yes --unit="$fu" "$@" 2>&1) \
        || { echo "systemd-run отказал: $err" > "$D/skipped"; return 1; }
    M > "$D/mE0.txt"; date +%s > "$D/tE0"
    sleep "$win"
    M > "$D/mE1.txt"; date +%s > "$D/tE1"
    A $(( $(date +%s) - $(cat "$D/tC0") + 5 )) > "$D/alerts-CE.json"
    I > "$D/incidents.json"
    systemctl show "$fu.service" -p ActiveState -p Result -p ExecMainStartTimestamp -p ExecMainExitTimestamp -p ExecMainStatus > "$D/force-unit.txt"
    systemctl stop "$fu.timer" "$fu.service" > /dev/null 2>&1
    systemctl reset-failed "$fu.timer" "$fu.service" > /dev/null 2>&1
    echo "[$(date -u +%FT%TZ)] $name: C [$(cat "$D/tC0"),$(cat "$D/tC1")] E [$(cat "$D/tE0"),$(cat "$D/tE1")]"
}

_units_journal() { # <каталог> <юниты...>
    local D="$1"; shift
    local u
    for u in "$@"; do
        journalctl -u "$u" --since "@$(cat "$D/tE0")" -o short-iso --no-pager > "$D/journal-$u.txt" 2>&1
    done
}

if has A; then
    PRE_E='for s in "${STAMPS[@]}"; do touch -d "2 days ago" "$s"; done
           { for s in "${STAMPS[@]}"; do echo "$s $(stat -c %Y "$s")"; done; } > "$D/stamps-before.txt"'
    _phase "$OUT/A" apt-daily "$W" /usr/bin/systemctl start apt-daily.service
    PRE_E=
    { for s in "${STAMPS[@]}"; do echo "$s $(stat -c %Y "$s")"; done; } > "$OUT/A/stamps-after.txt"
    while read -r s t; do touch -d "@$t" "$s"; done < "$OUT/stamps-orig.txt"
    { for s in "${STAMPS[@]}"; do echo "$s $(stat -c %Y "$s")"; done; } > "$OUT/A/stamps-restored.txt"
    _units_journal "$OUT/A" apt-daily.service apt-news.service esm-cache.service
    sleep 30
fi

if has E; then
    _phase "$OUT/E" esm-news "$W" /usr/bin/systemctl start esm-cache.service apt-news.service
    _units_journal "$OUT/E" apt-news.service esm-cache.service
    sleep 30
fi

if has F; then
    _phase "$OUT/F" fwupd-refresh "$W" /usr/bin/systemctl start fwupd-refresh.service
    _units_journal "$OUT/F" fwupd-refresh.service fwupd.service
    sleep 30
fi

# ── P ── положительные контроли: каждая правка обязана не ослепить правило.
if has P; then
    D="$OUT/P"; mkdir -p "$D" /var/tmp/w81h5p
    P=/var/tmp/w81h5p
    M > "$D/m0.txt"; date +%s > "$D/t0"
    # P1: настоящая остановка юнита от root → impact_systemd_service_disabled.
    systemd-run --quiet --unit=w81h5-dummy /bin/sleep 600; sleep 2
    /usr/bin/systemctl stop w81h5-dummy.service; echo "P1 systemctl stop rc=$?" >> "$D/steps.txt"
    # P2: остановка под спуфом argv[0]. Основной путь коллектора (exec_ts)
    #     argv не обнуляет — глагол виден; запасной (/proc) обнуляет — ветка
    #     «пустой proc.args». Правило обязано сработать на любом из двух.
    systemd-run --quiet --unit=w81h5-dummy2 /bin/sleep 600; sleep 2
    bash -c 'exec -a w81h5-spoof /usr/bin/systemctl stop w81h5-dummy2.service'; echo "P2 exec -a systemctl stop rc=$?" >> "$D/steps.txt"
    # N1: чтение состояния без спуфа — правило обязано молчать.
    /usr/bin/systemctl is-active -q ssh.service; echo "N1 systemctl is-active rc=$?" >> "$D/steps.txt"
    # P3: настоящий systemd-detect-virt в НЕдоверенном юните читает /proc/1/environ.
    systemd-run --quiet --wait --unit=w81h5-virt /usr/bin/systemd-detect-virt > /dev/null 2>&1; echo "P3 detect-virt в w81h5-virt.service rc=$?" >> "$D/steps.txt"
    # P4: копия под именем метода APT из /var/tmp читает /proc/1/cgroup.
    cp /bin/cat "$P/http"; "$P/http" /proc/1/cgroup > /dev/null 2>&1; echo "P4 /var/tmp/http /proc/1/cgroup rc=$?" >> "$D/steps.txt"
    sleep 30
    M > "$D/m1.txt"; date +%s > "$D/t1"
    A $(( $(date +%s) - $(cat "$D/t0") + 5 )) > "$D/alerts.json"
    systemctl reset-failed w81h5-dummy.service w81h5-dummy2.service w81h5-virt.service > /dev/null 2>&1
    rm -rf "$P"
fi

journalctl -u $UNIT --since "@$(cat "$OUT/t-start")" -o cat --no-pager -a > "$OUT/journal.txt"
echo "[$(date -u +%FT%TZ)] done"
echo "done $(date -u +%FT%TZ)" > "$OUT/DONE"
