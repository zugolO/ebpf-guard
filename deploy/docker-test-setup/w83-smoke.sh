#!/bin/bash
# w83-smoke.sh — смок долгов 8.3 (10.10.2026): п. 8.3.1, 8.3.2, 8.3.3.
#   8.3.1 — impact_systemd_service_disabled: исключение deb-systemd-invoke-stop
#           по образу РОДИТЕЛЯ (proc.parent_exe_path = /usr/bin/deb-systemd-invoke).
#           Событие — `dpkg -r` + `apt-get install` пакета с сервисом в
#           транзиентном юните: prerm remove зовёт deb-systemd-invoke stop
#           (`--reinstall` СТОП НЕ ДАЁТ — prerm только на remove, postinst —
#           restart; проверено на стенде 10.10.2026). Свидетель образа родителя —
#           цикл-сэмплер /proc, не агент.
#   8.3.2 — мягкие правила systemd-detect-virt под таймерным юнитом (ось
#           proc.systemd_unit): mitre_vm_detect_dmi_read, mitre_sandbox_detect_proc_read,
#           sigma_memory_proc_dump, sigma_cpu_info_access.
#   8.3.3 — evasion_hidden_elf_in_tmp на apt-daily: apt-gpgv-tmp-unit,
#           apt-key-gpghome-unit.
# Фазы (PHASES="A E I P"):
#   A — форсированный apt-daily со сдвигом штампов (8.3.3; заодно 8.3.2);
#   E — `systemctl start esm-cache.service apt-news.service` (detect-virt, 8.3.2);
#   I — remove/install irqbalance в транзиентном юните (8.3.1);
#   P — положительные контроли каждой правки: detect-virt в НЕдоверенном юните,
#       apt-key-подобная запись вне юнита, остановка из копии родителя, голый stop.
# Окно C — той же длины без события; в окнах скрипт только спит
# ([[waiting-loop-must-not-ssh-into-window]]). Штампы apt возвращаются.
set -u
OUT=${OUT:-/var/tmp/w83-smoke}
PHASES=${PHASES:-"A E I P"}
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
echo "[$(date -u +%FT%TZ)] w83-smoke: фазы $PHASES"

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
for x in "node-timer-detect-virt:rules/mitre-additional.yaml" "node-timer-detect-virt:rules/sigma-linux.yaml" "apt-gpgv-tmp-unit:rules/defense-evasion.yaml" "apt-key-gpghome-unit:rules/defense-evasion.yaml" "deb-systemd-invoke-stop:rules/impact-gaps.yaml"; do
    grep -q "name: ${x%%:*}" "$REPO/${x#*:}" || die "правила на диске без ${x%%:*} (${x#*:})"
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
M | grep -q '^ebpf_guard_systemd_unit_lookups_total{' || die "бинарь без ebpf_guard_systemd_unit_lookups_total"
echo "[$(date -u +%FT%TZ)] агент pid $PID sha ${sf:0:12}, прогрев $WARM с"
sleep "$WARM"

# _phase <каталог> <имя> <окно> <команда события...> — C, затем E с событием.
_phase() {
    local D="$1" name="$2" win="$3"; shift 3
    local fu="w83-force-$name" err
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

# ── I ── 8.3.1: настоящая остановка сервиса из prerm под dpkg.
if has I; then
    D="$OUT/I"; mkdir -p "$D"
    dpkg -s irqbalance > /dev/null 2>&1 || die "irqbalance не установлен"
    head -1 /usr/bin/deb-systemd-invoke > "$D/invoke-shebang.txt"
    readlink -f /usr/bin/perl >> "$D/invoke-shebang.txt"
    sleep 60
    M > "$D/mC0.txt"; date +%s > "$D/tC0"; sleep "$W"; M > "$D/mC1.txt"; date +%s > "$D/tC1"
    # сэмплер образа родителя у каждого systemctl (второй свидетель, не агент)
    ( while :; do
        for p in $(pgrep -x systemctl 2>/dev/null); do
            pp=$(awk '/^PPid:/{print $2}' /proc/$p/status 2>/dev/null)
            [ -n "$pp" ] && echo "$(date +%s.%N) systemctl=$p args=$(tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null) ppid=$pp parent_exe=$(readlink /proc/$pp/exe 2>/dev/null) parent_comm=$(cat /proc/$pp/comm 2>/dev/null)"
        done; sleep 0.01; done ) > "$D/parent-sampler.txt" 2>&1 &
    SAMP=$!
    M > "$D/mE0.txt"; date +%s > "$D/tE0"
    systemd-run --quiet --wait --unit=w83-pkg --collect /bin/sh -c 'dpkg -r irqbalance; echo "dpkg -r rc=$?"; apt-get install -y irqbalance; echo "apt-get install rc=$?"' > "$D/pkg.log" 2>&1
    echo "systemd-run rc=$?" >> "$D/pkg.log"
    sleep $(( W > 60 ? W - 60 : 30 ))
    kill $SAMP 2>/dev/null; wait $SAMP 2>/dev/null
    M > "$D/mE1.txt"; date +%s > "$D/tE1"
    A $(( $(date +%s) - $(cat "$D/tC0") + 5 )) > "$D/alerts-CE.json"
    I > "$D/incidents.json"
    dpkg -s irqbalance | sed -n '1,3p' > "$D/dpkg-after.txt"; systemctl is-active irqbalance >> "$D/dpkg-after.txt"
    echo "target" > "$D/target"; echo "dpkg -r irqbalance && apt-get install irqbalance" > "$D/command"
    sleep 30
fi

# ── P ── положительные контроли: каждая правка обязана не ослепить правило.
if has P; then
    D="$OUT/P"; mkdir -p "$D" /var/tmp/w83p
    P=/var/tmp/w83p
    M > "$D/m0.txt"; date +%s > "$D/t0"
    # P1: голый systemctl stop от root (родитель — не deb-systemd-invoke) → impact.
    systemd-run --quiet --unit=w83-dummy /bin/sleep 600; sleep 2
    /usr/bin/systemctl stop w83-dummy.service; echo "P1 systemctl stop rc=$?" >> "$D/steps.txt"
    # P2: stop из копии родителя под тем же именем — образ не /usr/bin/deb-systemd-invoke → impact.
    systemd-run --quiet --unit=w83-dummy2 /bin/sleep 600; sleep 2
    cp /usr/bin/perl "$P/deb-systemd-invoke"
    "$P/deb-systemd-invoke" -e 'system("/usr/bin/systemctl","stop","w83-dummy2.service")'; echo "P2 stop из копии deb-systemd-invoke rc=$?" >> "$D/steps.txt"
    # P3: stop из perl-родителя (интерпретатор вместо скрипта) → impact.
    systemd-run --quiet --unit=w83-dummy3 /bin/sleep 600; sleep 2
    /usr/bin/perl -e 'system("/usr/bin/systemctl","stop","w83-dummy3.service")'; echo "P3 stop из /usr/bin/perl rc=$?" >> "$D/steps.txt"
    # P4: настоящий systemd-detect-virt в НЕдоверенном юните → четыре мягких правила (что он читает — видно в отчёте).
    systemd-run --quiet --wait --unit=w83-virt /usr/bin/systemd-detect-virt > /dev/null 2>&1; echo "P4 detect-virt в w83-virt.service rc=$?" >> "$D/steps.txt"
    # P5: запись apt-key-формы вне юнита (сессия ssh, user.slice) → evasion_hidden_elf_in_tmp.
    mkdir /tmp/apt-key-gpghome.Ab3dEf9hIj; cp /bin/true /tmp/apt-key-gpghome.Ab3dEf9hIj/pubring.gpg; echo "P5 cp в /tmp/apt-key-gpghome.* из сессии rc=$?" >> "$D/steps.txt"
    # P6: то же из чужого системного юнита (не apt-daily) → тоже срабатывает.
    systemd-run --quiet --wait --unit=w83-tmpwriter /bin/cp /bin/true /tmp/apt-key-gpghome.Ab3dEf9hIj/trustdb.gpg > /dev/null 2>&1; echo "P6 cp из w83-tmpwriter.service rc=$?" >> "$D/steps.txt"
    sleep 30
    M > "$D/m1.txt"; date +%s > "$D/t1"
    A $(( $(date +%s) - $(cat "$D/t0") + 5 )) > "$D/alerts.json"
    systemctl reset-failed w83-dummy.service w83-dummy2.service w83-dummy3.service w83-virt.service w83-tmpwriter.service > /dev/null 2>&1
    rm -rf "$P" /tmp/apt-key-gpghome.Ab3dEf9hIj
fi

journalctl -u $UNIT --since "@$(cat "$OUT/t-start")" -o cat --no-pager -a > "$OUT/journal.txt"
echo "[$(date -u +%FT%TZ)] done"
echo "done $(date -u +%FT%TZ)" > "$OUT/DONE"
