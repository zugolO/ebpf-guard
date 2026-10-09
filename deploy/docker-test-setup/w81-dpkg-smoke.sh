#!/bin/bash
# w81-dpkg-smoke.sh — волна 8.1, №543: смок починки регрессии ночи H на ОДНОМ
# бинаре, одним плечом (тумблера EBPF_GUARD_FILE_MUTATION_HOOKS больше нет —
# хуки item 7 стоят всегда, и сравнивать нечего: предмет смока — не цена, а
# исход на контролях).
#
# Фазы (каждая между двумя снимками /metrics и с дампом стора):
#   M  только мутации в /lib/modules (добавлена после первого захода 07.10.2026):
#      файлы созданы ДО окна, в окне — mv/truncate/rm/rmdir от root shell. Фаза D
#      этого не меряет: dpkg в /lib/modules делает и open(.dpkg-new), и
#      chmod(каталог.dpkg-new) после mkdir(…, 000) — op 0 и 3, класс до item 7
#      (свидетель strace), а op в сторе нет. Ожидание M:
#      container_escape_module_access 0 по трём слоям, impact срабатывает (он
#      op называет); затем open-контроль — module_access срабатывает.
#   D  dpkg-контроль: крошечный .deb с файлами в /lib/modules/w81-test/,
#      /var/log/w81-test/, /boot/w81-test/, /etc/w81-test/ — установка,
#      переустановка, обновление с удалёнными файлами, purge; затем
#      apt-get install --reinstall bc (libapt: дамп планировщика eipp.log.xz).
#      Ожидание: rename/unlink/rmdir видны в file_events_by_op_total;
#      container_escape_module_access (и его Rego-имя) и четыре лог-правила на
#      этих мутациях — 0 на всех трёх слоях; package-manager считается в
#      rule_exceptions_total.
#   P  положительный контроль item 7 от root shell: truncate/mv/rm/rmdir в
#      /var/log и rmdir в /etc — все четыре лог-правила срабатывают.
#   S  спуф: копия rm под именем dpkg (comm=dpkg, exe=/var/tmp/w81spoof/dpkg)
#      удаляет журнал — срабатывает; rm, запущенный `dpkg --pre-invoke`
#      (родитель — настоящий dpkg) — срабатывает: исключение по ОБРАЗУ самого
#      процесса, не по предку.
#   C  долги 8.1 (08.10.2026), два окна:
#      C1 dpkg-цикл двух пакетов — w81-conf (conffile /etc/w81c.conf; preinst
#         копирует его в /etc/w81c.conf.pre-conffile, postinst удаляет копию —
#         как sudo в ночи H2, №550) и w81-rt (/usr/bin/containerd-w81test —
#         префикс integrity_container_runtime_modified, №547; настоящий
#         containerd не трогается: на стенде k3s). Установка, обновление,
#         purge. Ожидание: impact_mass_file_deletion_critical и
#         integrity_container_runtime_modified — 0 по трём слоям;
#         package-transient-artifact (impact) и package-manager (runtime)
#         считаются в rule_exceptions_total — подавление не вакуумно.
#      C2 положительные контроли от root shell: rm /etc/w81c-victim.conf →
#         impact; приманка rm /var/log/w81c.log.pre-conffile → impact и
#         evasion_log_clear; mv поверх /usr/bin/containerd-w81ctl → runtime;
#         спуф (копия mv под именем dpkg) и mv под dpkg --pre-invoke → runtime.
# Каждый шаг печатает сторож результата ([[positive-control-needs-result-sentinel]])
# и /proc/self/comm исполнителя ([[shebang-control-comm-is-interpreter]]).
# Артефакты контролей — в /var/tmp, не в /root ([[control-artifacts-must-live-outside-root]]).
#
# Запуск на стенде отцепленным процессом; результаты забирать отдельным
# коротким ssh после маркера $OUT/DONE ([[waiting-loop-must-not-ssh-into-window]]).
set -u
OUT=${OUT:-/var/lib/w81-smoke}
WARM=${WARM:-300}
SETUP=/opt/ebpf-guard/deploy/docker-test-setup
REPO=/opt/ebpf-guard
UNIT=ebpf-guard-test.service
BIN=$REPO/build/ebpf-guard
CFG=$SETUP/config-test.yaml
API=http://localhost:19090
W=/var/tmp/w81smoke
TOKEN=$(grep '^admin=' /var/lib/ebpf-guard/token | cut -d= -f2)
M() { curl -s --max-time 30 -H "Authorization: Bearer $TOKEN" "$API/metrics"; }
A() { curl -s --max-time 30 -H "Authorization: Bearer $TOKEN" "$API/api/v1/alerts?since=$(( $(date +%s) - $1 + 5 ))s&limit=5000"; }
die() { echo "DIE: $*" | tee "$OUT/DIE"; echo "die: $*" > "$OUT/DONE"; exit 1; }
selfcomm() { local c; read -r c < /proc/self/comm; echo "$c"; }

rm -rf "$OUT" "$W"; mkdir -p "$OUT" "$W"
exec > "$OUT/smoke.log" 2>&1
echo "[$(date -u +%FT%TZ)] w81-dpkg-smoke: comm исполнителя=$(selfcomm)"

# ── преflight: что меряем ────────────────────────────────────────────────────
[ "$(ps -eo cmd | grep -c '[e]bpf-guard --config')" -eq 1 ] || die "агентов не 1"
"$BIN" version > "$OUT/binary-version.txt" 2>&1
grep -q 'rego=true' "$OUT/binary-version.txt" || die "бинарь без тега rego"
"$BIN" rules --config "$CFG" > "$OUT/rules.txt" 2>&1
n=$(grep -oE '^loaded [0-9]+ rules' "$OUT/rules.txt" | grep -oE '[0-9]+' | head -1)
[ "${n:-0}" -gt 0 ] || die "бинарь не загружает правила (см. rules.txt)"
for id in container_escape_module_access impact_mass_file_deletion_critical evasion_log_clear \
          defense_evasion_journald_log_clear ransomware_log_wipe integrity_container_runtime_modified; do
    grep -q "$id" "$OUT/rules.txt" || die "правило $id не загружено"
done
for t in dpkg-deb dpkg apt-get; do command -v $t > /dev/null || die "нет $t"; done
# №545: правила с сужением container_escape_module_access (ветка посадки
# видит rename root shell'а в фазе M) — отчёт выбирает ожидание по этому файлу.
grep -q 'name: host-module-tooling' $REPO/rules/container-escape.yaml && echo 1 > "$OUT/rules-545.txt" || echo 0 > "$OUT/rules-545.txt"

# ── рестарт с чистым стором ──────────────────────────────────────────────────
systemctl stop $UNIT
rm -f /var/lib/ebpf-guard/test-events.db*
date +%s > "$OUT/t-start"
systemctl start $UNIT
for i in $(seq 1 60); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 $API/health)" = 200 ] && break; sleep 2
done
PID=$(systemctl show -p MainPID --value $UNIT)
sf=$(sha256sum "$BIN" | cut -d' ' -f1); sp=$(sha256sum /proc/$PID/exe | cut -d' ' -f1)
{ echo "path=$BIN"; echo "sha256=$sf"; echo "sha256_proc=$sp"; echo "pid=$PID"
  echo "cmdline=$(tr '\0' ' ' < /proc/$PID/cmdline)"; echo "git=$(git -C $REPO rev-parse HEAD)"
  echo "dirty_rules_go=$(sha256sum $REPO/internal/correlator/rules.go | cut -c1-16)"
  cat "$OUT/binary-version.txt"; } > "$OUT/binary-identity.txt"
[ "$sf" = "$sp" ] || die "sha процесса ≠ sha файла"
sleep 10
journalctl -u $UNIT --since "@$(cat "$OUT/t-start")" -o cat --no-pager -a > "$OUT/journal-start.txt"
grep -a '"mutation_hooks":8' "$OUT/journal-start.txt" > /dev/null || die "mutation_hooks ≠ 8 — хуки item 7 не привязаны, мутаций не будет"
echo "[$(date -u +%FT%TZ)] агент pid $PID sha ${sf:0:12}, прогрев $WARM с"
sleep "$WARM"

# ── M: только мутации в /lib/modules ─────────────────────────────────────────
mm=/lib/modules/w81-mut
mkdir -p $mm/sub && head -c 4096 /dev/urandom > $mm/a.ko && head -c 4096 /dev/urandom > $mm/b.ko
sleep 70   # подготовка (open/O_CREAT) вне окна и вне минуты лимитера
M > "$OUT/mM0.txt"; date +%s > "$OUT/tM0"
{
    echo "comm исполнителя: $(selfcomm)"
    mv $mm/a.ko $mm/a2.ko; echo "rename rc=$? exists=$(test -f $mm/a2.ko && echo 1)"
    # truncate(2) по пути, не coreutils: `truncate -s0` сначала openat(O_CREAT)
    # — op 0, и первый заход 07.10.2026 поймал именно этот open (strace).
    perl -e 'truncate($ARGV[0], 0) or die' $mm/b.ko; echo "truncate(2) rc=$? size=$(stat -c %s $mm/b.ko)"
    rm $mm/a2.ko $mm/b.ko; echo "unlink rc=$? gone=$(test ! -e $mm/a2.ko && test ! -e $mm/b.ko && echo 1)"
    rmdir $mm/sub $mm; echo "rmdir rc=$? gone=$(test ! -e $mm && echo 1)"
} > "$OUT/control-M.txt" 2>&1
sleep 20
M > "$OUT/mM1.txt"; date +%s > "$OUT/tM1"
A $(( $(cat "$OUT/tM1") - $(cat "$OUT/tM0") )) > "$OUT/alerts-M.json"
{
    mkdir -p $mm && head -c 4096 /dev/urandom > $mm/c.ko
    cat $mm/c.ko > /dev/null; echo "open-контроль rc=$?"
    rm -f $mm/c.ko; rmdir $mm
} > "$OUT/control-M-open.txt" 2>&1
sleep 20
M > "$OUT/mM2.txt"; date +%s > "$OUT/tM2"
sleep 40   # выход из минуты лимитера перед D

# ── D: dpkg-контроль ─────────────────────────────────────────────────────────
mkdeb() { # mkdeb <версия> <с-лишними-файлами 0|1>
    local v=$1 extra=$2 r=$W/pkg-$1
    rm -rf "$r"; mkdir -p "$r/DEBIAN" "$r/lib/modules/w81-test/kernel" "$r/var/log/w81-test" \
        "$r/boot/w81-test" "$r/etc/w81-test"
    printf 'Package: w81-test\nVersion: %s\nArchitecture: all\nMaintainer: w81 <w81@localhost>\nDescription: wave 8.1 smoke (№543)\n' "$v" > "$r/DEBIAN/control"
    head -c 4096 /dev/urandom > "$r/lib/modules/w81-test/kernel/a.ko"
    echo "w81 $v" > "$r/lib/modules/w81-test/modules.w81"
    echo "log $v" > "$r/var/log/w81-test/a.log"
    echo "map $v" > "$r/boot/w81-test/System.map"
    echo "conf $v" > "$r/etc/w81-test/x.conf"
    if [ "$extra" = 1 ]; then
        mkdir -p "$r/lib/modules/w81-test/kernel/sub"
        head -c 4096 /dev/urandom > "$r/lib/modules/w81-test/kernel/sub/b.ko"
        echo "log b $v" > "$r/var/log/w81-test/b.log"
    fi
    dpkg-deb --build --root-owner-group "$r" "$W/w81-test_$v.deb" > /dev/null
}
st() { dpkg-query -W -f='${Status} ${Version}' w81-test 2>/dev/null || echo "not-installed"; }
mkdeb 1.0 1 && mkdeb 1.1 0 || die "dpkg-deb не собрал пакет"

M > "$OUT/m0.txt"; date +%s > "$OUT/t0"
{
    echo "comm исполнителя: $(selfcomm)"
    dpkg -i "$W/w81-test_1.0.deb" > "$W/d1.log" 2>&1; echo "install 1.0 rc=$? status=$(st) b.ko=$(test -f /lib/modules/w81-test/kernel/sub/b.ko && echo 1)"
    dpkg -i "$W/w81-test_1.0.deb" > "$W/d2.log" 2>&1; echo "reinstall 1.0 rc=$? status=$(st)"
    dpkg -i "$W/w81-test_1.1.deb" > "$W/d3.log" 2>&1; echo "upgrade 1.1 rc=$? status=$(st) b.ko_gone=$(test ! -e /lib/modules/w81-test/kernel/sub/b.ko && echo 1) sub_gone=$(test ! -e /lib/modules/w81-test/kernel/sub && echo 1) b.log_gone=$(test ! -e /var/log/w81-test/b.log && echo 1)"
    dpkg --purge w81-test > "$W/d4.log" 2>&1; echo "purge rc=$? status=$(st) modules_dir_gone=$(test ! -e /lib/modules/w81-test && echo 1) log_dir_gone=$(test ! -e /var/log/w81-test && echo 1)"
    eipp0=$(stat -c %i /var/log/apt/eipp.log.xz 2>/dev/null || echo none)
    DEBIAN_FRONTEND=noninteractive apt-get install --reinstall -y -q bc > "$W/d5.log" 2>&1
    echo "apt reinstall bc rc=$? eipp_inode $eipp0 → $(stat -c %i /var/log/apt/eipp.log.xz 2>/dev/null || echo none)"
} > "$OUT/control-D.txt" 2>&1
sleep 30
M > "$OUT/m1.txt"; date +%s > "$OUT/t1"
A $(( $(cat "$OUT/t1") - $(cat "$OUT/t0") )) > "$OUT/alerts-D.json"

# ── P: положительный контроль item 7 от root shell ───────────────────────────
r=/var/log/w81ctl e=/etc/w81ctl.d
{
    echo "comm исполнителя: $(selfcomm)"
    mkdir -p $r && echo "mkdir ok"
    echo payload > $r/a.log && echo "write ok"
    truncate -s0 $r/a.log; echo "truncate rc=$? size=$(stat -c %s $r/a.log)"
    mv $r/a.log $r/b.log; echo "rename rc=$? exists_b=$(test -f $r/b.log && echo 1)"
    rm $r/b.log; echo "unlink rc=$? gone=$(test ! -e $r/b.log && echo 1)"
    rmdir $r; echo "rmdir-varlog rc=$? gone=$(test ! -e $r && echo 1)"
    mkdir -p $e && rmdir $e; echo "rmdir-etc rc=$? gone=$(test ! -e $e && echo 1)"
} > "$OUT/control-P.txt" 2>&1
sleep 20
M > "$OUT/m2.txt"; date +%s > "$OUT/t2"
A $(( $(cat "$OUT/t2") - $(cat "$OUT/t1") )) > "$OUT/alerts-P.json"

# ── S: спуф образа и потомок dpkg ────────────────────────────────────────────
S=/var/tmp/w81spoof
{
    mkdir -p $S
    cp /bin/cat $S/dpkg && echo "comm копии под именем dpkg: $($S/dpkg /proc/self/comm)"
    cp /usr/bin/rm $S/dpkg
    echo x > /var/log/w81spoof.log
    $S/dpkg /var/log/w81spoof.log; echo "spoof-unlink rc=$? gone=$(test ! -e /var/log/w81spoof.log && echo 1) exe=$S/dpkg"
    echo x > /var/log/w81pre.log
    dpkg --pre-invoke='rm -f /var/log/w81pre.log' -i "$W/w81-test_1.1.deb" > "$W/s1.log" 2>&1
    echo "pre-invoke rc=$? gone=$(test ! -e /var/log/w81pre.log && echo 1) status=$(st)"
    dpkg --purge w81-test > "$W/s2.log" 2>&1; echo "purge rc=$? status=$(st)"
    rm -rf $S
} > "$OUT/control-S.txt" 2>&1
sleep 20
M > "$OUT/m3.txt"; date +%s > "$OUT/t3"
A $(( $(cat "$OUT/t3") - $(cat "$OUT/t2") )) > "$OUT/alerts-S.json"

# ── C: долги 8.1 — .pre-conffile (№550) и рантайм контейнеров (№547) ───────
sleep 40   # выход из минуты лимитера после S
mkconf() { # mkconf <версия>
    local v=$1 r=$W/conf-$1
    rm -rf "$r"; mkdir -p "$r/DEBIAN" "$r/etc"
    printf 'Package: w81-conf\nVersion: %s\nArchitecture: all\nMaintainer: w81 <w81@localhost>\nDescription: wave 8.1 debt smoke (№550)\n' "$v" > "$r/DEBIAN/control"
    echo "conf $v" > "$r/etc/w81c.conf"
    echo /etc/w81c.conf > "$r/DEBIAN/conffiles"
    # Как sudo.preinst/postinst: копия conffile до распаковки, удаление после.
    printf '#!/bin/sh\nset -e\n[ -f /etc/w81c.conf ] && cp -p /etc/w81c.conf /etc/w81c.conf.pre-conffile\nexit 0\n' > "$r/DEBIAN/preinst"
    printf '#!/bin/sh\nset -e\nrm -f /etc/w81c.conf.pre-conffile\nexit 0\n' > "$r/DEBIAN/postinst"
    chmod 0755 "$r/DEBIAN/preinst" "$r/DEBIAN/postinst"
    dpkg-deb --build --root-owner-group "$r" "$W/w81-conf_$v.deb" > /dev/null
}
mkrt() { # mkrt <версия>
    local v=$1 r=$W/rt-$1
    rm -rf "$r"; mkdir -p "$r/DEBIAN" "$r/usr/bin"
    printf 'Package: w81-rt\nVersion: %s\nArchitecture: all\nMaintainer: w81 <w81@localhost>\nDescription: wave 8.1 debt smoke (№547)\n' "$v" > "$r/DEBIAN/control"
    printf '#!/bin/sh\necho w81 %s\n' "$v" > "$r/usr/bin/containerd-w81test"; chmod 0755 "$r/usr/bin/containerd-w81test"
    dpkg-deb --build --root-owner-group "$r" "$W/w81-rt_$v.deb" > /dev/null
}
stp() { dpkg-query -W -f='${Status} ${Version}' "$1" 2>/dev/null || echo "not-installed"; }
mkconf 1.0 && mkconf 1.1 && mkrt 1.0 && mkrt 1.1 || die "dpkg-deb не собрал пакеты фазы C"

M > "$OUT/mC0.txt"; date +%s > "$OUT/tC0"
{
    echo "comm исполнителя: $(selfcomm)"
    dpkg -i "$W/w81-conf_1.0.deb" > "$W/c1.log" 2>&1; echo "conf install 1.0 rc=$? status=$(stp w81-conf)"
    dpkg -i "$W/w81-conf_1.1.deb" > "$W/c2.log" 2>&1; echo "conf upgrade 1.1 rc=$? status=$(stp w81-conf) pre_conffile_gone=$(test ! -e /etc/w81c.conf.pre-conffile && echo 1)"
    grep -q 'w81c.conf.pre-conffile' "$W/c2.log" && echo "  (dpkg упомянул pre-conffile в выводе)"
    dpkg --purge w81-conf > "$W/c3.log" 2>&1; echo "conf purge rc=$? status=$(stp w81-conf) conf_gone=$(test ! -e /etc/w81c.conf && echo 1)"
    dpkg -i "$W/w81-rt_1.0.deb" > "$W/c4.log" 2>&1; echo "rt install 1.0 rc=$? status=$(stp w81-rt) bin=$(test -x /usr/bin/containerd-w81test && echo 1)"
    dpkg -i "$W/w81-rt_1.1.deb" > "$W/c5.log" 2>&1; echo "rt upgrade 1.1 rc=$? status=$(stp w81-rt) ver=$(/usr/bin/containerd-w81test 2>/dev/null)"
    dpkg --purge w81-rt > "$W/c6.log" 2>&1; echo "rt purge rc=$? status=$(stp w81-rt) bin_gone=$(test ! -e /usr/bin/containerd-w81test && echo 1)"
} > "$OUT/control-C1.txt" 2>&1
sleep 30
M > "$OUT/mC1.txt"; date +%s > "$OUT/tC1"
A $(( $(cat "$OUT/tC1") - $(cat "$OUT/tC0") )) > "$OUT/alerts-C1.json"
sleep 40   # выход из минуты лимитера перед положительными контролями

S=/var/tmp/w81spoof
{
    echo "comm исполнителя: $(selfcomm)"
    echo victim > /etc/w81c-victim.conf
    rm /etc/w81c-victim.conf; echo "victim-unlink rc=$? gone=$(test ! -e /etc/w81c-victim.conf && echo 1)"
    echo bait > /var/log/w81c.log.pre-conffile
    rm /var/log/w81c.log.pre-conffile; echo "bait-unlink rc=$? gone=$(test ! -e /var/log/w81c.log.pre-conffile && echo 1)"
    printf '#!/bin/sh\n' > /usr/bin/containerd-w81ctl.tmp
    mv /usr/bin/containerd-w81ctl.tmp /usr/bin/containerd-w81ctl; echo "rt-shell-rename rc=$? exists=$(test -f /usr/bin/containerd-w81ctl && echo 1)"
    mkdir -p $S && cp /usr/bin/mv $S/dpkg
    printf '#!/bin/sh\n' > /usr/bin/containerd-w81spoof.tmp
    $S/dpkg /usr/bin/containerd-w81spoof.tmp /usr/bin/containerd-w81spoof; echo "rt-spoof-rename rc=$? exists=$(test -f /usr/bin/containerd-w81spoof && echo 1) exe=$S/dpkg"
    printf '#!/bin/sh\n' > /usr/bin/containerd-w81pre.tmp
    dpkg --pre-invoke='mv /usr/bin/containerd-w81pre.tmp /usr/bin/containerd-w81pre' -i "$W/w81-rt_1.0.deb" > "$W/c7.log" 2>&1
    echo "rt-pre-invoke rc=$? exists=$(test -f /usr/bin/containerd-w81pre && echo 1) status=$(stp w81-rt)"
    dpkg --purge w81-rt > "$W/c8.log" 2>&1; echo "rt purge rc=$? status=$(stp w81-rt)"
    rm -f /usr/bin/containerd-w81ctl /usr/bin/containerd-w81spoof /usr/bin/containerd-w81pre
    rm -rf $S
} > "$OUT/control-C2.txt" 2>&1
sleep 20
M > "$OUT/mC2.txt"; date +%s > "$OUT/tC2"
A $(( $(cat "$OUT/tC2") - $(cat "$OUT/tC1") )) > "$OUT/alerts-C2.json"

journalctl -u $UNIT --since "@$(cat "$OUT/t-start")" -o cat --no-pager -a > "$OUT/journal.txt"
cp "$W"/*.log "$OUT/" 2>/dev/null
rm -rf "$W"
echo "[$(date -u +%FT%TZ)] done"
echo "done $(date -u +%FT%TZ)" > "$OUT/DONE"
