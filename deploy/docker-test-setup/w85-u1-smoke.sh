#!/bin/bash
# w85-u1-smoke.sh <API host:port> <TOKEN> [метка] — волна 8.5, U1: юнит systemd в событии ядра.
# Предъявляет КЛАСС (ноль без класса не судится, память verdict-zero-needs-its-class-presented):
# форсированный юнит system.slice с охранным comm и путём, у которых сходится охрана правил
# apt-key-gpghome-unit / defense-evasion — оценка правила доходит до proc.systemd_unit, то есть
# резолвер ВЫЗЫВАЕТСЯ. Юнит транзитный, имя w85-u1probe-<ts>.service, лежит прямо под system.slice.
#   до/после: systemd_unit_lookups_total{result=resolved}, systemd_unit_scans_total (полный обход),
#   systemd_unit_top_scans_total (верхний уровень, U1).
# ДОСТИГНУТО: U1 — resolved вырос (≥ 1) И полных сканов за пробу 0 (U1_MAX_FULL_SCANS, умолч. 0).
# НЕИЗМЕРИМ — нет серий или проба не создала юнит. Окружение: U1_PROBE_CMD заменяет systemd-run (фикстуры).
set -u
API=${1:?usage: w85-u1-smoke.sh <host:port> <token> [label]}; TOKEN=${2:?}; LABEL=${3:-u1}
MAXFULL=${U1_MAX_FULL_SCANS:-0}
M() { curl -s --max-time 30 -H "Authorization: Bearer $TOKEN" "http://$API/metrics"; }
val() { awk -v n="$2" -v l="${3:-}" '/^#/ { next } { name = $1; sub(/\{.*/, "", name) } name == n && (l == "" || index($1, l)) { s += $NF; f = 1 } END { if (f) printf "%.0f", s }' "$1"; }
D=$(mktemp -d); trap 'rm -rf "$D"' EXIT
M > "$D/before.txt"
for m in systemd_unit_lookups_total systemd_unit_scans_total systemd_unit_top_scans_total; do
    [ -n "$(val "$D/before.txt" "ebpf_guard_$m")" ] || { echo "НЕИЗМЕРИМ: U1/$LABEL НЕИЗМЕРИМ (класс НАЗВАН: нет серии ebpf_guard_$m — бинарь без U1)"; exit 0; }
done
R0=$(val "$D/before.txt" ebpf_guard_systemd_unit_lookups_total 'result="resolved"')
S0=$(val "$D/before.txt" ebpf_guard_systemd_unit_scans_total)
T0=$(val "$D/before.txt" ebpf_guard_systemd_unit_top_scans_total)
U=w85-u1probe-$(date +%s)
DIRN=/tmp/apt-key-gpghome.$(head -c 64 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 10)
CMD=${U1_PROBE_CMD:-"systemd-run --quiet --unit=$U /bin/sh -c 'mkdir -p $DIRN; for i in 1 2 3 4 5; do cp /etc/hostname $DIRN/f\$i; sleep 3; done; rm -rf $DIRN'"}
echo "проба: $U (comm cp, путь $DIRN/f*)"
eval "$CMD" > "$D/probe.out" 2>&1 || { echo "НЕИЗМЕРИМ: U1/$LABEL НЕИЗМЕРИМ (класс НАЗВАН: проба не стартовала: $(head -c 200 "$D/probe.out"))"; exit 0; }
sleep 25
M > "$D/after.txt"
R1=$(val "$D/after.txt" ebpf_guard_systemd_unit_lookups_total 'result="resolved"')
S1=$(val "$D/after.txt" ebpf_guard_systemd_unit_scans_total)
T1=$(val "$D/after.txt" ebpf_guard_systemd_unit_top_scans_total)
echo "  resolved: $R0 → ${R1:-?}; полных сканов (systemd_unit_scans_total): $S0 → ${S1:-?}; сканов верхнего уровня: $T0 → ${T1:-?}"
for l in unresolved no_resolver; do echo "  $l: $(val "$D/before.txt" ebpf_guard_systemd_unit_lookups_total "result=\"$l\"") → $(val "$D/after.txt" ebpf_guard_systemd_unit_lookups_total "result=\"$l\"")"; done
if [ -z "$R1" ] || [ -z "$S1" ]; then
    echo "НЕИЗМЕРИМ: U1/$LABEL НЕИЗМЕРИМ (класс НАЗВАН: серии пропали после пробы)"
elif [ $((R1 - R0)) -lt 1 ]; then
    echo "ПРОВАЛЕН: U1/$LABEL ПРОВАЛЕН (resolved не вырос за пробу: охрана правила сошлась, а юнит не разрешён — U1 не работает или проба не дошла до поля)"
elif [ $((S1 - S0)) -gt "$MAXFULL" ]; then
    echo "ПРОВАЛЕН: U1/$LABEL ПРОВАЛЕН (resolved +$((R1 - R0)), но полных сканов $((S1 - S0)) > $MAXFULL — резолвер идёт запасным путём)"
else
    echo "ДОСТИГНУТО: U1/$LABEL ДОСТИГНУТО (resolved +$((R1 - R0)) за пробу, полных сканов $((S1 - S0)), сканов верхнего уровня $((T1 - T0)))"
fi
