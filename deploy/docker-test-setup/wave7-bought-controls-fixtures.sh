#!/usr/bin/env bash
# wave7-bought-controls-fixtures.sh — фикстуры РАЗБОРА сторожевого файла контролей
# купленных правил (wave7-bought-rules-controls.sh, W7B_MODE=analyze). Нагрузки
# здесь не запускаются (это Linux/x86_64 на стенде); проверяется то, что решает
# КЛАСС правила: вердикт даёт величина из файлов, а не рассуждение.
#
# Каждый класс — своя фикстура, и у каждой есть ПАРНЫЙ негатив, который обязан
# дать ДРУГОЙ класс: иначе зелёный разбор значил бы лишь «случай не встречался»
# (правило 1 постановки, №514).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
CTL="$HERE/wave7-bought-rules-controls.sh"
T=$(mktemp -d /tmp/w7bought.XXXXXX); trap 'rm -rf "$T"' EXIT
FAIL=0
ok()  { echo "  OK    $1"; }
bad() { echo "  FAIL  $1"; FAIL=1; }
command -v jq >/dev/null || { echo "jq нет — фикстуры не исполнимы"; exit 2; }

NOW=$(date +%s)
iso() { date -u -r "$1" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ; }

# _case <имя> — чистит каталог артефактов, строки добавляет _pay/_met/_alert
_case() { A="$T/$1"; rm -rf "$A"; mkdir -p "$A"; : > "$A/bought-payloads.txt"; : > "$A/bought-metrics-before.txt"; : > "$A/bought-metrics-after.txt"; echo '[]' > "$A/bought-alerts-after.json"; ALERTS=""; }
# _pay <rule> <nr> <pid> <comm> <rc> [open=yes]
_pay() { echo "rule=$1 payload_nr=$2 t=$NOW pids=$3 comm=$4 expect_comm=python3 rc=$5 errno=0 open=${6:-yes}" >> "$A/bought-payloads.txt"; }
# _met <before|after> <nr> <значение>
_met() { echo "ebpf_guard_syscall_events_by_nr_total{nr=\"$2\"} $3" >> "$A/bought-metrics-$1.txt"; }
_lim() { echo "ebpf_guard_alerts_ratelimited_by_rule_total{rule_id=\"$2\"} $3" >> "$A/bought-metrics-$1.txt"; }
_ren() { echo "ebpf_guard_alert_rule_id_renamed_total{base_rule_id=\"$2\",rule_id=\"$3\"} 1" >> "$A/bought-metrics-$1.txt"; }
# _alert <rule_id> <pid> <epoch> [суффикс времени]
_alert() {
    local ts; ts="$(iso "$3")"
    [ -n "${4:-}" ] && ts="${ts%Z}$4"
    ALERTS="${ALERTS}${ALERTS:+,}{\"rule_id\":\"$1\",\"pid\":$2,\"comm\":\"python3\",\"timestamp\":\"$ts\"}"
    echo "[$ALERTS]" > "$A/bought-alerts-after.json"
}
_run() { W7B_ART="$A" W7B_CONTROL=on W7B_MODE=analyze bash "$CTL" >/dev/null 2>&1; cat "$A/bought-rules-controls.txt"; }
_cls_of() { printf '%s\n' "$1" | sed -n "s/^rule=$2 class=\([A-Z_]*\).*/\1/p"; }
expect() { # <имя> <вывод> <rule> <класс>
    local got; got=$(_cls_of "$2" "$3")
    if [ "$got" = "$4" ]; then ok "$1: $3 = $4"; else bad "$1: $3 дал '$got', ожидался $4 — $(printf '%s' "$2" | head -3 | cut -c1-200)"; fi
}

echo "[класс SHOWN и его парные негативы]"
_case shown; _pay r_a 62 111 python3 0; _met before 62 10; _met after 62 14; _alert r_a 111 $NOW
o=$(_run); expect "алерт по pid нагрузки" "$o" r_a SHOWN

_case shown_ren; _pay r_a 62 111 python3 0; _met before 62 10; _met after 62 14; _ren after r_a r_a_renamed; _alert r_a_renamed 111 $NOW
o=$(_run); expect "алерт под Rego-переименованием зачтён" "$o" r_a SHOWN
_case shown_ren_neg; _pay r_a 62 111 python3 0; _met before 62 10; _met after 62 14; _alert r_a_renamed 111 $NOW
o=$(_run); expect "то же БЕЗ серии переименования — не зачтён (SILENT)" "$o" r_a SILENT

_case other_pid; _pay r_a 62 111 python3 0; _met before 62 10; _met after 62 14; _alert r_a 222 $NOW
o=$(_run); expect "алерт того же правила от ЧУЖОГО pid не засчитывается" "$o" r_a SILENT

_case old_alert; _pay r_a 62 111 python3 0; _met before 62 10; _met after 62 14; _alert r_a 111 $((NOW - 3600))
o=$(_run); expect "алерт того же pid часовой давности не засчитывается" "$o" r_a SILENT

_case tz_frac; _pay r_a 62 111 python3 0; _met before 62 10; _met after 62 14; _alert r_a 111 $NOW ".123456789+00:00"
o=$(_run); expect "метка времени с долей секунды и +00:00 разбирается" "$o" r_a SHOWN

echo "[SWALLOWED против SILENT: слои подавления разводят их]"
_case swallowed; _pay r_a 62 111 python3 0; _met before 62 10; _met after 62 14; _lim before r_a 5; _lim after r_a 8
o=$(_run); expect "лимитер вырос, алерта нет" "$o" r_a SWALLOWED
_case silent; _pay r_a 62 111 python3 0; _met before 62 10; _met after 62 14; _lim before r_a 5; _lim after r_a 5
o=$(_run); expect "событие доехало, слои не выросли, алерта нет" "$o" r_a SILENT

echo "[приборные классы]"
_case no_event; _pay r_a 62 111 python3 0; _met before 62 10; _met after 62 10
o=$(_run); expect "ось nr не выросла" "$o" r_a NO_EVENT
_case no_event_noaxis; _pay r_a 62 111 python3 0; _met before 99 1; _met after 99 1
o=$(_run); expect "серии nr нет в снимках — не SILENT" "$o" r_a NO_EVENT
_case not_open; _pay r_a 62 0 - -9 no; _met before 99 1; _met after 99 1
o=$(_run); expect "номер не в аллоулисте рантайма" "$o" r_a NOT_OPEN
_case instr_comm; _pay r_a 62 111 sh 0; _met before 62 10; _met after 62 14
o=$(_run); expect "comm нагрузки не тот — результатный сторож" "$o" r_a INSTRUMENT
_case instr_noresult; _pay r_a 62 0 - -9; _met before 62 10; _met after 62 14
o=$(_run); expect "нагрузка не напечатала результат" "$o" r_a INSTRUMENT

echo "[несколько правил в одном файле не мешают друг другу]"
_case multi; _pay r_a 62 111 python3 0; _pay r_b 280 222 python3 0
_met before 62 10; _met after 62 14; _met before 280 3; _met after 280 3; _alert r_a 111 $NOW
o=$(_run); expect "r_a SHOWN при соседе" "$o" r_a SHOWN; expect "r_b NO_EVENT при соседе" "$o" r_b NO_EVENT

echo "[входы]"
_case miss; _met before 62 1; rm -f "$A/bought-metrics-after.txt"; _pay r_a 62 111 python3 0
o=$(_run); [ "$(printf '%s' "$o" | head -1)" = "class=input_missing_bought-metrics-after.txt" ] && ok "нет снимка после — class=input_missing_…, не нулевые классы" || bad "нет снимка после: '$o'"
_case off; rm -f "$A/bought-rules-controls.txt"
W7B_ART="$A" W7B_CONTROL=off bash "$CTL" >/dev/null 2>&1; [ ! -e "$A/bought-rules-controls.txt" ] && ok "W7B_CONTROL=off файла не пишет" || bad "off написал файл"
_case observer; touch "$T/orp"
W7B_ART="$A" W7B_CONTROL=on W7B_ORPF="$T/orp" bash "$CTL" >/dev/null 2>&1
[ "$(cat "$A/bought-rules-controls.txt" 2>/dev/null)" = "class=observer_tree_armed" ] && ok "observer-root-pid существует — class=observer_tree_armed, нагрузка не идёт" || bad "observer: '$(cat "$A/bought-rules-controls.txt" 2>/dev/null)'"
if [ "$(uname -m)" != "x86_64" ]; then
    _case arch
    W7B_ART="$A" W7B_CONTROL=on W7B_ORPF="$T/nonexistent" bash "$CTL" >/dev/null 2>&1
    grep -q '^class=arch_not_x86_64' "$A/bought-rules-controls.txt" && ok "не x86_64 — class=arch_…, таблица nr x86_64 к ней не применима" || bad "arch: '$(cat "$A/bought-rules-controls.txt" 2>/dev/null)'"
fi

echo "[таблица контролей = состав «куплено» боевого манифеста]"
man="$HERE/attacks/wave7-nr-portions.txt"
bought=$(awk '$1 ~ /^P[0-9]+$/ && $2 == "RULE" { print $3 }' "$man" | sort -u)
table=$(sed -n '/^_TABLE="/,/"$/p' "$CTL" | sed 's/^_TABLE="//; s/"$//' | awk -F'|' 'NF >= 4 { print $1 }' | sort -u)
if [ "$bought" = "$table" ]; then ok "каждое купленное правило имеет строку контроля и наоборот ($(printf '%s\n' "$bought" | grep -c .) правил)"; else
    bad "состав расходится: купленные без контроля: $(comm -23 <(printf '%s\n' "$bought") <(printf '%s\n' "$table") | tr '\n' ' ') / контроль без покупки: $(comm -13 <(printf '%s\n' "$bought") <(printf '%s\n' "$table") | tr '\n' ' ')"; fi
for fn in $(sed -n '/^_TABLE="/,/"$/p' "$CTL" | grep -o '_p_[a-z_]*' | sort -u); do
    grep -q "^$fn()" "$CTL" && ok "функция нагрузки $fn определена" || bad "функция нагрузки $fn в таблице, а определения нет"
done

echo
[ "$FAIL" -eq 0 ] && { echo "wave7-bought-controls-fixtures: расхождений 0"; exit 0; }
echo "wave7-bought-controls-fixtures: ЕСТЬ РАСХОЖДЕНИЯ"; exit 1
