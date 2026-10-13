#!/bin/bash
# Фикстуры w85-cmd3-parse.sh и мутации. --mutate: каждая мутация обязана покраснеть.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
P=${PARSER:-$HERE/w85-cmd3-parse.sh}
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fails=0; ok() { echo "ok   $1"; }; bad() { echo "FAIL $1"; fails=$((fails + 1)); }
cat > "$T/good.txt" <<'X'
Attaching 2 probes...

@c[2218, 1]: 12000
@c[2218, 24]: 700
@c[2218, 3]: 36
@c[3300, 1]: 9000
@c[3300, 3]: 4
@c[999, 3]: 100000
@c[999, 5]: 2
X
want() { local n=$1 pat=$2; shift 2; local out; out=$("$@" 2>&1); if echo "$out" | grep -aqE "$pat"; then ok "$n"; else bad "${n} — нет «${pat}»"; echo "$out" | sed 's/^/    | /'; fi; }
want cmd3-work   'ИТОГ cmd=3 .*за 3600 с: рабочий агент pid=2218 — 36 вызовов \(36\.0 в час' bash "$P" "$T/good.txt" 2218 3300 3600
want cmd3-second 'ИТОГ cmd=3 .*второй агент pid=3300 — 4 вызовов \(4\.0 в час' bash "$P" "$T/good.txt" 2218 3300 3600
want cmd3-rate   'рабочий агент pid=2218 — 36 вызовов \(18\.0 в час' bash "$P" "$T/good.txt" 2218 3300 7200
want cmd3-other-pid-ignored 'второй агент pid=3300 — 4 вызовов' bash "$P" "$T/good.txt" 2218 3300 3600
# агент без единого bpf()-вызова в окне — не «0 вызовов», а НЕИЗМЕРИМ
want cmd3-absent 'НЕИЗМЕРИМ: cmd3 второй агент pid=7777 НЕИЗМЕРИМ' bash "$P" "$T/good.txt" 2218 7777 3600
# у агента вызовы есть, cmd 3 среди них нет — честный ноль с предъявленными строками
printf '@c[2218, 1]: 5\n' > "$T/no3.txt"
want cmd3-honest-zero 'рабочий агент pid=2218 — 0 вызовов' bash "$P" "$T/no3.txt" 2218 3300 3600
printf 'Attaching 1 probe...\nERROR\n' > "$T/empty.txt"
want cmd3-empty 'НЕИЗМЕРИМ: cmd3 НЕИЗМЕРИМ .*нет ни одной строки' bash "$P" "$T/empty.txt" 2218 3300 3600
if [ "${1:-}" = "--mutate" ]; then
    echo "== мутации"
    mut() { local n=$1 expr=$2 m=$T/mut-$1.sh; sed -e "$expr" "$P" > "$m"
        cmp -s "$m" "$P" && { bad "мутация $n не изменила парсер"; return; }
        if ! PARSER=$m bash "$0" > /dev/null 2>&1; then ok "мутация $n покраснила фикстуры"; else bad "мутация $n ПРОШЛА"; fi; }
    mut split-by-fields   's/sed -nE .s\/\^@c\\\[(\[0-9\]+), (\[0-9\]+)\\\]: (\[0-9\]+)\[\[:space:\]\]\*\$\/\\1 \\2 \\3\/p./awk "{ print }"/'
    mut any-pid           's/\$1 == p \&\& \$2 == 3 { s += \$3 }/$2 == 3 { s += $3 }/'
    mut cmd-any           's/\$1 == p \&\& \$2 == 3 { s += \$3 }/$1 == p { s += $3 }/'
    mut absent-as-zero    's/if \[ "\$seen" -eq 0 \]; then/if false; then/'
    mut empty-as-zero     's/if \[ -z "\$rows" \]; then/if false; then/'
    mut hour-scale        's/n \* 3600 \/ t/n * 60 \/ t/'
fi
echo "-- fails=$fails"; [ "$fails" = 0 ]
