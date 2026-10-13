#!/bin/bash
# Фикстуры w84-execprobe-judge.sh и мутации (--mutate).
set -u
HERE=$(cd "$(dirname "$0")" && pwd); J=${JUDGE:-$HERE/w84-execprobe-judge.sh}
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT; fails=0; P=/var/tmp/w84p
ok() { echo "ok   $1"; }; bad() { echo "FAIL $1"; fails=$((fails + 1)); }
cat > "$T/good.txt" <<X
Attaching 1 probe...
EXEC comm=s.sh file=$P/s.sh
EXEC comm=s.sh file=./s.sh
EXEC comm=s.sh file=$P/s.sh
EXEC comm=s.sh file=$P/link.sh
EXEC comm=p.pl file=$P/p.pl
EXEC comm=sh file=/usr/bin/sh
EXEC comm=cron file=/usr/sbin/cron
X
want() { local n=$1 f=$2 pat=$3 out; out=$(bash "$J" "$f" 2>&1); if echo "$out" | grep -aqE "$pat"; then ok "$n"; else bad "${n} — нет «${pat}»"; echo "$out" | sed 's/^/    | /'; fi; }
want all-good "$T/good.txt" '^ДОСТИГНУТО: execprobe/C1-shebang-direct'
want c2 "$T/good.txt" '^ДОСТИГНУТО: execprobe/C2-relative'
want c3 "$T/good.txt" '^ДОСТИГНУТО: execprobe/C3-exec-a'
want c4 "$T/good.txt" '^ДОСТИГНУТО: execprobe/C4-symlink'
want c5 "$T/good.txt" '^ДОСТИГНУТО: execprobe/C5-perl-script'
want c6 "$T/good.txt" '^ДОСТИГНУТО: execprobe/C6-explicit-interpreter'
# ядро показало бы ИНТЕРПРЕТАТОР вместо скрипта (гипотеза опровергнута): C1 — НЕИЗМЕРИМ с названным классом, не ДОСТИГНУТО
sed "s#file=$P/s.sh#file=/bin/sh#" "$T/good.txt" > "$T/interp.txt"
want hypothesis-refuted "$T/interp.txt" '^НЕИЗМЕРИМ: execprobe/C1-shebang-direct .*file='"$P"'/s.sh нет в выводе'
# exec -a запуск не виден зонду (одна строка вместо двух)
awk -v p="file=$P/s.sh" 'index($0, p) && !s++ { print; next } index($0, p) { next } { print }' "$T/good.txt" > "$T/one.txt"
want c3-one-line "$T/one.txt" '^НЕИЗМЕРИМ: execprobe/C3-exec-a .*1 < 2'
# префикс пути не засчитывается за точный путь
sed "s#file=$P/s.sh#file=$P/s.sh.bak#" "$T/good.txt" > "$T/prefix.txt"
want exact-path-only "$T/prefix.txt" '^НЕИЗМЕРИМ: execprobe/C1-shebang-direct'
printf 'Attaching 1 probe...\nERROR: x\n' > "$T/empty.txt"
want no-exec-lines "$T/empty.txt" '^НЕИЗМЕРИМ: execprobe НЕИЗМЕРИМ .*ни одной строки EXEC'
if [ "${1:-}" = "--mutate" ]; then
    echo "== мутации"
    mut() { local n=$1 expr=$2 m=$T/mut-$1.sh; sed -e "$expr" "$J" > "$m"
        cmp -s "$m" "$J" && { bad "мутация $n не изменила"; return; }
        if ! JUDGE=$m bash "$0" > /dev/null 2>&1; then ok "мутация $n покраснила"; else bad "мутация $n ПРОШЛА"; fi; }
    mut substring-match 's/substr(\$0, i + 6) == want) { print; exit }/index(substr($0, i + 6), want) == 1) { print; exit }/'
    mut c3-single-line  's/\[ "\$n" -ge 2 \]/[ "$n" -ge 1 ]/'
    mut no-lines-guard  's/if ! grep -aq .\^EXEC . "\$BT" 2>\/dev\/null; then/if false; then/'
fi
echo "-- fails=$fails"; [ "$fails" = 0 ]
