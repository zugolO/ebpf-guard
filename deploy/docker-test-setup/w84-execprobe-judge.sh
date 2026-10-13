#!/bin/bash
# w84-execprobe-judge.sh <bt.txt> — вердикты проверки «exec filename из sched_process_exec = путь шебанг-скрипта,
# exec -a его не трогает» (основа 8.4.2). Вход — вывод bpftrace строками «EXEC comm=<c> file=<путь>»
# (w84-execprobe.sh). Вердикт считает разбор, не человек; случай без строки в окне — НЕИЗМЕРИМ с названным классом.
# Кейсы (скрипты /var/tmp/w84p/): C1 прямой запуск шебанг-скрипта; C2 относительный путь; C3 exec -a dpkg;
# C4 симлинк на скрипт; C5 perl-скрипт напрямую; C6 sh <скрипт> (интерпретатор явно — скрипт только в argv).
set -u
BT=${1:?bt.txt}
P=/var/tmp/w84p
# строка с ТОЧНЫМ file=<путь> (весь остаток строки после «file=» равен пути — префикс «s.sh.bak» не подходит)
get() { grep -a '^EXEC ' "$BT" | awk -v want="$1" '{ i = index($0, " file="); if (i && substr($0, i + 6) == want) { print; exit } }'; }
have() { [ -n "$(get "$1")" ]; }
verdict() { # <кейс> <ожидание-путь> <описание>
    if have "$2"; then echo "ДОСТИГНУТО: execprobe/$1 ДОСТИГНУТО ($3: exec filename = «$2», строка: $(get "$2" | head -c 120))"
    else echo "НЕИЗМЕРИМ: execprobe/$1 НЕИЗМЕРИМ (класс НАЗВАН: строки с file=$2 нет в выводе зонда — $3 не исполнился или filename другой)"; fi
}
if ! grep -aq '^EXEC ' "$BT" 2>/dev/null; then
    echo "НЕИЗМЕРИМ: execprobe НЕИЗМЕРИМ (класс НАЗВАН: в $BT нет ни одной строки EXEC — зонд не отработал)"; exit 0
fi
verdict C1-shebang-direct "$P/s.sh" "шебанг-скрипт запущен напрямую: filename — путь САМОГО скрипта"
verdict C2-relative "./s.sh" "относительный запуск: filename — как передан"
verdict C4-symlink "$P/link.sh" "симлинк на скрипт: filename — путь симлинка"
verdict C5-perl-script "$P/p.pl" "perl-скрипт напрямую: filename — путь скрипта"
# C3: exec -a dpkg НЕ меняет filename: строка с filename скрипта обязана быть (та же, что у C1, но от процесса, где argv[0]=dpkg)
n=$(grep -a '^EXEC ' "$BT" | awk -v want="$P/s.sh" '{ i = index($0, " file="); if (i && substr($0, i + 6) == want) c++ } END { print c + 0 }')
if [ "$n" -ge 2 ]; then echo "ДОСТИГНУТО: execprobe/C3-exec-a ДОСТИГНУТО (exec -a dpkg не трогает filename: две exec-строки с file=$P/s.sh — прямой запуск и под argv[0]=dpkg)"
else echo "НЕИЗМЕРИМ: execprobe/C3-exec-a НЕИЗМЕРИМ (класс НАЗВАН: строк с file=$P/s.sh $n < 2 — exec -a запуск не виден зонду)"; fi
# C6: явный интерпретатор — filename = интерпретатор, скрипта среди filename нет НИ в одной строке сверх C1/C3 (там тоже он)
if grep -a '^EXEC ' "$BT" | grep -aqE "file=(/usr)?/bin/(sh|dash) *$"; then
    echo "ДОСТИГНУТО: execprobe/C6-explicit-interpreter ДОСТИГНУТО (sh <скрипт>: filename — интерпретатор, скрипт только в argv — maintainer-путь по exec filename так не подделать, а так же и не распознать)"
else echo "НЕИЗМЕРИМ: execprobe/C6-explicit-interpreter НЕИЗМЕРИМ (класс НАЗВАН: нет строки с file=/bin/sh|/usr/bin/sh)"; fi
