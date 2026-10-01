#!/bin/bash
# wave7-family-price.sh — ЦЕНА ПРОДЮСЕРОВ ТРЁХ СЕМЕЙСТВ НЕМОТЫ, у которых продюсера
# нет (задача Т волны 7): ось `proto` (ICMP/GRE/raw), тип события `cgroup_esc`.
# Ось `file.op` оценена отдельно по сырой карте (id,comm) зонда Ц1: хуки
# unlink/rmdir/truncate/rename уже лежат в bpftrace-raw.txt как sys_enter_*.
#
# ЧТО ЭТО ЗА ВЕЛИЧИНА. Для каждого кандидата-хука — сколько раз он СРАБАТЫВАЕТ на
# idle-ноде за окно: потолок числа событий, которые продюсер отдал бы продукту.
# Это НЕ число алертов и не вердикт (вердикт даёт пара A/B после появления
# продюсера, [[bpftrace-zero-is-a-moment-not-a-property]]): ноль за окно — момент, а
# не свойство; хук, которого на ядре нет, печатается available=no, а не нулём
# ([[metric-anchor-must-carry-full-series-name]] в применении к зонду).
#
# КАЖДЫЙ ХУК — ОТДЕЛЬНЫЙ bpftrace. Программа с несуществующим символом не грузится
# целиком; отдельные процессы дают одному хуку упасть, не унеся остальные. Идут
# параллельно на одно окно, поэтому время замера — окно, а не окно × число хуков.
#
# Вход: W7F_SECS (умолчание 300), W7F_ART (умолчание /var/lib/w7-family-price).
# Выход: $W7F_ART/family-price.txt, по строке на хук:
#   probe=<хук> family=<T2|T3> available=<yes|no> count=<N> per_min=<N/мин> top_comms=<comm:N,…>
set -u
W7F_SECS="${W7F_SECS:-300}"
W7F_ART="${W7F_ART:-/var/lib/w7-family-price}"
_OUT="$W7F_ART/family-price.txt"

# <семейство>|<хук>|<что он дал бы продукту>
_PROBES="T3|tracepoint:cgroup:cgroup_attach_task|миграция процесса между cgroup (шаг техники container_escape_cgroup_*)
T3|tracepoint:cgroup:cgroup_transfer_tasks|массовый перенос задач между cgroup
T2|kprobe:icmp_rcv|принятый ICMP (proto=1 на входе)
T2|kprobe:__icmp_send|отправленный ядром ICMP-ответ
T2|kprobe:raw_sendmsg|отправка через SOCK_RAW (proto 255/41/47/50/51 и ICMP через raw)
T2|kprobe:ping_v4_sendmsg|ICMP-эхо через SOCK_DGRAM (ping без CAP_NET_RAW)
T2|kprobe:gre_rcv|принятый GRE (proto=47)"

# _w7f_count <файл вывода> — число срабатываний (@n) или пусто.
_w7f_count() { awk '/^@n:/ { print $2; f = 1; exit } END { if (!f) exit 1 }' "$1" 2>/dev/null; }
# _w7f_top <файл вывода> — три самых частых comm «comm:N,…»; разбор всей строки, не $1.
_w7f_top() {
    awk '
        match($0, /^@c\[.*\]:[ \t]+[0-9]+[ \t]*$/) {
            k = $0; sub(/^@c\[/, "", k)
            n = k; sub(/.*\]:[ \t]+/, "", n); gsub(/[^0-9]/, "", n)
            c = k; sub(/\]:[ \t]+[0-9]+[ \t]*$/, "", c)
            printf "%s:%s\n", c, n
        }' "$1" | sort -t: -k2,2nr | head -3 | tr '\n' ',' | sed 's/,$//'
}
# _w7f_line <семейство> <хук> <доступен yes|no> <файл вывода> — строка отчёта.
_w7f_line() {
    local fam="$1" probe="$2" av="$3" f="$4" n pm top
    if [ "$av" != yes ]; then
        echo "probe=$probe family=$fam available=no count=- per_min=- top_comms=-"; return
    fi
    # bpftrace не печатает карту, в которую не писали: пустой @n при напечатанном
    # маркере окна `@done` — честный ноль (программа отработала окно целиком), а
    # пустой вывод без маркера — отказ программы, и нулём он не становится.
    if n=$(_w7f_count "$f"); then :
    elif grep -q '^@done:' "$f" 2>/dev/null; then n=0
    else echo "probe=$probe family=$fam available=yes count=? per_min=? top_comms=- reason=no_marker_program_did_not_finish"; return; fi
    pm=$(awk -v c="$n" -v s="$W7F_SECS" 'BEGIN{printf "%.1f", (s>0)? c*60.0/s : 0}')
    top=$(_w7f_top "$f")
    echo "probe=$probe family=$fam available=yes count=$n per_min=$pm top_comms=${top:--}"
}

if [ "${1:-}" = "--self-test" ]; then
    fail=0; d=$(mktemp -d); W7F_SECS=60
    printf '@c[bash]: 4\n@c[systemd]: 17\n@c[sshd]: 9\n@c[cron]: 1\n@n: 31\n' > "$d/a.txt"
    : > "$d/b.txt"
    chk() { if printf '%s\n' "$2" | grep -qF -- "$3"; then echo "    OK  $1"; else echo "    ПРОВАЛ: $1 — нет «$3» в «$2»"; fail=1; fi; }
    chk "число срабатываний и per_min от окна" "$(_w7f_line T3 tracepoint:x yes "$d/a.txt")" "count=31 per_min=31.0"
    chk "comm отсортированы по величине, срез три" "$(_w7f_line T3 tracepoint:x yes "$d/a.txt")" "top_comms=systemd:17,sshd:9,bash:4"
    chk "хука нет на ядре — available=no, НЕ ноль" "$(_w7f_line T2 kprobe:gre_rcv no "$d/b.txt")" "available=no count=-"
    chk "хук есть, ни @n, ни маркера окна — отказ программы, а не ноль" "$(_w7f_line T2 kprobe:x yes "$d/b.txt")" "count=? per_min=?"
    printf '@done: 1\n' > "$d/m.txt"
    chk "маркер окна есть, @n нет — честный ноль" "$(_w7f_line T2 kprobe:x yes "$d/m.txt")" "count=0 per_min=0.0"
    printf '@n: 0\n' > "$d/z.txt"
    chk "честный ноль печатается нулём" "$(_w7f_line T2 kprobe:x yes "$d/z.txt")" "count=0 per_min=0.0"
    rm -rf "$d"
    [ "$fail" = 0 ] && { echo "САМОПРОВЕРКА ЗОНДА СЕМЕЙСТВ ПРОЙДЕНА: расхождений 0"; exit 0; }
    echo "САМОПРОВЕРКА ЗОНДА СЕМЕЙСТВ ПРОВАЛЕНА"; exit 1
fi

mkdir -p "$W7F_ART" 2>/dev/null
command -v bpftrace >/dev/null 2>&1 || { echo "class=bpftrace_не_установлен" > "$_OUT"; echo "  class=bpftrace_не_установлен"; exit 0; }
[ "$(id -u)" = 0 ] || { echo "class=не_root" > "$_OUT"; echo "  class=не_root"; exit 0; }

: > "$W7F_ART/pids.txt"
i=0
while IFS='|' read -r fam probe why; do
    [ -n "$probe" ] || continue
    i=$((i + 1)); f="$W7F_ART/probe-$i.txt"
    if bpftrace -l "$probe" 2>/dev/null | grep -q .; then
        echo "yes" > "$W7F_ART/probe-$i.av"
        bpftrace -e "$probe { @n = count(); @c[comm] = count(); } interval:s:${W7F_SECS} { printf(\"@done: 1\\n\"); exit(); }" > "$f" 2>"$W7F_ART/probe-$i.err" &
        echo "$i $! $fam $probe" >> "$W7F_ART/pids.txt"
    else
        echo "no" > "$W7F_ART/probe-$i.av"; : > "$f"
    fi
done <<< "$_PROBES"
wait
: > "$_OUT"
echo "window_s=$W7F_SECS" >> "$_OUT"
i=0
while IFS='|' read -r fam probe why; do
    [ -n "$probe" ] || continue
    i=$((i + 1))
    _w7f_line "$fam" "$probe" "$(cat "$W7F_ART/probe-$i.av")" "$W7F_ART/probe-$i.txt" >> "$_OUT"
done <<< "$_PROBES"
# bpftrace с пустой картой не печатает @n вовсе: «хук есть, события не было» отличается от
# «вывод пуст из-за отказа» по файлу ошибок, а не по молчанию.
cat "$_OUT"
