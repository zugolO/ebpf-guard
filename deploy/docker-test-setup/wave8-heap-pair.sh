#!/bin/bash
# wave8-heap-pair.sh — item 1 волны 8.1: ПАРА снимков /debug/pprof/heap и
# `go tool pprof -base` (plan.md, «Items волны 8.1», №1). Это НЕ боевой прогон и не
# A/B на правку: прибор атрибуции роста. Профиль в архиве collect-6.3-L1 был ОДИН
# (RSS 250 МиБ), при RSS 311 профиля нет — поэтому +56 МиБ роста не атрибутированы.
#
# ЧЕМ НЕЛЬЗЯ СУДИТЬ: этим скриптом не судят ПРАВКУ. Разброс прогонов бьёт атрибуцию
# к коду ([[run-to-run-variance-beats-code-attribution]]); принятая правка предъявляет
# цену A/B на ОДНОМ бинаре смежными равными окнами. Здесь — только «где лежит куча и
# что в ней росло за окно», вход для items 2–4.
#
# ДВЕ РАЗНЫЕ РАЗНОСТИ, и они читаются порознь:
#   inuse_space — что ДЕРЖИТ куча на втором снимке сверх первого (рост удержанного);
#   alloc_space — что аллоцировано за окно (темп; ≈72 ГБ/ч на idle по паре порции 3).
# Рост inuse при нулевом alloc невозможен, а большой alloc при нулевом росте inuse —
# норма (мусор): поэтому обе печатаются, а вывод о «утечке» из одной не делается.
#
# ЧТО ПЕЧАТАЕТСЯ ВСЕГДА: go_memstats_* и RSS на обоих снимках (RSS ≠ живые данные,
# [[rss-is-retained-heap-not-live-data]]), чтобы разность профиля читалась против
# разности процесса. gc=1 перед ПЕРВЫМ снимком: иначе inuse первого включает
# мусор, и разность занижена.
#
# Вход: W8_API (умолчание http://localhost:19090), W8_TOKEN, W8_GAP_S (умолчание 600),
#       W8_ART (умолчание /var/lib/w8-heap-pair), W8_GO (умолчание go).
#       W8_MODE=analyze — только разбор готовых snap1.pprof/snap2.pprof (фикстуры).
# Выход: $W8_ART/heap-pair-summary.txt, heap-diff-inuse.txt, heap-diff-alloc.txt.
set -u
export PATH=$PATH:/usr/local/go/bin
W8_API="${W8_API:-http://localhost:19090}"
W8_TOKEN="${W8_TOKEN:-}"
W8_GAP_S="${W8_GAP_S:-600}"
W8_ART="${W8_ART:-/var/lib/w8-heap-pair}"
W8_GO="${W8_GO:-go}"
W8_MODE="${W8_MODE:-run}"
_S="$W8_ART/heap-pair-summary.txt"
mkdir -p "$W8_ART" 2>/dev/null

_curl() { curl -s --max-time 60 -H "Authorization: Bearer $W8_TOKEN" "$@"; }
# _mem <файл метрик> — величины процесса одной строкой «name=bytes …».
_mem() {
    awk '$1 ~ /^(go_memstats_(alloc_bytes|heap_alloc_bytes|heap_inuse_bytes|heap_idle_bytes|heap_released_bytes|sys_bytes|alloc_bytes_total)|process_resident_memory_bytes)$/ { printf "%s=%.0f ", $1, $2 }' "$1" 2>/dev/null
}
# _delta_mib <метрика> <файл до> <файл после> — разность в МиБ; пусто, если серии нет в ОБОИХ.
_delta_mib() {
    awk -v m="$1" 'FNR == 1 { f++ } $1 == m { v[f] = $2; s[f] = 1 }
        END { if (s[1] && s[2]) printf "%.2f", (v[2] - v[1]) / 1048576; else exit 1 }' "$2" "$3" 2>/dev/null
}

if [ "$W8_MODE" = "run" ]; then
    [ -n "$W8_TOKEN" ] || { echo "class=нет_токена_W8_TOKEN" > "$_S"; echo "class=нет_токена_W8_TOKEN"; exit 0; }
    # gc=1: принудительный GC до снимка (параметр pprof.Handler heap).
    _curl "$W8_API/debug/pprof/heap?gc=1" > "$W8_ART/snap1.pprof"
    _curl "$W8_API/metrics" > "$W8_ART/metrics1.txt"
    [ -s "$W8_ART/snap1.pprof" ] && [ -s "$W8_ART/metrics1.txt" ] || { echo "class=первый_снимок_пуст_enable_pprof_или_токен" > "$_S"; echo "class=первый_снимок_пуст_enable_pprof_или_токен"; exit 0; }
    echo "  первый снимок снят $(date -u +%FT%TZ), окно ${W8_GAP_S}s (локально, без захода на стенд)"
    sleep "$W8_GAP_S"
    _curl "$W8_API/debug/pprof/heap?gc=1" > "$W8_ART/snap2.pprof"
    _curl "$W8_API/metrics" > "$W8_ART/metrics2.txt"
fi

for f in snap1.pprof snap2.pprof metrics1.txt metrics2.txt; do
    [ -s "$W8_ART/$f" ] || { echo "class=нет_входа_$f" > "$_S"; echo "class=нет_входа_$f"; exit 0; }
done
command -v "$W8_GO" >/dev/null 2>&1 || { echo "class=go_не_найден_pprof_разобрать_нечем" > "$_S"; echo "class=go_не_найден_pprof_разобрать_нечем"; exit 0; }

# -base ВЫЧИТАЕТ первый профиль из второго: положительное — выросло/добавлено.
"$W8_GO" tool pprof -sample_index=inuse_space -top -nodecount=25 -base "$W8_ART/snap1.pprof" "$W8_ART/snap2.pprof" > "$W8_ART/heap-diff-inuse.txt" 2>&1
"$W8_GO" tool pprof -sample_index=alloc_space -top -nodecount=25 -base "$W8_ART/snap1.pprof" "$W8_ART/snap2.pprof" > "$W8_ART/heap-diff-alloc.txt" 2>&1
{
    echo "window_s=$W8_GAP_S"
    echo "mem_before: $(_mem "$W8_ART/metrics1.txt")"
    echo "mem_after:  $(_mem "$W8_ART/metrics2.txt")"
    for m in process_resident_memory_bytes go_memstats_heap_alloc_bytes go_memstats_heap_inuse_bytes go_memstats_heap_idle_bytes go_memstats_heap_released_bytes go_memstats_alloc_bytes_total; do
        d=$(_delta_mib "$m" "$W8_ART/metrics1.txt" "$W8_ART/metrics2.txt") || d="серии нет"
        echo "delta_mib $m = $d"
    done
    echo "--- inuse_space: рост удержанного (голова разности) ---"
    sed -n '1,14p' "$W8_ART/heap-diff-inuse.txt"
    echo "--- alloc_space: аллоцировано за окно (голова разности) ---"
    sed -n '1,14p' "$W8_ART/heap-diff-alloc.txt"
} > "$_S"
cat "$_S"
