#!/bin/bash
# w82-mem-report.sh <каталог инвентаря> — эмиттер волны 8.2, item A1.
#
# Печатает таблицу бюджета памяти по строкам из архива w82-mem-inventory.sh и
# вердикты меток, которые судятся одним снимком: 8.2.2 (idle) и 8.2.4 (BPF).
# Вход вердикта считает эмиттер, а не человек по таблице (память
# verdict-input-must-be-computed-by-emitter). Отсутствующий файл — НЕИЗМЕРИМ с
# названным классом, а не ноль (память empty-metric-snapshot-is-silently-zero).
#
# Учёт — cgroup юнита стенда, НЕ под: текст бинаря на стенде записан на cgroup
# сборки (№542). 8.2.1/8.2.2 «учёт пода» судит A4; здесь печатается оговорка.
set -u
D=${1:?каталог инвентаря (w82-mem-inventory.sh OUT)}
IDLE_MIN_S=${IDLE_MIN_S:-1800}   # 8.2.2: idle через 30 мин
IDLE_MAX_MIB=${IDLE_MAX_MIB:-120}
BPF_MAX_MIB=${BPF_MAX_MIB:-40}   # 8.2.4: карты + кольца, физ. страницы

mib() { awk -v b="$1" 'BEGIN { printf "%.1f", b / 1048576 }'; }
stat_of() { awk -v k="$1" '$1 == k { print $2; f = 1 } END { if (!f) print "" }' "$D/memory.stat" 2>/dev/null; }
# metric <файл> <имя> — сумма всех серий метрики (с лейблами и без).
metric() {
    [ -s "$1" ] || { echo ""; return; }
    awk -v n="$2" '($1 == n || index($1, n "{") == 1) { s += $NF; f = 1 } END { if (f) printf "%.0f", s; else print "" }' "$1"
}
row() { printf '  %-34s %10s  %s\n' "$1" "$2" "${3:-}"; }

echo "== w82 инвентарь: $D"
[ -s "$D/meta.txt" ] && sed 's/^/  /' "$D/meta.txt"
etimes=$(sed -n 's/.*etimes= *\([0-9]*\).*/\1/p' "$D/meta.txt" 2>/dev/null)
echo "  учёт: cgroup юнита стенда, не под (текст бинаря на чужом счёте, №542 — судит A4)"
echo ""

echo "-- cgroup (МиБ)"
cur=$(cat "$D/memory.current" 2>/dev/null)
if [ -n "$cur" ]; then row "memory.current" "$(mib "$cur")"; else row "memory.current" "НЕИЗМЕРИМ" "нет memory.current"; fi
[ -s "$D/memory.current60" ] && row "memory.current через 60 с" "$(mib "$(cat "$D/memory.current60")")"
[ -s "$D/memory.peak" ] && row "memory.peak (с начала cgroup)" "$(mib "$(cat "$D/memory.peak")")"
if [ -s "$D/memory.stat" ]; then
    for k in anon file kernel_stack slab pagetables sock; do
        v=$(stat_of "$k"); [ -n "$v" ] && row "$k" "$(mib "$v")"
    done
else
    row "memory.stat" "НЕИЗМЕРИМ" "файл не снят"
fi
echo ""

echo "-- ядро BPF"
maps_phys=""; ring_phys=""
if [ -s "$D/bpf_vmalloc.txt" ]; then
    # строки: "<МиБ> MiB phys <n> <caller>"
    maps_phys=$(awk '$5 ~ /bpf_map_area_alloc|bpf_map_kmalloc|array_map_alloc|htab_map_alloc/ { s += $1 } END { printf "%.1f", s }' "$D/bpf_vmalloc.txt")
    ring_phys=$(awk '$5 ~ /ringbuf/ { s += $1 } END { printf "%.1f", s }' "$D/bpf_vmalloc.txt")
    jit_phys=$(awk '$5 ~ /jit|bpf_prog_pack/ { s += $1 } END { printf "%.1f", s }' "$D/bpf_vmalloc.txt")
    row "карты, физ. страницы (МиБ)" "$maps_phys" "vmallocinfo"
    ring_vm=$ring_phys
    row "программы/JIT (МиБ)" "$jit_phys" "vmallocinfo"
else
    row "карты/кольца, физ. страницы" "НЕИЗМЕРИМ" "нет bpf_vmalloc.txt (архив старше прибора)"
fi
unref_n=""; ring_ml=0
if [ -s "$D/maps.json" ] && [ -s "$D/progs.json" ] && jq -e 'type == "array"' "$D/maps.json" > /dev/null 2>&1; then
    read -r maps_n maps_ml ring_n ring_ml unref_n unref_ml < <(jq -r --slurpfile p "$D/progs.json" '
        ([$p[0][] | (.map_ids // [])[]] | unique) as $ref
        | [ length,
            (map(.bytes_memlock // 0) | add),
            (map(select(.type == "ringbuf")) | length),
            (map(select(.type == "ringbuf") | .max_entries) | add // 0),
            (map(select((.id as $i | $ref | index($i)) == null)) | length),
            (map(select((.id as $i | $ref | index($i)) == null) | .bytes_memlock // 0) | add // 0) ]
        | @tsv' "$D/maps.json")
    row "карт на ноде" "$maps_n" "memlock $(mib "$maps_ml") МиБ"
    row "колец (ringbuf)" "$ring_n" "размер $(mib "$ring_ml") МиБ"
    row "карт без программ (мёртвые)" "$unref_n" "memlock $(mib "$unref_ml") МиБ"
    # Страницы колец выделяются vmap'ом целиком при создании: в vmallocinfo у
    # таких строк нет pages=, и прибор видит 0 (снимок 10.10.2026). Тогда
    # физический объём кольца = его размер из bpftool.
    if [ -n "$ring_phys" ]; then
        if awk -v v="$ring_vm" 'BEGIN { exit !(v + 0 == 0) }' && [ "$ring_ml" -gt 0 ]; then
            ring_phys=$(mib "$ring_ml")
            row "кольца, физ. страницы (МиБ)" "$ring_phys" "= размер колец (vmap без pages= в vmallocinfo)"
        else
            row "кольца, физ. страницы (МиБ)" "$ring_phys" "vmallocinfo"
        fi
    fi
    jq -r --slurpfile p "$D/progs.json" '
        ([$p[0][] | (.map_ids // [])[]] | unique) as $ref
        | map(select((.id as $i | $ref | index($i)) == null))
        | group_by(.name) | map({n: .[0].name, c: length, m: (map(.bytes_memlock // 0) | add)})
        | sort_by(-.m) | .[:8][] | "    \(.n // "?") ×\(.c) — \(.m / 1048576 * 10 | floor / 10) МиБ memlock"' "$D/maps.json"
else
    row "карты по bpftool" "НЕИЗМЕРИМ" "нет maps.json/progs.json"
fi
echo ""

echo "-- Go (МиБ)"
for m in go_memstats_heap_inuse_bytes go_memstats_heap_idle_bytes go_memstats_heap_released_bytes go_memstats_heap_sys_bytes go_memstats_stack_inuse_bytes go_memstats_sys_bytes; do
    v=$(metric "$D/metrics.txt" "$m"); [ -n "$v" ] && row "${m#go_memstats_}" "$(mib "$v")"
done
a0=$(metric "$D/metrics.txt" go_memstats_alloc_bytes_total); a1=$(metric "$D/metrics60.txt" go_memstats_alloc_bytes_total)
e0=$(metric "$D/metrics.txt" ebpf_guard_events_total); e1=$(metric "$D/metrics60.txt" ebpf_guard_events_total)
if [ -n "$a0" ] && [ -n "$a1" ] && [ -n "$e0" ] && [ -n "$e1" ] && [ "$e1" -gt "$e0" ]; then
    awk -v a="$((a1 - a0))" -v e="$((e1 - e0))" 'BEGIN {
        printf "  %-34s %10.2f  МБ/с\n", "поток аллокаций (60 с)", a / 60 / 1e6
        printf "  %-34s %10.0f  событий/с\n", "темп событий (60 с)", e / 60
        printf "  %-34s %10.0f  Б/событие (стенд; судит A2)\n", "аллокаций на событие", a / e }'
else
    row "поток аллокаций" "НЕИЗМЕРИМ" "нет пары metrics/metrics60 или событий 0"
fi
echo ""

echo "-- метки"
if [ -z "$cur" ]; then
    echo "НЕИЗМЕРИМ: 8.2.2 НЕИЗМЕРИМ (класс НАЗВАН: нет memory.current)"
elif [ -z "$etimes" ] || [ "$etimes" -lt "$IDLE_MIN_S" ]; then
    echo "НЕИЗМЕРИМ: 8.2.2 НЕИЗМЕРИМ (класс НАЗВАН: аптайм ${etimes:-?} с < $IDLE_MIN_S — idle судится через 30 мин); memory.current $(mib "$cur") МиБ"
else
    awk -v c="$cur" -v lim="$IDLE_MAX_MIB" 'BEGIN { v = c / 1048576
        if (v <= lim) printf "ДОСТИГНУТО: 8.2.2 ДОСТИГНУТО (memory.current idle %.1f МиБ ≤ %d; учёт юнита, не пода)\n", v, lim
        else printf "ПРОВАЛЕН: 8.2.2 ПРОВАЛЕН (memory.current idle %.1f МиБ > %d; учёт юнита, не пода)\n", v, lim }'
fi
if [ -z "$unref_n" ]; then
    echo "НЕИЗМЕРИМ: 8.2.4 НЕИЗМЕРИМ (класс НАЗВАН: нет maps.json/progs.json)"
elif [ -z "$maps_phys" ]; then
    echo "НЕИЗМЕРИМ: 8.2.4 НЕИЗМЕРИМ (класс НАЗВАН: нет bpf_vmalloc.txt — физ. страницы не сняты); карт без программ $unref_n"
else
    awk -v u="$unref_n" -v m="$maps_phys" -v r="$ring_phys" -v lim="$BPF_MAX_MIB" 'BEGIN { s = m + r
        if (u == 0 && s <= lim) printf "ДОСТИГНУТО: 8.2.4 ДОСТИГНУТО (карт без программ 0, карты+кольца %.1f МиБ ≤ %d)\n", s, lim
        else printf "ПРОВАЛЕН: 8.2.4 ПРОВАЛЕН (карт без программ %d, карты+кольца %.1f МиБ против ≤ %d)\n", u, s, lim }'
fi
