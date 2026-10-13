#!/bin/bash
# w85-o1-report.sh — O1 (волна 8.5, этап 4): цена clone(56) парой одновременных агентов, предикат для socket(41) по bpftrace,
# положительные контроли. Считает эмиттер; включение номеров решает владелец, порогов продукта у метки нет.
#   OUT=<каталог w85-o1-pair.sh> [AB_NULL_GAP=19] bash w85-o1-report.sh
#   8.5.O1p — ДОСТИГНУТО: anomaly_detection B ≤ A + max(2·√A, AB_NULL_GAP) (решение 13.10 п. 5), дропы B ≤ A, аллокации B ≤ A·1,04
#             (пол шума соседних окон ±4%). Печатается и CPU (userspace, с/с), события по номерам.
#   8.5.O1c — ДОСТИГНУТО: правила socket (3) сработали у ОБОИХ агентов, clone: B ≥ 1, A = 0 (мало того что B видит — A немой).
#   8.5.O1s — ИЗМЕРЕНО: доля вызовов socket, которую оставил бы предикат (type&15 = SOCK_RAW или family = AF_PACKET), по bpftrace.
# Нет серии/файла — НЕИЗМЕРИМ с названным классом.
set -u
OUT=${OUT:-}; AB_NULL_GAP=${AB_NULL_GAP:-19}; ALLOC_NOISE_PCT=${ALLOC_NOISE_PCT:-4}

val() { # <файл> <метрика> [label=value]… → значение первой серии, содержащей все пары
    local f=$1 n=$2; shift 2
    awk -v n="$n" -v pairs="$*" 'BEGIN { k = split(pairs, P, " ") }
        index($0, n "{") == 1 || index($0, n " ") == 1 {
            ok = 1; for (i = 1; i <= k; i++) { split(P[i], kv, "="); if (index($0, kv[1] "=\"" kv[2] "\"") == 0) ok = 0 }
            if (ok) { print $NF; exit }
        }' "$f"
}
sumof() { # <файл> <метрика> — сумма всех серий метрики
    awk -v n="$1" 'index($0, n "{") == 1 || index($0, n " ") == 1 { s += $NF; seen = 1 } END { if (seen) printf "%.0f", s }' "$2"
}
dlt() { # <m0> <m1> <метрика> [пары] — «?» нет серии
    local m0=$1 m1=$2 n=$3; shift 3
    local a b; a=$(val "$m0" "$n" "$@"); b=$(val "$m1" "$n" "$@")
    [ -n "$b" ] || { echo "?"; return; }
    awk -v a="${a:-0}" -v b="$b" 'BEGIN { printf "%.0f", b - a }'
}
dsum() { local a b; a=$(sumof "$1" "$2"); b=$(sumof "$1" "$3"); a=${a:-0}; [ -n "$b" ] || { echo "?"; return; }; echo $((b - a)); }
fdel() { # <m0> <m1> <метрика> → дробная дельта для CPU/allocs
    local a b; a=$(val "$1" "$3"); b=$(val "$2" "$3"); [ -n "$b" ] || { echo "?"; return; }
    awk -v a="${a:-0}" -v b="$b" 'BEGIN { printf "%.6f", b - a }'
}

echo "== w85 8.5.O1: OUT=${OUT:-—}"
if [ -z "$OUT" ] || [ ! -d "$OUT" ]; then echo "НЕИЗМЕРИМ: 8.5.O1 НЕИЗМЕРИМ (класс НАЗВАН: нет каталога ${OUT:-—})"; exit 0; fi
if ! grep -q '^done' "$OUT/DONE" 2>/dev/null; then echo "НЕИЗМЕРИМ: 8.5.O1 НЕИЗМЕРИМ (класс НАЗВАН: прогон не завершён: $(cat "$OUT/DONE" 2>/dev/null || echo нет DONE))"; exit 0; fi
cls=""
for r in A B; do for f in m0.txt m1.txt ctl.txt; do [ -s "$OUT/$r/$f" ] || cls="$cls; $r: нет $f"; done; done
[ -s "$OUT/bt.txt" ] || cls="$cls; нет bt.txt"
W=$(cat "$OUT/window_s.txt" 2>/dev/null); case "$W" in ''|*[!0-9]*|0) cls="$cls; нет длины окна" ;; esac
if [ -n "$cls" ]; then echo "НЕИЗМЕРИМ: 8.5.O1 НЕИЗМЕРИМ (класс НАЗВАН:${cls#;})"; exit 0; fi

# ── цена (8.5.O1p) ──
NR=ebpf_guard_syscall_events_by_nr_total
e41a=$(dlt "$OUT/A/m0.txt" "$OUT/A/m1.txt" $NR nr=41); e41b=$(dlt "$OUT/B/m0.txt" "$OUT/B/m1.txt" $NR nr=41)
e56a=$(dlt "$OUT/A/m0.txt" "$OUT/A/m1.txt" $NR nr=56); e56b=$(dlt "$OUT/B/m0.txt" "$OUT/B/m1.txt" $NR nr=56)
ta=$(dsum $NR "$OUT/A/m0.txt" "$OUT/A/m1.txt"); tb=$(dsum $NR "$OUT/B/m0.txt" "$OUT/B/m1.txt")
anom() { awk '/^ebpf_guard_alert_volume_by_event_type_total\{/ && index($1, "rule_id=\"anomaly_detection\"") { s += $NF; seen = 1 } END { if (seen) printf "%.0f\n", s }' "$1" < /dev/null; }
a0=$(anom "$OUT/A/m0.txt"); a1=$(anom "$OUT/A/m1.txt"); b0=$(anom "$OUT/B/m0.txt"); b1=$(anom "$OUT/B/m1.txt")
da=$(dsum ebpf_guard_events_dropped_total "$OUT/A/m0.txt" "$OUT/A/m1.txt"); db=$(dsum ebpf_guard_events_dropped_total "$OUT/B/m0.txt" "$OUT/B/m1.txt")
ca=$(fdel "$OUT/A/m0.txt" "$OUT/A/m1.txt" process_cpu_seconds_total); cb=$(fdel "$OUT/B/m0.txt" "$OUT/B/m1.txt" process_cpu_seconds_total)
la=$(fdel "$OUT/A/m0.txt" "$OUT/A/m1.txt" go_memstats_alloc_bytes_total); lb=$(fdel "$OUT/B/m0.txt" "$OUT/B/m1.txt" go_memstats_alloc_bytes_total)
miss=""
for v in e41a e41b e56a e56b ta tb da db ca cb la lb; do eval "x=\$$v"; case "$x" in ''|'?') miss="$miss $v" ;; esac; done
for v in a0 a1 b0 b1; do eval "x=\$$v"; [ -n "$x" ] || miss="$miss $v(anomaly)"; done
if [ -n "$miss" ]; then
    echo "НЕИЗМЕРИМ: 8.5.O1p НЕИЗМЕРИМ (класс НАЗВАН: нет серий в снимках:$miss)"
else
    A=$((a1 - a0)); B=$((b1 - b0))
    band=$(awk -v a="$A" 'BEGIN { printf "%.0f", 2 * sqrt(a) }'); [ "$AB_NULL_GAP" -gt "$band" ] && band=$AB_NULL_GAP
    echo "  события за ${W} с: socket(41) A $e41a B $e41b (открыт у обоих); clone(56) A $e56a B $e56b; всего по номерам A $ta B $tb (+$((tb - ta)))"
    echo "  anomaly_detection: A $A, B $B, полоса max(2·√A, $AB_NULL_GAP) = $band; дропы A $da B $db; CPU userspace A $(awk -v c=$ca -v w=$W 'BEGIN{printf "%.4f", c/w}') B $(awk -v c=$cb -v w=$W 'BEGIN{printf "%.4f", c/w}') с/с; аллокации A $(awk -v x=$la 'BEGIN{printf "%.0f", x/1048576}') МиБ B $(awk -v x=$lb 'BEGIN{printf "%.0f", x/1048576}') МиБ"
    fail=""
    [ "$B" -le $((A + band)) ] || fail="$fail; anomaly_detection B $B > A $A + полоса $band"
    [ "$db" -le "$da" ] || fail="$fail; дропы B $db > A $da"
    awk -v a="$la" -v b="$lb" -v p="$ALLOC_NOISE_PCT" 'BEGIN { exit !(b <= a * (1 + p / 100)) }' || fail="$fail; аллокации B выше A больше чем на $ALLOC_NOISE_PCT%"
    if [ -z "$fail" ]; then echo "ДОСТИГНУТО: 8.5.O1p ДОСТИГНУТО (цена clone(56): +$e56b событий за ${W} с, в шуме пары по anomaly/дропам/аллокациям)"
    else echo "ПРОВАЛЕН: 8.5.O1p ПРОВАЛЕН (${fail#;})"; fi
fi

# ── контроли (8.5.O1c) ──
fail=""; bad=""
get() { awk -v r="$2" '$1 == r { print $2; exit }' "$OUT/$1/ctl.txt"; }
for r in A B; do for rule in c2_raw_socket_shell exfil_raw_socket_by_non_root mitre_arp_spoof_raw_socket impact_fork_bomb_pattern; do
    v=$(get $r $rule); case "$v" in ''|none|*[!0-9]*) bad="$bad; $r/$rule: счёт не получен" ;; esac
done; done
if [ -n "$bad" ]; then echo "НЕИЗМЕРИМ: 8.5.O1c НЕИЗМЕРИМ (класс НАЗВАН:${bad#;})"
else
    for r in A B; do for rule in c2_raw_socket_shell exfil_raw_socket_by_non_root mitre_arp_spoof_raw_socket; do
        v=$(get $r $rule); [ "$v" -ge 1 ] || fail="$fail; $rule у $r не сработало"
    done; done
    vb=$(get B impact_fork_bomb_pattern); va=$(get A impact_fork_bomb_pattern)
    [ "$vb" -ge 1 ] || fail="$fail; impact_fork_bomb_pattern у B (clone открыт) не сработало"
    [ "$va" -eq 0 ] || fail="$fail; impact_fork_bomb_pattern у A (clone закрыт) = $va ≠ 0 — немоту не доказать"
    echo "  контроли сырым syscall: socket-правила A $(get A c2_raw_socket_shell)/$(get A exfil_raw_socket_by_non_root)/$(get A mitre_arp_spoof_raw_socket), B $(get B c2_raw_socket_shell)/$(get B exfil_raw_socket_by_non_root)/$(get B mitre_arp_spoof_raw_socket); fork_bomb: A $va, B $vb"
    if [ -z "$fail" ]; then echo "ДОСТИГНУТО: 8.5.O1c ДОСТИГНУТО (3 socket-правила живы у обоих; clone-правило: B сработало, A немой)"
    else echo "ПРОВАЛЕН: 8.5.O1c ПРОВАЛЕН (${fail#;})"; fi
fi

# ── предикат для socket(41) по bpftrace (8.5.O1s) ──
bt=$OUT/bt.txt
tot=$(awk '/^@s\[/ { s += $NF } END { printf "%d", s }' "$bt"); 
pass=$(awk '/^@s\[/ { k = $0; sub(/^@s\[/, "", k); sub(/\]:.*/, "", k); split(k, kv, ", "); if (kv[2] == 3 || kv[1] == 17) s += $NF } END { printf "%d", s }' "$bt")
cl=$(awk '/^@cl\[/ { s += $NF } END { printf "%d", s }' "$bt")
if ! grep -aq '^@s\[' "$bt"; then echo "НЕИЗМЕРИМ: 8.5.O1s НЕИЗМЕРИМ (класс НАЗВАН: bpftrace не напечатал ни одной строки @s — окно без socket-вызовов или зонд не встал)"
else
    echo "ИЗМЕРЕНО: 8.5.O1s socket за ${W} с: вызовов $tot, из них SOCK_RAW или AF_PACKET (то, что оставил бы предикат) $pass = $(awk -v p=$pass -v t=$tot 'BEGIN{printf "%.2f", 100*p/t}')%; clone вызовов $cl"
fi
