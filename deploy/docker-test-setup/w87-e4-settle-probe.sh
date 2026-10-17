#!/bin/bash
# Волна 8.7, заход Е4: почему settle-луп mode=null упирается в потолок (settle_reason=ceiling, ночь 8.7: 30 срезов, 572 событий/с).
# Прибор: второй агент (w85-second-agent-lib.sh), на нём
#   1) сэмплер: PROBE_S секунд пары (время с долями секунды, ev+dr) с той же каденцией, что у лупа (curl + sleep 1);
#   2) НАСТОЯЩИЙ counting_settle_loop из attacks/run-all-attacks.sh в режиме null (его собственное решение);
#   3) пересчёт по ряду сэмплера: решение лупа при целой секунде в elapsed (как в коде) и при дробной.
#   w87-e4-settle-probe.sh <SRC> <OUT> [PROBE_S=60]
set -u
SRC=${1:?SRC}; OUT=${2:?OUT}; PROBE=${3:-60}
HERE=$(cd "$(dirname "$0")" && pwd)
source "$HERE/w85-second-agent-lib.sh"
rm -rf "$OUT"; mkdir -p "$OUT"; exec > "$OUT/driver.log" 2>&1
trap 'sa_stop 2> /dev/null' EXIT
die() { echo "die: $*" > "$OUT/DONE"; echo "DIE: $*"; exit 1; }
[ "$(ps -eo cmd | grep -c '[e]bpf-guard --config')" -eq 1 ] || die "ожидался ровно один (рабочий) агент до запуска"
sa_start "$SRC" /root/w87-e4-run 19262 || die "агент не поднялся"
sleep 60
export EBPF_GUARD_API=$SA_API EBPF_GUARD_TOKEN=$SA_TOKEN
# --- 1) сэмплер -----------------------------------------------------------------------------------------------
# sum_metric — та же функция, что у лупа (из run-all-attacks.sh), а не её копия
sed -n '/^sum_metric() {/,/^}/p' "$SRC/deploy/docker-test-setup/attacks/run-all-attacks.sh" > "$OUT/sum.sh"
[ -s "$OUT/sum.sh" ] || die "sum_metric не извлечён"
source "$OUT/sum.sh"
: > "$OUT/series.tsv"
for i in $(seq 1 "$PROBE"); do
    m=$(curl -s --max-time 10 -H "Authorization: Bearer $SA_TOKEN" "$SA_API/metrics")
    ev=$(echo "$m" | sum_metric 'ebpf_guard_events_total\{.*type="file"'); dr=$(echo "$m" | sum_metric 'ebpf_guard_events_dropped_total\{collector="fileaccess"')
    printf '%s\t%s\t%s\n' "$(date +%s.%N)" "$(date +%s)" "$(( ev + dr ))" >> "$OUT/series.tsv"
    sleep 1
done
# --- 2) настоящий луп ------------------------------------------------------------------------------------------
sed -n '/^counting_settle_loop() {/,/^}/p' "$SRC/deploy/docker-test-setup/attacks/run-all-attacks.sh" > "$OUT/loop.sh"
[ -s "$OUT/loop.sh" ] || die "counting_settle_loop не извлечён"
t1=$(date +%s)
( source "$OUT/loop.sh"; counting_settle_loop null 30 0 "$t1" "$OUT/no-such-marker"; echo "settle_reason=$SETTLE_REASON iterations=$SETTLE_I" ) > "$OUT/real-loop.txt" 2>&1
echo "настоящий луп: $(cat $OUT/real-loop.txt)"
# --- 3) пересчёт по ряду ---------------------------------------------------------------------------------------
awk -F'\t' '
    function jit(r) { j = r * 0.10; return (j < 5) ? 5 : j }
    { T[NR] = $1; I[NR] = $2; C[NR] = $3 }
    END {
        for (mode = 0; mode < 2; mode++) {
            ok = 0; win = 0; flat = 0
            for (k = 2; k <= NR; k++) {
                e = (mode == 0) ? I[k] - I[k-1] : T[k] - T[k-1]
                if (mode == 0 && e < 1) e = 1
                r = (C[k] - C[k-1]) / e
                d1 = d2; d2 = d3; d3 = r; if (win < 3) win++
                if (win == 3) {
                    ref = (d1 + d2 + d3) / 3
                    mx = d1; if (d2 > mx) mx = d2; if (d3 > mx) mx = d3
                    mn = d1; if (d2 < mn) mn = d2; if (d3 < mn) mn = d3
                    tot++; if (mx - mn <= jit(ref)) { flat++; if (!first) first = k }
                }
            }
            printf "%s: окон из трёх %d, из них «сошлось» %d, первое сошедшееся окно — срез %s\n", (mode == 0 ? "целая секунда в elapsed (как в коде)" : "дробная секунда"), tot, flat, (first ? first : "нет")
            tot = 0; flat = 0; first = 0; d1 = d2 = d3 = 0; win = 0
        }
        n = 0; for (k = 2; k <= NR; k++) { dI = I[k] - I[k-1]; if (dI >= 2) n++ }
        printf "срезов с elapsed >= 2 с по целым секундам: %d из %d\n", n, NR - 1
    }' "$OUT/series.tsv" | tee "$OUT/recount.txt"
awk -F'\t' 'NR > 1 { printf "%.0f\n", ($3 - p) / ($1 - q) } { p = $3; q = $1 }' "$OUT/series.tsv" | sort -n | awk '{ a[NR] = $1 } END { printf "темп событий в секунду по срезам: мин %s, медиана %s, макс %s\n", a[1], a[int((NR + 1) / 2)], a[NR] }' | tee -a "$OUT/recount.txt"
echo "done $(date -u +%FT%TZ)" > "$OUT/DONE"
