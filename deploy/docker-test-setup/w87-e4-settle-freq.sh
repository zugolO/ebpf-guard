#!/bin/bash
# Волна 8.7, заход Е4: как часто НАСТОЯЩИЙ counting_settle_loop (mode=null) упирается в потолок на фоне стенда.
# Второй агент, K запусков лупа подряд (каждый — свои до 30 срезов), печатается причина остановки и число срезов.
#   w87-e4-settle-freq.sh <SRC> <OUT> [K=12]
set -u
SRC=${1:?SRC}; OUT=${2:?OUT}; K=${3:-12}
HERE=$(cd "$(dirname "$0")" && pwd)
source "$HERE/w85-second-agent-lib.sh"
rm -rf "$OUT"; mkdir -p "$OUT"; exec > "$OUT/driver.log" 2>&1
trap 'sa_stop 2> /dev/null' EXIT
die() { echo "die: $*" > "$OUT/DONE"; echo "DIE: $*"; exit 1; }
[ "$(ps -eo cmd | grep -c '[e]bpf-guard --config')" -eq 1 ] || die "ожидался ровно один (рабочий) агент до запуска"
sa_start "$SRC" /root/w87-e4f-run 19263 || die "агент не поднялся"
sleep 60
export EBPF_GUARD_API=$SA_API EBPF_GUARD_TOKEN=$SA_TOKEN
A="$SRC/deploy/docker-test-setup/attacks/run-all-attacks.sh"
sed -n '/^sum_metric() {/,/^}/p' "$A" > "$OUT/sum.sh"; sed -n '/^counting_settle_loop() {/,/^}/p' "$A" > "$OUT/loop.sh"
[ -s "$OUT/sum.sh" ] && [ -s "$OUT/loop.sh" ] || die "функции не извлечены"
for k in $(seq 1 "$K"); do
    t1=$(date +%s)
    ( source "$OUT/sum.sh"; source "$OUT/loop.sh"; counting_settle_loop null 30 0 "$t1" "$OUT/no-such-marker"; echo "run=$k settle_reason=$SETTLE_REASON iterations=$SETTLE_I" ) | tee -a "$OUT/runs.txt"
done
awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^settle_reason=/) { split($i, a, "="); c[a[2]]++ } n++ } END { for (r in c) printf "%s: %d из %d\n", r, c[r], n }' "$OUT/runs.txt" | tee "$OUT/summary.txt"
echo "done $(date -u +%FT%TZ)" > "$OUT/DONE"
