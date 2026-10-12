#!/bin/bash
# w82-pod-attack.sh [OUT] — волна 8.2, этап 4, item E: пик memory.current ПОДА под
# пакетом атак (run-all-attacks.sh без наведённого дропа). Под уже поднят
# w82-pod-run.sh; сэмплер 10 Гц по cgroup контейнера, отчёт — пик и пик по минутам.
# HOLD_S (умолч. 30) — сколько секунд мерить после пакета; t-att1 — конец пакета
# (с от t0), m-att1.txt — метрики на конце пакета (потери окна атак, 8.2.5).
set -u
OUT=${1:-/var/tmp/w82-pod-attack}
SETUP=${SETUP:-/opt/ebpf-guard/deploy/docker-test-setup}
TOKEN=${TOKEN:-w82-stage4-pod-token}
API=localhost:${API_PORT:-19091}
rm -rf "$OUT"; mkdir -p "$OUT"
die() { echo "die: $*" > "$OUT/DONE"; exit 1; }
p=$(pgrep -f '^/usr/local/bin/ebpf-guard --config' | head -1); [ -n "$p" ] || die "под не найден"
cg=/sys/fs/cgroup$(awk -F: '$1=="0"{print $3}' /proc/"$p"/cgroup)
[ "$(ps -eo cmd | grep -c '[e]bpf-guard --config')" -eq 1 ] || die "агентов не 1"
t0=$(date +%s.%N); echo "$t0 $cg" > "$OUT/t0"
M() { curl -s --max-time 30 -H "Authorization: Bearer $TOKEN" "$API/metrics"; }
M > "$OUT/m-pre.txt"
curl -s --max-time 10 -H "Authorization: Bearer $TOKEN" "$API/debug/pprof/heap" > "$OUT/heap-pre.pprof"
( while [ ! -e "$OUT/STOP" ]; do
    v=$(cat "$cg/memory.current" 2>/dev/null) && {
        ts=$(awk -v t="$t0" -v n="$(date +%s.%N)" 'BEGIN { printf "%.1f", n - t }')
        echo "$ts $v"
        echo "$ts $v $(awk '$1=="inactive_file"{print $2}' "$cg/memory.stat" 2>/dev/null)" >> "$OUT/samples-ws.tsv"
    }
    sleep 0.1
  done ) > "$OUT/samples.tsv" &
SP=$!
# Куча по ходу окна, каждые 150 с (доводка 8.2, T1): «buildAncestry не растёт между
# 5-й и 10-й минутой» без средней точки не судится — были только pre и post.
( while [ ! -e "$OUT/STOP" ]; do
    for _ in $(seq 1 15); do [ -e "$OUT/STOP" ] || sleep 10; done
    [ -e "$OUT/STOP" ] && break
    curl -s --max-time 10 -H "Authorization: Bearer $TOKEN" "$API/debug/pprof/heap" > "$OUT/heap-mid-$(awk -v t="$t0" -v n="$(date +%s.%N)" 'BEGIN { printf "%04.0f", n - t }').pprof"
  done ) &
HP=$!
ls "$SETUP/attacks/attack-results" 2>/dev/null | sort > "$OUT/results-before.lst"
( cd "$SETUP/attacks" && EBPF_GUARD_API="http://$API" EBPF_GUARD_TOKEN="$TOKEN" SKIP_INDUCED_DROP=1 bash ./run-all-attacks.sh > "$OUT/attacks.log" 2>&1; echo "rc=$?" > "$OUT/attacks.rc" )
awk -v t="$t0" -v n="$(date +%s.%N)" 'BEGIN { printf "%.1f\n", n - t }' > "$OUT/t-att1"
M > "$OUT/m-att1.txt"
# Recall пода (8.2.5): манифест и снимки алертов ЭТОГО пакета — каталог
# attack-results общий с пакетом гейта хоста, берутся только новые файлы.
cp "$SETUP/attacks/attack-manifest.json" "$OUT/" 2>/dev/null
ls "$SETUP/attacks/attack-results" 2>/dev/null | sort | comm -13 "$OUT/results-before.lst" - > "$OUT/results-new.lst"
for f in $(grep -E '^(baseline|final)-alerts-.*\.json$' "$OUT/results-new.lst"); do cp "$SETUP/attacks/attack-results/$f" "$OUT/"; done
# HOLD_S после пакета: сэмплер и куча продолжают идти. Ночь 8.2 держит 600 с —
# выселение ancestry тиком Cleanup (TTL 5 мин + тик 5 мин) видно только после тика (T1).
sleep "${HOLD_S:-30}"
touch "$OUT/STOP"; wait $SP $HP
M > "$OUT/m-post.txt"
curl -s --max-time 10 -H "Authorization: Bearer $TOKEN" "$API/debug/pprof/heap" > "$OUT/heap-post.pprof"
cat "$cg/memory.stat" > "$OUT/memory.stat"
# 8.5 сторож F1: состояние предикатов и kernel_filtered на трёх снимках окна.
for s in pre att1 post; do
    grep -aE '^ebpf_guard_(kernel_predicate_state|syscall_events_kernel_filtered_total|syscall_counts_folded_total)' "$OUT/m-$s.txt" | sed "s/^/$s /" >> "$OUT/f1.txt"
done
f1post=$(grep -a '^post ebpf_guard_kernel_predicate_state' "$OUT/f1.txt" | grep -a ' 1$' | sed 's/.*state="\([^"]*\)".*/\1/')
f1pre=$(grep -a '^pre ebpf_guard_kernel_predicate_state' "$OUT/f1.txt" | grep -a ' 1$' | sed 's/.*state="\([^"]*\)".*/\1/')
echo "f1_state pre=${f1pre:-НЕТ СЕРИИ} post=${f1post:-НЕТ СЕРИИ} requested=${ARG_PREDICATES:-0}" | tee -a "$OUT/f1.txt"
if [ "${ARG_PREDICATES:-0}" = 1 ] && { [ "$f1pre" != active ] || [ "$f1post" != active ]; }; then
    echo "die: F1 запрошен, а за окно атак состояние pre=${f1pre:-нет} post=${f1post:-нет}" > "$OUT/DONE"; exit 1
fi
# 8.2.1: рестарт контейнера за окно (OOM на лимите пода) — провал, не пропуск.
export PATH=$PATH:/root/bin:/usr/local/bin KUBECONFIG=${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}
kubectl -n ebpf-guard get pods -o jsonpath='{.items[0].status.containerStatuses[0].restartCount}' > "$OUT/restarts.txt" 2>/dev/null \
    || rm -f "$OUT/restarts.txt"
kubectl -n ebpf-guard get pods -o jsonpath='{.items[0].status.containerStatuses[0].lastState.terminated.reason}' > "$OUT/last-state.txt" 2>/dev/null
awk 'NF == 2 && $2 > m { m = $2; t = $1 } END { printf "peak_mib=%.1f peak_s=%s\n", m / 1048576, t }' "$OUT/samples.tsv" > "$OUT/peak.txt"
bash "$SETUP/w82-ws-peak.sh" "$OUT/samples-ws.tsv" >> "$OUT/peak.txt"
awk 'NF == 2 { s = int($1 / 60); if ($2 > m[s]) m[s] = $2 } END { for (s in m) printf "%3d %.1f\n", s, m[s] / 1048576 }' "$OUT/samples.tsv" | sort -n > "$OUT/per-minute-mib.txt"
echo "done $(date -u +%FT%TZ)" > "$OUT/DONE"
