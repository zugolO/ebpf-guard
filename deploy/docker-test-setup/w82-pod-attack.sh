#!/bin/bash
# w82-pod-attack.sh [OUT] — волна 8.2, этап 4, item E: пик memory.current ПОДА под
# пакетом атак (run-all-attacks.sh без наведённого дропа). Под уже поднят
# w82-pod-run.sh; сэмплер 10 Гц по cgroup контейнера, отчёт — пик и пик по минутам.
set -u
OUT=${1:-/var/tmp/w82-pod-attack}
SETUP=/opt/ebpf-guard/deploy/docker-test-setup
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
( cd "$SETUP/attacks" && EBPF_GUARD_API="http://$API" EBPF_GUARD_TOKEN="$TOKEN" SKIP_INDUCED_DROP=1 bash ./run-all-attacks.sh > "$OUT/attacks.log" 2>&1; echo "rc=$?" > "$OUT/attacks.rc" )
sleep 30
touch "$OUT/STOP"; wait $SP
M > "$OUT/m-post.txt"
curl -s --max-time 10 -H "Authorization: Bearer $TOKEN" "$API/debug/pprof/heap" > "$OUT/heap-post.pprof"
cat "$cg/memory.stat" > "$OUT/memory.stat"
awk 'NF == 2 && $2 > m { m = $2; t = $1 } END { printf "peak_mib=%.1f peak_s=%s\n", m / 1048576, t }' "$OUT/samples.tsv" > "$OUT/peak.txt"
bash "$SETUP/w82-ws-peak.sh" "$OUT/samples-ws.tsv" >> "$OUT/peak.txt"
awk 'NF == 2 { s = int($1 / 60); if ($2 > m[s]) m[s] = $2 } END { for (s in m) printf "%3d %.1f\n", s, m[s] / 1048576 }' "$OUT/samples.tsv" | sort -n > "$OUT/per-minute-mib.txt"
echo "done $(date -u +%FT%TZ)" > "$OUT/DONE"
