#!/bin/bash
# w82-startup-sampler.sh [OUT] — волна 8.2, item A3: пик памяти СТАРТА.
#
# На 5.15 нет memory.peak, а окно атак без первых 60 с процесса пик не видит
# (№536: 292 МиБ на 24-й секунде). Прибор перезапускает агента с чистым стором и
# 90 с снимает memory.current cgroup юнита 10 раз в секунду; с момента, когда
# API ответил, раз в 5 с — heap-профиль и /metrics. Отчёт называет пик (МиБ,
# секунда от старта) и heap-профиль, ближайший к пику по времени.
#
# Запуск на стенде отсоединённо, ВНЕ измеряемых окон (рестарт агента):
#   setsid nohup /opt/ebpf-guard/deploy/docker-test-setup/w82-startup-sampler.sh > /root/w82-a3.log 2>&1 < /dev/null &
set -u
OUT=${1:-/var/tmp/w82-a3}
UNIT=ebpf-guard-test.service
CGDIR=/sys/fs/cgroup/system.slice/$UNIT
API=http://localhost:19090
DUR=${DUR:-90}
TOK=$(grep '^admin=' /var/lib/ebpf-guard/token | cut -d= -f2)
rm -rf "$OUT"; mkdir -p "$OUT/heap"
die() { echo "die: $*" > "$OUT/DONE"; exit 1; }
[ "$(ps -eo cmd | grep -c '[e]bpf-guard --config')" -eq 1 ] || die "агентов не 1"

systemctl stop $UNIT
rm -f /var/lib/ebpf-guard/test-events.db*
t0=$(date +%s.%N); echo "$t0" > "$OUT/t0"
systemctl start --no-block $UNIT

# 10 Гц: «сек_от_старта байты»; файл cgroup появляется не мгновенно.
(
    end=$(awk -v t="$t0" -v d="$DUR" 'BEGIN { printf "%.0f", t + d }')
    while [ "$(date +%s)" -lt "$end" ]; do
        v=$(cat "$CGDIR/memory.current" 2>/dev/null) && echo "$(awk -v t="$t0" -v n="$(date +%s.%N)" 'BEGIN { printf "%.1f", n - t }') $v"
        sleep 0.1
    done
) > "$OUT/samples.tsv" &
SAMPLER=$!

# heap + metrics раз в 5 с, как только API ответил.
(
    end=$(awk -v t="$t0" -v d="$DUR" 'BEGIN { printf "%.0f", t + d }')
    while [ "$(date +%s)" -lt "$end" ]; do
        s=$(awk -v t="$t0" -v n="$(date +%s.%N)" 'BEGIN { printf "%05.1f", n - t }')
        if curl -s -o "$OUT/heap/heap-$s.pprof" --max-time 3 -H "Authorization: Bearer $TOK" "$API/debug/pprof/heap" && [ -s "$OUT/heap/heap-$s.pprof" ]; then
            curl -s -o "$OUT/heap/metrics-$s.txt" --max-time 3 -H "Authorization: Bearer $TOK" "$API/metrics"
            sleep 5
        else
            rm -f "$OUT/heap/heap-$s.pprof"; sleep 0.5
        fi
    done
) &
PROFILER=$!
wait $SAMPLER $PROFILER

PID=$(systemctl show -p MainPID --value $UNIT)
{ echo "pid=$PID"; sha256sum /proc/"$PID"/exe | cut -c1-12; } > "$OUT/meta.txt"
# Пик и ближайший к нему профиль.
awk 'NF == 2 && $2 > m { m = $2; t = $1 } END { printf "peak_mib=%.1f peak_s=%s\n", m / 1048576, t }' "$OUT/samples.tsv" > "$OUT/peak.txt"
pk=$(sed -n 's/.*peak_s=\([0-9.]*\).*/\1/p' "$OUT/peak.txt")
ls "$OUT/heap" | sed -n 's/^heap-\([0-9.]*\)\.pprof$/\1/p' \
    | awk -v p="$pk" '{ d = $1 - p; if (d < 0) d = -d; if (best == "" || d < bd) { best = $1; bd = d } } END { print "nearest_heap=heap-" best ".pprof delta_s=" bd }' >> "$OUT/peak.txt"
awk 'NF == 2 { s = int($1); if ($2 > m[s]) m[s] = $2 } END { for (s in m) printf "%3d %.1f\n", s, m[s] / 1048576 }' "$OUT/samples.tsv" | sort -n > "$OUT/per-second-mib.txt"
echo "done $(date -u +%FT%TZ)" > "$OUT/DONE"
