#!/usr/bin/env bash
#
# idle-run.sh — ночной прогон ebpf-guard без атак.
#
# Снимает срезы /metrics, /api/v1/status, /debug/state и RSS агента каждые
# INTERVAL секунд, в конце делает рестарт агента для проверки profiler
# state persistence (P0-3) и складывает всё в один tar.gz.
#
# Использование:
#   sudo ./idle-run.sh                 # 8 часов, срез каждые 5 минут
#   sudo DURATION=3600 ./idle-run.sh   # 1 час
#   sudo NO_RESTART=1 ./idle-run.sh    # без финального рестарта
#
set -uo pipefail

API="${EBPF_GUARD_API:-http://localhost:19090}"
TOKEN="${EBPF_GUARD_TOKEN:-$(grep '^admin=' /var/lib/ebpf-guard/token 2>/dev/null | cut -d= -f2)}"
INTERVAL="${INTERVAL:-300}"        # 5 минут между срезами
DURATION="${DURATION:-28800}"      # 8 часов
SERVICE="${SERVICE:-ebpf-guard-test.service}"
NO_RESTART="${NO_RESTART:-0}"

TS="$(date -u +%Y%m%d_%H%M%S)"
OUT="${OUT_DIR:-$(pwd)/idle-results/idle-$TS}"
mkdir -p "$OUT/snapshots"

log() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$OUT/idle-run.log"; }
api() { curl -s --max-time 15 -H "Authorization: Bearer $TOKEN" "$API$1"; }

if [[ -z "$TOKEN" ]]; then
    echo "ОШИБКА: не найден admin-токен (/var/lib/ebpf-guard/token). Задай EBPF_GUARD_TOKEN=..." >&2
    exit 1
fi
if [[ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H "Authorization: Bearer $TOKEN" "$API/health")" != "200" ]]; then
    echo "ОШИБКА: $API/health недоступен — агент не запущен или токен неверный." >&2
    exit 1
fi

# --- проверка, что state persistence включён (иначе рестарт-тест бессмыслен) ---
CFG="${CONFIG:-/opt/ebpf-guard/deploy/docker-test-setup/config-test.yaml}"
if ! grep -q 'state_persistence' "$CFG" 2>/dev/null; then
    log "ВНИМАНИЕ: state_persistence не найден в $CFG — проверка P0-3 будет пропущена."
    log "         Добавь в секцию profiler:  state_persistence: {enabled: true, path: /var/lib/ebpf-guard/profiler-state.json}"
fi

log "=== IDLE RUN START ==="
log "выход:      $OUT"
log "интервал:   ${INTERVAL}s, длительность: ${DURATION}s ($((DURATION/3600))ч)"
log "сервис:     $SERVICE"

# --- контекст окружения (для интерпретации шума) ---
{
    echo "=== date ==="; date -u
    echo "=== uname ==="; uname -a
    echo "=== config ==="; cat "$CFG" 2>/dev/null
    echo "=== crontab -l (root) ==="; crontab -l 2>/dev/null
    echo "=== /etc/cron.d ==="; ls -la /etc/cron.d/ 2>/dev/null
    echo "=== systemd timers ==="; systemctl list-timers --all --no-pager 2>/dev/null
    echo "=== docker ps ==="; docker ps 2>/dev/null
} > "$OUT/environment.txt" 2>&1

# --- стартовый срез ---
api /api/v1/alerts > "$OUT/alerts-start.json"
api /metrics       > "$OUT/metrics-start.txt"
api /api/v1/status > "$OUT/status-start.json"

snapshot() {
    local n="$1" pad
    pad="$(printf '%04d' "$n")"
    local t; t="$(date -u +%Y%m%dT%H%M%SZ)"

    api /metrics       > "$OUT/snapshots/metrics-$pad.txt"
    api /api/v1/status > "$OUT/snapshots/status-$pad.json"
    api /debug/state   > "$OUT/snapshots/state-$pad.json"

    # RSS/CPU агента + системный контекст — в один TSV для построения графиков
    local pid rss cpu nseries alerts loadavg memavail
    pid="$(systemctl show -p MainPID --value "$SERVICE" 2>/dev/null)"
    if [[ -n "$pid" && "$pid" != "0" ]]; then
        rss="$(awk '/VmRSS/{print $2}' "/proc/$pid/status" 2>/dev/null)"
        cpu="$(ps -o %cpu= -p "$pid" 2>/dev/null | tr -d ' ')"
    fi
    nseries="$(grep -c '^ebpf_guard_profiler_anomaly_score{' "$OUT/snapshots/metrics-$pad.txt" 2>/dev/null)"
    alerts="$(grep '^ebpf_guard_alerts_total{' "$OUT/snapshots/metrics-$pad.txt" 2>/dev/null \
              | awk '{s+=$NF} END{printf "%d", s+0}')"
    loadavg="$(cut -d' ' -f1 /proc/loadavg)"
    memavail="$(awk '/MemAvailable/{print $2}' /proc/meminfo)"

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$t" "$n" "${rss:-0}" "${cpu:-0}" "${nseries:-0}" "${alerts:-0}" "$loadavg" "${memavail:-0}" \
        >> "$OUT/timeseries.tsv"

    log "срез $pad: rss=${rss:-?}kB cpu=${cpu:-?}% anomaly_series=${nseries:-?} alerts_total=${alerts:-?}"
}

printf 'timestamp\tn\trss_kb\tcpu_pct\tanomaly_series\talerts_total\tloadavg\tmem_avail_kb\n' > "$OUT/timeseries.tsv"

END=$(( $(date +%s) + DURATION ))
n=0
snapshot "$n"
while [[ $(date +%s) -lt $END ]]; do
    sleep "$INTERVAL"
    n=$((n+1))
    snapshot "$n"
done

# --- финальный срез до рестарта ---
log "=== сбор финальных данных ==="
api /api/v1/alerts > "$OUT/alerts-end.json"
api /metrics       > "$OUT/metrics-end.txt"
api /api/v1/status > "$OUT/status-end.json"
api /debug/state   > "$OUT/state-end.json"

# --- проверка P0-3: переживает ли learning рестарт ---
if [[ "$NO_RESTART" != "1" ]]; then
    log "=== P0-3: рестарт агента для проверки state persistence ==="
    api /api/v1/status | tee "$OUT/p0-3-status-before-restart.json" \
        | grep -o '"learning_complete":[a-z]*' | head -1 | sed 's/^/  before: /' | tee -a "$OUT/idle-run.log"
    ls -la /var/lib/ebpf-guard/profiler-state.json > "$OUT/p0-3-state-file.txt" 2>&1 || \
        echo "profiler-state.json ОТСУТСТВУЕТ — persistence выключен или SaveState не отработал" > "$OUT/p0-3-state-file.txt"
    cat "$OUT/p0-3-state-file.txt" | tee -a "$OUT/idle-run.log"

    systemctl restart "$SERVICE"
    sleep 20

    api /api/v1/status > "$OUT/p0-3-status-after-restart.json"
    grep -o '"learning_complete":[a-z]*' "$OUT/p0-3-status-after-restart.json" | head -1 \
        | sed 's/^/  after:  /' | tee -a "$OUT/idle-run.log"
    log "ожидание: learning_complete=true сразу после рестарта, если P0-3 починен"
fi

# --- журнал за весь период ---
journalctl -u "$SERVICE" --since "@$(( $(date +%s) - DURATION - 600 ))" --no-pager \
    > "$OUT/journal.log" 2>&1

# --- сводка на месте, чтобы сразу видеть аномалии ---
{
    echo "=== IDLE RUN SUMMARY ($TS) ==="
    echo "срезов: $((n+1)), интервал ${INTERVAL}s, длительность ${DURATION}s"
    echo
    echo "--- рост RSS / cardinality (первый → последний срез) ---"
    head -2 "$OUT/timeseries.tsv" | tail -1
    tail -1 "$OUT/timeseries.tsv"
    echo
    echo "--- алерты за прогон ---"
    echo "start: $(grep -c '"rule_id"' "$OUT/alerts-start.json" 2>/dev/null)"
    echo "end:   $(grep -c '"rule_id"' "$OUT/alerts-end.json" 2>/dev/null)"
    echo
    echo "--- critical / confirmed attack на idle (должно быть 0 — P1-6/P1-13) ---"
    echo "incident_confirmed_attack: $(grep -c 'incident_confirmed_attack' "$OUT/alerts-end.json" 2>/dev/null)"
    grep '^ebpf_guard_incidents_total' "$OUT/metrics-end.txt" 2>/dev/null
    echo
    echo "--- CPU watchdog циклы в журнале (не должно быть на idle) ---"
    echo "reducing:  $(grep -c 'cpu pressure: reducing' "$OUT/journal.log" 2>/dev/null)"
    echo "escalating:$(grep -c 'cpu pressure: escalating' "$OUT/journal.log" 2>/dev/null)"
    echo "recovered: $(grep -c 'cpu pressure: recovered' "$OUT/journal.log" 2>/dev/null)"
    echo
    echo "--- рестарты агента за прогон (незапланированные = баг) ---"
    # 5.6d: считать смены PID агента (ebpf-guard[NNNNNN]), а не строки
    # "ebpf-guard starting" — та же строка печатается один раз при самом
    # первом запуске прогона (не рестарт) и один раз на каждый настоящий
    # рестарт, так что счётчик был завышен на 1 всегда. Первая увиденная в
    # журнале смена PID — это старт самого прогона, не рестарт, и
    # исключается явно. Каждая следующая смена PID считается плановой, если
    # где-то среди строк под старым PID встретилась "graceful shutdown:
    # complete" (не обязательно последней — за ней ещё идут короткие строки
    # cleanup); иначе — незапланированный рестарт (баг).
    awk '
        /ebpf-guard\[[0-9]+\]/ {
            line = $0
            sub(/.*ebpf-guard\[/, "", line)
            sub(/\].*/, "", line)
            pid = line
            if (pid != last_pid) {
                if (seen) {
                    if (graceful) planned++
                    else unplanned++
                }
                seen = 1
                graceful = 0
            }
            last_pid = pid
            if ($0 ~ /graceful shutdown: complete/) graceful = 1
        }
        END {
            printf "рестартов: %d (плановых: %d, незапланированных: %d)\n", planned+unplanned, planned, unplanned
        }
    ' "$OUT/journal.log" 2>/dev/null
} > "$OUT/SUMMARY.txt" 2>&1

cat "$OUT/SUMMARY.txt" | tee -a "$OUT/idle-run.log"

ARCHIVE="$(dirname "$OUT")/idle-$TS.tar.gz"
tar czf "$ARCHIVE" -C "$(dirname "$OUT")" "$(basename "$OUT")"
log "=== IDLE RUN DONE ==="
log "архив: $ARCHIVE ($(du -h "$ARCHIVE" | cut -f1))"
