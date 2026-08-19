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
# 5.9a (находки №27/№28): этот файл — канал, которым харнесс сообщает агенту
# корень СВОЕГО дерева процессов, чтобы correlator.observer_exclude (см.
# config-test.yaml) исключил его до оценки правил. Путь должен совпадать с
# correlator.observer_exclude.root_pid_file в конфиге агента.
OBSERVER_ROOT_PID_FILE="${OBSERVER_ROOT_PID_FILE:-/var/lib/ebpf-guard/observer-root-pid}"

TS="$(date -u +%Y%m%d_%H%M%S)"
OUT="${OUT_DIR:-$(pwd)/idle-results/idle-$TS}"
mkdir -p "$OUT/snapshots"

log() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$OUT/idle-run.log"; }

# 5.9a половина 1: один срез — один процесс curl вместо трёх (`--next`
# держит соединение открытым между запросами и переиспользует его через
# keep-alive, но даже без переиспользования это один fork/exec вместо трёх,
# что и было целью — было 3 curl на срез, эта функция даёт 1 независимо от
# числа URL). Аргументы идут парами <path> <outfile>.
api_multi() {
    local args=(-s)
    local first=1
    while [[ $# -gt 0 ]]; do
        if [[ $first -eq 1 ]]; then
            first=0
        else
            args+=(--next)
        fi
        # --max-time — per-transfer опция: после --next сбрасывается, поэтому
        # повторяется в каждом сегменте (иначе таймаут был бы только у первого
        # URL, а зависший второй/третий держал бы срез бесконечно).
        args+=(--max-time 20 -H "Authorization: Bearer $TOKEN" -o "$2" "$API$1")
        shift 2
    done
    curl "${args[@]}"
}

if [[ -z "$TOKEN" ]]; then
    echo "ОШИБКА: не найден admin-токен (/var/lib/ebpf-guard/token). Задай EBPF_GUARD_TOKEN=..." >&2
    exit 1
fi

# 5.9a половина 2 + 5.9.1a (находка №34, третий пункт): сообщить агенту
# корень своего дерева процессов ($$ — PID именно этого bash-скрипта;
# curl/ps/grep/awk/journalctl/tar, которых он порождает, все получат его как
# PPID напрямую или через цепочку) ДО первого HTTP-запроса харнесса — раньше
# это писалось после проверки /health, а тот curl (и всё, что случится до
# подтверждения подхвата) не мог быть исключён в принципе. Агент поллит файл
# раз в 2с (см. cmd/ebpf-guard/main.go) и исключает дерево из корреляции,
# если correlator.observer_exclude.enabled: true в его конфиге — вне
# тестового стенда это выключено, и запись файла безвредна.
#
# Ограничение: между концом этого прогона и следующим стартом харнесса PID
# может быть переиспользован не связанным процессом (та же оговорка, что у
# 5.8e про selfTree, см. plan.md). trap ниже обнуляет файл при выходе, чтобы
# сузить это окно до времени жизни самого прогона, но не убирает его совсем.
if echo "$$" > "$OBSERVER_ROOT_PID_FILE" 2>/dev/null; then
    log "5.9a: наблюдательное дерево харнесса зарегистрировано, root_pid=$$ ($OBSERVER_ROOT_PID_FILE)"
    cleanup_observer_root() { echo 0 > "$OBSERVER_ROOT_PID_FILE" 2>/dev/null || true; }
    trap cleanup_observer_root EXIT
else
    log "ВНИМАНИЕ: не удалось записать $OBSERVER_ROOT_PID_FILE — фильтр 5.9a не подхватит корень, шум харнесса не будет исключён агентом."
fi

# 5.9.1a: не делать вообще НИЧЕГО сетевого (включая /health) до того, как
# агент подтвердит через /debug/state, что забрал именно этот root_pid —
# иначе окно между записью файла (только что) и следующим тиком 2с-поллера
# само даёт события собственного дерева харнесса, которые фильтр ещё не
# исключает (находка №34, третий пункт: инцидент на самом root_pid в момент
# регистрации).
#
# ВАЖНО про стоимость самой проверки: каждый пробный запрос к /debug/state —
# это отдельный процесс curl, то есть ровно тот источник алертов, который мы
# тут и закрываем (libc/NSS читает /etc/passwd в первые миллисекунды жизни
# curl — находка №27/№34, три алерта на процесс). Пока агент не подтвердил
# подхват, эти алерты НЕ исключаются фильтром, поэтому опрос обязан быть
# максимально редким, а не максимально частым: сначала ждём 3с вслепую (тик
# поллера — 2с, см. cmd/ebpf-guard/main.go), и только потом опрашиваем с шагом
# 2с. В типичном случае это ОДИН curl до подтверждения — против пятнадцати у
# посекундного опроса, который стоил бы до 45 неисключаемых алертов на ровном
# месте. Потолок — 3с + 7*2с ≈ 17с; если агент выключен или observer_exclude
# не включён в его конфиге, дальше просто предупреждаем и продолжаем как
# раньше (не блокируем прогон навсегда).
observer_confirmed=0
sleep 3
for _ in $(seq 1 7); do
    reported_root="$(curl -s --max-time 5 -H "Authorization: Bearer $TOKEN" "$API/debug/state" 2>/dev/null \
        | jq -r '.engine_stats.observer_root_pid // empty' 2>/dev/null)"
    if [[ "$reported_root" == "$$" ]]; then
        observer_confirmed=1
        break
    fi
    sleep 2
done
if [[ "$observer_confirmed" -eq 1 ]]; then
    log "5.9.1a: агент подтвердил подхват root_pid=$$ через /debug/state"
else
    log "ВНИМАНИЕ: агент не подтвердил подхват root_pid=$$ за ~17с (/debug/state недоступен, observer_exclude выключен в его конфиге, или агент не запущен) — продолжаем без подтверждения, окно регистрации не закрыто."
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

# --- стартовый срез (1 curl вместо 3) ---
# 5.9.1b (находка №35): граница измерительного окна для критерия
# incident_confirmed_attack ниже по файлу — снята здесь, а не в SUMMARY,
# чтобы отметить момент максимально близко к самому первому запросу окна.
RUN_START_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
api_multi /api/v1/alerts "$OUT/alerts-start.json" /metrics "$OUT/metrics-start.txt" /api/v1/status "$OUT/status-start.json"

# --- CPU без `ps`: тики utime+stime из /proc/<pid>/stat, штатным `read` bash ---
# (5.9a половина 1). CLK_TCK снят один раз на весь прогон, не на срез.
CLK_TCK="$(getconf CLK_TCK 2>/dev/null || echo 100)"
PREV_CPU_PID=""
PREV_UTIME=0
PREV_STIME=0
PREV_CPU_TS=0

# Результат — в глобальной CPU_PCT, НЕ через echo/$(...): подстановка команды
# запускает функцию в сабшелле, и присваивания PREV_* терялись бы между
# срезами — cpu печатался бы 0.0 весь прогон (первый вызов всегда 0.0, а
# «предыдущие» тики никогда бы не сохранялись).
proc_cpu_pct() {
    local pid="$1" now stat rest utime stime dt dticks cpu_x10
    CPU_PCT="0.0"
    now=$(date +%s)
    if [[ ! -r "/proc/$pid/stat" ]]; then
        return
    fi
    read -r stat < "/proc/$pid/stat" 2>/dev/null
    # comm (2-е поле) в скобках и может содержать пробелы/скобки — режем по
    # ПОСЛЕДНЕЙ ") ", остаток — поля начиная с state (3-е поле общей нумерации).
    rest="${stat##*) }"
    read -ra parts <<< "$rest"
    utime="${parts[11]:-0}"   # 14-е поле общей нумерации = 12-е в rest (0-based 11)
    stime="${parts[12]:-0}"   # 15-е поле общей нумерации = 13-е в rest (0-based 12)

    if [[ "$pid" == "$PREV_CPU_PID" && "$PREV_CPU_TS" -gt 0 ]]; then
        dt=$(( now - PREV_CPU_TS ))
        dticks=$(( (utime + stime) - (PREV_UTIME + PREV_STIME) ))
        if (( dt > 0 && dticks >= 0 )); then
            cpu_x10=$(( dticks * 1000 / CLK_TCK / dt ))
            CPU_PCT="$(( cpu_x10 / 10 )).$(( cpu_x10 % 10 ))"
        fi
    fi

    PREV_CPU_PID="$pid"
    PREV_UTIME="$utime"
    PREV_STIME="$stime"
    PREV_CPU_TS="$now"
}

snapshot() {
    local n="$1" pad
    pad="$(printf '%04d' "$n")"
    local t; t="$(date -u +%Y%m%dT%H%M%SZ)"

    # 5.9a половина 1: один curl-процесс на все три эндпоинта вместо трёх.
    api_multi /metrics "$OUT/snapshots/metrics-$pad.txt" \
              /api/v1/status "$OUT/snapshots/status-$pad.json" \
              /debug/state "$OUT/snapshots/state-$pad.json"

    # RSS напрямую из /proc (уже не форкает ничего); CPU — через
    # proc_cpu_pct (bash read, без `ps`). Разбор снятых снимков (nseries,
    # alerts_total через grep|awk) сюда сознательно НЕ вынесен — та часть
    # харнесса, которая раньше грепала/awk'ала на каждом срезе, теперь
    # выполняется один раз в конце окна измерения (см. постобработку ниже),
    # чтобы не добавлять grep/awk-процессы в сам измеряемый период.
    local pid rss loadavg memavail
    pid="$(systemctl show -p MainPID --value "$SERVICE" 2>/dev/null)"
    if [[ -n "$pid" && "$pid" != "0" ]]; then
        rss="$(awk '/VmRSS/{print $2}' "/proc/$pid/status" 2>/dev/null)"
    fi
    loadavg="$(cut -d' ' -f1 /proc/loadavg)"
    memavail="$(awk '/MemAvailable/{print $2}' /proc/meminfo)"
    local cpu="0.0"
    if [[ -n "${pid:-}" && "$pid" != "0" ]]; then
        proc_cpu_pct "$pid"   # результат в CPU_PCT — см. комментарий у функции
        cpu="$CPU_PCT"
    fi

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$t" "$n" "${rss:-0}" "$cpu" "$loadavg" "${memavail:-0}" \
        >> "$OUT/timeseries-raw.tsv"

    log "срез $pad: rss=${rss:-?}kB cpu=${cpu}%"
}

printf 'timestamp\tn\trss_kb\tcpu_pct\tloadavg\tmem_avail_kb\n' > "$OUT/timeseries-raw.tsv"

END=$(( $(date +%s) + DURATION ))
n=0
snapshot "$n"
while [[ $(date +%s) -lt $END ]]; do
    sleep "$INTERVAL"
    n=$((n+1))
    snapshot "$n"
done

# --- постобработка (5.9a половина 1): разбор снятых снимков (anomaly_series,
# alerts_total) переносится СЮДА, после конца измерительного окна — раньше
# это grep|awk на КАЖДОМ срезе, то есть каждые INTERVAL секунд в течение всех
# DURATION секунд измерения. Теперь один проход по уже сохранённым файлам,
# вне окна, которое считает шум. ---
log "=== постобработка снимков (nseries/alerts_total) ==="
{
    printf 'timestamp\tn\trss_kb\tcpu_pct\tanomaly_series\talerts_total\tloadavg\tmem_avail_kb\n'
    tail -n +2 "$OUT/timeseries-raw.tsv" | while IFS=$'\t' read -r t n rss cpu loadavg memavail; do
        pad="$(printf '%04d' "$n")"
        mf="$OUT/snapshots/metrics-$pad.txt"
        nseries="$(grep -c '^ebpf_guard_profiler_anomaly_score{' "$mf" 2>/dev/null)"
        alerts="$(grep '^ebpf_guard_alerts_total{' "$mf" 2>/dev/null \
                  | awk '{s+=$NF} END{printf "%d", s+0}')"
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$t" "$n" "$rss" "$cpu" "${nseries:-0}" "${alerts:-0}" "$loadavg" "$memavail"
    done
} > "$OUT/timeseries.tsv"

# --- финальный срез до рестарта (1 curl вместо 4) ---
log "=== сбор финальных данных ==="
RUN_END_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
api_multi /api/v1/alerts "$OUT/alerts-end.json" /metrics "$OUT/metrics-end.txt" \
          /api/v1/status "$OUT/status-end.json" /debug/state "$OUT/state-end.json"

# --- проверка P0-3: переживает ли learning рестарт ---
if [[ "$NO_RESTART" != "1" ]]; then
    log "=== P0-3: рестарт агента для проверки state persistence ==="
    api_multi /api/v1/status "$OUT/p0-3-status-before-restart.json"
    grep -o '"learning_complete":[a-z]*' "$OUT/p0-3-status-before-restart.json" | head -1 \
        | sed 's/^/  before: /' | tee -a "$OUT/idle-run.log"
    ls -la /var/lib/ebpf-guard/profiler-state.json > "$OUT/p0-3-state-file.txt" 2>&1 || \
        echo "profiler-state.json ОТСУТСТВУЕТ — persistence выключен или SaveState не отработал" > "$OUT/p0-3-state-file.txt"
    cat "$OUT/p0-3-state-file.txt" | tee -a "$OUT/idle-run.log"

    systemctl restart "$SERVICE"
    sleep 20

    api_multi /api/v1/status "$OUT/p0-3-status-after-restart.json"
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
    echo "--- алерты за прогон (стор/API, /api/v1/alerts) ---"
    # 5.8b (находка №21): grep -c '"rule_id"' считает СТРОКИ, не вхождения —
    # /api/v1/alerts отдаёт минифицированный JSON одной строкой, поэтому старая
    # формулировка печатала 1 при непустом файле независимо от числа алертов
    # (SUMMARY замера №2.4 показал "start: 1, end: 1" при 67 и 2805 реальных).
    # jq length считает элементы массива, а не строки.
    alerts_store_start=$(jq 'length' "$OUT/alerts-start.json" 2>/dev/null || echo "n/a")
    alerts_store_end=$(jq 'length' "$OUT/alerts-end.json" 2>/dev/null || echo "n/a")
    echo "start: $alerts_store_start"
    echo "end:   $alerts_store_end"
    store_delta=""
    if [[ "$alerts_store_start" =~ ^[0-9]+$ && "$alerts_store_end" =~ ^[0-9]+$ ]]; then
        store_delta=$((alerts_store_end - alerts_store_start))
        echo "дельта за idle-час (стор/API), фильтр 5.9a активен если включён: $store_delta"
    fi
    # Метрика ebpf_guard_alerts_total — второе измерение того же самого
    # (находка №21, волна 5.8b): расходится со стором в разы, потому что
    # canary-tamper и hidden-process алерты пишутся в стор в обход счётчика
    # (cmd/ebpf-guard/main.go: canaryAlertFn/hiddenAlertFn вызывают
    # alertStore.StoreBatch напрямую, минуя exporter.RecordAlert), и часть
    # обычных правил расходится сильнее, чем объясняет этот обходной путь —
    # причина для отдельных правил (owasp_log_tampering, sigma_log_deletion:
    # 184 в сторе против 6 в метрике на замере №2.4) не установлена, см.
    # plan.md, волна 5.8b.
    metrics_alerts_start=$(grep '^ebpf_guard_alerts_total{' "$OUT/metrics-start.txt" 2>/dev/null \
        | awk '{s+=$NF} END{printf "%d", s+0}')
    metrics_alerts_end=$(grep '^ebpf_guard_alerts_total{' "$OUT/metrics-end.txt" 2>/dev/null \
        | awk '{s+=$NF} END{printf "%d", s+0}')
    echo "дельта за idle-час (метрика ebpf_guard_alerts_total): $(( ${metrics_alerts_end:-0} - ${metrics_alerts_start:-0} ))"
    echo
    echo "--- 5.9a: дерево измерителя (events_excluded_total{reason=\"observer_tree\"}) ---"
    # 5.9.1g (находка «SUMMARY складывает алерты с событиями»): раньше здесь
    # печаталась строка "верхняя оценка дельты БЕЗ фильтра 5.9a: N", где N =
    # store_delta (АЛЕРТЫ, /api/v1/alerts) + excluded_delta (СОБЫТИЯ,
    # events_excluded_total{reason="observer_tree"}) — величины разной
    # природы, их сумма не является ни числом алертов, ни числом событий, и
    # смысла не несёт, хотя внешне выглядела как главное число пункта 5.9a
    # (на замере №2.9 — 4275 = 147 алертов + 4128 событий). Строка убрана
    # целиком, не заменена пересчётом в алертах — второй вариант постановки
    # («прогон с выключенным фильтром на том же стенде, чтобы честно
    # посчитать верхнюю оценку в алертах») требует отдельного прогона на
    # живом стенде, недоступного в этой сессии; печатать оценку, которую
    # нечем подтвердить, было бы тем же дефектом другими словами. Число
    # исключённых событий остаётся ниже отдельной строкой без арифметики —
    # это по-прежнему полезное наблюдение (сколько трафика измерителя
    # фильтр 5.9a убрал ДО оценки правил), просто больше не складывается с
    # алертами.
    excluded_start=$(grep '^ebpf_guard_events_excluded_total{reason="observer_tree"}' "$OUT/metrics-start.txt" 2>/dev/null \
        | awk '{s+=$NF} END{printf "%d", s+0}')
    excluded_end=$(grep '^ebpf_guard_events_excluded_total{reason="observer_tree"}' "$OUT/metrics-end.txt" 2>/dev/null \
        | awk '{s+=$NF} END{printf "%d", s+0}')
    excluded_delta=$(( ${excluded_end:-0} - ${excluded_start:-0} ))
    echo "событий исключено как дерево измерителя за прогон (СОБЫТИЯ, не алерты — см. дельту стора выше отдельной величиной): $excluded_delta"
    echo
    echo "--- critical / confirmed attack на idle (должно быть 0 — P1-6/P1-13) ---"
    # 5.9.1b (находка №35): alerts-end.json — это ВЕСЬ стор на момент финального
    # среза, не только то, что произошло за это измерительное окно. Раньше
    # здесь считался абсолют — любой incident_confirmed_attack, оставшийся в
    # сторе с ДО начала окна (например, от запуска пайплайна по ssh при
    # непустом сторе), навсегда засчитывался волне в минус, хотя гигиена
    # прогона (очистка стора шагом 1 пайплайна) тут ни при чём: подготовка
    # стенда между очисткой и стартом окна — отдельная, ненулевая величина
    # сама по себе (см. открытый вопрос 5.9f), и её надо печатать отдельно,
    # а не сваливать в один счётчик с окном.
    #
    # Тот же дефект со счётом, что починен выше по файлу (5.8b): grep -c
    # считает СТРОКИ, а /api/v1/alerts отдаёт минифицированный JSON одной
    # строкой — печаталось 0 или 1 независимо от реального числа инцидентов.
    # jq считает элементы; grep -o оставлен запасным путём без разбивки по
    # окну на случай, если jq не установлен (окно тогда не проверяется).
    if command -v jq >/dev/null 2>&1 && [[ -n "${RUN_START_TS:-}" && -n "${RUN_END_TS:-}" ]]; then
        confirmed_attack_total=$(jq '[.[] | select(.rule_id == "incident_confirmed_attack")] | length' \
            "$OUT/alerts-end.json" 2>/dev/null || echo "n/a")
        confirmed_attack=$(jq --arg start "$RUN_START_TS" --arg end "$RUN_END_TS" '
            def toepoch: sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601;
            ($start | toepoch) as $s | ($end | toepoch) as $e |
            [.[] | select(.rule_id == "incident_confirmed_attack")
                 | select((.timestamp | toepoch) >= $s and (.timestamp | toepoch) <= $e)] | length
        ' "$OUT/alerts-end.json" 2>/dev/null || echo "n/a")
        echo "incident_confirmed_attack (окно $RUN_START_TS .. $RUN_END_TS): $confirmed_attack"
        if [[ "$confirmed_attack_total" =~ ^[0-9]+$ && "$confirmed_attack" =~ ^[0-9]+$ ]]; then
            outside_window=$((confirmed_attack_total - confirmed_attack))
            echo "наблюдение: incident_confirmed_attack вне окна (до старта или после конца измерения): $outside_window"
        fi
    elif command -v jq >/dev/null 2>&1; then
        confirmed_attack=$(jq '[.[] | select(.rule_id == "incident_confirmed_attack")] | length' \
            "$OUT/alerts-end.json" 2>/dev/null || echo "n/a")
        echo "ВНИМАНИЕ: RUN_START_TS/RUN_END_TS не заданы — incident_confirmed_attack ниже АБСОЛЮТНЫЙ, не по окну."
        echo "incident_confirmed_attack (абсолют, весь стор): $confirmed_attack"
    else
        confirmed_attack=$(grep -o 'incident_confirmed_attack' "$OUT/alerts-end.json" 2>/dev/null | wc -l | tr -d ' ')
        echo "ВНИМАНИЕ: jq не найден — incident_confirmed_attack ниже АБСОЛЮТНЫЙ, не по окну."
        echo "incident_confirmed_attack (абсолют, весь стор): $confirmed_attack"
    fi
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
# 5.9f (находка №32): чтобы run-gate.sh посчитал критерий 16 (слепое окно
# idle-конец → attack-baseline), перед запуском run-all-attacks.sh/run-gate.sh
# передать пути этого прогона:
#   export IDLE_STATE_END="$OUT/state-end.json"
#   export IDLE_METRICS_END="$OUT/metrics-end.txt"
#
# 5.9.1d (находка №37): критерию 6 (состав детекта, вычитание фоновых правил
# из потерь, 5.8a) отдельно нужен IDLE_METRICS_START — снимок /metrics с
# НАЧАЛА этого же idle-часа. Раньше эта строка-подсказка называла только
# STATE_END/METRICS_END (для критерия 16), и составитель run-2.9-pipeline.sh
# скопировал ровно то, что здесь напечатано — START не попал в пайплайн
# вообще, и критерий 6 на замере №2.9 засчитал 8 фоновых правил как потери
# вместо вычитания. Печатаем все три переменные одной строкой, чтобы копипаста
# больше не теряла ни одну:
#   export IDLE_METRICS_START="$OUT/metrics-start.txt"
log "для критерия 6 (состав детекта) и критерия 16 (слепое окно) run-gate.sh: IDLE_METRICS_START=$OUT/metrics-start.txt IDLE_STATE_END=$OUT/state-end.json IDLE_METRICS_END=$OUT/metrics-end.txt"
