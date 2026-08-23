#!/bin/bash
# Master скрипт для запуска всех атак против Juice Shop
# Запускает все типы атак последовательно и собирает результаты

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VPS_IP="${VPS_IP:-localhost}"
JUICE_SH_URL="http://${VPS_IP}:3000"
EBPF_GUARD_API="http://${VPS_IP}:19090"
# admin token from config-test.yaml (auth.admin_token) — needed because auth.enabled=true;
# /debug/state and /metrics require a bearer token. Override via env if changed.
EBPF_GUARD_TOKEN="${EBPF_GUARD_TOKEN:-$(grep '^admin=' /var/lib/ebpf-guard/token 2>/dev/null | cut -d= -f2)}"
RESULTS_DIR="./attack-results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Shared with the four attack sub-scripts and run-gate.sh. Anchored to
# SCRIPT_DIR rather than the working directory so every producer and consumer
# agrees on one path regardless of where the run was launched from
# (plan.md волна 1.5g).
MANIFEST_FILE="$SCRIPT_DIR/attack-manifest.json"

# 5.9.7d (№80, P1): маркер окна атаки. Прежде темп детекта (крит. 6
# run-gate.sh) делился на всё окно baseline→final, то есть на длину ВСЕГО
# пайплайна — get_baseline_metrics, три режима run_counting_control,
# kill-сценарий, наведённый дроп и снятие финальных метрик считались частью
# "окна атаки", хотя ни один из них не отправляет трафик атаки. Каждый шаг,
# который реально его отправляет, зовёт mark_attack_window ДО и ПОСЛЕ своей
# работы; марка "first" пишется только первым вызовом за прогон и больше не
# трогается, "last" перезаписывается каждым — так okно считается по факту
# того, что действительно случилось, а не вычисляется гейтом по именам
# функций (иначе следующий добавленный шаг снова уедет в знаменатель, то же
# искажение, найденное этой волной, повторится с другим виновником).
ATTACK_WINDOW_MARKER="$RESULTS_DIR/attack-window-$TIMESTAMP.txt"
mark_attack_window() {
    local now
    now=$(date +%s.%N)
    if [ ! -f "$ATTACK_WINDOW_MARKER" ]; then
        echo "first=$now" > "$ATTACK_WINDOW_MARKER"
    fi
    if grep -q '^last=' "$ATTACK_WINDOW_MARKER" 2>/dev/null; then
        awk -v n="$now" -F= 'BEGIN{OFS="="} $1=="last"{$2=n} {print}' "$ATTACK_WINDOW_MARKER" > "$ATTACK_WINDOW_MARKER.tmp" \
            && mv "$ATTACK_WINDOW_MARKER.tmp" "$ATTACK_WINDOW_MARKER"
    else
        echo "last=$now" >> "$ATTACK_WINDOW_MARKER"
    fi
}

# Цвета
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
info() { echo -e "${BLUE}[INFO]${NC} $1"; }

# Создание директории для результатов
mkdir -p "$RESULTS_DIR"

# 5.9.7g (находка №84, P2): регистрация дерева измерителя в observer_tree —
# тот же канал (OBSERVER_ROOT_PID_FILE), что уже использует idle-run.sh
# (5.9a/5.9.1a), но ДО этой правки run-all-attacks.sh его не трогал вовсе.
# Разбор находки №84 (57 алертов от curl/grep/jq/date/rm в слепом окне)
# показал, что дело не в том, что цепочка real_parent не успевала дойти до
# корня — цепочка была цела, но агент никогда не узнавал, что у ЭТОГО дерева
# вообще есть корень: check_services/get_baseline_metrics — тот самый пролог
# сбора baseline — исполнялись под PID'ом, который ни разу не публиковался в
# observer_root_pid.
#
# ГРАНИЦА РЕГИСТРАЦИИ — не весь скрипт, а только пролог. Это не деталь
# оформления, а условие корректности: observer_should_drop() (bpf/common.h)
# роняет в ядре ВСЕ события ЛЮБОГО потомка корня на глубину до 12 хопов, до
# резервирования в кольце. run-all-attacks.sh — одновременно измеритель И
# генератор атак, в отличие от idle-run.sh, который только измеряет. Если
# корнем объявить $$ на весь прогон, из корреляции исчезают ровно те
# процессы, ради которых прогон существует: по архиву №2.9.6 это sqlmap
# (202 алерта), curl (169), chmod (6), tee (5) — то есть весь непустой
# знаменатель recall'а (крит. 7) и почти весь числитель темпа детекта
# (крит. 6), плюс канарейка run_counting_control (её N openat() перестали бы
# считаться вовсе — тождество 5.9.7a обнулилось бы) и канарейка
# run_ringbuf_overflow (кольцо нечем стало бы переполнять — 5.9.7b).
# Поэтому корнем регистрируется САБШЕЛЛ пролога (run_measurement_prologue),
# а не сам скрипт: check_services/get_baseline_metrics — его потомки и
# исключаются, всё, что запускается после, потомками не является и остаётся
# видимым. Это в точности окно, которое меряет крит. 16 (idle-конец →
# attack-baseline), и ни секундой больше.
OBSERVER_ROOT_PID_FILE="${OBSERVER_ROOT_PID_FILE:-/var/lib/ebpf-guard/observer-root-pid}"

# Регистрация вызывается ВНУТРИ сабшелла пролога, поэтому пишет $BASHPID
# (PID сабшелла), а не $$ (PID скрипта — в сабшелле $$ остаётся прежним).
observer_root_register() {
    local root="$BASHPID"
    if ! echo "$root" > "$OBSERVER_ROOT_PID_FILE" 2>/dev/null; then
        warn "не удалось записать $OBSERVER_ROOT_PID_FILE — 5.9.7g не подхватит корень, пролог baseline (curl/grep/jq/date/rm) не будет исключён из корреляции"
        return 0
    fi
    log "5.9.7g: дерево пролога зарегистрировано, root_pid=$root ($OBSERVER_ROOT_PID_FILE); шаги после пролога под ним НЕ идут и остаются видимыми"
    if ! command -v jq &> /dev/null; then
        warn "jq недоступен — подтверждение подхвата root_pid=$root не проверено, пролог продолжается вслепую"
        return 0
    fi
    local observer_confirmed=0 reported_root
    sleep 3
    for _ in $(seq 1 7); do
        reported_root="$(curl -s --max-time 5 -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/debug/state" 2>/dev/null \
            | jq -r '.engine_stats.observer_root_pid // empty' 2>/dev/null || true)"
        if [ "$reported_root" = "$root" ]; then
            observer_confirmed=1
            break
        fi
        sleep 2
    done
    if [ "$observer_confirmed" -eq 1 ]; then
        log "5.9.7g: агент подтвердил подхват root_pid=$root через /debug/state"
    else
        warn "агент не подтвердил подхват root_pid=$root за ~17с (/debug/state недоступен, observer_exclude выключен в его конфиге, или агент не запущен) — пролог продолжается без подтверждения"
    fi
}

# Пролог замера целиком в сабшелле: всё, что он порождает, — потомки
# зарегистрированного корня и исключается в ядре; всё, что вызывается ПОСЛЕ
# него, потомком не является. Статус возвращается наружу как обычно, поэтому
# `run_measurement_prologue || exit 1` ведёт себя ровно как прежний
# `check_services || exit 1`.
#
# После выхода сабшелла корень остаётся указывать на уже мёртвый PID. Это не
# упущение и не новое состояние: idle-run.sh ведёт себя так же с 5.9a (его
# EXIT-trap пишет в файл 0, но агент значение 0 игнорирует — см. plan.md,
# находка о мёртвом освобождении корня), и весь attack-прогон до этой волны
# шёл именно под мёртвым корнем idle-run.sh. Мёртвый PID никому не предок,
# то есть фильтр после пролога фактически выключен — что здесь и требуется.
run_measurement_prologue() {
    (
        observer_root_register
        check_services || exit 1
        get_baseline_metrics
    )
}

# Проверка доступности сервисов
check_services() {
    log "==========================================="
    log "ПРОВЕРКА ДОСТУПНОСТИ СЕРВИСОВ"
    log "==========================================="

    # Проверка Juice Shop
    if curl -s -o /dev/null -w "%{http_code}" "$JUICE_SH_URL" | grep -q "200\|302"; then
        log "✓ Juice Shop доступен: $JUICE_SH_URL"
    else
        error "✗ Juice Shop недоступен"
        return 1
    fi

    # Проверка ebpf-guard
    if curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/health" | grep -q "200"; then
        log "✓ ebpf-guard доступен: $EBPF_GUARD_API"
    else
        error "✗ ebpf-guard недоступен"
        return 1
    fi

    echo ""
}

# Получение начальных метрик
get_baseline_metrics() {
    log "==========================================="
    log "СБОР БАЗОВЫХ МЕТРИК"
    log "==========================================="

    # Clear the shared attack-manifest.json (plan.md волна 1.5g, вопрос 8) so
    # each sub-script's record_manifest starts this run from an empty file —
    # otherwise categories/comms from a previous run would leak into this
    # run's precision/recall calculation below.
    rm -f "$MANIFEST_FILE"

    # Pre-populate with docker-proxy as a transit attack process (план 1.75c).
    # Attack traffic to localhost:3000 is carried by Docker's port-forwarder
    # (comm=docker-proxy) — в замере №1 оно дало 402 из 912 "атакующих"
    # алертов, но без записи в манифесте выпадало из множества comms атакующих
    # и критерий "алерты от атакующих" занижался в ~2 раза. transit:true
    # маркирует запись как вспомогательную: она участвует в precision и в
    # критерии темпа алертов от атакующих, но исключена из recall (это не
    # отдельная категория атаки, а транзит).
    if command -v jq &> /dev/null; then
        docker_proxy_entry=$(jq -n --arg cat "transit" --arg comm "docker-proxy" --arg ts "$(date -Iseconds)" \
            '{category: $cat, comm: $comm, timestamp: $ts, transit: true}' 2>/dev/null)
        if [ -n "$docker_proxy_entry" ]; then
            echo "[$docker_proxy_entry]" | jq '.' > "$MANIFEST_FILE" 2>/dev/null || rm -f "$MANIFEST_FILE"
        fi
    fi

    # 5.9.1c (находка №36): если этот прогон стартует сразу после рестарта
    # агента (P0-3 в idle-run.sh или ручной), стартовый всплеск алертов ещё
    # не дотёк от alertsGenerated (engine_stats.total_alerts) до экспорта
    # (ebpf_guard_alerts_total) — снятый в этот момент baseline несёт offset
    # engine−filtered−suppressed−exported ≠ 0, и весь attack-прогон
    # наследует этот перекос как расхождение критерия 15 в run-gate.sh,
    # хотя тождество на самом деле верно. Ждём схождения offset к нулю перед
    # снятием снимков, а не сразу за check_services; таймаут 30с (лаг слива
    # на находке №36 был ~20с) — если конвейер не сошёлся, снимаем всё равно
    # (иначе baseline не будет снят вовсе) и печатаем фактический offset,
    # чтобы run-gate.sh не молчал о нём.
    if command -v jq &> /dev/null; then
        drain_offset="n/a"
        for _ in $(seq 1 15); do
            engine_now=$(curl -s --max-time 5 -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/debug/state" 2>/dev/null \
                | jq -r '.engine_stats.total_alerts // empty' 2>/dev/null)
            metrics_now=$(curl -s --max-time 5 -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/metrics" 2>/dev/null)
            filtered_now=$(echo "$metrics_now" | grep '^ebpf_guard_alerts_filtered_total{' | awk -F'} ' '{s+=$2} END{printf "%d", s+0}')
            suppressed_now=$(echo "$metrics_now" | grep '^ebpf_guard_alerts_suppressed_total{' | awk -F'} ' '{s+=$2} END{printf "%d", s+0}')
            exported_now=$(echo "$metrics_now" | grep '^ebpf_guard_alerts_total{' | awk -F'} ' '{s+=$2} END{printf "%d", s+0}')
            if [ -n "$engine_now" ]; then
                drain_offset=$(( engine_now - ${filtered_now:-0} - ${suppressed_now:-0} - ${exported_now:-0} ))
                if [ "$drain_offset" -eq 0 ]; then
                    break
                fi
            fi
            sleep 2
        done
        if [ "$drain_offset" = "0" ]; then
            log "5.9.1c: конвейер слился перед baseline (offset=0)"
        else
            warn "5.9.1c: offset конвейера не сошёлся к нулю за 30с (offset=$drain_offset) — baseline снимается как есть, критерий 15 обязан это учесть"
        fi
        echo "drain_offset_before_baseline=$drain_offset" > "$RESULTS_DIR/baseline-drain-offset-$TIMESTAMP.txt"
    fi

    # 5.9.5i (находка №70): критерий 16 в run-gate.sh (слепое окно idle-конец →
    # attack-baseline) три замера подряд получал зазор < 10с и печатал «не
    # измерялось» — числитель/знаменатель были оба вырождены (№58). Если
    # оператор передал IDLE_STATE_END (тот же файл, что идёт в run-gate.sh —
    # см. подсказку в конце вывода idle-run.sh), ждём здесь явно перед
    # снятием baseline, когда естественного зазора не набралось. Это не
    # «ssh внутрь окна» и не разрыв цепочки (гигиена замеров, 5.9f) — тот же
    # процесс, та же последовательность вызовов, просто пауза перед curl.
    if [ -n "$IDLE_STATE_END" ] && [ -s "$IDLE_STATE_END" ] && command -v jq &> /dev/null; then
        local idle_end_ts idle_end_epoch now_epoch gap wait_for
        idle_end_ts=$(jq -r '.timestamp // empty' "$IDLE_STATE_END" 2>/dev/null || true)
        if [ -n "$idle_end_ts" ]; then
            idle_end_epoch=$(date -d "$idle_end_ts" +%s 2>/dev/null || echo 0)
            now_epoch=$(date +%s)
            gap=$(( now_epoch - idle_end_epoch ))
            log "5.9.5i: конец idle-часа $idle_end_ts, сейчас $(date -Iseconds), зазор до этого момента ${gap}с"
            if [ "$idle_end_epoch" -gt 0 ] && [ "$gap" -lt 10 ]; then
                wait_for=$(( 15 - gap ))
                if [ "$wait_for" -gt 0 ]; then
                    log "5.9.5i: зазор ${gap}с < 10с — ждём ещё ${wait_for}с перед baseline, иначе критерий 16 снова напечатает «не измерялось»"
                    sleep "$wait_for"
                fi
            fi
        else
            warn "5.9.5i: IDLE_STATE_END задан, но .timestamp не разобран — гарантированное окно для критерия 16 не применено"
        fi
    fi

    curl -s -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/metrics" > "$RESULTS_DIR/baseline-metrics-$TIMESTAMP.txt"
    curl -s -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/api/v1/alerts" > "$RESULTS_DIR/baseline-alerts-$TIMESTAMP.json"
    curl -s -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/health" > "$RESULTS_DIR/baseline-health-$TIMESTAMP.json"
    # /health не отдаёт фазу обучения (она только в /api/v1/status) — см. P1-4/P2-7 п.6.
    curl -s -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/api/v1/status" > "$RESULTS_DIR/baseline-status-$TIMESTAMP.json"
    curl -s -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/debug/state" > "$RESULTS_DIR/baseline-state-$TIMESTAMP.json"
    # Baseline counterpart of the final incidents snapshot — lets the idle FP
    # rate (570 incidents per 2h in run #4, all on sshd) be compared against the
    # attack run rather than only counted once.
    curl -s -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/api/v1/incidents" > "$RESULTS_DIR/baseline-incidents-$TIMESTAMP.json"
    if ! curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/debug/state" | grep -q "200"; then
        warn "server.enable_debug не включен в конфиге ebpf-guard — /debug/state недоступен, Alerts/Events/Anomalies Total в отчете будут нулевыми"
    fi

    # Подсчет начальных алертов
    if command -v jq &> /dev/null; then
        local alert_count=$(curl -s -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/api/v1/alerts" | jq '. | length' 2>/dev/null || echo 0)
        log "Начальное количество алертов: $alert_count"
    else
        log "Начальные метрики сохранены"
    fi

    echo ""
}

# sum_metric PATTERN — sums the value field of every line of a Prometheus
# text exposition (read from stdin) whose label set matches the ERE PATTERN.
# Same idiom as run-gate.sh's sum_metric_delta, but operating on one snapshot
# already held in a shell variable rather than two files on disk — 5.9.6c/
# 5.9.6d need before/after deltas within a single function call, not across
# the whole run's baseline/final files.
sum_metric() {
    local pattern="$1"
    awk -F'} ' -v p="$pattern" '$0 ~ p {s+=$2} END{printf "%.0f", s+0}'
}

# sum_metric_delta PATTERN FILE_BASE FILE_FINAL — same idiom as run-gate.sh's
# function of the same name (deliberately identical body, not an independent
# reimplementation): sums a metric family matched by ERE PATTERN in each of
# two on-disk snapshots and returns final-base. Needed here (not just in
# run-gate.sh) by get_final_metrics's events_drain_offset settle loop (5.9.8d,
# №97), which diffs the on-disk baseline snapshot against a live poll taken
# during the loop, before run-gate.sh ever runs.
sum_metric_delta() {
    local pattern="$1" file_base="$2" file_final="$3"
    awk -F'} ' -v p="$pattern" '
        FNR==NR { if ($0 ~ p) base+=$2+0; next }
        { if ($0 ~ p) fin+=$2+0 }
        END { printf "%.0f", fin-base }
    ' "$file_base" "$file_final"
}

# emit_counting_canary N PATH — opens PATH for read exactly N times, back to
# back, from a single python3 process. One process (not N bash forks/curl
# calls) so wall-clock cost is dominated by the syscalls under test, not by
# shell fork overhead — at N=300000 the fork cost alone would swamp the
# window and make the "under drop" pass indistinguishable from ordinary
# fork-storm noise. Re-opening ONE file N times (rather than N unique paths)
# is deliberate: fileaccess.bpf.c emits one event per openat() regardless of
# path uniqueness (bpf/fileaccess.bpf.c trace_open), and creating N real
# inodes would make the idle-pass's own I/O the dominant cost instead of the
# syscall path 5.9.6c is meant to isolate.
#
# Возвращает 1 вместо падения, если создать канарейку или прогнать генератор
# не удалось. Скрипт под `set -e`, а этот шаг стоит ПЕРВЫМ в full_run — до
# всех атак и до финальных снимков: необработанная ошибка здесь унесла бы
# весь прогон целиком, ровно как нелегальный DNS-лейбл 5.9.5c уносил его до
# kill-сценария (P0 ревизии волны 5.9.5). Контроль счётности не наступил —
# это SKIP одного критерия, а не потеря замера.
emit_counting_canary() {
    local n="$1" path="$2"
    : > "$path" || return 1
    python3 - "$n" "$path" <<'PYEOF' || return 1
import os, sys
n = int(sys.argv[1])
path = sys.argv[2]
for _ in range(n):
    fd = os.open(path, os.O_RDONLY)
    os.close(fd)
PYEOF
}

# 5.9.8f (№93, P1): общий settle-луп для run_counting_control и
# run_ringbuf_overflow. Старое условие выхода — «сумма events+drops не
# выросла между двумя последовательными срезами» — это РАВЕНСТВО, а не
# производная, и на стенде с непрерывным фоном (idle-фон здесь ~500/с,
# счётные строки collect-2.9.7) недостижимо в принципе: сумма растёт КАЖДУЮ
# секунду, петля всегда докручивала все 30 срезов, а маркер печатал
# quiesced_iterations=30 неотличимо от «настояще устоялось за 30 срезов» —
# это и есть находка №93.
#
# Новое условие — производная: ТЕМП за этот срез (прирост, делённый на
# реально измеренную длительность среза — она не равна 1с, см. prev_t ниже)
# сравнивается с фоном плюс джиттер, а не с нулём.
#   - для mode != null, если рядом уже лежит маркер mode=null ЭТОГО ЖЕ
#     прогона (null всегда идёт первым, см. комментарий выше по коду) —
#     фон берётся из него: sum/window_seconds этого маркера, то есть
#     реально измеренный темп фона за минуту до этого вызова;
#   - для mode == null (или когда null-маркер недоступен — процесс
#     запущен не через run_counting_control, а отдельно) внешнего фона
#     нет по определению: null И ЕСТЬ измерение фона. Вместо него —
#     разброс последних ТРЁХ приростов этого же лупа (скользящее окно,
#     не кумулятивное среднее с начала лупа — среднее «с начала»
#     оставалось бы задранным всплеском генератора ещё долго ПОСЛЕ того,
#     как реальный темп уже стал плоским, потому что первые несколько
#     больших приростов навсегда тянут кумулятивное среднее вверх;
#     проверено вручную на синтетическом ряде до правки — кумулятивная
#     версия признавала лупа «устоявшимся» уже на первом срезе после
#     всплеска, пока в среднем ещё сидели сами всплесковые числа).
#     Устоявшимся признаётся возврат к СВОЕЙ недавней стабильной
#     скорости (max−min трёх последних приростов <= джиттер), а не
#     падение к нулю, которого на шумном стенде не бывает.
#   Джиттер — 10% от опорного значения, не меньше 5 (та же форма допуска,
#   что run-gate.sh уже применяет к канареечной серии, max(5, доля)).
#
# settle_reason (пишется в маркер вызывающей функцией, не этой):
#   flattened — прирост за срез сошёлся к опорному значению +- джиттер;
#   ceiling   — луп доработал MAX_ITERS срезов, не сойдясь (то самое
#               "quiesced_iterations=30" без причины — находка №93);
#   timeout   — /metrics не ответил три среза подряд подряд — харнесс не
#               может судить о затухании вовсе, это отдельная причина от
#               "не сошлось за отведённое время".
#
# Возвращает через globals, не echo: вызывающему нужен полный текст
# последнего снятого /metrics (SETTLE_AFTER), а не только числа.
counting_settle_loop() {
    local mode="$1" max_iters="$2" min_wait_after="$3" t1="$4" null_marker="$5"

    local bg_rate=""
    if [ "$mode" != "null" ] && [ -f "$null_marker" ]; then
        local bg_sum bg_window
        bg_sum=$(awk -F= '$1=="sum"{print $2+0}' "$null_marker" 2>/dev/null)
        bg_window=$(awk -F= '$1=="window_seconds"{print $2+0}' "$null_marker" 2>/dev/null)
        if [ -n "${bg_sum:-}" ] && [ -n "${bg_window:-}" ] && awk -v w="${bg_window:-0}" 'BEGIN{exit !(w>0)}'; then
            bg_rate=$(awk -v s="$bg_sum" -v w="$bg_window" 'BEGIN{printf "%.4f", s/w}')
        fi
    fi

    # prev_t/now_t: срез снимается НЕ ровно раз в секунду — sleep 1 плюс
    # время самого curl дают период 1.0…1.5с. Опорное значение bg_rate —
    # темп В СЕКУНДУ (sum/window_seconds null-маркера), поэтому прирост за
    # срез обязан делиться на реальную длительность среза, иначе сравнение
    # идёт в разных единицах и систематически завышает левую часть: при
    # фоне 500/с и периоде 1.2с прирост 600 против порога 550 (=r+10%) не
    # сходится НИКОГДА, и луп докручивает до потолка с settle_reason=ceiling
    # — то есть 5.9.8f печатал бы «не устоялось» на исправном стенде
    # (ревизия волны 5.9.8).
    local prev_sum=-1 cur_sum ev dr i miss=0 delta ref jitter have_ref spread
    local prev_t=0 now_t elapsed rate
    # Скользящее окно последних трёх приростов (d1 — самый старый из
    # трёх, d3 — только что вычисленный), win_n — сколько слотов реально
    # заполнено (0..3).
    local d1=0 d2=0 d3=0 win_n=0
    SETTLE_REASON="ceiling"
    SETTLE_AFTER=""
    SETTLE_I=0
    for i in $(seq 1 "$max_iters"); do
        SETTLE_AFTER=$(curl -s --max-time 10 -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/metrics" 2>/dev/null)
        if [ -z "$SETTLE_AFTER" ]; then
            miss=$(( miss + 1 ))
            if [ "$miss" -ge 3 ]; then
                SETTLE_REASON="timeout"
                SETTLE_I="$i"
                return
            fi
            sleep 1
            continue
        fi
        miss=0
        ev=$(echo "$SETTLE_AFTER" | sum_metric 'ebpf_guard_events_total\{.*type="file"')
        dr=$(echo "$SETTLE_AFTER" | sum_metric 'ebpf_guard_events_dropped_total\{collector="fileaccess"')
        cur_sum=$(( ${ev:-0} + ${dr:-0} ))
        now_t=$(date +%s)
        if [ "$prev_sum" -ge 0 ] && [ "$(( now_t - t1 ))" -ge "${min_wait_after:-0}" ]; then
            delta=$(( cur_sum - prev_sum ))
            elapsed=$(( now_t - prev_t ))
            [ "$elapsed" -lt 1 ] && elapsed=1
            # Темп за этот срез, в событиях в секунду — та же единица, что
            # у bg_rate и что у скользящего окна ниже.
            rate=$(awk -v d="$delta" -v e="$elapsed" 'BEGIN{printf "%.4f", d/e}')
            have_ref=0
            if [ -n "$bg_rate" ]; then
                # Внешний фон (idle/drop/ringbuf_overflow с null-маркером
                # под рукой) сравнивается напрямую, без окна — он уже
                # измерен отдельным прогоном, самоопорного смещения нет.
                ref="$bg_rate"
                have_ref=1
            fi
            d1=$d2; d2=$d3; d3=$rate
            [ "$win_n" -lt 3 ] && win_n=$((win_n + 1))
            if [ "$have_ref" -eq 0 ] && [ "$win_n" -eq 3 ]; then
                ref=$(awk -v a="$d1" -v b="$d2" -v c="$d3" 'BEGIN{printf "%.4f", (a+b+c)/3}')
                spread=$(awk -v a="$d1" -v b="$d2" -v c="$d3" 'BEGIN{mx=a; if(b>mx)mx=b; if(c>mx)mx=c; mn=a; if(b<mn)mn=b; if(c<mn)mn=c; printf "%.4f", mx-mn}')
                jitter=$(awk -v r="$ref" 'BEGIN{j=r*0.10; if(j<5) j=5; printf "%.4f", j}')
                if awk -v s="$spread" -v j="$jitter" 'BEGIN{exit !(s<=j)}'; then
                    SETTLE_REASON="flattened"
                    SETTLE_I="$i"
                    return
                fi
            elif [ "$have_ref" -eq 1 ]; then
                jitter=$(awk -v r="$ref" 'BEGIN{j=r*0.10; if(j<5) j=5; printf "%.4f", j}')
                if awk -v d="$rate" -v r="$ref" -v j="$jitter" 'BEGIN{exit !(d <= r+j)}'; then
                    SETTLE_REASON="flattened"
                    SETTLE_I="$i"
                    return
                fi
            fi
        fi
        prev_sum=$cur_sum
        prev_t=$now_t
        sleep 1
    done
    SETTLE_I="$i"
}

# 5.9.6c (P0, "ни один вызов не теряется"): positive control on counting.
# 5.9.6b's balance proves the counters agree with EACH OTHER; it says nothing
# about whether the kernel saw the call in the first place (a tracepoint that
# silently didn't fire would still balance — nothing was ever emitted to
# balance against). This generates a KNOWN N and checks it against an
# INDEPENDENT input: Δevents_total{type="file"} + Δevents_dropped_total{
# collector="fileaccess"} (all reasons — a call counted as any kind of drop
# is not "lost", it is accounted for) must equal N.
#
# Deliberately NOT run concurrently with run_induced_drop's tar burst: tar
# opens AND reads every file in its list, so its own activity would inflate
# both sides of the equation by an unknown amount, and the check would no
# longer be against a KNOWN N. mode=drop instead reuses this same generator
# at a size intended to overflow the ring buffer on its own (no tar
# involved) — self-contained, so the only fileaccess-collector traffic
# during its window is the canary itself, and Δevents+Δdrops staying == N
# while ringbuf_full > 0 is exactly "counted correctly even while losing
# heavily", which is the property 5.9.6c exists to prove.
#
# 5.9.7a (№78, P0): mode=null is a THIRD, negative-control mode — same
# window, same settle loop, same snapshots, N=0 (no canary at all). Its own
# Δevents+Δdrops IS the background of the window: file events from
# prometheus/grafana/docker/containerd that ebpf_guard_events_total{type=
# "file"} counts indiscriminately alongside the canary (the metric has no
# path label). The previous approach — sampling the rate for
# COUNTING_CONTROL_BG_WINDOW seconds BEFORE the generator — is deleted, not
# adjusted: measured 3s before 300k openat() calls, it carries none of the
# tail those calls leave in the collector/router/queue chain, so it
# systematically underestimates the background of the idle/drop windows
# that follow it. null must run FIRST, before idle and before drop, so
# neither positive-control window's background is contaminated by the
# canary traffic of the other (plan.md 5.9.7a).
run_counting_control() {
    local mode="$1" n="$2"
    local marker="$RESULTS_DIR/counting-control-${mode}-$TIMESTAMP.txt"
    local canary_path="/tmp/ebpf-guard-counting-canary-$TIMESTAMP-$mode"

    log "==========================================="
    log "КОНТРОЛЬ СЧЁТНОСТИ (5.9.7a, mode=$mode, N=$n)"
    log "==========================================="

    if [ "$mode" != "null" ] && ! command -v python3 &> /dev/null; then
        warn "python3 не найден — контроль счётности ($mode) пропущен, критерий 5.9.7a без входа для этого режима"
        echo "skipped=1" > "$marker"
        echo ""
        return
    fi

    local before events_before drops_before ringbuf_full_before canary_events_before canary_dropped_before
    before=$(curl -s --max-time 10 -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/metrics" 2>/dev/null)
    events_before=$(echo "$before" | sum_metric 'ebpf_guard_events_total\{.*type="file"')
    drops_before=$(echo "$before" | sum_metric 'ebpf_guard_events_dropped_total\{collector="fileaccess"')
    ringbuf_full_before=$(echo "$before" | sum_metric 'ebpf_guard_events_dropped_total\{collector="fileaccess",reason="ringbuf_full"\}')
    # 5.9.8b (№91): canary-only series, background-free by construction —
    # see CountingCanaryTotal (internal/exporter/prometheus.go). Read
    # alongside the general series above (kept for comparison/diagnostics),
    # not instead of it — the general series remains useful context even
    # after run-gate.sh's criterion 20 stops judging by it.
    canary_events_before=$(echo "$before" | sum_metric 'ebpf_guard_counting_canary_total\{stage="events"')
    canary_dropped_before=$(echo "$before" | sum_metric 'ebpf_guard_counting_canary_total\{stage="dropped"')
    local window_start
    window_start=$(date +%s)

    local t0 t1
    if [ "$mode" = "null" ]; then
        log "негативный контроль: генератор не запускается (N=0) — это окно и есть измерение фона"
        t0=$(date +%s)
        t1=$t0
    else
        log "генератор: $n открытий $canary_path"
        t0=$(date +%s)
        if ! emit_counting_canary "$n" "$canary_path"; then
            warn "генератор канарейки ($mode) не отработал — контроль счётности пропущен, критерий 5.9.7a без входа для этого режима"
            echo "skipped=1" > "$marker"
            rm -f "$canary_path"
            echo ""
            return 0
        fi
        t1=$(date +%s)
        log "генератор закончил за $((t1 - t0))с"
    fi

    # Устояться перед снимком "после": конвейер (ringbuf → router → bulk
    # queue → correlator) асинхронный, и снятие "после" сразу за концом
    # генератора недосчитало бы события, ещё лежащие в очереди — то же
    # искажение границы, которое 5.9.4c нашла между baseline и attack-окном.
    # 5.9.8f (№93): условие выхода — производная (counting_settle_loop),
    # не равенство; null-маркер этого же прогона (если mode!=null и он уже
    # написан — null всегда идёт первым) даёт опорный фон.
    local null_marker="$RESULTS_DIR/counting-control-null-$TIMESTAMP.txt"
    counting_settle_loop "$mode" 30 0 "$t1" "$null_marker"
    local after="$SETTLE_AFTER" i="$SETTLE_I" settle_reason="$SETTLE_REASON"

    local events_after drops_after ringbuf_full_after canary_events_after canary_dropped_after
    events_after=$(echo "$after" | sum_metric 'ebpf_guard_events_total\{.*type="file"')
    drops_after=$(echo "$after" | sum_metric 'ebpf_guard_events_dropped_total\{collector="fileaccess"')
    ringbuf_full_after=$(echo "$after" | sum_metric 'ebpf_guard_events_dropped_total\{collector="fileaccess",reason="ringbuf_full"\}')
    canary_events_after=$(echo "$after" | sum_metric 'ebpf_guard_counting_canary_total\{stage="events"')
    canary_dropped_after=$(echo "$after" | sum_metric 'ebpf_guard_counting_canary_total\{stage="dropped"')

    local events_delta drops_delta ringbuf_full_delta sum diff window_seconds
    local canary_events_delta canary_dropped_delta canary_sum canary_diff
    events_delta=$(( ${events_after:-0} - ${events_before:-0} ))
    drops_delta=$(( ${drops_after:-0} - ${drops_before:-0} ))
    ringbuf_full_delta=$(( ${ringbuf_full_after:-0} - ${ringbuf_full_before:-0} ))
    sum=$(( events_delta + drops_delta ))
    diff=$(( sum - n ))
    canary_events_delta=$(( ${canary_events_after:-0} - ${canary_events_before:-0} ))
    canary_dropped_delta=$(( ${canary_dropped_after:-0} - ${canary_dropped_before:-0} ))
    canary_sum=$(( canary_events_delta + canary_dropped_delta ))
    canary_diff=$(( canary_sum - n ))
    # Длина окна «до»→«после» целиком, включая устаканивание: именно столько
    # времени фон (mode=null) или фон+канарейка (idle/drop) копились в обе
    # метрики. run-gate.sh делит null's sum на это же поле, чтобы получить
    # темп фона независимо от того, сколько заняло устаканивание в этом
    # конкретном прогоне.
    window_seconds=$(( $(date +%s) - window_start ))

    {
        echo "mode=$mode"
        echo "n=$n"
        echo "events_delta=$events_delta"
        echo "drops_delta=$drops_delta"
        echo "ringbuf_full_delta=$ringbuf_full_delta"
        echo "sum=$sum"
        echo "diff=$diff"
        echo "canary_events_delta=$canary_events_delta"
        echo "canary_dropped_delta=$canary_dropped_delta"
        echo "canary_sum=$canary_sum"
        echo "canary_diff=$canary_diff"
        echo "quiesced_iterations=$i"
        echo "settle_reason=$settle_reason"
        echo "generator_seconds=$((t1 - t0))"
        echo "window_seconds=$window_seconds"
    } > "$marker"

    log "N=$n Δevents(file)=$events_delta Δdrops(fileaccess,все причины)=$drops_delta Δringbuf_full(fileaccess)=$ringbuf_full_delta сумма=$sum сумма-N=$diff канарейка:Δevents=$canary_events_delta Δdropped=$canary_dropped_delta сумма=$canary_sum сумма-N=$canary_diff (причина остановки: ${settle_reason}, за ${i} срезов, окно ${window_seconds}с)"
    if [ "$settle_reason" = "ceiling" ]; then
        warn "mode=$mode: settle-луп не сошёлся за 30 срезов (5.9.8f, №93) — снимок «после» мог уйти раньше конца асинхронного хвоста"
    fi
    if [ "$mode" = "drop" ] && [ "${ringbuf_full_delta:-0}" -le 0 ]; then
        warn "mode=drop: ringbuf_full не вырос — N=$n не переполнил кольцо на этом стенде; критерий 5.9.6c для этого режима останется без второй половины (см. открытые вопросы, COUNTING_CONTROL_DROP_N не откалиброван)"
    fi
    rm -f "$canary_path"
    echo ""
}

# 5.9.7b (№79, P0): кольцо переполняется управляемо, а не надеждой на
# нагрузку. Пункты 1 и 5 постановки №2.9.6 остались недоказанными на любой
# нагрузке, которую этот харнесс способен создать против дефолтного кольца
# (auto-sized от MemAvailable, десятки МБ — internal/bpf/ringbuf_size.go) —
# читатель успевает вычерпывать его быстрее любого генератора.
#
# Метод А постановки (сузить bpf.ring_buf_size и перезапустить агента) на
# этом коде НЕ исполним: ComputeRingBufSize клэмпит ЛЮБОЕ заданное значение
# в [4 МБ, 32 МБ] (ringBufMinBytes/ringBufMaxBytes), так что "порядка 4096
# байт" из постановки после клэмпа неотличимо от дефолта. Комментарий у
# ringBufMinBytes называет его "kernel enforced minimum" — это неточно:
# BPF_MAP_TYPE_RINGBUF требует только степень двойки и выравнивание по
# странице, 4 МБ — собственный пол продукта. Метод А отмечен как
# заблокированный кодом, а не пропущен молча (открытый вопрос 5.9.7b) —
# смена этого пола не входит в 5.9.7b и не делалась.
#
# Метод Б (исполняется здесь): SIGSTOP всему процессу агента на время
# генератора. Кольцо — BPF-карта в ядре, живёт независимо от userspace;
# пока читающий poll-луп заморожен, bpf_ringbuf_reserve() в BPF-программе
# всё равно исполняется при каждом syscall'е канарейки и промахивается,
# когда кольцо заполнено — сам промах считается в перцпу-карте
# ringbuf_full_counters (5.9.6a) НЕЗАВИСИМО от того, читает ли кто-то
# userspace-часть. SIGCONT возвращает процесс; events_dropped_total{reason=
# "ringbuf_full"} обновляется на следующем скрейпе (prescrape hook,
# beb16a0), bpf_lost_events_total — на следующем тике watchdog'а (≤10с,
# internal/watchdog/watchdog.go runDropTracking) — отсюда settle-луп ждёт
# не только стабилизации events+drops, но и минимум 12с после SIGCONT.
run_ringbuf_overflow() {
    local n="${RINGBUF_OVERFLOW_N:-300000}"
    local service="${RINGBUF_OVERFLOW_SERVICE:-ebpf-guard-test.service}"
    local marker="$RESULTS_DIR/ringbuf-overflow-$TIMESTAMP.txt"
    # 5.9.8c (№92): путь обязан начинаться с CountingCanaryPathPrefix
    # (internal/exporter/prometheus.go) — иначе ebpf_guard_counting_canary_total
    # не увидит эти open()'ы вовсе, и counting_control_residual (run-gate.sh)
    # молча свалится в устаревший (не-канареечный) путь на каждом прогоне.
    # Суффикс "-ringbuf-overflow" — тот же приём именования, что "-$mode" у
    # run_counting_control, различает серии разных шагов по одному пути.
    local canary_path="/tmp/ebpf-guard-counting-canary-$TIMESTAMP-ringbuf-overflow"
    local method_a_blocked="ComputeRingBufSize клэмпит SizeBytes в [4МБ,32МБ] (internal/bpf/ringbuf_size.go) — узкая карта из постановки недостижима без правки кода, не делалась в 5.9.7b"

    log "==========================================="
    log "ПЕРЕПОЛНЕНИЕ КОЛЬЦА ПОД КОНТРОЛЕМ (5.9.7b, №79, N=$n, метод=SIGSTOP)"
    log "==========================================="

    if ! command -v python3 &> /dev/null; then
        warn "python3 не найден — run_ringbuf_overflow пропущен, критерий 5.9.7b без входа"
        { echo "skipped=1"; echo "skip_reason=python3 недоступен на харнессе"; } > "$marker"
        echo ""
        return
    fi
    if [ "$(id -u)" -ne 0 ]; then
        warn "не root — SIGSTOP/SIGCONT сервиса недоступны, run_ringbuf_overflow пропущен"
        { echo "skipped=1"; echo "skip_reason=харнесс запущен не от root, SIGSTOP сервиса невозможен"; } > "$marker"
        echo ""
        return
    fi

    local pid
    pid=$(systemctl show -p MainPID --value "$service" 2>/dev/null)
    if [ -z "$pid" ] || [ "$pid" = "0" ]; then
        warn "не удалось получить MainPID $service — run_ringbuf_overflow пропущен"
        { echo "skipped=1"; echo "skip_reason=MainPID $service не найден (systemctl show)"; } > "$marker"
        echo ""
        return
    fi
    log "агент: $service pid=$pid"

    # Справочное значение — критерий 18 (run-gate.sh) судит его отдельно за
    # окно idle-часа; здесь только печатается в маркер, если снимки под рукой
    # (тот же приём, что IDLE_METRICS_START/END в остальном харнессе).
    local idle_ringbuf_full=""
    if [ -n "$IDLE_METRICS_START" ] && [ -n "$IDLE_METRICS_END" ] \
        && [ -s "$IDLE_METRICS_START" ] && [ -s "$IDLE_METRICS_END" ]; then
        idle_ringbuf_full=$(awk -F'} ' '
            FNR==NR { if ($0 ~ "ebpf_guard_events_dropped_total\\{" && $0 ~ "collector=\"fileaccess\"" && $0 ~ "reason=\"ringbuf_full\"") base+=$2+0; next }
            { if ($0 ~ "ebpf_guard_events_dropped_total\\{" && $0 ~ "collector=\"fileaccess\"" && $0 ~ "reason=\"ringbuf_full\"") fin+=$2+0 }
            END { printf "%.0f", fin-base }
        ' "$IDLE_METRICS_START" "$IDLE_METRICS_END" 2>/dev/null)
    fi

    local before events_before drops_before ringbuf_full_before bpf_lost_before
    local canary_events_before canary_dropped_before
    before=$(curl -s --max-time 10 -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/metrics" 2>/dev/null)
    events_before=$(echo "$before" | sum_metric 'ebpf_guard_events_total\{.*type="file"')
    drops_before=$(echo "$before" | sum_metric 'ebpf_guard_events_dropped_total\{collector="fileaccess"')
    ringbuf_full_before=$(echo "$before" | sum_metric 'ebpf_guard_events_dropped_total\{collector="fileaccess",reason="ringbuf_full"\}')
    bpf_lost_before=$(echo "$before" | sum_metric 'ebpf_guard_bpf_lost_events_total\{collector="fileaccess"\}')
    # 5.9.8c (№92): та же канареечная серия, что run_counting_control читает
    # для критерия 20 — counting_control_residual (run-gate.sh) сравнивает их
    # тем же кодом, а не переоткрытой копией формулы.
    canary_events_before=$(echo "$before" | sum_metric 'ebpf_guard_counting_canary_total\{stage="events"')
    canary_dropped_before=$(echo "$before" | sum_metric 'ebpf_guard_counting_canary_total\{stage="dropped"')
    if [ -z "$before" ]; then
        warn "снимок /metrics до заморозки пуст — run_ringbuf_overflow пропущен (агент недоступен ДО SIGSTOP, замораживать нечего)"
        { echo "skipped=1"; echo "skip_reason=пустой снимок /metrics до SIGSTOP"; } > "$marker"
        echo ""
        return
    fi
    local window_start
    window_start=$(date +%s)

    : > "$canary_path" || true
    log "SIGSTOP pid=$pid"
    if ! kill -STOP "$pid" 2>/dev/null; then
        warn "kill -STOP $pid не удался — run_ringbuf_overflow пропущен"
        { echo "skipped=1"; echo "skip_reason=kill -STOP не удался"; } > "$marker"
        rm -f "$canary_path"
        echo ""
        return
    fi

    local t0 t1
    t0=$(date +%s)
    # Генератор запускается, ПОКА агент заморожен: кольцо в ядре продолжает
    # принимать резервирования (bpf_ringbuf_reserve) от каждого openat(),
    # читающий poll-луп не выгребает ничего, и кольцо обязано заполниться
    # раньше, чем закончатся N попыток, если N калиброван достаточно щедро
    # относительно auto-sized кольца этого стенда.
    if ! emit_counting_canary "$n" "$canary_path"; then
        warn "генератор канарейки под SIGSTOP не отработал — SIGCONT немедленно, run_ringbuf_overflow без входа"
        kill -CONT "$pid" 2>/dev/null || true
        { echo "skipped=1"; echo "skip_reason=генератор канарейки под SIGSTOP не отработал"; } > "$marker"
        rm -f "$canary_path"
        echo ""
        return
    fi
    t1=$(date +%s)
    log "генератор закончил за $((t1 - t0))с (кольцо заморожено всё это время)"

    log "SIGCONT pid=$pid"
    kill -CONT "$pid" 2>/dev/null || true

    # Settle-луп той же формы, что run_counting_control (counting_settle_loop,
    # 5.9.8f/№93 — производная, не равенство), ПЛЮС минимум 12с после
    # SIGCONT — bpf_lost_events_total обновляется watchdog'ом раз в 10с
    # (internal/watchdog/watchdog.go runDropTracking), не на скрейпе, и без
    # этого хвоста критерий 5.9.7b сравнивал бы его со значением, которое
    # ещё не успело догнать events_dropped_total{reason=ringbuf_full} (тот
    # обновляется на скрейпе, prescrape hook, beb16a0). mode="ringbuf_overflow"
    # (не "null") — читает фон из null-маркера ЭТОГО прогона, если он уже
    # написан (шаг может исполняться и отдельно, до run_counting_control —
    # тогда фон берётся из скользящего среднего этого же лупа, см.
    # counting_settle_loop).
    local null_marker="$RESULTS_DIR/counting-control-null-$TIMESTAMP.txt"
    counting_settle_loop "ringbuf_overflow" 30 12 "$t1" "$null_marker"
    local after="$SETTLE_AFTER" i="$SETTLE_I" settle_reason="$SETTLE_REASON"

    local events_after drops_after ringbuf_full_after bpf_lost_after
    local canary_events_after canary_dropped_after
    events_after=$(echo "$after" | sum_metric 'ebpf_guard_events_total\{.*type="file"')
    drops_after=$(echo "$after" | sum_metric 'ebpf_guard_events_dropped_total\{collector="fileaccess"')
    ringbuf_full_after=$(echo "$after" | sum_metric 'ebpf_guard_events_dropped_total\{collector="fileaccess",reason="ringbuf_full"\}')
    bpf_lost_after=$(echo "$after" | sum_metric 'ebpf_guard_bpf_lost_events_total\{collector="fileaccess"\}')
    canary_events_after=$(echo "$after" | sum_metric 'ebpf_guard_counting_canary_total\{stage="events"')
    canary_dropped_after=$(echo "$after" | sum_metric 'ebpf_guard_counting_canary_total\{stage="dropped"')

    local events_delta drops_delta ringbuf_full_delta bpf_lost_delta sum diff window_seconds
    local canary_events_delta canary_dropped_delta canary_sum canary_diff
    events_delta=$(( ${events_after:-0} - ${events_before:-0} ))
    drops_delta=$(( ${drops_after:-0} - ${drops_before:-0} ))
    ringbuf_full_delta=$(( ${ringbuf_full_after:-0} - ${ringbuf_full_before:-0} ))
    bpf_lost_delta=$(( ${bpf_lost_after:-0} - ${bpf_lost_before:-0} ))
    sum=$(( events_delta + drops_delta ))
    diff=$(( sum - n ))
    canary_events_delta=$(( ${canary_events_after:-0} - ${canary_events_before:-0} ))
    canary_dropped_delta=$(( ${canary_dropped_after:-0} - ${canary_dropped_before:-0} ))
    canary_sum=$(( canary_events_delta + canary_dropped_delta ))
    canary_diff=$(( canary_sum - n ))
    # 5.9.8c (№92): тот же смысл, что window_seconds у run_counting_control —
    # длина всего окна «до»→«после», которую counting_control_residual делит
    # на темп null-фона в запасном (не-канареечном) пути.
    window_seconds=$(( $(date +%s) - window_start ))

    {
        echo "n=$n"
        echo "pid=$pid"
        echo "events_delta=$events_delta"
        echo "drops_delta=$drops_delta"
        echo "ringbuf_full_delta=$ringbuf_full_delta"
        echo "bpf_lost_delta=$bpf_lost_delta"
        echo "sum=$sum"
        echo "diff=$diff"
        echo "canary_events_delta=$canary_events_delta"
        echo "canary_dropped_delta=$canary_dropped_delta"
        echo "canary_sum=$canary_sum"
        echo "canary_diff=$canary_diff"
        echo "window_seconds=$window_seconds"
        echo "quiesced_iterations=$i"
        echo "settle_reason=$settle_reason"
        echo "generator_seconds=$((t1 - t0))"
        echo "method_a_blocked_reason=$method_a_blocked"
        [ -n "$idle_ringbuf_full" ] && echo "idle_hour_ringbuf_full=$idle_ringbuf_full"
    } > "$marker"

    log "N=$n Δevents(file)=$events_delta Δdrops(fileaccess)=$drops_delta сумма-N=$diff канарейка:Δevents=$canary_events_delta Δdropped=$canary_dropped_delta сумма=$canary_sum сумма-N=$canary_diff Δringbuf_full=$ringbuf_full_delta Δbpf_lost_events_total=$bpf_lost_delta (причина остановки: ${settle_reason}, за ${i} срезов, окно ${window_seconds}с)"
    if [ "$settle_reason" = "ceiling" ]; then
        warn "run_ringbuf_overflow: settle-луп не сошёлся за 30 срезов (5.9.8f, №93) — снимок «после» мог уйти раньше конца асинхронного хвоста"
    fi
    if [ "${ringbuf_full_delta:-0}" -le 0 ]; then
        warn "ringbuf_full не вырос под SIGSTOP — N=$n не переполнил кольцо на этом стенде даже с замороженным читателем; критерий 5.9.7b без входа (см. открытые вопросы)"
    elif [ "${ringbuf_full_delta:-0}" -ne "${bpf_lost_delta:-0}" ]; then
        warn "ringbuf_full=$ringbuf_full_delta != bpf_lost_events_total=$bpf_lost_delta — 5.9.6a не подтверждается живьём на этом прогоне"
    else
        log "ringbuf_full=$ringbuf_full_delta == bpf_lost_events_total=$bpf_lost_delta — 5.9.6a подтверждена живьём"
    fi
    rm -f "$canary_path"
    echo ""
}

# Запуск SQLMap атак
run_sqlmap_attacks() {
    log "==========================================="
    log "ЗАПУСК SQLMAP АТАК"
    log "==========================================="

    if [ -f "$SCRIPT_DIR/sqlmap-attacks.sh" ]; then
        mark_attack_window
        bash "$SCRIPT_DIR/sqlmap-attacks.sh" || warn "SQLMap атаки завершились с ошибками"
        mark_attack_window
    else
        warn "SQLMap скрипт не найден, пропускаем..."
    fi
    echo ""
}

# Запуск brute force атак
run_bruteforce_attacks() {
    log "==========================================="
    log "ЗАПУСК BRUTE FORCE АТАК"
    log "==========================================="

    if [ -f "$SCRIPT_DIR/bruteforce-attacks.sh" ]; then
        mark_attack_window
        bash "$SCRIPT_DIR/bruteforce-attacks.sh" || warn "Brute force атаки завершились с ошибками"
        mark_attack_window
    else
        warn "Brute force скрипт не найден, пропускаем..."
    fi
    echo ""
}

# Запуск SSRF атак
run_ssrf_attacks() {
    log "==========================================="
    log "ЗАПУСК SSRF АТАК"
    log "==========================================="

    if [ -f "$SCRIPT_DIR/ssrf-attacks.sh" ]; then
        mark_attack_window
        bash "$SCRIPT_DIR/ssrf-attacks.sh" || warn "SSRF атаки завершились с ошибками"
        mark_attack_window
    else
        warn "SSRF скрипт не найден, пропускаем..."
    fi
    echo ""
}

# Запуск LDAP/CSRF атак
run_ldap_csrf_attacks() {
    log "==========================================="
    log "ЗАПУСК LDAP/CSRF АТАК"
    log "==========================================="

    if [ -f "$SCRIPT_DIR/ldap-csrf-attacks.sh" ]; then
        mark_attack_window
        bash "$SCRIPT_DIR/ldap-csrf-attacks.sh" || warn "LDAP/CSRF атаки завершились с ошибками"
        mark_attack_window
    else
        warn "LDAP/CSRF скрипт не найден, пропускаем..."
    fi
    echo ""
}

# 5.9.1e (остаток 5.9d): attack-сторона критерия 5.9d — «на attack-прогоне
# детект по sigma_sensitive_file_chmod сохраняется там, где chmod
# действительно был» — не была проверена ни одним прогоном №2.9/№2.9.1,
# потому что манифест атак не содержал ни одного настоящего chmod-syscall.
# С 5.9d правило переведено на syscall-ось (nr in chmod/fchmod/fchmodat,
# путь не разрешается), поэтому детект больше не привязан к конкретному
# файлу — важен сам факт chmod от не-демона. Создаём одноразовый canary-файл
# внутри /etc (песочница прогона — этот стенд одноразовый, файл не
# существовавший до атаки и удаляемый сразу после), чтобы не трогать ни один
# реальный системный файл. comm=chmod (внешняя команда, не builtin), что не
# входит в исключение [sshd, cron] правила.
run_chmod_attack() {
    log "==========================================="
    log "ЗАПУСК CHMOD АТАКИ (5.9.1e)"
    log "==========================================="

    local canary_file="/etc/.ebpf-guard-attack-canary-$TIMESTAMP"

    if ! touch "$canary_file" 2>/dev/null; then
        warn "Нет прав на запись в /etc — chmod-атака (5.9.1e) пропущена, sigma_sensitive_file_chmod останется непроверенным на attack-стороне"
        echo ""
        return
    fi

    mark_attack_window
    chmod 755 "$canary_file" 2>/dev/null || warn "chmod на $canary_file завершился с ошибкой"
    mark_attack_window
    log "chmod 755 $canary_file выполнен — ожидается срабатывание sigma_sensitive_file_chmod"
    rm -f "$canary_file"

    if command -v jq &> /dev/null; then
        chmod_entry=$(jq -n --arg cat "chmod" --arg comm "chmod" --arg ts "$(date -Iseconds)" \
            '{category: $cat, comm: $comm, timestamp: $ts}' 2>/dev/null)
        if [ -n "$chmod_entry" ] && [ -f "$MANIFEST_FILE" ]; then
            jq --argjson e "$chmod_entry" '. + [$e]' "$MANIFEST_FILE" > "$MANIFEST_FILE.tmp" 2>/dev/null \
                && mv "$MANIFEST_FILE.tmp" "$MANIFEST_FILE"
        fi
    fi

    echo ""
}

# 5.9.2b (находка №39): attack-сторона для трёх сисколлов, чей вход в
# in-kernel allowlist эта волна открывает впервые — setuid (105), bpf (321),
# init_module/finit_module/delete_module (175/313/176). Без шага здесь
# "вход открыт" неотличимо от "вход закрыт": критерий 5.9.2b требует, чтобы
# каждый новый номер был либо покрыт срабатыванием на attack-прогоне, либо
# записан в intentional-loss.txt с причиной — не подтверждённые тут остаются
# в списке (см. deploy/docker-test-setup/attacks/intentional-loss.txt).
# 5.9.7e / риск №3 постановки №2.9.7: ПОЗИТИВНЫЙ КОНТРОЛЬ сужения двух правил.
# Волна 5.9.7e сузила rootkit_ssh_authorized_keys_modified условием `op: eq
# write`, чтобы штатный ssh-логин (sshd читает authorized_keys) перестал
# считаться детектом. Это ровно тот приём, которым 5.9.3b убила восемь типов
# разом (находка №57): «правило молчит» и «правило ослепло» по артефактам
# прогона неотличимы, если на том же прогоне нет записи, которая ОБЯЗАНА его
# поднять. Юнит-тест (TestWave597*) проверяет ту же пару офлайн; здесь —
# живьём, на настоящем ядре, тем же конвейером, которым считается критерий.
#
# Запись делается посторонним comm (`tee -a`), а не sshd, и только
# комментарием: файл сначала копируется, потом восстанавливается из копии,
# так что доступ по ключу не может быть потерян даже при обрыве шага
# (комментарий в authorized_keys безвреден для sshd и сам по себе).
run_ssh_keys_positive_control() {
    log "==========================================="
    log "ПОЗИТИВНЫЙ КОНТРОЛЬ 5.9.7e (риск №3): запись в authorized_keys посторонним comm"
    log "==========================================="

    local keys="/root/.ssh/authorized_keys"
    local backup="/root/.ssh/authorized_keys.ebpf-guard-bak-$TIMESTAMP"

    if [ ! -f "$keys" ]; then
        warn "$keys отсутствует — позитивный контроль 5.9.7e пропущен, сужение правила остаётся недоказанным (риск №3)"
        echo ""
        return
    fi
    if ! cp -p "$keys" "$backup" 2>/dev/null; then
        warn "не удалось сделать копию $keys — позитивный контроль 5.9.7e пропущен (без копии запись не делается)"
        echo ""
        return
    fi

    mark_attack_window
    echo "# ebpf-guard 5.9.7e positive control $TIMESTAMP" | tee -a "$keys" >/dev/null 2>&1 \
        && log "запись в $keys выполнена comm=tee — ожидается срабатывание rootkit_ssh_authorized_keys_modified" \
        || warn "запись в $keys не удалась — позитивный контроль 5.9.7e не исполнен"
    mark_attack_window

    # Восстановление обязательно и проверяется: шаг, который умеет испортить
    # ключи и не умеет это заметить, хуже отсутствующего шага.
    if cp -p "$backup" "$keys" 2>/dev/null && ! grep -q "ebpf-guard 5.9.7e positive control $TIMESTAMP" "$keys"; then
        rm -f "$backup"
        log "$keys восстановлен из копии, строка контроля снята"
    else
        error "НЕ УДАЛОСЬ восстановить $keys — копия оставлена в $backup, снять вручную"
    fi

    if command -v jq &> /dev/null; then
        keys_entry=$(jq -n --arg cat "ssh_keys_positive_control" --arg comm "tee" --arg ts "$(date -Iseconds)" \
            '{category: $cat, comm: $comm, timestamp: $ts}' 2>/dev/null)
        if [ -n "$keys_entry" ] && [ -f "$MANIFEST_FILE" ]; then
            jq --argjson e "$keys_entry" '. + [$e]' "$MANIFEST_FILE" > "$MANIFEST_FILE.tmp" 2>/dev/null \
                && mv "$MANIFEST_FILE.tmp" "$MANIFEST_FILE"
        fi
    fi

    echo ""
}

# 5.9.8g (находка №96, риск №3 постановки): позитивный контроль сужения
# webshell_script_write_via_web_process (rules/webshell-detection.yaml) до
# comm веб-воркера. №2.9.7 поймал живьём critical от comm=bash, писавшего
# .sh — правило матчило любой comm, хотя его собственное сообщение обещает
# "apache2, nginx, or httpd worker". Условие сужено (proc.comm in
# [apache2, nginx, httpd]); без этого шага сужение неотличимо от ослепления
# (тот же приём, что и №57/5.9.7e — TestWave598g_WebshellScriptWrite
# проверяет то же офлайн, здесь — живьём, на настоящем ядре).
#
# На этом стенде нет apache2/nginx/httpd (Juice Shop — node-приложение),
# поэтому comm подделывается тем же приёмом, что уже применён к SSH-контролю
# выше: символическая ссылка с именем "apache2" на существующий бинарь
# (tee) — comm ядро берёт из последнего компонента ПУТИ, переданного
# execve(), а не из инода/цели ссылки, так что запуск через $fake_bin даёт
# proc.comm="apache2" без модификации системных пакетов.
run_webshell_script_write_positive_control() {
    log "==========================================="
    log "ПОЗИТИВНЫЙ КОНТРОЛЬ 5.9.8g (риск №3): запись .php веб-воркером (comm=apache2)"
    log "==========================================="

    local tee_bin
    tee_bin="$(command -v tee 2>/dev/null)"
    if [ -z "$tee_bin" ]; then
        warn "tee не найден — позитивный контроль 5.9.8g пропущен, сужение webshell_script_write_via_web_process остаётся недоказанным (риск №3)"
        echo ""
        return
    fi

    local fake_dir fake_bin target
    fake_dir="$(mktemp -d)"
    fake_bin="$fake_dir/apache2"
    target="$fake_dir/control-$TIMESTAMP.php"
    if ! ln -s "$tee_bin" "$fake_bin" 2>/dev/null; then
        warn "не удалось создать $fake_bin — позитивный контроль 5.9.8g пропущен"
        rm -rf "$fake_dir"
        echo ""
        return
    fi

    mark_attack_window
    echo "<?php /* ebpf-guard 5.9.8g positive control $TIMESTAMP */ ?>" | "$fake_bin" "$target" >/dev/null 2>&1 \
        && log "запись $target выполнена comm=apache2 — ожидается срабатывание webshell_script_write_via_web_process" \
        || warn "запись через $fake_bin не удалась — позитивный контроль 5.9.8g не исполнен"
    mark_attack_window

    rm -f "$target"
    rm -rf "$fake_dir"

    if command -v jq &> /dev/null; then
        wc_entry=$(jq -n --arg cat "webshell_positive_control" --arg comm "apache2" --arg ts "$(date -Iseconds)" \
            '{category: $cat, comm: $comm, timestamp: $ts}' 2>/dev/null)
        if [ -n "$wc_entry" ] && [ -f "$MANIFEST_FILE" ]; then
            jq --argjson e "$wc_entry" '. + [$e]' "$MANIFEST_FILE" > "$MANIFEST_FILE.tmp" 2>/dev/null \
                && mv "$MANIFEST_FILE.tmp" "$MANIFEST_FILE"
        fi
    fi

    echo ""
}

run_setuid_attack() {
    log "==========================================="
    log "ЗАПУСК SETUID АТАКИ (5.9.2b, sigma_setuid_syscall)"
    log "==========================================="

    if command -v python3 &> /dev/null; then
        # setuid(getuid()) — no-op privilege change, invokes syscall 105
        # directly without altering the process's actual privileges.
        mark_attack_window
        python3 -c 'import os; os.setuid(os.getuid())' 2>/dev/null \
            && log "setuid(getuid()) выполнен — ожидается срабатывание sigma_setuid_syscall" \
            || warn "setuid-атака (5.9.2b) завершилась с ошибкой или пропущена"
        mark_attack_window
    else
        warn "python3 не найден — setuid-атака (5.9.2b) пропущена"
    fi
    echo ""
}

run_bpf_attack() {
    log "==========================================="
    log "ЗАПУСК BPF(2) АТАКИ (5.9.2b/5.9.4e, rootkit_bpf_*/ebpf_subversion_*)"
    log "==========================================="

    # Read-only bpf(2) subcommand (BPF_PROG_GET_NEXT_ID / BPF_PROG_GET_FD_BY_ID /
    # BPF_OBJ_GET_INFO_BY_FD, verified via strace on the stand) — enumerates
    # loaded programs without loading or modifying anything. Invokes syscall
    # 321, but its arg0 is none of the destructive/load/create commands any
    # repo rule now looks for (5.9.4e, №56: rootkit_bpf_* used to match on
    # bare nr + a comm whitelist, which this call satisfied by accident; now
    # it correctly matches nothing).
    if command -v bpftool &> /dev/null; then
        mark_attack_window
        bpftool prog list >/dev/null 2>&1 \
            && log "bpftool prog list выполнен (не ожидается срабатывание правил — read-only bpf(2), см. 5.9.4e)" \
            || warn "bpf-атака (5.9.2b) завершилась с ошибкой (нет прав/BPF недоступен)"

        # Positive control for rootkit_bpf_map_create_suspicious (BPF_MAP_CREATE=0,
        # verified via strace: bpf(BPF_MAP_CREATE, ...) then BPF_OBJ_PIN). Pinned
        # under a run-scoped name and removed immediately after.
        local bpf_map_pin="/sys/fs/bpf/ebpf-guard-attack-canary-$TIMESTAMP"
        if bpftool map create "$bpf_map_pin" type hash key 4 value 4 entries 8 name gate_canary >/dev/null 2>&1; then
            log "bpftool map create выполнен — ожидается срабатывание rootkit_bpf_map_create_suspicious"
            rm -f "$bpf_map_pin"
        else
            warn "bpftool map create завершился с ошибкой (нет прав/BPF недоступен) — rootkit_bpf_map_create_suspicious останется непроверенным на attack-стороне"
        fi
        mark_attack_window
    else
        warn "bpftool не найден — bpf-атака (5.9.2b/5.9.4e) пропущена"
    fi

    # 5.9.5j (долг 5.9.4e, №1): positive control for rootkit_bpf_prog_load_suspicious
    # (BPF_PROG_LOAD=5). `bpftool prog load` on a bogus/empty file fails in
    # libbpf before ever reaching the bpf(2) syscall (the same class of gap
    # as the insmod/rmmod no-op below for kmod attacks) — needs a real
    # compiled BPF object. attacks/fixtures/gate-canary.bpf.c is a minimal
    # no-op SEC("socket") program with no maps/helpers, compiled here rather
    # than checked in as a prebuilt .bpf.o: a binary fixture would be tied to
    # whatever clang/kernel produced it and can't be verified by reading the
    # repo. If clang has no bpf target on this host, this step is skipped
    # like the map-create control above when bpftool itself is missing.
    local bpf_fixture_src="$SCRIPT_DIR/fixtures/gate-canary.bpf.c"
    local bpf_fixture_obj="/tmp/ebpf-guard-gate-canary-$TIMESTAMP.bpf.o"
    local bpf_prog_pin="/sys/fs/bpf/ebpf-guard-attack-canary-prog-$TIMESTAMP"
    if command -v bpftool &> /dev/null && command -v clang &> /dev/null && [ -f "$bpf_fixture_src" ]; then
        mark_attack_window
        if clang -target bpf -O2 -c "$bpf_fixture_src" -o "$bpf_fixture_obj" >/dev/null 2>&1; then
            if bpftool prog load "$bpf_fixture_obj" "$bpf_prog_pin" >/dev/null 2>&1; then
                log "bpftool prog load выполнен — ожидается срабатывание rootkit_bpf_prog_load_suspicious"
                rm -f "$bpf_prog_pin"
            else
                warn "bpftool prog load завершился с ошибкой (нет прав/BPF недоступен) — rootkit_bpf_prog_load_suspicious останется непроверенным на attack-стороне"
            fi
        else
            warn "clang -target bpf не собрал fixtures/gate-canary.bpf.c (нет BPF-таргета на этом хосте) — rootkit_bpf_prog_load_suspicious останется непроверенным на attack-стороне"
        fi
        mark_attack_window
        rm -f "$bpf_fixture_obj"
    else
        warn "bpftool и/или clang не найдены, либо fixtures/gate-canary.bpf.c отсутствует — BPF_PROG_LOAD-атака (5.9.5j) пропущена"
    fi
    echo ""
}

# 5.9.5c (findings №64/№65): positive control for the four DNS rules that
# match on qname_length alone (dns_tunneling_long_domain > 50,
# exfil_dns_txt_long_label/webshell_dns_exfil_long_subdomain > 60,
# netintr_dns_long_label > 100 — see rules/dns-threats.yaml,
# rules/data-exfiltration.yaml, rules/network-intrusion.yaml,
# rules/webshell-detection.yaml). On замер №2.9.4 all four were silent for the
# whole agent uptime with no scenario ever exercising them — silence that
# could not be told apart from a DNS-parse regression (the same run also had
# dns_decode_errors_total=69 against 53 parsed events). This step gives them
# a real, uniquely identifiable query: a label well past all four thresholds,
# built from this run's TIMESTAMP so a hit can never be mistaken for the
# background comm=grafana traffic that tripped these same rules on №2.9.3.
run_dns_long_label_attack() {
    log "==========================================="
    log "ЗАПУСК DNS LONG-LABEL АТАКИ (5.9.5c, findings №64/№65)"
    log "==========================================="

    if ! command -v dig &> /dev/null; then
        warn "dig не найден — DNS long-label атака (5.9.5c) пропущена, dns_tunneling_long_domain/exfil_dns_txt_long_label/netintr_dns_long_label/webshell_dns_exfil_long_subdomain останутся непроверенными на attack-стороне"
        echo ""
        return
    fi

    # qname_length (rules.go, getFieldValue) counts the FULL dotted name, not
    # the longest single label — so the way to clear netintr_dns_long_label's
    # threshold of 100 is a long NAME, and it must be built out of several
    # labels: RFC 1035 §2.3.4 caps one label at 63 octets, and dig refuses to
    # even send a query containing a longer one ("is not a legal name (label
    # too long)", exit 10) — the first cut of this step used a single ~130-char
    # label and would have sent nothing at all, leaving the positive control
    # silent in exactly the way находка №64 could not tell apart from a parse
    # regression. Three labels of 60/60/31 give a 179-char name: над всеми
    # четырьмя порогами (50/60/60/100), под общим лимитом имени в 253 октета,
    # и под DNS_MAX_PAYLOAD=256 в dns.bpf.c вместе с 12-байтным заголовком.
    local filler_a filler_b
    filler_a=$(printf 'x%.0s' $(seq 1 60))
    filler_b=$(printf 'y%.0s' $(seq 1 60))
    local long_qname="${filler_a}.${filler_b}.ebpfguard-5951c-${TIMESTAMP}.dns-tunnel-canary.invalid"

    # +short/+time/+tries: a bounded, best-effort lookup — NXDOMAIN (expected,
    # .invalid never resolves) still puts the query itself, long qname and
    # all, on the wire and through the sendto/sendmsg tracepoints dns.go
    # attaches to. The event is generated by the query, not the answer.
    #
    # `|| true` is not cosmetic: this script runs under `set -e`, and dig exits
    # non-zero on a refused name (10) or an unreachable resolver (9). Without
    # it a failed positive control would abort run-all-attacks.sh right here —
    # before run_kill_scenario, run_induced_drop and get_final_metrics — and
    # take the whole замер with it instead of costing one step.
    mark_attack_window
    dig +short +time=2 +tries=1 "$long_qname" >/dev/null 2>&1 || \
        warn "dig вернул ненулевой код на $long_qname — запрос мог не уйти в сеть; проверить резолвер стенда (шаг не валит прогон, но критерий 5.9.5c останется без входа)"
    mark_attack_window
    log "dig на $long_qname выполнен (длина qname: ${#long_qname}) — ожидается срабатывание dns_tunneling_long_domain/exfil_dns_txt_long_label/netintr_dns_long_label/webshell_dns_exfil_long_subdomain"

    # Намеренно БЕЗ записи в attack-manifest.json — по образцу run_bpf_attack
    # (постановка 5.9.5c: «прямой вызов, без записи в манифест»). Манифест
    # питает критерий 7 гейта (recall с порогом 1.000), а тот сопоставляет
    # категорию с алертами ПО comm: у DNS-события comm берётся из
    # bpf_get_current_comm в контексте sendmsg/sendto, то есть это имя ПОТОКА
    # вызывающего процесса — у современного dig (bind9 9.18+, libuv) это
    # `isc-net-0000`, а не `dig`. Запись в манифест подняла бы знаменатель
    # recall до 5 и завалила бы весь гейт по недоказанному предположению об
    # имени потока. Позитивный контроль засчитывается не манифестом, а секцией
    # 5.9.5c run-gate.sh — по срабатыванию самих четырёх правил. Comm шага при
    # этом остаётся в knownAttackerComms (rules_coverage_test.go), как и просит
    # постановка: это защита от будущего `comm not_in`-исключения (находка №56),
    # она манифеста не требует.

    echo ""
}

# 5.9.8a (№94, P0, запрет №6): the two controls the fix to dns_socket_map is
# not accepted without, on the same run. Both are standalone, outside the
# idle/attack measurement window — invoked via `--dns-fd-reuse-controls`,
# same convention as `--ringbuf-overflow` (5.9.7b): a step whose own
# side-effects must not land inside the window another criterion measures.
#
# NEGATIVE CONTROL (№94's actual failure mode): open a UDP socket,
# connect() it to port 53, close() it, then immediately open a TCP socket —
# CPython's socket module allocates the lowest free fd, so closing the UDP
# socket first makes fd reuse by the very next socket() call highly likely
# on the same thread. Writing TLS-ClientHello-shaped bytes to that reused fd
# number must produce zero DNS events: before the 5.9.8a key fix, a
# dns_socket_map entry surviving past close() (or matched via stale
# thread-scoped state) would have let this write() be misread as a DNS
# query, which is exactly how a real ClientHello reached the long-label
# rules on №2.9.7.
run_dns_fd_reuse_negative_control() {
    local marker="$RESULTS_DIR/dns-negative-control-$TIMESTAMP.txt"

    log "==========================================="
    log "DNS: НЕГАТИВНЫЙ КОНТРОЛЬ ПЕРЕИСПОЛЬЗОВАНИЯ FD (5.9.8a, №94)"
    log "==========================================="

    if ! command -v python3 &> /dev/null; then
        warn "python3 не найден — негативный контроль DNS (5.9.8a) пропущен"
        echo "skipped=1" > "$marker"
        echo ""
        return
    fi

    local before after events_before events_after
    before=$(curl -s --max-time 10 -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/metrics" 2>/dev/null)
    events_before=$(echo "$before" | sum_metric 'ebpf_guard_events_total\{.*type="dns"')

    local py_out
    py_out=$(python3 - <<'PYEOF' 2>&1
import os, socket, threading

# Negative control: reproduce находка №94 exactly, which requires the
# close() to happen on a DIFFERENT thread than the connect().
#
# Ревизия волны 5.9.8: первая редакция этого контроля делала connect(),
# close() и write() на одном потоке — и была тавтологией. Под СТАРЫМ
# (потоковым) ключом close() с того же потока попадал ровно в ту запись,
# что вставил connect(), удалял её, и переиспользованный fd не совпадал ни
# с чем: контроль давал 0 DNS-событий и ДО правки, и ПОСЛЕ, то есть не мог
# отличить починку от ослепления — ровно то, что запрет №6 постановки
# требует исключить.
#
# Настоящий сценарий №94: connect() на потоке A (запись ключа), close() на
# потоке B (под старым ключом НЕ удаляет запись потока A — это и есть
# первая половина дефекта), затем поток A получает тот же номер fd под
# TCP-сокет и пишет в него ClientHello. Под старым ключом lookup потока A
# попадает в протухшую запись → байты TLS уходят в DNS-разбор. Под новым
# (tgid) ключом close() потока B удаляет запись процесса, и попадать
# некуда.
#
# Реальная сетевая достижимость не нужна: write() на неподключённом
# TCP-сокете всё равно входит в ядро (и в sys_enter_write), хотя и падает
# с ENOTCONN — трейспойнт срабатывает на входе в вызов, независимо от
# кода возврата.
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.connect(("127.0.0.1", 53))
fd = u.fileno()

# close() из ЧУЖОГО потока — половина дефекта №94, которую старый ключ не
# видел. os.close(fd) напрямую, а не u.close(): нужен именно системный
# вызов close() с другого tid, без участия объекта сокета главного потока.
closer_err = []
def closer():
    try:
        os.close(fd)
    except OSError as e:
        closer_err.append(str(e))
th = threading.Thread(target=closer)
th.start()
th.join()
u.detach()  # объект больше не владеет уже закрытым дескриптором

t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
reused = (t.fileno() == fd)

# 60 bytes shaped like a TLS record + ClientHello handshake header (content
# type 0x16, version 0x0301, length, handshake type 0x01) followed by
# arbitrary payload — enough to clear the dns.bpf.c len>=12 floor and to
# fail validateDNSHeader's structural checks if it ever reaches userspace.
clienthello = bytes.fromhex(
    "160301003b0100003703035b3fc0ff112233445566778899aabbccddeeff"
    "00112233445566778899aabbccddeeff0011223344556677889900130100"
)
try:
    os.write(t.fileno(), clienthello)
except OSError:
    pass
t.close()

print(f"reused_fd={int(reused)}")
print(f"target_fd={fd}")
print(f"cross_thread_close={int(not closer_err)}")
PYEOF
    )
    local py_status=$?

    # Устояться перед снимком "после" — тот же приём, что run_counting_control.
    local prev=-1 cur i=0
    for i in $(seq 1 10); do
        after=$(curl -s --max-time 10 -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/metrics" 2>/dev/null)
        cur=$(echo "$after" | sum_metric 'ebpf_guard_events_total\{.*type="dns"')
        if [ "$cur" = "$prev" ]; then break; fi
        prev=$cur
        sleep 1
    done
    events_after=$(echo "$after" | sum_metric 'ebpf_guard_events_total\{.*type="dns"')

    local events_delta
    events_delta=$(( ${events_after:-0} - ${events_before:-0} ))

    {
        echo "$py_out"
        echo "python_status=$py_status"
        echo "events_dns_delta=$events_delta"
    } > "$marker"

    log "негативный контроль: $py_out (python exit=$py_status), Δevents_total{type=dns}=$events_delta"
    if [ "$events_delta" -gt 0 ]; then
        warn "негативный контроль DNS: events_total{type=dns} вырос на $events_delta — dns_socket_map всё ещё принимает переиспользованный fd за DNS (см. run-gate.sh, критерий 5.9.8a)"
    fi
    echo ""
}

# POSITIVE CONTROL: the OTHER failure mode the same key change fixes — a
# write()/read() from a thread that did NOT call connect() on that fd. A
# thread pool handing an already-connected DNS socket to a worker thread is
# exactly how real multi-threaded resolvers behave, and is invisible to a
# pid_tgid-keyed (thread-scoped) dns_socket_map even though the fd is
# legitimately a live DNS query. main thread connect()s N UDP sockets;
# N worker threads each write()/read() one of them — same tgid throughout,
# different tid than the one that inserted the dns_socket_map entry.
run_dns_cross_thread_positive_control() {
    local n="${DNS_CROSS_THREAD_N:-8}"
    local marker="$RESULTS_DIR/dns-positive-control-$TIMESTAMP.txt"

    log "==========================================="
    log "DNS: ПОЗИТИВНЫЙ КОНТРОЛЬ МЕЖПОТОЧНОГО FD (5.9.8a, №94, N=$n)"
    log "==========================================="

    if ! command -v python3 &> /dev/null; then
        warn "python3 не найден — позитивный контроль DNS (5.9.8a) пропущен"
        echo "skipped=1" > "$marker"
        echo ""
        return
    fi

    local before after events_before events_after
    before=$(curl -s --max-time 10 -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/metrics" 2>/dev/null)
    events_before=$(echo "$before" | sum_metric 'ebpf_guard_events_total\{.*type="dns"')

    local resolver
    resolver=$(awk '/^nameserver/{print $2; exit}' /etc/resolv.conf 2>/dev/null)
    resolver="${resolver:-127.0.0.53}"

    local py_out
    py_out=$(python3 - "$n" "$resolver" <<'PYEOF' 2>&1
import random, socket, struct, sys, threading

n = int(sys.argv[1])
resolver = sys.argv[2]

def build_query(name):
    qid = random.randint(0, 0xffff)
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    question = b""
    for label in name.split("."):
        question += bytes([len(label)]) + label.encode()
    question += b"\x00" + struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN
    return header + question

# Main thread: connect() every socket. This is the thread that populates
# dns_socket_map under both the old and new key.
socks = []
for i in range(n):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    try:
        s.connect((resolver, 53))
    except OSError:
        pass
    socks.append(s)

# Worker threads: write()/read() on a socket a DIFFERENT thread connected —
# the exact cross-thread pattern a pid_tgid-scoped map cannot recognize.
def worker(sock, name):
    q = build_query(name)
    try:
        sock.send(q)
    except OSError:
        pass
    try:
        sock.recv(512)
    except OSError:
        pass

threads = []
for i, s in enumerate(socks):
    th = threading.Thread(target=worker, args=(s, f"ebpfguard-598a-{i}.dns-tunnel-canary.invalid"))
    threads.append(th)
    th.start()
for th in threads:
    th.join()
for s in socks:
    s.close()

print(f"n={n}")
PYEOF
    )
    local py_status=$?

    local prev=-1 cur i=0
    for i in $(seq 1 15); do
        after=$(curl -s --max-time 10 -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/metrics" 2>/dev/null)
        cur=$(echo "$after" | sum_metric 'ebpf_guard_events_total\{.*type="dns"')
        if [ "$cur" = "$prev" ]; then break; fi
        prev=$cur
        sleep 1
    done
    events_after=$(echo "$after" | sum_metric 'ebpf_guard_events_total\{.*type="dns"')

    local events_delta
    events_delta=$(( ${events_after:-0} - ${events_before:-0} ))

    {
        echo "$py_out"
        echo "python_status=$py_status"
        echo "resolver=$resolver"
        echo "events_dns_delta=$events_delta"
    } > "$marker"

    log "позитивный контроль: N=$n резолвер=$resolver Δevents_total{type=dns}=$events_delta (python exit=$py_status)"
    if [ "$events_delta" -lt "$n" ]; then
        warn "позитивный контроль DNS: Δevents_total{type=dns}=$events_delta < N=$n — межпоточный резолв недосчитан (см. run-gate.sh, критерий 5.9.8a)"
    fi
    echo ""
}

run_kmod_attack() {
    log "==========================================="
    log "ЗАПУСК KMOD АТАКИ (5.9.2b, rootkit_init_module_syscall/rootkit_delete_module_syscall)"
    log "==========================================="

    # ВАЖНО: `insmod /несуществующий.ko` НЕ вызывает finit_module вообще —
    # kmod открывает файл сам и падает на ENOENT ещё в userspace, до всякого
    # сисколла; то же с `rmmod несуществующий-модуль` (он смотрит
    # /sys/module/... и выходит, не доходя до delete_module). Первая редакция
    # шага 5.9.2b была написана именно так и не дала бы НИ ОДНОГО события —
    # ровно тот класс «механизм не может сработать, а индикатор рядом печатает
    # PASS», ради которого заведена волна. Поэтому:
    #   * finit_module (313) — insmod на РЕАЛЬНО СУЩЕСТВУЮЩИЙ пустой файл:
    #     kmod открывает его успешно и вызывает сисколл, ядро отвергает
    #     содержимое (ENOEXEC). В ядро ничего не попадает.
    #   * init_module (175) и delete_module (176) — прямым syscall(2) через
    #     ctypes, с заведомо невалидными аргументами: сисколл вызывается и
    #     возвращает ошибку, модуль не загружается и не выгружается.
    local bogus_module="/tmp/ebpf-guard-canary-$TIMESTAMP.ko"
    : > "$bogus_module"

    if command -v insmod &> /dev/null; then
        # `|| warn` обязателен: скрипт под `set -e`, а insmod здесь ВСЕГДА
        # возвращает ненулевой код (ядро отвергает пустой файл). Без guard'а
        # прогон обрывался бы прямо здесь — до get_final_metrics,
        # generate_final_report и check_final_gate, то есть замер остался бы
        # вообще без итоговых срезов и без гейта.
        mark_attack_window
        insmod "$bogus_module" >/dev/null 2>&1 \
            || log "insmod $bogus_module отвергнут ядром (ожидаемо, ENOEXEC) — сисколл finit_module(313) вызван"
        mark_attack_window
    else
        warn "insmod не найден — finit_module-часть kmod-атаки (5.9.2b) пропущена"
    fi
    rm -f "$bogus_module"

    if command -v python3 &> /dev/null; then
        # init_module(64 нулевых байта, 64, "") -> ENOEXEC;
        # delete_module("несуществующий модуль", 0) -> ENOENT.
        # Оба сисколла вызываются напрямую, потому что штатные утилиты до них
        # не доходят: rmmod проверяет /sys/module/<name> в userspace и выходит
        # с ошибкой, не вызвав delete_module вовсе.
        rc=0
        mark_attack_window
        python3 - >/dev/null 2>&1 <<'PYEOF' || rc=$?
import ctypes
libc = ctypes.CDLL(None, use_errno=True)
buf = ctypes.create_string_buffer(b"\x00" * 64)
libc.syscall(175, buf, ctypes.c_size_t(64), b"")             # init_module
libc.syscall(176, b"ebpf_guard_canary_mod", ctypes.c_int(0)) # delete_module
PYEOF
        mark_attack_window
        if [ "$rc" -eq 0 ]; then
            log "syscall(175)/syscall(176) вызваны напрямую (ожидаемо отвергнуты ядром) — ожидается rootkit_init_module_syscall/rootkit_delete_module_syscall"
        else
            warn "прямой вызов init_module/delete_module (5.9.2b) не выполнился, код $rc"
        fi
    else
        warn "python3 не найден — init_module/delete_module-часть kmod-атаки (5.9.2b) пропущена"
    fi
    echo ""
}

# 5.9.1d, часть (в) — разбор owasp_log_tampering, не выполненный в сессии,
# где закрывались 5.9.1c/5.9.1d. Причина установлена по снятым данным №2.9,
# без нового прогона: правило матчит filename РЕГУЛЯРКОЙ
# (/var/log/.*\.log$, /var/log/nginx/, /var/log/apache2/, /var/log/httpd/),
# а его daemon-двойник owasp_log_tampering_daemon — той же регуляркой с тем же
# списком comm — дал 0, тогда как sigma_log_deletion_daemon с ТЕМ ЖЕ списком
# comm, но префиксом /var/log/, дал 60. Один и тот же трафик, одни и те же
# процессы, разница только в предикате пути: на стенде нет ни nginx/apache,
# ни rsyslogd — журналирование идёт через journald в /var/log/journal/*.journal,
# и ни один файл с суффиксом .log под /var/log/ не открывается вообще. То есть
# это не регресс детекта, а отсутствие сценария трафика — ровно тот же случай,
# что sigma_sensitive_file_chmod до 5.9.1e.
#
# Решение то же, что 5.9.1e выбрала для chmod, и НЕ запись в
# intentional-loss.txt: запрет №3 постановки волны 5.9.1 требует, чтобы каждая
# такая запись сопровождалась проверкой, что правило срабатывает там, где
# обязано, — а проверить это можно только дав правилу трафик. Даём: canary-файл
# с суффиксом .log под /var/log/, запись и усечение из-под не-демона (comm
# tee/truncate, ни один из них не входит в исключения [rsyslogd, rs:main Q:Reg,
# systemd-journal, systemd-journald]). Файл не существовал до атаки и удаляется
# сразу после — ни один настоящий системный лог не тронут.
run_log_tamper_attack() {
    log "==========================================="
    log "ЗАПУСК LOG-TAMPER АТАКИ (5.9.1d в)"
    log "==========================================="

    local canary_log="/var/log/.ebpf-guard-attack-canary-$TIMESTAMP.log"

    if ! touch "$canary_log" 2>/dev/null; then
        warn "Нет прав на запись в /var/log — log-tamper атака (5.9.1d в) пропущена, owasp_log_tampering останется непроверенным на attack-стороне"
        echo ""
        return
    fi

    # Запись (append) и усечение — две операции, которые правило называет в
    # своём description ("writing to or truncating log files").
    mark_attack_window
    echo "ebpf-guard attack canary $(date -Iseconds)" | tee -a "$canary_log" >/dev/null 2>&1 \
        || warn "запись в $canary_log завершилась с ошибкой"
    : > "$canary_log" 2>/dev/null || warn "усечение $canary_log завершилось с ошибкой"
    mark_attack_window
    log "запись и усечение $canary_log выполнены — ожидается срабатывание owasp_log_tampering (и sigma_log_deletion по префиксу)"
    rm -f "$canary_log"

    if command -v jq &> /dev/null; then
        log_tamper_entry=$(jq -n --arg cat "log_tamper" --arg comm "tee" --arg ts "$(date -Iseconds)" \
            '{category: $cat, comm: $comm, timestamp: $ts}' 2>/dev/null)
        if [ -n "$log_tamper_entry" ] && [ -f "$MANIFEST_FILE" ]; then
            jq --argjson e "$log_tamper_entry" '. + [$e]' "$MANIFEST_FILE" > "$MANIFEST_FILE.tmp" 2>/dev/null \
                && mv "$MANIFEST_FILE.tmp" "$MANIFEST_FILE"
        fi
    fi

    echo ""
}

# 5.9.5a (находка №62, P0) — kill-сценарий, живой позитивный контроль
# предохранителя энфорсера. На №2.9.4 оба счётчика (enforcement_actions_total
# и enforcement_dryrun_total) стояли на 0/0 за весь аптайм — ни одно
# разрушительное правило не сработало ни разу, и "dry_run гасит kill"
# осталось недоказанным (риск №3 постановки 5.9.4, материализовавшийся
# дословно). Контрольное правило — ebpf_subversion_detach_nonroot
# (rules/ebpf-subversion.yaml, единственное с action: kill в репозитории,
# см. attacks/destructive-actions.txt, блок 5.9.5a и
# TestKillScenarioControlRule_ActionIsKill): нет comm-условия, значит его
# нельзя обойти сменой имени процесса, и оно матчит nr=321 (bpf syscall),
# arg0 in [3,6,9,33] (деструктивные bpf(2)-команды), uid>0.
#
# Жертва — ОДИН И ТОТ ЖЕ одноразовый дочерний процесс харнесса, не системный
# демон (урок №53: ebpf_subversion_unauthorized_caller бил по systemd,
# TestExecuteKill_DryRun — тот же приём в internal/enforcer/kill_test.go,
# только здесь на стенде): непривилегированный (uid>0) python3 под
# пользователем nobody вызывает bpf(BPF_MAP_DELETE_ELEM=3) напрямую через
# ctypes.syscall и после этого ещё несколько секунд жив, чтобы можно было
# проверить, убил ли его энфорсер (не должен — dry_run: true).
run_kill_scenario() {
    log "==========================================="
    log "ЗАПУСК KILL-СЦЕНАРИЯ (5.9.5a, №62 P0: живой контроль предохранителя, критерий 17)"
    log "==========================================="

    if ! id nobody >/dev/null 2>&1; then
        warn "пользователь nobody недоступен — kill-сценарий (5.9.5a) пропущен, критерий 17 останется без входа"
        echo ""
        return
    fi
    if ! command -v python3 &> /dev/null; then
        warn "python3 не найден — kill-сценарий (5.9.5a) пропущен, критерий 17 останется без входа"
        echo ""
        return
    fi
    if ! command -v runuser &> /dev/null; then
        warn "runuser не найден — kill-сценарий (5.9.5a) пропущен, критерий 17 останется без входа"
        echo ""
        return
    fi

    local victim_script="/tmp/ebpf-guard-kill-scenario-$TIMESTAMP.py"
    cat > "$victim_script" <<'PYEOF'
import ctypes
import time

libc = ctypes.CDLL(None, use_errno=True)
# bpf(BPF_MAP_DELETE_ELEM=3, attr=NULL, size=0) as an unprivileged (uid>0)
# process — matches ebpf_subversion_detach_nonroot's nr=321/arg0=3/uid>0
# condition regardless of the syscall's return value (it always fails here,
# there is no valid map fd; the rule looks at the call, not its outcome).
libc.syscall(321, ctypes.c_long(3), None, ctypes.c_ulong(0))
time.sleep(6)
PYEOF
    chmod 644 "$victim_script"

    runuser -u nobody -- python3 "$victim_script" &
    local victim_pid=$!
    log "жертва kill-сценария: pid=$victim_pid (nobody, вызвал bpf(BPF_MAP_DELETE_ELEM), arg0=3, uid>0)"
    sleep 3
    if kill -0 "$victim_pid" 2>/dev/null; then
        log "наблюдение: жертва pid=$victim_pid жива через 3с после bpf() — согласуется с dry_run: true, ЕСЛИ правило сработало (само срабатывание смотреть в критерии 17)"
    else
        error "наблюдение: жертва pid=$victim_pid мертва раньше срока (sleep 6 не должен был закончиться) — проверить журнал: настоящий SIGKILL при dry_run: true был бы регрессом находки №52"
    fi
    # `|| true`: под `set -e` статус wait — это статус жертвы, а убитая жертва
    # даёт 137. То есть без этой заглушки ровно тот случай, ради которого
    # заведён критерий 17 (сломанный предохранитель реально убил процесс),
    # обрывал бы run-all-attacks.sh здесь — до run_induced_drop и
    # get_final_metrics, — и гейт не увидел бы ни финальных метрик, ни
    # доказательства регресса. Регресс диагностируется строкой error выше и
    # критерием 17, а не аварийным выходом скрипта.
    wait "$victim_pid" 2>/dev/null || true
    rm -f "$victim_script"
    log "kill-сценарий завершён — вердикт в run-gate.sh, критерий 17 (enforcement_dryrun_total{action=kill} >= 1 и enforcement_actions_total{action=kill} == 0)"
    echo ""
}

# 5.9.5b (находка №62, P1) — наведённый дроп, управляемый вход для критерия 3.
# Дожидаться, пока стенд сам уронит события, — ждать случая: 222 дропа на
# №2.9.3, 0 на №2.9.4. Всплеск файловых операций внутри дерева харнесса (а не
# от отдельного, вне-дерева процесса — то дало бы алерты вне
# observer_exclude, находка №68) должен перегрузить bulk-очередь настолько,
# чтобы приоритетная очередь начала дропать и /health показал status=degraded
# — переход опрашивается, пока всплеск идёт, потому что критерию нужен
# НАБЛЮДАВШИЙСЯ переход, а не вывод постфактум. Итог (исполнен ли всплеск,
# зафиксирован ли degraded) пишется в файл-маркер, который читает run-gate.sh
# критерий 3, — «дроп не случился» тоже обязана быть строкой отчёта, а не
# молчанием.
run_induced_drop() {
    log "==========================================="
    log "НАВЕДЁННЫЙ ДРОП (5.9.5b, №62 P1: вход для критерия 3)"
    log "==========================================="

    local marker="$RESULTS_DIR/induced-drop-$TIMESTAMP.txt"
    local executed=0
    local degraded_seen=0
    local rounds_done=0

    # 5.9.6d (находка №73, P1): снимок до всплеска, для наведённой потери
    # ЭТОГО шага по хопам — отдельно от baseline/final всего прогона, которые
    # печатает раздел 1 run-gate.sh и с которыми это число не обязано
    # совпадать (baseline снят задолго до этого шага).
    local metrics_before_drop
    metrics_before_drop=$(curl -s --max-time 10 -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/metrics" 2>/dev/null)

    # 5.9.6d: список файлов вместо `tar -cf - /usr` целиком — на №2.9.5
    # неограниченный `/usr` дал 795 тыс. дропов, из которых для перехода в
    # degraded хватило первой доли секунды, а остальное сгорело уже после
    # финального снимка, не измеренным ничем. Список фиксированной длины
    # сохраняет свойство, ради которого выбран именно tar (один процесс,
    # массовое чтение, без per-файлового fork — `find | xargs cat` такой
    # скорости не даёт), но ограничивает объём числом, известным заранее.
    # Калибровка (сколько файлов реально нужно, чтобы получить переход) не
    # проверялась на стенде в этой сессии — см. открытые вопросы 5.9.6d.
    local max_files="${INDUCED_DROP_MAX_FILES:-20000}"
    local filelist="/tmp/ebpf-guard-induced-drop-filelist-$TIMESTAMP.txt"
    find /usr -type f 2>/dev/null | head -n "$max_files" > "$filelist"
    local bounded_files
    bounded_files=$(wc -l < "$filelist" | tr -d ' ')
    log "наведённый дроп ограничен списком: $bounded_files файлов (лимит INDUCED_DROP_MAX_FILES=$max_files)"

    # Уровень CPU-шединга (ebpf_guard_cpu_pressure_level: 0=норма,
    # 1=file_sampling_reduced, 2=all_noisy_sampling_reduced). Пишется в маркер
    # обоими концами окна: пока регулятор держит пониженную выборку файловых
    # событий, всплеск физически не может уронить bulk-очередь, и «перехода не
    # видели» означает работающий регулятор, а не сломанный дроп. Без этой
    # величины критерий 3 не отличил бы одно от другого — это ровно тот класс
    # немого SKIP, из-за которого заведена находка №62.
    pressure_level() {
        curl -s --max-time 5 -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/metrics" 2>/dev/null \
            | awk '/^ebpf_guard_cpu_pressure_level /{print $2; found=1} END{if(!found) print "n/a"}' || echo "n/a"
    }
    local pressure_before pressure_after
    pressure_before=$(pressure_level)
    log "cpu_pressure_level до всплеска: $pressure_before (0=норма; при 1/2 файловая выборка снижена, дроп навести нельзя)"

    # До трёх раундов с паузой: регулятор CPU-давления держит пониженную
    # выборку min_dwell = 180с после срабатывания (internal/watchdog/cpu.go), а
    # окно атак прямо перед этим шагом само поднимает нагрузку. Один раунд,
    # попавший в дежурство регулятора, — это гарантированный SKIP критерия 3
    # (третий замер подряд); пауза между раундами даёт регулятору выйти в
    # recovery и делает вход управляемым, как того требует постановка 5.9.5b.
    local round
    for round in 1 2 3; do
        rounds_done=$round
        # `tar -cf - /usr | cat` открывает И читает каждый файл дерева, поэтому
        # даёт прирост fileaccess/ringbuf_to_router с первой же секунды
        # (замерено на стенде 2026-08-21: +813 дропов за 1с, /health
        # status=degraded, degraded_queues=["bulk"]). Важно, что архив идёт в
        # ПОТОК: GNU tar, увидев архивом /dev/null, содержимое файлов не читает
        # вовсе — вариант `tar -cf /dev/null` проверен здесь же и перехода не
        # дал, как и прежний `find /usr -type f` (find делает getdents/statx, а
        # коллектор смотрит open/read/write — ноль дропов за 6с, /health
        # healthy все опросы; это и была причина SKIP на №2.9.3/№2.9.4).
        log "раунд $round/3: всплеск tar -cf - --files-from=$bounded_files-файлового-списка | cat (в дереве харнесса, наблюдательный root не меняется)"
        ( tar -cf - --files-from="$filelist" 2>/dev/null | cat >/dev/null 2>&1 ) &
        local burst_pid=$!
        if kill -0 "$burst_pid" 2>/dev/null; then
            executed=1
        fi

        # Опрос идёт и ПОСЛЕ конца всплеска (до 20 срезов всего): состояние
        # degraded держится degradationThreshold = 5с после последнего дропа
        # (cmd/ebpf-guard/main.go), а обход прогретого кэша укладывается в
        # 1-3с — цикл, выходящий вместе с всплеском, пропустил бы переход,
        # который к этому моменту уже наступил.
        local i=0
        while { kill -0 "$burst_pid" 2>/dev/null || [ "$i" -lt 10 ]; } && [ "$i" -lt 20 ]; do
            # `|| true` на обеих ветках: под `set -e` и неудачный curl (агент
            # занят/недоступен под всплеском — а это ровно ожидаемое
            # состояние), и падение jq на неполном JSON обрывали бы прогон
            # прямо в момент наведённого дропа.
            st=$(curl -s -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/health" 2>/dev/null \
                | jq -r '.status // empty' 2>/dev/null || true)
            if [ "$st" = "degraded" ]; then
                degraded_seen=1
                log "  /health status=degraded во время всплеска (раунд $round, опрос №$i)"
                break
            fi
            sleep 1
            i=$(( i + 1 ))
        done
        kill "$burst_pid" 2>/dev/null || true
        wait "$burst_pid" 2>/dev/null || true

        if [ "$degraded_seen" -eq 1 ]; then
            # Пауза перед выходом: WARN «visibility reduced» пишет секундный
            # тикер агента, а следом идёт get_final_metrics — на №2.9.5 строка
            # легла в ту же секунду, что и финальный снимок, и критерий 3
            # потерял её на границе окна journalctl. Запас на стороне гейта
            # (+15с к --until) это чинит, но пусть и порядок событий будет
            # правильным: строка в журнале раньше снимка, а не вровень с ним.
            sleep 3
            break
        fi
        if [ "$round" -lt 3 ]; then
            warn "раунд $round: перехода не видели — пауза 90с на выход регулятора CPU-давления из min_dwell (180с), затем повтор"
            sleep 90
        fi
    done

    pressure_after=$(pressure_level)

    # 5.9.6d: ждать окончания раунда мало — на №2.9.5 финальный снимок
    # ушёл в 09:28:41.284, а 795 тыс. дропов той же самой пачки легли
    # тридцатью секундами позже, вне снимка вообще. Опрашиваем, пока либо
    # /health не выйдет из degraded ("visibility restored"), либо прирост
    # events_dropped_total{collector="fileaccess"} не остановится два среза
    # подряд — до 60с. Идёт всегда, не только при degraded_seen=1: даже
    # необнаруженный переход мог оставить дропы в полёте.
    local settle_prev=-1 settle_cur settle_status settle_reason="timeout" settle_i
    for settle_i in $(seq 1 60); do
        settle_cur=$(curl -s --max-time 5 -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/metrics" 2>/dev/null \
            | sum_metric 'ebpf_guard_events_dropped_total\{collector="fileaccess"')
        settle_status=$(curl -s --max-time 5 -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/health" 2>/dev/null \
            | jq -r '.status // empty' 2>/dev/null || true)
        if [ -n "$settle_status" ] && [ "$settle_status" != "degraded" ]; then
            settle_reason="visibility_restored"
            break
        fi
        if [ "$settle_cur" = "$settle_prev" ]; then
            settle_reason="growth_flattened"
            break
        fi
        settle_prev="$settle_cur"
        sleep 1
    done
    log "5.9.6d: снимок откладывается до затухания — причина остановки: $settle_reason (за ${settle_i}с)"

    local metrics_after_drop
    metrics_after_drop=$(curl -s --max-time 10 -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/metrics" 2>/dev/null)
    local d_ringbuf_full d_ringbuf_to_router d_router_to_queue d_path_denylist d_total
    d_ringbuf_full=$(( $(echo "$metrics_after_drop" | sum_metric 'collector="fileaccess".*reason="ringbuf_full"') \
        - $(echo "$metrics_before_drop" | sum_metric 'collector="fileaccess".*reason="ringbuf_full"') ))
    d_ringbuf_to_router=$(( $(echo "$metrics_after_drop" | sum_metric 'collector="fileaccess".*reason="ringbuf_to_router"') \
        - $(echo "$metrics_before_drop" | sum_metric 'collector="fileaccess".*reason="ringbuf_to_router"') ))
    d_router_to_queue=$(( $(echo "$metrics_after_drop" | sum_metric 'collector="fileaccess".*reason="router_to_queue"') \
        - $(echo "$metrics_before_drop" | sum_metric 'collector="fileaccess".*reason="router_to_queue"') ))
    d_path_denylist=$(( $(echo "$metrics_after_drop" | sum_metric 'collector="fileaccess".*reason="path_denylist"') \
        - $(echo "$metrics_before_drop" | sum_metric 'collector="fileaccess".*reason="path_denylist"') ))
    d_total=$(( $(echo "$metrics_after_drop" | sum_metric 'ebpf_guard_events_dropped_total\{collector="fileaccess"') \
        - $(echo "$metrics_before_drop" | sum_metric 'ebpf_guard_events_dropped_total\{collector="fileaccess"') ))
    log "5.9.6d: наведённая потеря этого шага (fileaccess), по хопам — ringbuf_full=$d_ringbuf_full ringbuf_to_router=$d_ringbuf_to_router router_to_queue=$d_router_to_queue path_denylist=$d_path_denylist | всего=$d_total"
    rm -f "$filelist"

    {
        echo "executed=$executed"
        echo "degraded_seen=$degraded_seen"
        echo "rounds=$rounds_done"
        echo "cpu_pressure_level_before=$pressure_before"
        echo "cpu_pressure_level_after=$pressure_after"
        echo "bounded_files=$bounded_files"
        echo "settle_reason=$settle_reason"
        echo "settle_seconds=$settle_i"
        echo "induced_drop_ringbuf_full=$d_ringbuf_full"
        echo "induced_drop_ringbuf_to_router=$d_ringbuf_to_router"
        echo "induced_drop_router_to_queue=$d_router_to_queue"
        echo "induced_drop_path_denylist=$d_path_denylist"
        echo "induced_drop_total=$d_total"
    } > "$marker"

    if [ "$degraded_seen" -eq 1 ]; then
        log "PASS (наблюдение): переход в degraded зафиксирован во время наведённого дропа (раунд $rounds_done) — критерий 3 получит вход"
    elif [ "$executed" -eq 1 ]; then
        warn "всплеск исполнен в $rounds_done раунда(х), но status=degraded не замечен — cpu_pressure_level до/после: $pressure_before/$pressure_after (при 1/2 файловая выборка снижена регулятором, и дроп навести нельзя по построению)"
    else
        warn "наведённый дроп не запустился (tar/cat недоступны?) — критерий 3 останется без входа"
    fi
    echo ""
}

# Сбор финальных метрик
get_final_metrics() {
    log "==========================================="
    log "СБОР ФИНАЛЬНЫХ МЕТРИК"
    log "==========================================="

    # 5.9.4c (находка №54): то же ожидание слива конвейера, что 5.9.1c
    # поставила перед baseline (get_baseline_metrics выше) — без него
    # финальный снимок наследует временный перекос
    # engine−filtered−suppressed−exported ≠ 0 просто потому, что последний
    # алерт прогона ещё не дотёк до экспорта в момент снятия среза, и
    # критерий 15 в run-gate.sh находит "четвёртый счётчик", которого на
    # самом деле нет — тот же класс ложного расхождения, что 5.9.1c закрыла
    # на baseline-конце. Таймаут 30с, тот же порог. Результат пишется в
    # final-drain-offset-$TIMESTAMP.txt независимо от того, сошёлся offset
    # или нет — критерий 15 обязан видеть его в обоих случаях.
    if command -v jq &> /dev/null; then
        local drain_offset="n/a"
        local engine_now metrics_now filtered_now suppressed_now exported_now
        for _ in $(seq 1 15); do
            engine_now=$(curl -s --max-time 5 -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/debug/state" 2>/dev/null \
                | jq -r '.engine_stats.total_alerts // empty' 2>/dev/null)
            metrics_now=$(curl -s --max-time 5 -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/metrics" 2>/dev/null)
            filtered_now=$(echo "$metrics_now" | grep '^ebpf_guard_alerts_filtered_total{' | awk -F'} ' '{s+=$2} END{printf "%d", s+0}')
            suppressed_now=$(echo "$metrics_now" | grep '^ebpf_guard_alerts_suppressed_total{' | awk -F'} ' '{s+=$2} END{printf "%d", s+0}')
            exported_now=$(echo "$metrics_now" | grep '^ebpf_guard_alerts_total{' | awk -F'} ' '{s+=$2} END{printf "%d", s+0}')
            if [ -n "$engine_now" ]; then
                drain_offset=$(( engine_now - ${filtered_now:-0} - ${suppressed_now:-0} - ${exported_now:-0} ))
                if [ "$drain_offset" -eq 0 ]; then
                    break
                fi
            fi
            sleep 2
        done
        if [ "$drain_offset" = "0" ]; then
            log "5.9.4c: конвейер слился перед final (offset=0)"
        else
            warn "5.9.4c: offset конвейера не сошёлся к нулю за 30с (offset=$drain_offset) — final снимается как есть, критерий 15 обязан это учесть"
        fi
        echo "drain_offset_before_final=$drain_offset" > "$RESULTS_DIR/final-drain-offset-$TIMESTAMP.txt"
    fi

    # 5.9.8d (№97, P1): тот же приём, что 5.9.4c выше, но для событийного
    # тождества критерия 19 (run-gate.sh), а не для алертного offset. Без
    # него финальный срез наследует хвост в очереди коллектор→router→bulk
    # queue как невязку, которая выглядит как потерянное событие, хотя это
    # просто событие, ещё не дотёкшее до events_total на момент снятия среза
    # — тот же класс перекоса, что 5.9.4c закрыла для алертов, применённый ко
    # второму независимому тождеству. Условие выхода — «остаток перестал
    # убывать по модулю», а не «стал нулём» (секция 19 держит допуск
    # 500/0.5%, не 0) — на стенде с непрерывным фоном точный ноль
    # недостижим. Таймаут 30с (15 срезов × 2с), тот же порядок величины, что
    # у алертного drain_offset. baseline-metrics-$TIMESTAMP.txt уже на диске
    # (get_baseline_metrics выше) — берётся как есть, без повторного снятия.
    local baseline_metrics_file="$RESULTS_DIR/baseline-metrics-$TIMESTAMP.txt"
    local events_drain_offset="n/a"
    if [ -s "$baseline_metrics_file" ]; then
        local cur_metrics_file="$RESULTS_DIR/.events-drain-probe-$TIMESTAMP.txt"
        local prev_abs=-1 cur_abs c19_c c19_type em_d ev_d r2r_d r2q_d mf_d res
        for _ in $(seq 1 15); do
            curl -s --max-time 5 -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/metrics" > "$cur_metrics_file" 2>/dev/null
            cur_abs=0
            for c19_c in syscall network fileaccess; do
                case "$c19_c" in
                    fileaccess) c19_type="file" ;;
                    *) c19_type="$c19_c" ;;
                esac
                em_d=$(sum_metric_delta "ebpf_guard_events_emitted_kernel_total\\{collector=\"$c19_c\"\\}" "$baseline_metrics_file" "$cur_metrics_file")
                ev_d=$(sum_metric_delta "^ebpf_guard_events_total\\{.*type=\"$c19_type\"" "$baseline_metrics_file" "$cur_metrics_file")
                r2r_d=$(sum_metric_delta "collector=\"$c19_c\".*reason=\"ringbuf_to_router\"" "$baseline_metrics_file" "$cur_metrics_file")
                r2q_d=$(sum_metric_delta "collector=\"$c19_c\".*reason=\"router_to_queue\"" "$baseline_metrics_file" "$cur_metrics_file")
                mf_d=$(sum_metric_delta "ebpf_guard_events_malformed_total\\{collector=\"$c19_c\"\\}" "$baseline_metrics_file" "$cur_metrics_file")
                res=$(awk -v e="${em_d:-0}" -v a="${ev_d:-0}" -v b="${r2r_d:-0}" -v d="${r2q_d:-0}" -v m="${mf_d:-0}" 'BEGIN{printf "%.0f", e-(a+b+d+m)}')
                cur_abs=$(awk -v s="$cur_abs" -v r="$res" 'BEGIN{r=(r<0)?-r:r; printf "%.0f", s+r}')
            done
            events_drain_offset=$cur_abs
            if [ "$prev_abs" -ge 0 ] && [ "$cur_abs" -ge "$prev_abs" ]; then
                break
            fi
            prev_abs=$cur_abs
            sleep 2
        done
        rm -f "$cur_metrics_file"
        log "5.9.8d: суммарный |остаток| тождества секции 19 по syscall/network/fileaccess перед final = $events_drain_offset (перестал убывать либо истёк таймаут 30с)"
    else
        warn "5.9.8d: baseline-metrics-$TIMESTAMP.txt отсутствует или пуст — events_drain_offset не измерен"
    fi
    echo "events_drain_offset=$events_drain_offset" >> "$RESULTS_DIR/final-drain-offset-$TIMESTAMP.txt"

    # 5.9.4c: порядок снимков — сначала стор и состояние (/api/v1/alerts,
    # /health, /api/v1/status, /debug/state, /api/v1/incidents), /metrics —
    # ПОСЛЕДНЕЙ. Раньше /metrics снималась первой: если стор ещё дописывал
    # алерт из последней атаки в момент снятия /metrics, тип был виден в
    # /api/v1/alerts, но отсутствовал в ebpf_guard_alerts_total{rule_id}, и
    # критерий 6 (который до 5.9.4c считал состав только по метрике) печатал
    # бы потерю там, где детект сработал — просто стор и метрика ещё не
    # синхронны. Метрика теперь никогда не может отстать от стора: она
    # снимается последней из всех.
    curl -s -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/api/v1/alerts" > "$RESULTS_DIR/final-alerts-$TIMESTAMP.json"
    curl -s -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/health" > "$RESULTS_DIR/final-health-$TIMESTAMP.json"
    curl -s -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/api/v1/status" > "$RESULTS_DIR/final-status-$TIMESTAMP.json"
    curl -s -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/debug/state" > "$RESULTS_DIR/final-state-$TIMESTAMP.json"
    # Incidents carry the P1-27 comm field that run-gate.sh criterion 4 checks.
    # Without this snapshot that criterion silently degrades to a WARN, i.e. the
    # headline result of wave 1 would go unverified by the very gate written to
    # verify it (plan.md волна 1.5h).
    curl -s -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/api/v1/incidents" > "$RESULTS_DIR/final-incidents-$TIMESTAMP.json"
    curl -s -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/metrics" > "$RESULTS_DIR/final-metrics-$TIMESTAMP.txt"

    echo ""
}

# Генерация итогового отчета
generate_final_report() {
    log "==========================================="
    log "ГЕНЕРАЦИЯ ИТОГОВОГО ОТЧЕТА"
    log "==========================================="

    local report_file="$RESULTS_DIR/FINAL-REPORT-$TIMESTAMP.txt"
    # generate_final_report's body runs inside a "{ ... } | tee" pipeline,
    # i.e. a subshell — a plain variable set there would be lost once the
    # pipeline exits. Use a flag file instead so the caller (full_run/
    # interactive_mode) can see whether any gate failed and exit non-zero.
    local gate_flag_file="$RESULTS_DIR/.gate-failed-$TIMESTAMP"
    rm -f "$gate_flag_file"

    {
        echo "╔═══════════════════════════════════════════════════════════════╗"
        echo "║          ebpf-guard SECURITY TESTING - FINAL REPORT          ║"
        echo "╚═══════════════════════════════════════════════════════════════╝"
        echo ""
        echo "Дата: $(date)"
        echo "Timestamp: $TIMESTAMP"
        echo ""
        echo "═══════════════════════════════════════════════════════════════"
        echo "ТЕСТОВОЕ ОКРУЖЕНИЕ"
        echo "═══════════════════════════════════════════════════════════════"
        echo "Juice Shop URL: $JUICE_SH_URL"
        echo "ebpf-guard API: $EBPF_GUARD_API"
        echo ""

        echo "═══════════════════════════════════════════════════════════════"
        echo "АНАЛИЗ МЕТРИК ebpf-guard"
        echo "═══════════════════════════════════════════════════════════════"

        # Сравнение метрик — берём точные счетчики из /debug/state (JSON),
        # т.к. ebpf_guard_alerts_total / ebpf_guard_events_total в /metrics
        # экспортируются по многим комбинациям лейблов (rule_id/severity/pod/...),
        # и grep по первой строке даёт только один срез, а не сумму.
        echo ""
        echo "=== КЛЮЧЕВЫЕ МЕТРИКИ ==="

        local baseline_state="$RESULTS_DIR/baseline-state-$TIMESTAMP.json"
        local final_state="$RESULTS_DIR/final-state-$TIMESTAMP.json"
        local baseline_metrics="$RESULTS_DIR/baseline-metrics-$TIMESTAMP.txt"
        local final_metrics="$RESULTS_DIR/final-metrics-$TIMESTAMP.txt"
        local baseline_alerts_json="$RESULTS_DIR/baseline-alerts-$TIMESTAMP.json"
        local final_alerts_json="$RESULTS_DIR/final-alerts-$TIMESTAMP.json"

        local baseline_alerts=0 final_alerts=0 baseline_events=0 final_events=0
        local baseline_anomalies=0 final_anomalies=0
        if command -v jq &> /dev/null; then
            baseline_alerts=$(jq -r '.engine_stats.total_alerts // 0' "$baseline_state" 2>/dev/null || echo 0)
            final_alerts=$(jq -r '.engine_stats.total_alerts // 0' "$final_state" 2>/dev/null || echo 0)
            baseline_events=$(jq -r '.engine_stats.total_events // 0' "$baseline_state" 2>/dev/null || echo 0)
            final_events=$(jq -r '.engine_stats.total_events // 0' "$final_state" 2>/dev/null || echo 0)
            baseline_anomalies=$(jq -r '.profiler_stats.anomalies_total // 0' "$baseline_state" 2>/dev/null || echo 0)
            final_anomalies=$(jq -r '.profiler_stats.anomalies_total // 0' "$final_state" 2>/dev/null || echo 0)
        else
            warn "jq не найден — пропускаем разбор /debug/state, проверьте *-state-$TIMESTAMP.json вручную"
        fi

        # 5.9c (находка №29): раньше здесь печаталось только engine_stats.total_alerts
        # (счётчик ДО store.min_severity) под подписью "Alerts Total", и "Новых: N"
        # считалось по нему же — то есть по величине, которая не совпадает ни с тем,
        # что реально экспортируется в /metrics (ebpf_guard_alerts_total{rule_id}),
        # ни с тем, что оказывается в сторе (/api/v1/alerts, длина). Печатаем все три
        # рядом с явными подписями, и "Новых:" теперь считается по ПОСЛЕ-фильтровой
        # величине (exported) — это то число, которое реально ушло получателям.
        local baseline_exported=0 final_exported=0
        baseline_exported=$(grep '^ebpf_guard_alerts_total{' "$baseline_metrics" 2>/dev/null \
            | awk -F'} ' '{s+=$2} END{printf "%d", s+0}')
        final_exported=$(grep '^ebpf_guard_alerts_total{' "$final_metrics" 2>/dev/null \
            | awk -F'} ' '{s+=$2} END{printf "%d", s+0}')
        local baseline_store=0 final_store=0
        if command -v jq &> /dev/null; then
            baseline_store=$(jq 'length' "$baseline_alerts_json" 2>/dev/null || echo 0)
            final_store=$(jq 'length' "$final_alerts_json" 2>/dev/null || echo 0)
        fi

        local new_alerts_exported=$(( ${final_exported:-0} - ${baseline_exported:-0} ))
        echo "Alerts (engine_stats.total_alerts, до store.min_severity):"
        echo "  До тестов: $baseline_alerts"
        echo "  После тестов: $final_alerts"
        echo ""
        echo "Alerts (ebpf_guard_alerts_total{rule_id}, после min_severity — экспортированные):"
        echo "  До тестов: ${baseline_exported:-0}"
        echo "  После тестов: ${final_exported:-0}"
        echo ""
        echo "Alerts (/api/v1/alerts, длина — стор):"
        echo "  До тестов: $baseline_store"
        echo "  После тестов: $final_store"
        echo ""
        echo "Новых: $new_alerts_exported"
        echo ""

        local new_events=$((final_events - baseline_events))
        echo "Events Total:"
        echo "  До тестов: $baseline_events"
        echo "  После тестов: $final_events"
        echo "  Новых: $new_events"
        echo ""

        local new_anomalies=$((final_anomalies - baseline_anomalies))
        echo "Anomalies Total:"
        echo "  До тестов: $baseline_anomalies"
        echo "  После тестов: $final_anomalies"
        echo "  Новых: $new_anomalies"
        echo ""

        # Фаза обучения — только в /api/v1/status, не в /health (см. P1-4, P2-7 п.6).
        local baseline_status="$RESULTS_DIR/baseline-status-$TIMESTAMP.json"
        local final_status="$RESULTS_DIR/final-status-$TIMESTAMP.json"
        if command -v jq &> /dev/null; then
            local b_complete b_progress f_complete f_progress
            # AgentHealth is nested under "health" in /api/v1/status
            # (see internal/exporter/api.go StatusAPIResponse.Health); the
            # top-level fallback covers a future flattened response shape
            # (plan.md волна 1.5f).
            b_complete=$(jq -r '.health.learning_complete // .learning_complete // "unknown"' "$baseline_status" 2>/dev/null)
            b_progress=$(jq -r '.health.learning_progress // .learning_progress // "unknown"' "$baseline_status" 2>/dev/null)
            f_complete=$(jq -r '.health.learning_complete // .learning_complete // "unknown"' "$final_status" 2>/dev/null)
            f_progress=$(jq -r '.health.learning_progress // .learning_progress // "unknown"' "$final_status" 2>/dev/null)
            echo "Learning Phase:"
            echo "  До тестов: complete=$b_complete progress=$b_progress"
            echo "  После тестов: complete=$f_complete progress=$f_progress"
            echo ""
        fi

        echo "═══════════════════════════════════════════════════════════════"
        echo "СТАТИСТИКА ПО ТИПАМ АТАК"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""

        # Статистика по результатам
        local attack_gate_failed=""
        for result_dir in sqlmap-results bruteforce-results ssrf-results ldap-csrf-results; do
            if [ -d "$result_dir" ]; then
                local file_count=$(find "$result_dir" -type f | wc -l)
                echo "📁 $result_dir:"
                echo "   Файлов создано: $file_count"

                # Подсчет атак attempts. curl's -w "...%{http_code}" writes the
                # *resolved* numeric status, so the literal string "http_code"
                # never appears in output files — only "Status: <code>" or
                # "<label>: <code>" do. Matching just "http_code" always
                # counted 0, which is why sqlmap/ssrf/ldap-csrf showed
                # "Попыток атак: 0" here despite real traffic being sent.
                local attempts=0
                for file in "$result_dir"/*.txt; do
                    if [ -f "$file" ]; then
                        # grep -c always prints a count (even "0") and only
                        # exits non-zero on no match, so "|| echo 0" used to
                        # append a second line and break the arithmetic below.
                        local count=$(grep -cE 'Status: [0-9]{3}|: [0-9]{3}$' "$file" 2>/dev/null)
                        attempts=$((attempts + count))
                    fi
                done
                echo "   Попыток атак: $attempts"
                echo ""

                # Gate: 0 попыток трафика делает любой вывод об алертах/детекте
                # для этой категории бессмысленным (см. P2-8) — отмечаем явно,
                # вместо того чтобы молча включать её в общий "новых алертов".
                if [ "$attempts" -eq 0 ]; then
                    attack_gate_failed="$attack_gate_failed $result_dir"
                fi
            fi
        done

        echo "=== ATTACK TRAFFIC GATE ==="
        if [ -n "$attack_gate_failed" ]; then
            warn "Категории без реального трафика (0 попыток):$attack_gate_failed"
            echo "GATE: FAILED — для этих категорий 'новых алертов: 0' не является валидным результатом детекта:$attack_gate_failed"
            touch "$gate_flag_file"
        else
            log "✓ Все категории атак отправили трафик"
            echo "GATE: OK"
        fi
        echo ""

        # Каждый под-скрипт (sqlmap/bruteforce/ssrf/ldap-csrf-attacks.sh) пишет
        # собственный "GATE: FAILED"/"GATE: OK" в свой summary-*.txt, но раньше
        # итоговый отчёт этот статус не читал вовсе — секция могла напечатать
        # "GATE: FAILED" и итог всё равно бы завершился как успешный прогон
        # (см. P3-16 п.2). Собираем реальный провал из всех summary-файлов.
        echo "=== PER-SCRIPT GATES ==="
        for result_dir in sqlmap-results bruteforce-results ssrf-results ldap-csrf-results; do
            local summary
            summary=$(find "$result_dir" -maxdepth 1 -name 'summary-*.txt' 2>/dev/null | sort | tail -1)
            if [ -n "$summary" ] && [ -f "$summary" ]; then
                if grep -q '^GATE: FAILED' "$summary"; then
                    echo "  $result_dir: FAILED ($summary)"
                    touch "$gate_flag_file"
                elif grep -q 'GATE: OK' "$summary"; then
                    echo "  $result_dir: OK"
                else
                    echo "  $result_dir: UNKNOWN (no GATE line in $summary)"
                fi
            else
                echo "  $result_dir: NO SUMMARY FOUND"
            fi
        done
        echo ""

        echo "═══════════════════════════════════════════════════════════════"
        echo "ТОП НОВЫХ АЛЕРТОВ ПО ТИПАМ (дельта baseline → final по id)"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""

        local baseline_alerts_json="$RESULTS_DIR/baseline-alerts-$TIMESTAMP.json"
        local final_alerts_json="$RESULTS_DIR/final-alerts-$TIMESTAMP.json"

        # Дельта считается по множеству id алертов (final \ baseline), а не по
        # абсолютным count'ам из /api/v1/alerts — иначе "топ алертов" не сходится
        # с "новых алертов: N" выше, т.к. эндпоинт отдаёт весь текущий стор, а не
        # только события с начала прогона.
        if command -v jq &> /dev/null; then
            echo "=== ALERT CATEGORIES (new only) ==="
            jq -s '
                (.[0] // []) as $baseline |
                (.[1] // []) as $final |
                ($baseline | map(.id) | unique) as $baseline_ids |
                ($final | map(select(.id as $id | ($baseline_ids | index($id)) | not))) as $new |
                $new | group_by(.rule_id) | map({rule: .[0].rule_id, count: length}) | sort_by(.count) | reverse | .[:10] | .[] | "\(.rule): \(.count)"
            ' -r "$baseline_alerts_json" "$final_alerts_json" 2>/dev/null || echo "Не удалось разобрать алерты"
            echo ""
        fi

        echo "═══════════════════════════════════════════════════════════════"
        echo "ДЕТЕКТИРУЕМЫЕ ТИПЫ АТАК"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""

        # Уникальные rule_id среди новых (final \ baseline) алертов
        local detected=0
        if command -v jq &> /dev/null; then
            detected=$(jq -s '
                (.[0] // []) as $baseline |
                (.[1] // []) as $final |
                ($baseline | map(.id) | unique) as $baseline_ids |
                ($final | map(select(.id as $id | ($baseline_ids | index($id)) | not))) as $new |
                $new | map(.rule_id) | unique | length
            ' -r "$baseline_alerts_json" "$final_alerts_json" 2>/dev/null || echo 0)
        fi
        echo "Уникальных типов атак детектировано (новых): $detected"
        echo ""

        # Топ атак по severity (тоже только новые, для согласованности с "Новых: $new_alerts")
        if command -v jq &> /dev/null; then
            echo "=== BY SEVERITY (new only) ==="
            jq -s '
                (.[0] // []) as $baseline |
                (.[1] // []) as $final |
                ($baseline | map(.id) | unique) as $baseline_ids |
                ($final | map(select(.id as $id | ($baseline_ids | index($id)) | not))) as $new |
                $new | group_by(.severity) | map({severity: .[0].severity, count: length}) | .[] | "\(.severity): \(.count)"
            ' -r "$baseline_alerts_json" "$final_alerts_json" 2>/dev/null || echo "Не удалось разобрать severity"
            echo ""
        fi

        echo "═══════════════════════════════════════════════════════════════"
        echo "ВЕРДИКТ ПО attack-manifest.json (plan.md волна 1.5g, вопрос 8)"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""

        # Precision/recall against the known attacker comms recorded by each
        # sub-script (sqlmap-attacks.sh etc. via record_manifest). This
        # replaces having to manually cross-reference alert PIDs against
        # attack logs (as required for the run #4 writeup) — recall is the
        # fraction of manifest categories that produced at least one new
        # alert whose comm matches, precision is the fraction of new alerts
        # whose comm is an attacker comm from the manifest.
        local manifest_file="$MANIFEST_FILE"
        if [ -f "$manifest_file" ] && command -v jq &> /dev/null; then
            local attacker_comms
            attacker_comms=$(jq -c '[.[].comm] | unique' "$manifest_file" 2>/dev/null || echo '[]')
            echo "Известные comm атакующих процессов (из манифеста): $attacker_comms"
            echo ""

            jq -s --argjson comms "$attacker_comms" '
                (.[0] // []) as $baseline |
                (.[1] // []) as $final |
                ($baseline | map(.id) | unique) as $baseline_ids |
                ($final | map(select(.id as $id | ($baseline_ids | index($id)) | not))) as $new |
                ($new | length) as $new_total |
                ($new | map(select(.comm as $c | $comms | index($c))) | length) as $new_attacker |
                {
                    new_alerts_total: $new_total,
                    new_alerts_from_attacker_comm: $new_attacker,
                    precision: (if $new_total > 0 then ($new_attacker / $new_total) else null end)
                }
            ' -r "$baseline_alerts_json" "$final_alerts_json" 2>/dev/null || echo "Не удалось посчитать precision"
            echo ""

            # 1.75a: тот же класс дефекта, что P2-7 и P2-28 (отчёт печатает
            # провал там, где система отработала). jq -s выше вызывался БЕЗ
            # аргументов-файлов — пустой stdin, $new_comms = [], index($c)
            # вернул null для каждой категории, recall печатался 0 при
            # фактических 4/4 = 1.0 в замере №1. Передаём те же два файла, что
            # в precision-блоке выше. Recall-категории исключают transit
            # (docker-proxy и подобные — транзитные процессы атаки, не её
            # источники; план 1.75c).
            jq -s --argjson manifest "$(jq -c '.' "$manifest_file" 2>/dev/null || echo '[]')" '
                (.[0] // []) as $baseline |
                (.[1] // []) as $final |
                ($baseline | map(.id) | unique) as $baseline_ids |
                ($final | map(select(.id as $id | ($baseline_ids | index($id)) | not))) as $new |
                ($new | map(.comm) | unique) as $new_comms |
                ($manifest | map(select(.transit != true))) as $real_manifest |
                ($real_manifest | map(.category) | unique) as $categories |
                ($real_manifest | group_by(.category) | map({
                    category: .[0].category,
                    comm: .[0].comm,
                    detected: ((.[0].comm as $c | $new_comms | index($c)) != null)
                })) as $per_category |
                {
                    categories_total: ($categories | length),
                    categories_detected: ($per_category | map(select(.detected)) | length),
                    recall: (if ($categories | length) > 0 then (($per_category | map(select(.detected)) | length) / ($categories | length)) else null end),
                    per_category: $per_category
                }
            ' -r "$baseline_alerts_json" "$final_alerts_json" 2>/dev/null || echo "Не удалось посчитать recall"
            echo ""
        else
            warn "attack-manifest.json не найден — precision/recall по вердикту не посчитаны"
            echo "GATE: FAILED — attack-manifest.json отсутствует"
            touch "$gate_flag_file"
        fi

        echo "═══════════════════════════════════════════════════════════════"
        echo "FALSE POSITIVE ANALYSIS"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""

        # Предложение для FP анализа
        echo "Для анализа false positives:"
        echo "1. Проверьте $RESULTS_DIR/baseline-alerts-$TIMESTAMP.json"
        echo "2. Проверьте $RESULTS_DIR/final-alerts-$TIMESTAMP.json"
        echo "3. Используйте analyze-alerts.py для детального анализа"
        echo ""

        echo "═══════════════════════════════════════════════════════════════"
        echo "РЕКОМЕНДАЦИИ"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""

        if [ "$new_alerts" -lt 50 ]; then
            warn "⚠️  Детектировано мало новых алертов ($new_alerts)"
            echo "   → Проверьте конфигурацию правил ebpf-guard"
            echo "   → Убедитесь, что правила подходят для вашего тестового окружения"
        else
            log "✓ Детектировано $new_alerts новых алертов"
        fi

        if [ "$new_anomalies" -lt 10 ]; then
            warn "⚠️  Детектировано мало аномалий ($new_anomalies)"
            echo "   → Проверьте настройку profiler в config"
        else
            log "✓ Детектировано $new_anomalies аномалий"
        fi

        echo ""
        echo "═══════════════════════════════════════════════════════════════"
        echo "ССЫЛКИ"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""
        echo "📊 Prometheus: http://${VPS_IP}:9090"
        echo "📈 Grafana: http://${VPS_IP}:3001 (admin/admin123)"
        echo "🔔 ebpf-guard Alerts API: $EBPF_GUARD_API/api/v1/alerts"
        echo "🏥 ebpf-guard Health: $EBPF_GUARD_API/health"
        echo ""

    } | tee "$report_file"

    log "Итоговый отчет сохранен: $report_file"

    # Также создадим JSON версию отчета
    local json_report="$RESULTS_DIR/FINAL-REPORT-$TIMESTAMP.json"
    if command -v jq &> /dev/null; then
        # P2-28 (второй регресс): счётчики выше объявлены `local` ВНУТРИ блока
        # "{ ... } | tee", то есть в субшелле, и к этому месту их уже не
        # существует — в JSON подставлялись пустые строки ("before": ,), из-за
        # чего файл был невалиден, пока текстовая ветка печатала верные числа.
        # Это ровно та же ловушка субшелла, что описана у gate_flag_file выше.
        # Перечитываем значения из state-файлов здесь, а не полагаемся на
        # переменные, переживание которых зависит от структуры пайплайна.
        local js_baseline_state="$RESULTS_DIR/baseline-state-$TIMESTAMP.json"
        local js_final_state="$RESULTS_DIR/final-state-$TIMESTAMP.json"
        local j_ba j_fa j_be j_fe j_ban j_fan
        j_ba=$(jq -r '.engine_stats.total_alerts // 0' "$js_baseline_state" 2>/dev/null || echo 0)
        j_fa=$(jq -r '.engine_stats.total_alerts // 0' "$js_final_state" 2>/dev/null || echo 0)
        j_be=$(jq -r '.engine_stats.total_events // 0' "$js_baseline_state" 2>/dev/null || echo 0)
        j_fe=$(jq -r '.engine_stats.total_events // 0' "$js_final_state" 2>/dev/null || echo 0)
        j_ban=$(jq -r '.profiler_stats.anomalies_total // 0' "$js_baseline_state" 2>/dev/null || echo 0)
        j_fan=$(jq -r '.profiler_stats.anomalies_total // 0' "$js_final_state" 2>/dev/null || echo 0)
        # Пустая строка от отсутствующего файла снова дала бы "before": ,
        # поэтому нормализуем всё, что не является целым числом, в 0.
        for v in j_ba j_fa j_be j_fe j_ban j_fan; do
            case "${!v}" in
                ''|*[!0-9]*) eval "$v=0" ;;
            esac
        done
        {
            echo "{"
            echo "  \"timestamp\": \"$TIMESTAMP\","
            echo "  \"date\": \"$(date -Iseconds)\","
            echo "  \"environment\": {"
            echo "    \"juice_shop_url\": \"$JUICE_SH_URL\","
            echo "    \"ebpf_guard_api\": \"$EBPF_GUARD_API\""
            echo "  },"
            echo "  \"metrics\": {"
            echo "    \"alerts\": {"
            echo "      \"before\": $j_ba,"
            echo "      \"after\": $j_fa,"
            echo "      \"new\": $((j_fa - j_ba))"
            echo "    },"
            echo "    \"events\": {"
            echo "      \"before\": $j_be,"
            echo "      \"after\": $j_fe,"
            echo "      \"new\": $((j_fe - j_be))"
            echo "    },"
            echo "    \"anomalies\": {"
            echo "      \"before\": $j_ban,"
            echo "      \"after\": $j_fan,"
            echo "      \"new\": $((j_fan - j_ban))"
            echo "    }"
            echo "  }"
            echo "}"
        } > "$json_report"

        # Regression guard (P2-28): the JSON branch broke silently once before
        # (empty $baseline_alerts/$final_alerts interpolated as bare commas,
        # producing invalid JSON) while the text branch above kept printing
        # correct numbers, so the break went unnoticed until manual review.
        # Validate the file we just wrote before calling the run done.
        if jq empty "$json_report" 2>/dev/null; then
            log "JSON отчет сохранен: $json_report"
        else
            error "JSON отчет невалиден: $json_report — см. вывод jq ниже"
            jq empty "$json_report"
            touch "$gate_flag_file"
        fi
    fi
}

# Проверяет флаг, выставленный generate_final_report при провале любого
# gate (traffic gate или per-script gate), и завершает процесс ненулевым
# кодом — раньше провал печатался в отчёт, но exit code всегда был 0
# (см. P3-16 п.2), поэтому CI/операторы, смотрящие только на код возврата,
# не видели проваленный прогон.
check_final_gate() {
    local gate_flag_file="$RESULTS_DIR/.gate-failed-$TIMESTAMP"

    # run-gate.sh checks the fourteen ЗАМЕР №1/№2/№3 thresholds from plan.md
    # (потери, dns probe, деградация, comm, JSON validity, детект жив,
    # recall, alerts_dropped, доля на демонах, process_chain, anomalies_total,
    # кардинальность, path_denylist, CPU-watchdog) — a superset of the
    # traffic/script gates above.
    # Its own FAIL also marks gate_flag_file so check_final_gate's exit code
    # reflects it too (plan.md волна 1.5h, вопрос 12). After 1.75c the gate
    # also runs an active DNS probe that needs EBPF_GUARD_API/TOKEN — pass
    # them explicitly so a non-exported env override on the master script
    # still reaches the gate (default fallbacks live in both scripts).
    if [ -f "$SCRIPT_DIR/run-gate.sh" ]; then
        EBPF_GUARD_API="$EBPF_GUARD_API" \
        EBPF_GUARD_TOKEN="$EBPF_GUARD_TOKEN" \
        VPS_IP="$VPS_IP" \
        bash "$SCRIPT_DIR/run-gate.sh" "$RESULTS_DIR" "$TIMESTAMP" || touch "$gate_flag_file"
        echo ""
    else
        warn "run-gate.sh не найден рядом с $0 — критерии замера №1 не проверены"
    fi

    if [ -f "$gate_flag_file" ]; then
        error "ATTACK TESTING GATE: FAILED — см. FINAL-REPORT-$TIMESTAMP.txt для деталей"
        return 1
    fi
    log "✓ ATTACK TESTING GATE: OK"
    return 0
}

# Главное меню
show_menu() {
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║     ebpf-guard SECURITY TESTING - MASTER MENU                 ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "1. Запустить все атаки (полный тест)"
    echo "2. Только SQLMap атаки"
    echo "3. Только Brute Force атаки"
    echo "4. Только SSRF атаки"
    echo "5. Только LDAP/CSRF атаки"
    echo "6. Только canary-атаки (chmod 5.9.1e + ssh-keys 5.9.7e + log tamper 5.9.1d в + setuid/bpf/kmod 5.9.2b + dns long-label 5.9.5c)"
    echo "7. Проверить состояние сервисов"
    echo "8. Собрать текущие метрики"
    echo "9. Сгенерировать отчет"
    echo "10. Выход"
    echo ""
}

# Интерактивный режим
interactive_mode() {
    while true; do
        show_menu
        read -p "Выберите опцию [1-10]: " choice

        case $choice in
            1)
                run_measurement_prologue || continue
                run_counting_control null 0
                run_counting_control idle "${COUNTING_CONTROL_N:-10000}"
                run_counting_control drop "${COUNTING_CONTROL_DROP_N:-300000}"
                run_sqlmap_attacks
                run_bruteforce_attacks
                run_ssrf_attacks
                run_ldap_csrf_attacks
                run_chmod_attack
                run_ssh_keys_positive_control
                run_webshell_script_write_positive_control
                run_log_tamper_attack
                run_setuid_attack
                run_bpf_attack
                run_kmod_attack
                run_dns_long_label_attack
                run_kill_scenario
                run_induced_drop
                get_final_metrics
                generate_final_report
                check_final_gate
                ;;
            2)
                check_services || continue
                run_sqlmap_attacks
                ;;
            3)
                check_services || continue
                run_bruteforce_attacks
                ;;
            4)
                check_services || continue
                run_ssrf_attacks
                ;;
            5)
                check_services || continue
                run_ldap_csrf_attacks
                ;;
            6)
                run_chmod_attack
                run_ssh_keys_positive_control
                run_webshell_script_write_positive_control
                run_log_tamper_attack
                run_setuid_attack
                run_bpf_attack
                run_kmod_attack
                run_dns_long_label_attack
                ;;
            7)
                check_services
                ;;
            8)
                get_baseline_metrics
                log "Текущие метрики сохранены в $RESULTS_DIR"
                ;;
            9)
                generate_final_report
                check_final_gate
                ;;
            10)
                log "Выход..."
                exit 0
                ;;
            *)
                error "Неверный выбор"
                ;;
        esac
    done
}

# Режим полного запуска (без интерактива)
#
# 5.9f (находка №32): baseline снимается ПОСЛЕ check_services, то есть после
# того, как оператор подтвердил готовность и Juice Shop, и ebpf-guard — не до
# входа оператора и подготовки стенда. Выбор сделан явно (а не "как получится"):
# альтернатива — снимать baseline ДО входа оператора — не отражала бы шум самой
# подготовки стенда в baseline, и он бы весь попал в окно атаки как "новые"
# алерты. Оставшийся зазор — между концом idle-часа (idle-run.sh) и запуском
# ЭТОГО скрипта оператором — этот выбор не устраняет: там, где раньше терялись
# все дропы прогона №2.5, всё ещё есть время между окончанием idle-run.sh и
# стартом full_run(), которое ни один автоматический скрипт не видит целиком.
# run-gate.sh критерий 16 измеряет объём этого зазора (по .timestamp снимков),
# если ему передали IDLE_STATE_END/IDLE_METRICS_END — как наблюдение, без
# порога (окно измеряется впервые, порог ставить рано).
full_run() {
    log "==========================================="
    log "ПОЛНЫЙ ЗАПУСК ВСЕХ АТАК"
    log "==========================================="

    run_measurement_prologue || exit 1
    run_counting_control null 0
    run_counting_control idle "${COUNTING_CONTROL_N:-10000}"
    run_counting_control drop "${COUNTING_CONTROL_DROP_N:-300000}"
    run_sqlmap_attacks
    run_bruteforce_attacks
    run_ssrf_attacks
    run_ldap_csrf_attacks
    run_chmod_attack
    run_ssh_keys_positive_control
    run_webshell_script_write_positive_control
    run_log_tamper_attack
    run_setuid_attack
    run_bpf_attack
    run_kmod_attack
    run_dns_long_label_attack
    run_kill_scenario
    run_induced_drop
    get_final_metrics
    generate_final_report

    log "==========================================="
    log "ВСЕ ТЕСТЫ ЗАВЕРШЕНЫ"
    log "==========================================="

    # check_final_gate returning 1 under "set -e" would abort before the log
    # lines above print — capture the result and exit after reporting instead
    # (see P3-16 п.2: exit code must reflect gate failure).
    check_final_gate || exit 1
}

# Главная точка входа
main() {
    cd "$SCRIPT_DIR"

    if [ "$1" = "--interactive" ] || [ "$1" = "-i" ]; then
        interactive_mode
    elif [ "$1" = "--ringbuf-overflow" ]; then
        # 5.9.7b: отдельный, короткий шаг пайплайна — ВНЕ окна замера
        # (baseline→final), поэтому не часть full_run(). Вызывается
        # пайплайном как самостоятельная команда, до или после основного
        # окна, не между get_baseline_metrics и get_final_metrics.
        check_services || exit 1
        run_ringbuf_overflow
    elif [ "$1" = "--dns-fd-reuse-controls" ]; then
        # 5.9.8a (№94, запрет №3/№6): оба контроля запрета №6 — своим шагом,
        # ДО окна замера (preflight, как реплей 5.9.7c и run_ringbuf_overflow
        # 5.9.7b), а не встроены в run_dns_long_label_attack внутри
        # full_run() — их собственные DNS-события/decode-errors не должны
        # засчитываться в idle-час или attack-окно, которые мерят другие
        # критерии.
        check_services || exit 1
        run_dns_fd_reuse_negative_control
        run_dns_cross_thread_positive_control
    elif [ "$1" = "--counting-control" ]; then
        # 5.9.8b/5.9.8c: три режима контроля счётности своим шагом, вне
        # full_run(). Нужен предпрогону: канареечная серия — второй P0 волны
        # (после DNS), и без этого шага она впервые оживает только на минуте
        # ~95 полного замера, внутри окна атак.
        #
        # Маркеры пишутся со СВОИМ TIMESTAMP, а секция 20 гейта ищет
        # counting-control-<mode>-$TIMESTAMP.txt по таймстампу основного
        # прогона — то есть эти маркеры в вердикт замера не попадают и
        # запрет №3 не нарушают. Вердикт остаётся за гейтом; здесь только
        # получение величин.
        check_services || exit 1
        run_counting_control null 0
        run_counting_control idle "${COUNTING_CONTROL_N:-10000}"
        run_counting_control drop "${COUNTING_CONTROL_DROP_N:-300000}"
    elif [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
        echo "Использование: $0 [опции]"
        echo ""
        echo "Опции:"
        echo "  -i, --interactive          Интерактивный режим с меню"
        echo "  --ringbuf-overflow         Только 5.9.7b: переполнение кольца под SIGSTOP, вне окна замера"
        echo "  --dns-fd-reuse-controls    Только 5.9.8a: негативный+позитивный контроль dns_socket_map, вне окна замера"
        echo "  --counting-control         Только 5.9.8b/c: три режима контроля счётности (null/idle/drop), вне окна замера"
        echo "  -h, --help            Показать эту справку"
        echo ""
        echo "Без опций: запуск всех атак последовательно"
        exit 0
    else
        full_run
    fi
}

# Запуск
main "$@"
