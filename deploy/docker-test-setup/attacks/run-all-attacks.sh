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

# Запуск SQLMap атак
run_sqlmap_attacks() {
    log "==========================================="
    log "ЗАПУСК SQLMAP АТАК"
    log "==========================================="

    if [ -f "$SCRIPT_DIR/sqlmap-attacks.sh" ]; then
        bash "$SCRIPT_DIR/sqlmap-attacks.sh" || warn "SQLMap атаки завершились с ошибками"
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
        bash "$SCRIPT_DIR/bruteforce-attacks.sh" || warn "Brute force атаки завершились с ошибками"
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
        bash "$SCRIPT_DIR/ssrf-attacks.sh" || warn "SSRF атаки завершились с ошибками"
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
        bash "$SCRIPT_DIR/ldap-csrf-attacks.sh" || warn "LDAP/CSRF атаки завершились с ошибками"
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

    chmod 755 "$canary_file" 2>/dev/null || warn "chmod на $canary_file завершился с ошибкой"
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
run_setuid_attack() {
    log "==========================================="
    log "ЗАПУСК SETUID АТАКИ (5.9.2b, sigma_setuid_syscall)"
    log "==========================================="

    if command -v python3 &> /dev/null; then
        # setuid(getuid()) — no-op privilege change, invokes syscall 105
        # directly without altering the process's actual privileges.
        python3 -c 'import os; os.setuid(os.getuid())' 2>/dev/null \
            && log "setuid(getuid()) выполнен — ожидается срабатывание sigma_setuid_syscall" \
            || warn "setuid-атака (5.9.2b) завершилась с ошибкой или пропущена"
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
    dig +short +time=2 +tries=1 "$long_qname" >/dev/null 2>&1 || \
        warn "dig вернул ненулевой код на $long_qname — запрос мог не уйти в сеть; проверить резолвер стенда (шаг не валит прогон, но критерий 5.9.5c останется без входа)"
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
        insmod "$bogus_module" >/dev/null 2>&1 \
            || log "insmod $bogus_module отвергнут ядром (ожидаемо, ENOEXEC) — сисколл finit_module(313) вызван"
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
        python3 - >/dev/null 2>&1 <<'PYEOF' || rc=$?
import ctypes
libc = ctypes.CDLL(None, use_errno=True)
buf = ctypes.create_string_buffer(b"\x00" * 64)
libc.syscall(175, buf, ctypes.c_size_t(64), b"")             # init_module
libc.syscall(176, b"ebpf_guard_canary_mod", ctypes.c_int(0)) # delete_module
PYEOF
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
    echo "ebpf-guard attack canary $(date -Iseconds)" | tee -a "$canary_log" >/dev/null 2>&1 \
        || warn "запись в $canary_log завершилась с ошибкой"
    : > "$canary_log" 2>/dev/null || warn "усечение $canary_log завершилось с ошибкой"
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
# `find /usr` от отдельного, вне-дерева процесса — то дало бы алерты вне
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

    log "старт всплеска: find /usr -type f | head -200000 (в дереве харнесса, наблюдательный root не меняется)"
    ( find /usr -type f 2>/dev/null | head -200000 >/dev/null ) &
    local burst_pid=$!
    if kill -0 "$burst_pid" 2>/dev/null; then
        executed=1
    fi

    local i=0
    while kill -0 "$burst_pid" 2>/dev/null && [ "$i" -lt 30 ]; do
        # `|| true` на обеих ветках: под `set -e` и неудачный curl (агент
        # занят/недоступен под всплеском — а это ровно ожидаемое состояние),
        # и падение jq на неполном JSON обрывали бы прогон прямо в момент
        # наведённого дропа.
        st=$(curl -s -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/health" 2>/dev/null \
            | jq -r '.status // empty' 2>/dev/null || true)
        if [ "$st" = "degraded" ]; then
            degraded_seen=1
            log "  /health status=degraded во время всплеска (опрос №$i)"
        fi
        sleep 1
        i=$(( i + 1 ))
    done
    wait "$burst_pid" 2>/dev/null || true

    {
        echo "executed=$executed"
        echo "degraded_seen=$degraded_seen"
    } > "$marker"

    if [ "$degraded_seen" -eq 1 ]; then
        log "PASS (наблюдение): переход в degraded зафиксирован во время наведённого дропа — критерий 3 получит вход"
    elif [ "$executed" -eq 1 ]; then
        warn "всплеск исполнен, но status=degraded за время опроса не замечен — критерий 3 останется без входа в этом прогоне"
    else
        warn "наведённый дроп не запустился (find/head недоступны?) — критерий 3 останется без входа"
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
    echo "6. Только canary-атаки (chmod 5.9.1e + log tamper 5.9.1d в + setuid/bpf/kmod 5.9.2b + dns long-label 5.9.5c)"
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
                check_services || continue
                get_baseline_metrics
                run_sqlmap_attacks
                run_bruteforce_attacks
                run_ssrf_attacks
                run_ldap_csrf_attacks
                run_chmod_attack
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

    check_services || exit 1
    get_baseline_metrics
    run_sqlmap_attacks
    run_bruteforce_attacks
    run_ssrf_attacks
    run_ldap_csrf_attacks
    run_chmod_attack
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
    elif [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
        echo "Использование: $0 [опции]"
        echo ""
        echo "Опции:"
        echo "  -i, --interactive    Интерактивный режим с меню"
        echo "  -h, --help           Показать эту справку"
        echo ""
        echo "Без опций: запуск всех атак последовательно"
        exit 0
    else
        full_run
    fi
}

# Запуск
main "$@"
