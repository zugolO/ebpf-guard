#!/usr/bin/env bash
# Отчёт «сверх обычного гейта» для ЗАМЕРА №2.9.4 (приёмка волны 5.9.4).
#
# Гейт (run-gate.sh) считает 16 критериев, включая переписанные волной 5.9.4:
# крит. 3 (переход в degraded, 5.9.4d), крит. 6 (состав по объединению
# метрики и стора, 5.9.4c), крит. 10 (обе величины, 5.9.4g), крит. 15
# (final_drain_offset, 5.9.4c), крит. 16 (слепое окно, 5.9.4g) и секцию
# 5.9.4h (немые правила). Здесь — только то, чего гейт не считает и что
# таблица постановки №2.9.4 требует поимённо:
#
#   п.1  — «KILL action executed» за весь аптайм при dry_run: true (5.9.4a)
#   п.2  — инвентарь разрушительных правил + ebpf_subversion_unauthorized_caller
#          на системных демонах за idle-час (5.9.4b)
#   п.5  — rootkit_bpf_map_create_suspicious/rootkit_bpf_prog_load_suspicious
#          под атакой (5.9.4e)
#   п.13 — DNS-алерты с process_chain (5.9.4i)
#   плюс наблюдения: enforcement_dryrun_total по действиям, alerts_total у
#   правил, тронутых волной.
#
# Использование:
#   IDLE_OUT=/opt/.../idle-results/idle-2.9.4 ./run-2.9.4-report.sh [RESULTS_DIR] [TIMESTAMP]
#
# Единственный сетевой ресурс, который скрипт трогает, — journalctl (локальный
# журнал). Никаких запросов к агенту: перезапуск на собранных артефактах даёт
# тот же результат (находка №43 — гейт, который приходится звать дважды).

set -u

SETUP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${1:-$SETUP_DIR/attacks/attack-results}"
TIMESTAMP="${2:-}"
IDLE_OUT="${IDLE_OUT:-}"
REPO_DIR="${REPO_DIR:-/opt/ebpf-guard}"
SERVICE_UNIT="${EBPF_GUARD_SERVICE_UNIT:-ebpf-guard-test.service}"
# Начало аптайма агента, записанное пайплайном в момент рестарта. Без него
# журнальные величины «за весь аптайм» пришлось бы угадывать по времени файлов.
AGENT_START_FILE="${AGENT_START_FILE:-/root/agent-start-2.9.4.txt}"

# Go на стенде стоит в /usr/local/go/bin, которого нет в PATH неинтерактивного
# ssh — без этого п.2 молча уходил бы в SKIP (тот же дефект чинился в №2.9.3).
export PATH="$PATH:/usr/local/go/bin"

# Сумма счётчика по одному rule_id. Через awk по метке, а не grep -F по
# префиксу строки: rule_id стоит НЕ первой меткой (namespace/node/pod идут
# раньше) — на №2.9.3 это дало ровный 0 у правила, которое в той же таблице
# выше показывало 122.
rule_counter() {
    local file="$1" rid="$2"
    [ -s "$file" ] || { echo 0; return; }
    awk -v rid="rule_id=\"$rid\"" '
        { gsub(/\r/, "") }
        index($0, "ebpf_guard_alerts_total{") != 1 { next }
        index($0, rid) == 0 { next }
        { s += $NF }
        END { printf "%d", s+0 }' "$file"
}

# Сумма произвольной метрики по всем лейблсетам, у которых совпадает подстрока
# метки (или по всем, если фильтр пуст).
metric_sum() {
    local file="$1" name="$2" label="${3:-}"
    [ -s "$file" ] || { echo 0; return; }
    awk -v n="$name{" -v l="$label" '
        { gsub(/\r/, "") }
        index($0, n) != 1 { next }
        l != "" && index($0, l) == 0 { next }
        { s += $NF }
        END { printf "%d", s+0 }' "$file"
}

if ! command -v jq >/dev/null 2>&1; then
    echo "jq не найден — отчёт №2.9.4 не может быть построен" >&2
    exit 2
fi

if [ -z "$TIMESTAMP" ]; then
    latest_state=$(find "$RESULTS_DIR" -maxdepth 1 -name 'baseline-state-*.json' 2>/dev/null | sort | tail -1)
    if [ -n "$latest_state" ]; then
        TIMESTAMP=$(basename "$latest_state" | sed -E 's/baseline-state-(.*)\.json/\1/')
    fi
fi

final_metrics="$RESULTS_DIR/final-metrics-$TIMESTAMP.txt"
baseline_metrics="$RESULTS_DIR/baseline-metrics-$TIMESTAMP.txt"
final_incidents="$RESULTS_DIR/final-incidents-$TIMESTAMP.json"
idle_metrics_start="${IDLE_OUT:+$IDLE_OUT/metrics-start.txt}"
idle_metrics_end="${IDLE_OUT:+$IDLE_OUT/metrics-end.txt}"

echo "==========================================="
echo "ОТЧЁТ №2.9.4 (сверх гейта): TIMESTAMP=$TIMESTAMP"
echo "  RESULTS_DIR=$RESULTS_DIR"
echo "  IDLE_OUT=${IDLE_OUT:-<не задан>}"
echo "==========================================="

# --- п.1: dry_run обязан гасить kill (5.9.4a, находка №52) -----------------
# На №2.9.3 в журнале было 17 записей «KILL action executed» при dry_run: true —
# агент реально слал SIGKILL. Критерий: ноль записей за весь аптайм,
# enforcement_actions_total{action="kill"} == 0 при ненулевом
# enforcement_dryrun_total{action="kill"} (правило срабатывало, но не убивало).
echo ""
echo "=== п.1: dry_run гасит kill (цель: 0 убийств, но ненулевой dryrun-счётчик) ==="
agent_start=""
[ -s "$AGENT_START_FILE" ] && agent_start=$(head -1 "$AGENT_START_FILE")
if command -v journalctl >/dev/null 2>&1; then
    if [ -n "$agent_start" ]; then
        journal_args=(--since "$agent_start")
        echo "  окно журнала: с $agent_start (рестарт агента, записан пайплайном)"
    else
        journal_args=(--boot)
        echo "  окно журнала: --boot ($AGENT_START_FILE не найден — точка отсчёта не зафиксирована)"
    fi
    kill_done=$(journalctl -u "$SERVICE_UNIT" "${journal_args[@]}" 2>/dev/null | grep -c "KILL action executed" || true)
    kill_dry=$(journalctl -u "$SERVICE_UNIT" "${journal_args[@]}" 2>/dev/null | grep -c "KILL action suppressed by dry_run" || true)
    blk_dry=$(journalctl -u "$SERVICE_UNIT" "${journal_args[@]}" 2>/dev/null | grep -c "action suppressed by dry_run" || true)
    echo "  записей «KILL action executed»: $kill_done (на №2.9.3 было 17)"
    echo "  записей «KILL action suppressed by dry_run»: $kill_dry; всех подавленных действий: $blk_dry"
    if [ "$kill_done" -eq 0 ]; then
        echo "  PASS: ни одного выполненного KILL за аптайм"
    else
        echo "  FAIL: $kill_done выполненных KILL при dry_run: true — находка №52 не закрыта"
    fi
else
    echo "  SKIP: journalctl недоступен"
fi
if [ -s "$final_metrics" ]; then
    act_kill=$(metric_sum "$final_metrics" ebpf_guard_enforcement_actions_total 'action="kill"')
    dry_kill=$(metric_sum "$final_metrics" ebpf_guard_enforcement_dryrun_total 'action="kill"')
    echo "  enforcement_actions_total{action=\"kill\"}=$act_kill (цель 0), enforcement_dryrun_total{action=\"kill\"}=$dry_kill"
    if [ "$act_kill" -eq 0 ] && [ "$dry_kill" -gt 0 ]; then
        echo "  PASS: правило срабатывало ($dry_kill раз) и ни разу не убило"
    elif [ "$act_kill" -eq 0 ]; then
        echo "  наблюдение: убийств нет, но и dryrun-счётчик нулевой — kill-правило за прогон не срабатывало вовсе,"
        echo "              то есть критерий выполнен формально и НЕ доказывает, что гейт работает (нужен сценарий)"
    else
        echo "  FAIL: enforcement_actions_total{kill}=$act_kill при dry_run: true"
    fi
    echo "  все действия по типам (actions_total / dryrun_total):"
    for a in kill throttle block lsm_block networkpolicy; do
        printf '    %-14s %6s / %-6s\n' "$a" \
            "$(metric_sum "$final_metrics" ebpf_guard_enforcement_actions_total "action=\"$a\"")" \
            "$(metric_sum "$final_metrics" ebpf_guard_enforcement_dryrun_total "action=\"$a\"")"
    done
else
    echo "  SKIP: $final_metrics не собран — счётчики enforcement не проверены"
fi

# --- п.2: инвентарь разрушительных правил (5.9.4b, находка №53) ------------
# Постановка требует «инвентарь напечатан в отчёте поимённо». Машинная проверка
# живёт в go-тесте; здесь печатается её вывод, чтобы результат был в протоколе
# прогона, а не только в чьей-то памяти.
echo ""
echo "=== п.2: инвентарь правил с разрушительным действием (цель: 0 без условия на аргумент) ==="
if [ -d "$REPO_DIR" ] && command -v go >/dev/null 2>&1; then
    ( cd "$REPO_DIR" && go test -count=1 -v -run 'TestDestructiveRulesInventory_RepoRules|TestExclusionsCollidingWithAttackerComms_RepoRules' ./internal/correlator/ 2>&1 ) \
        | grep -E 'разрушительных|правил проверено|^(ok|FAIL|--- )' | sed 's/^/    /'
else
    echo "  SKIP: нет $REPO_DIR или go в PATH"
fi

echo "  ebpf_subversion_unauthorized_caller за idle-час (цель 0 — whitelist демонов, 5.9.4b):"
if [ -n "$idle_metrics_start" ] && [ -s "$idle_metrics_start" ] && [ -s "$idle_metrics_end" ]; then
    us=$(rule_counter "$idle_metrics_start" ebpf_subversion_unauthorized_caller)
    ue=$(rule_counter "$idle_metrics_end" ebpf_subversion_unauthorized_caller)
    ud=$(( ue - us ))
    if [ "$ud" -eq 0 ]; then
        echo "    PASS: 0 срабатываний за idle-час"
    else
        echo "    FAIL: $ud срабатываний за idle-час — whitelist демонов не покрыл источник, см. DEBT в rules/ebpf-subversion.yaml"
    fi
else
    echo "    SKIP: нет срезов idle-метрик"
fi

# --- п.5: rootkit_bpf_* под атакой (5.9.4e, находка №56) -------------------
# 5.9.4e заменила comm-whitelist на условие по команде bpf(2): arg0=0
# (BPF_MAP_CREATE) и arg0=5 (BPF_PROG_LOAD). Позитивный контроль есть только у
# map_create (шаг `bpftool map create` в run_bpf_attack); у prog_load его нет —
# открытый вопрос 5.9.4e (1), нужен .bpf.o-фикстур. Печатаем оба, чтобы «ноль»
# у prog_load читался как известный пробел сценария, а не как провал правила.
echo ""
echo "=== п.5: rootkit_bpf_* под атакой (5.9.4e) ==="
if [ -s "$baseline_metrics" ] && [ -s "$final_metrics" ]; then
    for rid in rootkit_bpf_map_create_suspicious rootkit_bpf_prog_load_suspicious; do
        b=$(rule_counter "$baseline_metrics" "$rid")
        f=$(rule_counter "$final_metrics" "$rid")
        d=$(( f - b ))
        case "$rid" in
            rootkit_bpf_map_create_suspicious)
                if [ "$d" -gt 0 ]; then
                    echo "  PASS: $rid +$d (позитивный контроль 'bpftool map create' сработал)"
                else
                    echo "  FAIL: $rid +0 — шаг 'bpftool map create' есть, а правило не поднялось (проверить arg0=0 и права bpftool)"
                fi
                ;;
            *)
                echo "  наблюдение: $rid +$d — позитивного контроля на BPF_PROG_LOAD в наборе НЕТ"
                echo "              (открытый вопрос 5.9.4e (1): нужен целевой .bpf.o; ноль здесь ничего не доказывает)"
                ;;
        esac
    done
    echo "  для сравнения — ebpf_subversion_* под атакой:"
    for rid in ebpf_subversion_detach_nonroot ebpf_subversion_unauthorized_caller; do
        b=$(rule_counter "$baseline_metrics" "$rid"); f=$(rule_counter "$final_metrics" "$rid")
        printf '    %-40s +%d\n' "$rid" "$(( f - b ))"
    done
else
    echo "  SKIP: нет baseline/final метрик"
fi

# --- п.13: DNS-алерты с process_chain (5.9.4i) -----------------------------
# ВАЖНО про источник: /api/v1/alerts не отдаёт process_chain вовсе — цепочка
# живёт только в инцидентах (это уже стоило одного неверного вывода на №2.9.3).
# Поэтому считаем по final-incidents: инциденты, чьи правила пришли из
# DNS-набора, и есть ли у них непустая цепочка. Нулевой знаменатель печатается
# как «не измерялось», а не как 100%.
echo ""
echo "=== п.13: DNS-инциденты с process_chain (5.9.4i; до правки ppid у dns-событий не было) ==="
if [ ! -s "$final_incidents" ] || ! jq -e 'type == "array"' "$final_incidents" >/dev/null 2>&1; then
    echo "  SKIP: $final_incidents не собран или не JSON-массив"
else
    dns_rule_ids=$(grep -h -oE '^\s+- id:\s*\S+' "$REPO_DIR"/rules/dns-threats.yaml 2>/dev/null | awk '{print $NF}' | sort -u)
    if [ -z "$dns_rule_ids" ]; then
        echo "  SKIP: не удалось прочитать rules/dns-threats.yaml — список DNS-правил неизвестен"
    else
        dns_json=$(printf '%s\n' "$dns_rule_ids" | jq -R . | jq -s .)
        jq -r --argjson dns "$dns_json" '
          [.[] | select(((.rule_ids // [.rule_id]) | map(select(. != null))) as $ids
                        | ($ids | any(. as $r | $dns | index($r))))] as $d
          | ($d | length) as $t
          | ($d | map(select((.process_chain // []) | length > 0)) | length) as $wc
          | if $t == 0 then
              "  не измерялось: ни одного инцидента по правилам dns-threats.yaml за прогон"
            else
              "  DNS-инцидентов: \($t), с непустым process_chain: \($wc) (\(100*$wc/$t|floor)%) — цель 100%"
            end
        ' "$final_incidents"
    fi
    echo "  для справки — dns-события за прогон (коллектор жив?):"
    grep -hE '^ebpf_guard_events_total\{[^}]*type="dns"' "$final_metrics" 2>/dev/null | sed 's/^/    /' | head -3
fi

# --- наблюдение: правила, тронутые волной 5.9.4, по обеим сторонам --------
echo ""
echo "=== наблюдение: правила волны 5.9.4 (idle-дельта / attack-дельта) ==="
for rid in ebpf_subversion_unauthorized_caller ebpf_subversion_detach_nonroot \
           rootkit_bpf_map_create_suspicious rootkit_bpf_prog_load_suspicious; do
    idle_d="n/a"
    if [ -n "$idle_metrics_start" ] && [ -s "$idle_metrics_start" ] && [ -s "$idle_metrics_end" ]; then
        idle_d=$(( $(rule_counter "$idle_metrics_end" "$rid") - $(rule_counter "$idle_metrics_start" "$rid") ))
    fi
    atk_d="n/a"
    if [ -s "$baseline_metrics" ] && [ -s "$final_metrics" ]; then
        atk_d=$(( $(rule_counter "$final_metrics" "$rid") - $(rule_counter "$baseline_metrics" "$rid") ))
    fi
    printf '  %-42s idle: %-6s attack: %s\n' "$rid" "$idle_d" "$atk_d"
done

echo ""
echo "=== КОНЕЦ ОТЧЁТА №2.9.4 ==="
