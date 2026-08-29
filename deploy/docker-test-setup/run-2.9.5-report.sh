#!/usr/bin/env bash
# Отчёт «сверх обычного гейта» для ЗАМЕРА №2.9.5 (приёмка волны 5.9.5).
#
# Гейт (run-gate.sh) теперь считает 17 критериев: 16 унаследованных от 5.9.4
# (крит. 3 — переход в degraded, 5.9.4d/5.9.5b; крит. 6 — состав по
# объединению метрики и стора, 5.9.4c; крит. 10 — обе величины, 5.9.4g;
# крит. 15 — final_drain_offset, 5.9.4c; крит. 16 — слепое окно, 5.9.4g;
# секция 5.9.4h — немые правила) плюс новый крит. 17 (kill-сценарий парный,
# 5.9.5a). П.1 этого отчёта (ниже) стало ДУБЛЁМ крит. 17 — гейт теперь
# требует ту же пару машинно и проваливает прогон, если она не сходится;
# здесь она остаётся для протокола (человеко-читаемый журнал-контекст), но
# источником истины по этому пункту постановки №2.9.5 является run-gate.sh.
#
# Что гейт не считает и что таблица постановки №2.9.5 требует поимённо:
#
#   п.1  — «KILL action executed» за весь аптайм при dry_run: true (5.9.4a;
#          машинно — крит. 17 гейта, 5.9.5a)
#   п.2  — инвентарь разрушительных правил + ebpf_subversion_unauthorized_caller
#          на системных демонах за idle-час (5.9.4b)
#   п.5  — rootkit_bpf_map_create_suspicious/rootkit_bpf_prog_load_suspicious
#          под атакой (5.9.4e; позитивный контроль на prog_load — 5.9.5j,
#          gate-canary.bpf.c, компилируется на стенде и грузится через bpftool)
#   п.13 — DNS-алерты с process_chain (5.9.4i)
#   п.10 — метки времени idle-алертов не совпадают с моментами срезов (5.9.5f,
#          находка №68: было 26/48 наведены через systemctl show → PID 1 → /proc)
#   плюс наблюдения: enforcement_dryrun_total по действиям, alerts_total у
#   правил, тронутых волной.
#
# Использование:
#   IDLE_OUT=/opt/.../idle-results/idle-2.9.5 ./run-2.9.5-report.sh [RESULTS_DIR] [TIMESTAMP]
#
# Единственный сетевой ресурс, который скрипт трогает, — journalctl (локальный
# журнал). Никаких запросов к агенту: перезапуск на собранных артефактах даёт
# тот же результат (находка №43 — гейт, который приходится звать дважды).

set -u

SETUP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${1:-$SETUP_DIR/attacks/attack-results}"
TIMESTAMP="${2:-}"
IDLE_OUT="${IDLE_OUT:-}"
# 5.9.9f (№104): заголовок и подвал отчёта раньше были литералом "№2.9.5",
# хотя этот же скрипт — единственный запасной вариант отчёта на замерах
# №2.9.6…№2.9.9 (пока для них не заведён собственный run-2.9.N-report.sh,
# см. фолбэк в run-2.9.N-pipeline.sh) — заголовок печатал неверный номер
# замера на каждом из них. REPORT_LABEL передаётся пайплайном; без него —
# прежнее поведение (текст этого скрипта, "2.9.5").
REPORT_LABEL="${REPORT_LABEL:-2.9.5}"
REPO_DIR="${REPO_DIR:-/opt/ebpf-guard}"
SERVICE_UNIT="${EBPF_GUARD_SERVICE_UNIT:-ebpf-guard-test.service}"
# Начало аптайма агента, записанное пайплайном в момент рестарта. Без него
# журнальные величины «за весь аптайм» пришлось бы угадывать по времени файлов.
AGENT_START_FILE="${AGENT_START_FILE:-/root/agent-start-2.9.5.txt}"

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
    echo "jq не найден — отчёт №${REPORT_LABEL} не может быть построен" >&2
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
echo "ОТЧЁТ №${REPORT_LABEL} (сверх гейта): TIMESTAMP=$TIMESTAMP"
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

# --- п.5: rootkit_bpf_* под атакой (5.9.4e, находка №56; долг 5.9.4e (1)
# закрыт 5.9.5j) ------------------------------------------------------------
# 5.9.4e заменила comm-whitelist на условие по команде bpf(2): arg0=0
# (BPF_MAP_CREATE) и arg0=5 (BPF_PROG_LOAD). Оба теперь имеют позитивный
# контроль в run_bpf_attack: map_create через `bpftool map create`,
# prog_load с 5.9.5j — через компиляцию и `bpftool prog load` минимального
# фикстура (attacks/fixtures/gate-canary.bpf.c). Если clang на стенде не
# собрал fixture (нет BPF-таргета) или bpftool недоступен, run_bpf_attack
# печатает warn, а не молчит — тогда +0 здесь означает «шаг пропущен», а не
# «правило не сработало»; см. лог атак за строкой про gate-canary.
echo ""
echo "=== п.5: rootkit_bpf_* под атакой (5.9.4e/5.9.5j) ==="
if [ -s "$baseline_metrics" ] && [ -s "$final_metrics" ]; then
    for rid in rootkit_bpf_map_create_suspicious rootkit_bpf_prog_load_suspicious; do
        b=$(rule_counter "$baseline_metrics" "$rid")
        f=$(rule_counter "$final_metrics" "$rid")
        d=$(( f - b ))
        label="bpftool map create"
        [ "$rid" = "rootkit_bpf_prog_load_suspicious" ] && label="bpftool prog load (5.9.5j, gate-canary.bpf.c)"
        if [ "$d" -gt 0 ]; then
            echo "  PASS: $rid +$d (позитивный контроль '$label' сработал)"
        else
            echo "  FAIL: $rid +0 — шаг '$label' есть, а правило не поднялось (проверить arg0/права bpftool, либо лог атак на warn о пропуске шага)"
        fi
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

# --- п.10: idle-алерты не наведены срезами (5.9.5f/5.9.9.F.7b, №68/№174) ---
# Механизм №68: `systemctl show` на каждом срезе idle-run.sh шёл мимо дерева
# харнесса (не потомок root_pid — говорит с PID 1 по dbus), поэтому
# observer_exclude его не ловил по построению; PID 1 в ответ читал /proc, и
# это ловили mitre_sandbox_detect_proc_read/container_escape_init_proc с
# метками времени, совпадающими с моментами срезов ПОСЕКУНДНО. 5.9.5f убрал
# systemctl show из цикла срезов (idle-run.sh теперь читает MainPID один раз
# при старте окна).
#
# 5.9.9.F.7b (находка №174, P1): посекундное совпадение — само по себе НЕ
# достаточное условие. При частоте алертов ~585 за idle-час и 13 срезах
# случайное совпадение матожидается на уровне ~1.95 события (формула ниже) —
# ЛЮБОЕ шумное правило рано или поздно попадёт на секунду среза чисто по
# теории вероятностей, и старая формула (любой матч = FAIL) валила это как
# рецидив механизма №68, хотя совпавшие алерты принадлежали
# drift_exec_from_system_bin/sshd — правилу, которое №68 не производил и не
# мог производить (снят найденной на №2.9.9.F.6 проверкой: 3 совпадения, все
# drift_exec_from_system_bin/sshd, ни одного правила сигнатуры №68).
# Критерий теперь падает только тогда, когда совпавший алерт принадлежит
# САМОЙ сигнатуре №68 — mitre_sandbox_detect_proc_read/container_escape_init_proc
# (то, что механизм №68 и производил, actor pid 1). Фон печатается числом
# (наблюдённое совпадений всех правил + матожидание случайного совпадения),
# а не выводится из вердикта.
echo ""
echo "=== п.10: idle-алерты сигнатуры №68 не наведены срезами (5.9.9.F.7b, №174) ==="
idle_alerts_start="${IDLE_OUT:+$IDLE_OUT/alerts-start.json}"
idle_alerts_end="${IDLE_OUT:+$IDLE_OUT/alerts-end.json}"
idle_timeseries="${IDLE_OUT:+$IDLE_OUT/timeseries.tsv}"
if [ -n "$IDLE_OUT" ] && [ -s "$idle_alerts_start" ] && [ -s "$idle_alerts_end" ] && [ -s "$idle_timeseries" ]; then
    # timeseries.tsv пишет метку среза как YYYYMMDDTHHMMSSZ (idle-run.sh:
    # date -u +%Y%m%dT%H%M%SZ) — переводим в ISO с разделителями, чтобы
    # сравнивать напрямую с секундной частью timestamp алерта.
    snapshot_seconds=$(tail -n +2 "$idle_timeseries" | awk -F'\t' '
        {
            t=$1
            y=substr(t,1,4); mo=substr(t,5,2); d=substr(t,7,2)
            h=substr(t,10,2); mi=substr(t,12,2); s=substr(t,14,2)
            printf "%s-%s-%sT%s:%s:%sZ\n", y,mo,d,h,mi,s
        }' | sort -u)
    num_slices=$(printf '%s\n' "$snapshot_seconds" | grep -c . || true)
    new_only=$(comm -23 \
        <(jq -r '.[].id' "$idle_alerts_end" 2>/dev/null | sort -u) \
        <(jq -r '.[].id' "$idle_alerts_start" 2>/dev/null | sort -u))
    total_new=$(printf '%s\n' "$new_only" | grep -c . || true)
    if [ "$total_new" -eq 0 ]; then
        echo "  SKIP: нет новых алертов за idle-окно (alerts-end == alerts-start)"
    else
        matched_any=0
        matched_sig68=0
        sig68_ids=""
        matched_seconds=""
        while IFS= read -r id; do
            [ -z "$id" ] && continue
            row=$(jq -r --arg id "$id" '.[] | select(.id==$id) | [.timestamp, .rule_id] | @tsv' \
                "$idle_alerts_end" 2>/dev/null | head -1)
            ts_raw=$(cut -f1 <<< "$row")
            rid=$(cut -f2 <<< "$row")
            [ -z "$ts_raw" ] && continue
            ts_sec=$(sed -E 's/\.[0-9]+Z$/Z/' <<< "$ts_raw")
            if printf '%s\n' "$snapshot_seconds" | grep -qF "$ts_sec"; then
                matched_any=$((matched_any + 1))
                matched_seconds="$matched_seconds
$ts_sec"
                if [ "$rid" = "mitre_sandbox_detect_proc_read" ] || [ "$rid" = "container_escape_init_proc" ]; then
                    matched_sig68=$((matched_sig68 + 1))
                    sig68_ids="$sig68_ids $id($rid)"
                fi
            fi
        done <<< "$new_only"
        secs_with_alerts=$(printf '%s\n' "$new_only" | while IFS= read -r id; do
            [ -z "$id" ] && continue
            jq -r --arg id "$id" '.[] | select(.id==$id) | .timestamp' "$idle_alerts_end" 2>/dev/null \
                | head -1 | sed -E 's/\.[0-9]+Z$/Z/'
        done | sort -u | grep -c . || true)
        expected=$(awk -v s="$secs_with_alerts" -v n="$num_slices" \
            'BEGIN{ printf "%.2f", s*n/3600 }')
        echo "  новых idle-алертов: $total_new, срезов: $num_slices, секунд с алертами: $secs_with_alerts"
        echo "  матожидание случайного совпадения (секунд_с_алертами × срезов / 3600): $expected"
        echo "  совпало с секундой среза (любое правило, фон): $matched_any"
        echo "  совпало с секундой среза (правила сигнатуры №68 — mitre_sandbox_detect_proc_read/container_escape_init_proc): $matched_sig68"
        if [ "$matched_sig68" -eq 0 ]; then
            echo "  PASS: ни один idle-алерт сигнатуры №68 не совпал с моментом среза (совпадения фона — $matched_any, ожидаемо при $expected случайных)"
        else
            echo "  FAIL: $matched_sig68 idle-алертов сигнатуры №68 наведены срезами — механизм №68 не устранён ($sig68_ids)"
        fi
    fi
else
    echo "  SKIP: нет alerts-start.json/alerts-end.json/timeseries.tsv в \$IDLE_OUT"
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
echo "=== КОНЕЦ ОТЧЁТА №${REPORT_LABEL} ==="
