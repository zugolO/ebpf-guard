#!/usr/bin/env bash
# Отчёт «сверх обычного гейта» для ЗАМЕРА №2.9.3 (приёмка волны 5.9.3).
#
# Зачем отдельный скрипт, а не строки внутри run-2.9.3-pipeline.sh. Постановка
# замера (plan.md, «ЗАМЕР №2.9.3») требует девять величин, из которых гейт
# считает только пять (крит. 10, темп детекта, recall, состав детекта, слепое
# окно). Остальные четыре на №2.9.2 снимались руками из idle-run.log и из
# final-incidents-*.json — то есть в момент, когда прогон уже закончился и
# переспросить нечего. Здесь они считаются машиной и по тем же артефактам,
# что уже лежат на диске: скрипт можно перезапустить на собранных данных
# сколько угодно раз, ничего не меряя заново (ровно та проблема, из-за которой
# на №2.9.2 гейт пришлось вызывать дважды — находка №43).
#
# Использование:
#   IDLE_OUT=/opt/.../idle-results/idle-2.9.3 ./run-2.9.3-report.sh [RESULTS_DIR] [TIMESTAMP]
#
# Ничего не запрашивает по сети: только jq/awk по файлам. Значит, безопасен
# внутри и после измеряемого окна — ни одного лишнего процесса в поле зрения
# агента (гигиена замеров, 5.9a/observer_tree).

set -u

SETUP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${1:-$SETUP_DIR/attacks/attack-results}"
TIMESTAMP="${2:-}"
IDLE_OUT="${IDLE_OUT:-}"
REPO_DIR="${REPO_DIR:-/opt/ebpf-guard}"

# Go на стенде стоит в /usr/local/go/bin, которого нет в PATH неинтерактивного
# ssh — без этого п.5 молча уходил в SKIP.
export PATH="$PATH:/usr/local/go/bin"

# Сумма счётчика ebpf_guard_alerts_total по одному rule_id. Через awk по метке,
# а не grep -F по префиксу строки: rule_id стоит НЕ первой меткой
# (namespace/node/pod идут раньше), и `grep -F 'alerts_total{rule_id="X"'`
# не матчит ничего — на дымовом прогоне отчёта это дало ровный 0 у правила,
# которое в той же таблице выше показывало 122.
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

if ! command -v jq >/dev/null 2>&1; then
    echo "jq не найден — отчёт №2.9.3 не может быть построен" >&2
    exit 2
fi

if [ -z "$TIMESTAMP" ]; then
    latest_state=$(find "$RESULTS_DIR" -maxdepth 1 -name 'baseline-state-*.json' 2>/dev/null | sort | tail -1)
    if [ -n "$latest_state" ]; then
        TIMESTAMP=$(basename "$latest_state" | sed -E 's/baseline-state-(.*)\.json/\1/')
    fi
fi

final_incidents="$RESULTS_DIR/final-incidents-$TIMESTAMP.json"
idle_metrics_start="${IDLE_OUT:+$IDLE_OUT/metrics-start.txt}"
idle_metrics_end="${IDLE_OUT:+$IDLE_OUT/metrics-end.txt}"

echo "==========================================="
echo "ОТЧЁТ №2.9.3 (сверх гейта): TIMESTAMP=$TIMESTAMP"
echo "  RESULTS_DIR=$RESULTS_DIR"
echo "  IDLE_OUT=${IDLE_OUT:-<не задан>}"
echo "==========================================="

# --- п.3: алертов за idle-час, цель <= 150 (критерий 5.9.3b) --------------
# Считается дельтой ebpf_guard_alerts_total между срезами idle-run.sh, тем же
# способом, что критерий 6 гейта считает состав, — а НЕ длиной alerts-end.json:
# стор режется по store.min_severity, и на №2.9 это уже давало расхождение.
echo ""
echo "=== п.3: алертов за idle-час (цель <= 150; было 1993 на №2.9.2) ==="
if [ -z "$idle_metrics_start" ] || [ ! -s "$idle_metrics_start" ] || [ ! -s "$idle_metrics_end" ]; then
    echo "  SKIP: нет $idle_metrics_start / $idle_metrics_end (IDLE_OUT не задан или idle-run не отработал)"
else
    idle_delta=$(awk -F'[{}", ]+' '
        { gsub(/\r/, "") }
        index($0, "ebpf_guard_alerts_total{") != 1 { next }
        { if (FILENAME == ARGV[1]) s += $NF; else e += $NF }
        END { printf "%d", e - s }' "$idle_metrics_start" "$idle_metrics_end")
    if [ "$idle_delta" -le 150 ]; then
        echo "  PASS: $idle_delta алертов за idle-час (<= 150)"
    else
        echo "  FAIL: $idle_delta алертов за idle-час (требуется <= 150)"
    fi
    echo "  разбивка по правилам (дельта alerts_total, топ-20):"
    awk -F'[{}", ]+' '
        function rule_id(   i, rid) {
            for (i = 1; i <= NF; i++) if ($i ~ /^rule_id=?$/) { rid = $(i+1); break }
            return rid
        }
        { gsub(/\r/, "") }
        index($0, "ebpf_guard_alerts_total{") != 1 { next }
        { rid = rule_id(); if (rid == "") next
          if (FILENAME == ARGV[1]) s[rid] += $NF; else { e[rid] += $NF; seen[rid] = 1 } }
        END { for (r in seen) { d = e[r] - (s[r]+0); if (d > 0) printf "%8d  %s\n", d, r } }
    ' "$idle_metrics_start" "$idle_metrics_end" | sort -rn | head -20 | sed 's/^/    /'
fi

# --- п.4: incidents_total{verdict="attack"} за idle, цель 0 (закрывает №48) --
echo ""
echo "=== п.4: incidents_total{verdict=\"attack\"} за idle-час (цель 0; было 1) ==="
if [ -z "$idle_metrics_start" ] || [ ! -s "$idle_metrics_start" ] || [ ! -s "$idle_metrics_end" ]; then
    echo "  SKIP: нет срезов idle-метрик"
else
    for v in attack suspicious; do
        vs=$(grep -F "ebpf_guard_incidents_total{verdict=\"$v\"}" "$idle_metrics_start" 2>/dev/null | awk '{print $NF}' | head -1)
        ve=$(grep -F "ebpf_guard_incidents_total{verdict=\"$v\"}" "$idle_metrics_end" 2>/dev/null | awk '{print $NF}' | head -1)
        d=$(( ${ve:-0} - ${vs:-0} ))
        if [ "$v" = attack ]; then
            if [ "$d" -eq 0 ]; then echo "  PASS: attack-инцидентов за idle: 0"
            else echo "  FAIL: attack-инцидентов за idle: $d (требуется 0; см. находку №48 и кластер fwupd, волна 6)"; fi
        else
            echo "  наблюдение: suspicious за idle: $d"
        fi
    done
fi

# --- п.5: контекстно-пустые syscall-правила, цель <= 5 поимённо -------------
# Машинная проверка живёт в go-тесте (RuleEngine.ContextEmptySyscallRules,
# 5.9.3c). Постановка разрешает закрыть её кодом до прогона — но тогда её
# результат должен быть в отчёте прогона, а не только в чьей-то памяти.
echo ""
echo "=== п.5: контекстно-пустых syscall-правил (цель <= 5, поимённо) ==="
if [ -d "$REPO_DIR" ] && command -v go >/dev/null 2>&1; then
    ( cd "$REPO_DIR" && go test -count=1 -run 'TestContextEmptySyscallRules' ./internal/correlator/ 2>&1 ) \
        | sed 's/^/    /'
else
    echo "  SKIP: нет $REPO_DIR или go в PATH"
fi

# --- п.1/п.2: process_chain по инцидентам прогона ---------------------------
# Крит. 10 в гейте печатает долю и вердикт; здесь — то, что гейт не печатает:
# состав цепочек и признаки риска №2 (усечение comm до 15 символов,
# скобочные имена ядерных/systemd-потоков) и риска №3 (100% = тавтология).
echo ""
echo "=== п.1/п.2: process_chain — состав, а не только доля ==="
if [ ! -s "$final_incidents" ] || ! jq -e 'type == "array"' "$final_incidents" >/dev/null 2>&1; then
    echo "  SKIP: $final_incidents не собран или не JSON-массив"
else
    jq -r '
      (length) as $t
      | ([.[] | select((.process_chain // []) | length == 0)] | length) as $nochain
      | ([.[] | select((.alert_count // 1) > 1)] | length) as $multi
      | ([.[] | select((.alert_count // 1) > 1 and ((.process_chain // []) | length > 0))] | length) as $multichain
      | ([.[] | select(.verdict == "attack")] | length) as $atk
      | ([.[] | select(.verdict == "attack" and ((.process_chain // []) | length > 0))] | length) as $atkchain
      | "  инцидентов всего: \($t)",
        "  без цепочки: \($nochain) (\(if $t > 0 then (100*$nochain/$t|floor|tostring) else "n/a" end)%) — п.2, на №2.9.2 было 34 из 51",
        "  многоалертных: \($multi), из них с цепочкой: \($multichain) — п.1, цель >= 80%",
        "  attack-инцидентов: \($atk), из них с цепочкой: \($atkchain) — должно быть 100%"
    ' "$final_incidents"

    echo "  длина цепочки (риск №3: если все цепочки длиной 1, доля 100% ничего не различает):"
    jq -r '[.[] | (.process_chain // []) | length] | group_by(.) | map("\(.[0]) хопов: \(length)") | .[]' \
        "$final_incidents" | sed 's/^/    /'

    echo "  различных comm в цепочке (тот же риск №3 с другой стороны):"
    jq -r '[.[] | select((.process_chain // []) | length > 0) | (.process_chain | unique | length)]
           | group_by(.) | map("\(.[0]) различных comm: \(length)") | .[]' \
        "$final_incidents" | sed 's/^/    /'

    # Риск №2 постановки: списки comm/parent_comm в правилах волны 5.9.3
    # написаны по ожидаемым именам, а ядро отдаёт 15 значащих символов и
    # скобочные имена. Проверяем не «совпало ли», а какие значения реально
    # пришли — сверять списки правил надо против ЭТОГО, а не против ожиданий.
    echo "  риск №2 — фактические comm в цепочках (усечённые до 15 символов и скобочные помечены):"
    jq -r '[.[] | (.process_chain // [])[]] | group_by(.) | map({c: .[0], n: length})
           | sort_by(-.n) | .[] | "\(.n)\t\(.c)"' "$final_incidents" \
      | awk -F'\t' '{ mark=""
                      if (length($2) >= 15) mark=" <-- ровно 15+ символов, вероятно усечено ядром"
                      if ($2 ~ /^\(.*\)$/) mark=" <-- скобочное имя (sd-executor/kthread)"
                      printf "    %6d  %s%s\n", $1, $2, mark }' | head -40
fi

# --- наблюдение 5.9.3g: c2_ingress_piped_to_shell -------------------------
# На №2.9.2 это правило одно давало ~450 алертов/час и было главным вкладом в
# п.3. После правки 5.9.3g (proc.args) на смоуках оно давало 0 на простое при
# живом позитивном контроле. Печатаем обе стороны явно: idle-дельта должна
# быть около нуля, но и полное отсутствие под атакой — не «успех», а повод
# перечитать 5.9.3g (в attack-наборе стенда сценария `curl | sh` нет вовсе).
echo ""
echo "=== наблюдение 5.9.3g: c2_ingress_piped_to_shell ==="
c2_idle="n/a"
if [ -n "$idle_metrics_start" ] && [ -s "$idle_metrics_start" ] && [ -s "$idle_metrics_end" ]; then
    cs=$(rule_counter "$idle_metrics_start" c2_ingress_piped_to_shell)
    ce=$(rule_counter "$idle_metrics_end" c2_ingress_piped_to_shell)
    c2_idle=$(( ce - cs ))
fi
echo "  за idle-час: $c2_idle (на №2.9.2 — порядка 450/час)"
final_metrics="$RESULTS_DIR/final-metrics-$TIMESTAMP.txt"
baseline_metrics="$RESULTS_DIR/baseline-metrics-$TIMESTAMP.txt"
if [ -s "$final_metrics" ] && [ -s "$baseline_metrics" ]; then
    bs=$(rule_counter "$baseline_metrics" c2_ingress_piped_to_shell)
    fs=$(rule_counter "$final_metrics" c2_ingress_piped_to_shell)
    echo "  под атакой: $(( fs - bs ))" \
         "(в attack-наборе стенда нет сценария curl-в-шелл — ноль здесь ожидаем и НЕ доказывает работоспособность правила)"
fi

echo ""
echo "=== КОНЕЦ ОТЧЁТА №2.9.3 ==="
