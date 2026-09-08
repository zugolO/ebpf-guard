#!/usr/bin/env bash
# wave6.2.5-metrics-lib.sh — измерительная половина волны 6.2.3. Форк
# wave6.2.2-metrics-lib.sh: функции w625_ratelimited_by_rule/w625_volume_by_rule
# и их офлайн-сторож на collect-6.2.1 перенесены БЕЗ ИЗМЕНЕНИЙ (№238/№239,
# item, унаследованный из 6.2.2); добавлены три новые функции для item 2
# постановки волны 6.2.3 (№248 + решение 1):
#
#   w625_dedup_dropped_by_rule  — четвёртый слой (дедуп), по метрике;
#   w625_value_v_by_rule        — величина (в) поимённо: (а)-разбивка + срез
#                                  лимитера + срез дедупа на каждый rule_id,
#                                  ранжировано по СУММЕ, а не по остатку
#                                  после лимитера (это и есть критерий
#                                  6.2.5.2, отличие от 6.2.2.3);
#   w625_value_v_total           — та же сумма, одним числом, для сверки с
#                                  прямой дельтой в контролях.
#
# Файл самопроверяем: запуск
#
#   ./wave6.2.5-metrics-lib.sh --self-test ../../server-logs/collect-6.2.2-run1
#   ./wave6.2.5-metrics-lib.sh --self-test ../../server-logs/collect-6.2.2
#
# прогоняет ВСЕ функции на срезах архива и сверяет с числами, независимо
# пересчитанными прямой дельтой ДО того, как этот код был написан (память
# gate-offline-replay-on-mac: правка измерителя проверяется офлайн на ОБОИХ
# архивах 6.2.2 ДО стенда). Ожидаемые числа (см. plan.md, §6.2.3, находка
# №248):
#   collect-6.2.2-run1: величина (в) 8754 (52524/ч); вершина разбивки —
#     sigma_failed_login_syscall_daemon(3090), rootkit_pam_module_added_daemon(2970);
#   collect-6.2.2:      величина (в) 7128 (42768/ч); вершина —
#     sigma_failed_login_syscall_daemon(2400), rootkit_pam_module_added_daemon(2280);
#   на ОБОИХ архивах c2_periodic_beacon_pattern(985/985) НЕ первый — прежняя
#   разбивка 6.2.2.3 (по остатку после лимитера) печатала его вершиной.
# Правка измерителя, не воспроизводящая эти числа на обоих архивах, — не
# починка, а вторая догадка поверх первой.
#
# Пайплайн 6.2.3 обязан взять эти функции отсюда (source), а не переписать их
# заново: у переписанной копии сторожа нет.

set -euo pipefail

# ---------------------------------------------------------------------------
# №267 (item 5, волна 6.2.5). ЯДРО ФИЛЬТРА _w625_metric_sum ЖИВЁТ ЗДЕСЬ, а не
# в контролях, и по одной причине: офлайн-сторож обязан звать ТУ САМУЮ
# функцию, которой пользуется прогон. Первая редакция item 5 проверяла
# comm-фильтр синтетическим awk, переписанным внутри --self-test, — то есть
# доказывала концепцию, а не код (тот же класс, что находка №267 и весь item
# 6: «сторож судит не то, что напечатано»). wave6.2.5-controls.sh берёт эту
# функцию source'ом и делегирует ей, добавляя лишь чтение живого /metrics.
#
# Фильтр совпадает по ЗНАЧЕНИЮ любого лейбла в кавычках (rule_id, comm,
# exception_name…), а не только rule_id: метрика заморозки
# ebpf_guard_drift_baseline_signature_cap_reached_total лейблится comm, и без
# этого 6.2.5.11 вынужден звать сумму с пустым фильтром (архивный «+2» =
# 1×bash + 1×w624sig, вердикт совпал со счётом случайно).
# ---------------------------------------------------------------------------
w625_metric_sum_file() { # $1=метрика $2=значения лейблов через пробел (пусто = все) $3=файл среза ("-" или пусто = stdin)
    # "-" читается awk'ом как stdin — так живой /metrics суммируется БЕЗ
    # временного файла: любая запись на диск из-под контроля есть собственное
    # файловое событие измерителя (находки №242/№252).
    local src="${3:--}"
    [ -n "$src" ] || src="-"
    awk -v m="$1" -v ids="${2:-}" '
        BEGIN { n = split(ids, a, " ") }
        $0 ~ "^"m"[{ ]" {
            if (n == 0) { s += $NF; next }
            for (i = 1; i <= n; i++) if (index($0, "\"" a[i] "\"")) { s += $NF; next }
        }
        END { printf "%d", s+0 }' "$src"
}

# ---------------------------------------------------------------------------
# №238: поимённый список правил со срезом лимитера ЗА ОКНО — по МЕТРИКЕ.
#
# Перебираются rule_id из объединения имён в ОБОИХ срезах
# ebpf_guard_alerts_ratelimited_by_rule_total, а не из сторового списка.
# Печатает строки "rule_id +delta", по убыванию дельты; молчит, только если
# ни одно правило не срезано.
# ---------------------------------------------------------------------------
w625_ratelimited_by_rule() { # $1=срез-начало $2=срез-конец
    awk '
        function rid(line,   m) {
            if (match(line, /rule_id="[^"]*"/)) {
                m = substr(line, RSTART + 9, RLENGTH - 10)
                return m
            }
            return ""
        }
        FILENAME == ARGV[1] && /^ebpf_guard_alerts_ratelimited_by_rule_total[{ ]/ { a[rid($0)] = $NF }
        FILENAME == ARGV[2] && /^ebpf_guard_alerts_ratelimited_by_rule_total[{ ]/ { b[rid($0)] = $NF }
        END {
            for (r in b) if (r != "") { d = b[r] - (r in a ? a[r] : 0); if (d > 0) printf "%s %d\n", r, d }
            # Правило, исчезнувшее из второго среза, дельты не имеет — но и
            # молчать о нём нельзя: счётчик не убывает, исчезновение имени
            # означает рестарт агента внутри окна.
            for (r in a) if (r != "" && !(r in b)) printf "%s RESET\n", r
        }' "$1" "$2" | sort -k2 -rn
}

# ---------------------------------------------------------------------------
# №239: разбивка величины по правилам — по МЕТРИКЕ.
#
# Величина критерия 6.2.2.1 — это alerts_total + alerts_filtered_total (№227).
# Разбивка обязана суммироваться в неё же, иначе сужение работает вслепую
# (критерий 6.2.2.3: сумма разбивки ≥ 95% прямой дельты). Лейбла comm ни у
# одной из двух метрик нет, поэтому comm-срез остаётся сторовым и справочным —
# метрикой эту ось не восстановить.
# ---------------------------------------------------------------------------
w625_volume_by_rule() { # $1=срез-начало $2=срез-конец
    awk '
        function rid(line,   m) {
            if (match(line, /rule_id="[^"]*"/)) return substr(line, RSTART + 9, RLENGTH - 10)
            return ""
        }
        /^ebpf_guard_alerts_total[{ ]/ || /^ebpf_guard_alerts_filtered_total[{ ]/ {
            r = rid($0)
            if (r == "") next
            # Один rule_id встречается в нескольких строках (severity,
            # namespace, node…) — суммируются все.
            if (FILENAME == ARGV[1]) a[r] += $NF; else b[r] += $NF
        }
        END {
            for (r in b) { d = b[r] - (r in a ? a[r] : 0); if (d > 0) printf "%s %d\n", r, d }
        }' "$1" "$2" | sort -k2 -rn
}

# Прямая дельта объёма — та же формула, что у _w621_volume, повторена здесь,
# чтобы сторож ниже сверял разбивку с величиной, а не с самим собой.
w625_volume_delta() { # $1=срез-начало $2=срез-конец
    awk '
        /^ebpf_guard_alerts_total[{ ]/ || /^ebpf_guard_alerts_filtered_total[{ ]/ {
            if (FILENAME == ARGV[1]) a += $NF; else b += $NF
        }
        END { printf "%d", (b+0) - (a+0) }' "$1" "$2"
}

# ---------------------------------------------------------------------------
# ITEM 2 (№248 + решение 1). Четвёртый слой: срез дедупа, поимённо — по
# МЕТРИКЕ, симметрично w625_ratelimited_by_rule.
# ---------------------------------------------------------------------------
w625_dedup_dropped_by_rule() { # $1=срез-начало $2=срез-конец
    awk '
        function rid(line,   m) {
            if (match(line, /rule_id="[^"]*"/)) return substr(line, RSTART + 9, RLENGTH - 10)
            return ""
        }
        FILENAME == ARGV[1] && /^ebpf_guard_alerts_dedup_dropped_by_rule_total[{ ]/ { a[rid($0)] = $NF }
        FILENAME == ARGV[2] && /^ebpf_guard_alerts_dedup_dropped_by_rule_total[{ ]/ { b[rid($0)] = $NF }
        END {
            for (r in b) if (r != "") { d = b[r] - (r in a ? a[r] : 0); if (d > 0) printf "%s %d\n", r, d }
            for (r in a) if (r != "" && !(r in b)) printf "%s RESET\n", r
        }' "$1" "$2" | sort -k2 -rn
}

# ---------------------------------------------------------------------------
# №248 + РЕШЕНИЕ 1: величина (в) поимённо — критерий 6.2.5.2.
#
# (в) = (а)-разбивка [alerts_total+alerts_filtered_total] + срез лимитера +
# срез дедупа, СУММА на каждый rule_id. Отличие от 6.2.2.3 (которая
# ранжирует только (а)-разбивку): правило, упёршееся в лимитер и в дедуп,
# показывает в (а) лишь то, что просочилось через оба фильтра — вершина
# получается ложной (c2_periodic_beacon_pattern на архивах 6.2.2 показывает
# в (а) 103, но реальных срабатываний 985 — 89% съедено лимитером и
# дедупом). (в) складывает все три компонента ДО того, как что-либо
# отфильтровано, и поэтому ранжирует верно.
# ---------------------------------------------------------------------------
w625_value_v_by_rule() { # $1=срез-начало $2=срез-конец
    {
        w625_volume_by_rule "$1" "$2"
        w625_ratelimited_by_rule "$1" "$2" | awk '$2 != "RESET"'
        w625_dedup_dropped_by_rule "$1" "$2" | awk '$2 != "RESET"'
    } | awk '{ s[$1] += $2 } END { for (r in s) printf "%s %d\n", r, s[r] }' | sort -k2 -rn
}

# Прямая сумма величины (в) — для сверки разбивки с самой собой в контролях.
w625_value_v_total() { # $1=срез-начало $2=срез-конец
    local vol rl dd
    vol=$(w625_volume_delta "$1" "$2")
    rl=$(w625_ratelimited_by_rule "$1" "$2" | awk '$2 != "RESET" {s+=$2} END{printf "%d", s+0}')
    dd=$(w625_dedup_dropped_by_rule "$1" "$2" | awk '$2 != "RESET" {s+=$2} END{printf "%d", s+0}')
    printf "%d" "$(( vol + rl + dd ))"
}

# ---------------------------------------------------------------------------
# ИНЦИДЕНТНЫЙ СЛОЙ (критерии 6.2.4.6 / 6.2.5.16, item 3 волны 6.2.5). ЯДРО
# СЧЁТА ЖИВЁТ ЗДЕСЬ — по той же причине, что и w625_metric_sum_file: критерий
# инцидентного слоя переписывался в каждой из четырёх волн подряд (6.2.2.9 →
# 6.2.3.7 → 6.2.4.6) и каждый раз проверялся ТОЛЬКО на стенде, постфактум.
# Здесь он получает офлайн-сторож на архиве collect-6.2.4, где обе лжи
# известны поимённо (containerd-shim и k3s-server).
#
# Классы корня судятся по-разному (см. комментарий в контролях):
#   instr — дерево измерителя, ложь только внутри тихого окна [t0,t1];
#   node  — нодовый актор, ложь за прогон, МИНУС окно стартов подов 6.2.5.10
#           (item 3, №263: цена старта пода — предмет своего критерия с
#           порогом, а не повод простить весь прогон).
# Режимы: win|outwin (тихое окно), phase|outphase (фаза атак),
#         podstart|outpodstart (окно стартов подов), all.
# ---------------------------------------------------------------------------
w625_incident_roots() { # $1=alerts.json $2=класс $3=режим $4=t0 $5=t1 $6=ps $7=pe $8=cs $9=ce $10=instr-comms $11=node-actors
    jq --arg instr "${10}" --arg actors "${11}" \
       --arg cls "$2" --arg mode "$3" \
       --argjson t0 "${4:-0}" --argjson t1 "${5:-0}" \
       --argjson ps "${6:-0}" --argjson pe "${7:-0}" \
       --argjson cs "${8:-0}" --argjson ce "${9:-0}" '
    [ .[] | select(.rule_id=="incident_confirmed_attack")
      | (.details.root_comm // .comm) as $c
      | ((($instr|split(" "))|index($c)) != null) as $is_instr
      | ((($actors|split(" "))|index($c)) != null) as $is_node
      | select(if $cls == "instr" then $is_instr else ($is_node and ($is_instr|not)) end)
      | (.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // -1) as $t
      | select(if   $mode == "win"      then ($t >= $t0 and $t <= $t1)
               elif $mode == "outwin"   then ($t <  $t0 or  $t >  $t1)
               elif $mode == "phase"    then ($t >= $ps and $t <= $pe)
               elif $mode == "outphase" then ($t <  $ps or  $t >  $pe)
               # ITEM 3 (№263): пустое окно (ce==0) не вычитает ничего.
               elif $mode == "podstart"    then ($t >= $cs and $t <= $ce and $ce > 0)
               elif $mode == "outpodstart" then (($t <  $cs or  $t >  $ce) or $ce == 0)
               else true end)
      | $c ]' "$1" 2>/dev/null
}

# ---------------------------------------------------------------------------
# ITEM 5 (№267/№268, критерий 6.2.5.15). Доля величины на нерезолвленном
# образе — по МЕТРИКЕ ebpf_guard_exe_path_lookups_total{result}.
#
# Печатает "resolved=<Δ> unresolved=<Δ> total=<Δ> unresolved_pct=<X.Y>".
# Порог не назначается (5.9.6, диагностика гонки №261) — эта функция только
# печатает число, вердикт по ней контроли не выносят.
# ---------------------------------------------------------------------------
w625_exe_path_lookup_fraction() { # $1=срез-начало $2=срез-конец
    local r0 r1 u0 u1 rd ud total pct
    r0=$(awk '/^ebpf_guard_exe_path_lookups_total\{result="resolved"\}/{print $NF}' "$1")
    r1=$(awk '/^ebpf_guard_exe_path_lookups_total\{result="resolved"\}/{print $NF}' "$2")
    u0=$(awk '/^ebpf_guard_exe_path_lookups_total\{result="unresolved"\}/{print $NF}' "$1")
    u1=$(awk '/^ebpf_guard_exe_path_lookups_total\{result="unresolved"\}/{print $NF}' "$2")
    rd=$(( ${r1:-0} - ${r0:-0} ))
    ud=$(( ${u1:-0} - ${u0:-0} ))
    total=$(( rd + ud ))
    if [ "$total" -gt 0 ]; then
        pct=$(awk -v u="$ud" -v t="$total" 'BEGIN{printf "%.2f", 100.0*u/t}')
    else
        pct="0.00"
    fi
    printf "resolved=%d unresolved=%d total=%d unresolved_pct=%s\n" "$rd" "$ud" "$total" "$pct"
}

# ---------------------------------------------------------------------------
# ITEM 5 (№268, критерий 6.2.5.1 подпункт 2). Приращение
# rule_exceptions_total ПО КАЖДОМУ из четырёх правил-двойников №253, ПО
# ОБОИМ именованным исключениям (verified-daemon-image — исход развилки
# №253; verified-daemon-lineage — исход развилки №261, item 1 волны 6.2.5).
# Печатает "rule_id image=<Δ> lineage=<Δ> total=<Δ>" на каждое правило,
# отсутствующая серия читается как 0 (архив ДО item 1 не знает lineage —
# это не провал самопроверки, а факт истории волны).
# ---------------------------------------------------------------------------
W625_TWIN_RULES="sigma_passwd_shadow_read_daemon sigma_log_deletion_daemon sigma_utmp_wtmp_modified_daemon sensitive_file_read_daemon"
w625_daemon_twin_exceptions() { # $1=срез-начало $2=срез-конец
    local rid image0 image1 lineage0 lineage1 id imd lnd tot
    for rid in $W625_TWIN_RULES; do
        image0=$(awk -v r="$rid" '$0 ~ "^ebpf_guard_rule_exceptions_total\\{exception_name=\"verified-daemon-image\",rule_id=\""r"\"\\}" {print $NF}' "$1")
        image1=$(awk -v r="$rid" '$0 ~ "^ebpf_guard_rule_exceptions_total\\{exception_name=\"verified-daemon-image\",rule_id=\""r"\"\\}" {print $NF}' "$2")
        lineage0=$(awk -v r="$rid" '$0 ~ "^ebpf_guard_rule_exceptions_total\\{exception_name=\"verified-daemon-lineage\",rule_id=\""r"\"\\}" {print $NF}' "$1")
        lineage1=$(awk -v r="$rid" '$0 ~ "^ebpf_guard_rule_exceptions_total\\{exception_name=\"verified-daemon-lineage\",rule_id=\""r"\"\\}" {print $NF}' "$2")
        imd=$(( ${image1:-0} - ${image0:-0} ))
        lnd=$(( ${lineage1:-0} - ${lineage0:-0} ))
        tot=$(( imd + lnd ))
        printf "%s image=%d lineage=%d total=%d\n" "$rid" "$imd" "$lnd" "$tot"
    done
}

# ---------------------------------------------------------------------------
# Офлайн-сторож. Принимает ЛЮБОЙ из двух архивов 6.2.2 и знает ожидаемые
# числа для каждого по имени каталога (память gate-offline-replay-on-mac:
# правка проверяется на ОБОИХ архивах ДО стенда, поэтому числа — не одна
# пара, а таблица на два имени).
# ---------------------------------------------------------------------------
w625_self_test() { # $1=каталог архива (…/collect-6.2.2-run1 или …/collect-6.2.2)
    local archive="${1:?путь к архиву, например server-logs/collect-6.2.2-run1}"
    local s="$archive/controls/artifacts/metrics-window-start.txt"
    local e="$archive/controls/artifacts/metrics-window-end.txt"
    local rc=0
    local base; base=$(basename "$archive")

    for f in "$s" "$e"; do
        [ -s "$f" ] || { echo "СТОРОЖ ПРОВАЛЕН: нет среза $f"; return 1; }
    done

    echo "=== №238: правила со срезом лимитера за окно (по метрике) ==="
    local rl rl_sum
    rl=$(w625_ratelimited_by_rule "$s" "$e")
    echo "$rl" | sed 's/^/    /'
    # Сторож №238 — это СОГЛАСОВАННОСТЬ списка с суммой, а не «список обязан
    # быть непуст». Первая редакция требовала непустоты безусловно и потому
    # ложно проваливалась на архиве, где срез лимитера ЧЕСТНО нулевой
    # (collect-6.2.4: срез 0 второй прогон подряд — см. plan.md §6.2.4). Тот
    # же дефект, который лечит сам критерий 6.2.2.2 в контролях: пустой
    # список при НЕНУЛЕВОЙ сумме — находка №238; пустой список при нулевой
    # сумме — верное измерение.
    rl_sum=$(w625_metric_sum_file ebpf_guard_alerts_ratelimited_by_rule_total "" "$e")
    rl_sum=$(( rl_sum - $(w625_metric_sum_file ebpf_guard_alerts_ratelimited_by_rule_total "" "$s") ))
    echo "  прямая дельта среза лимитера за окно: $rl_sum"
    if [ -z "$rl" ] && [ "$rl_sum" -gt 0 ]; then
        echo "  ПРОВАЛ: пустой список при срезе $rl_sum — это и есть дефект №238"; rc=1
    elif [ -n "$rl" ] && [ "$rl_sum" -eq 0 ]; then
        echo "  ПРОВАЛ: список непуст при НУЛЕВОЙ сумме среза — разбивка считает не ту метрику"; rc=1
    else
        echo "  OK: список и сумма среза согласованы (обе пусты/нулевые либо обе ненулевые)"
    fi

    echo "=== №239: разбивка величины (а) по правилам (по метрике) — 6.2.2.3, унаследовано ==="
    local vol sum pct
    vol=$(w625_volume_delta "$s" "$e")
    sum=$(w625_volume_by_rule "$s" "$e" | awk '{s+=$2} END{printf "%d", s+0}')
    w625_volume_by_rule "$s" "$e" | head -8 | sed 's/^/    /'
    echo "  прямая дельта объёма (а): $vol; сумма разбивки: $sum"
    if [ "$vol" -le 0 ]; then
        echo "  ПРОВАЛ: прямая дельта объёма не положительна — архив не тот"; rc=1
    else
        pct=$(awk -v s="$sum" -v v="$vol" 'BEGIN{printf "%.1f", 100.0*s/v}')
        echo "  покрытие разбивки: $pct% (критерий 6.2.2.3 требует ≥ 95%)"
        awk -v s="$sum" -v v="$vol" 'BEGIN{exit !(s >= 0.95*v)}' || { echo "  ПРОВАЛ: разбивка (а) не покрывает величину"; rc=1; }
    fi

    echo "=== №248 + решение 1: величина (в) поимённо — критерий 6.2.5.2 ==="
    local v_total v_sum v_top v_second
    v_total=$(w625_value_v_total "$s" "$e")
    v_sum=$(w625_value_v_by_rule "$s" "$e" | awk '{s+=$2} END{printf "%d", s+0}')
    w625_value_v_by_rule "$s" "$e" | head -8 | sed 's/^/    /'
    v_top=$(w625_value_v_by_rule "$s" "$e" | awk 'NR==1{print $1}')
    v_second=$(w625_value_v_by_rule "$s" "$e" | awk 'NR==2{print $1}')
    echo "  величина (в) прямой суммой: $v_total; сумма разбивки по (в): $v_sum; вершина: ${v_top:-нет}, вторая: ${v_second:-нет}"

    # Ожидаемые числа — таблица на два известных архива волны 6.2.2 (найдены
    # независимо от этого кода прямой дельтой трёх метрик, см. plan.md §6.2.3).
    local want_v want_top want_top_v want_second want_second_v
    case "$base" in
        collect-6.2.2-run1)
            want_v=8754; want_top=sigma_failed_login_syscall_daemon; want_top_v=3090
            want_second=rootkit_pam_module_added_daemon; want_second_v=2970 ;;
        collect-6.2.2)
            want_v=7128; want_top=sigma_failed_login_syscall_daemon; want_top_v=2400
            want_second=rootkit_pam_module_added_daemon; want_second_v=2280 ;;
        *)
            echo "  (архив \"$base\" не в таблице ожидаемых чисел — печатаю без сверки)"
            want_v=""; want_top=""; want_second="" ;;
    esac

    if [ -n "$want_v" ]; then
        if [ "$v_total" = "$want_v" ]; then
            echo "  OK: величина (в) = $v_total (ожидалось $want_v, $(awk -v v="$v_total" 'BEGIN{printf "%.0f", v*6}')/ч)"
        else
            echo "  ПРОВАЛ: величина (в) = $v_total, ожидалось $want_v"; rc=1
        fi
        local top_line second_line top_v second_v
        top_line=$(w625_value_v_by_rule "$s" "$e" | awk -v r="$want_top" '$1==r{print $2}')
        second_line=$(w625_value_v_by_rule "$s" "$e" | awk -v r="$want_second" '$1==r{print $2}')
        if [ "$v_top" = "$want_top" ] && [ "${top_line:-0}" = "$want_top_v" ]; then
            echo "  OK: вершина разбивки (в) — $want_top($want_top_v), а не c2_periodic_beacon_pattern (как показала бы 6.2.2.3)"
        else
            echo "  ПРОВАЛ: ожидалась вершина $want_top($want_top_v), получено ${v_top:-нет}($top_line)"; rc=1
        fi
        if [ "$v_second" = "$want_second" ] && [ "${second_line:-0}" = "$want_second_v" ]; then
            echo "  OK: вторая строка разбивки (в) — $want_second($want_second_v)"
        else
            echo "  ПРОВАЛ: ожидалась вторая строка $want_second($want_second_v), получено ${v_second:-нет}($second_line)"; rc=1
        fi
        local beacon_v
        beacon_v=$(w625_value_v_by_rule "$s" "$e" | awk '$1=="c2_periodic_beacon_pattern"{print $2}')
        if [ "$v_top" = "c2_periodic_beacon_pattern" ]; then
            echo "  ПРОВАЛ: c2_periodic_beacon_pattern(${beacon_v:-?}) первый по (в) — страж №248 против ложной вершины не сработал"; rc=1
        else
            echo "  OK: c2_periodic_beacon_pattern(${beacon_v:-?}) НЕ первый по (в)"
        fi
    fi

    if [ "$v_total" -le 0 ]; then
        echo "  ПРОВАЛ: величина (в) не положительна — покрытие считать не от чего"; rc=1
    else
        pct=$(awk -v s="$v_sum" -v v="$v_total" 'BEGIN{printf "%.1f", 100.0*s/v}')
        echo "  покрытие разбивки (в): $pct% (критерий 6.2.5.2 требует ≥ 95%)"
        awk -v s="$v_sum" -v v="$v_total" 'BEGIN{exit !(s >= 0.95*v)}' || { echo "  ПРОВАЛ: разбивка (в) не покрывает величину"; rc=1; }
    fi

    echo "=== №267/№268 (item 5, критерий 6.2.5.15): доля величины на нерезолвленном образе ==="
    local frac
    frac=$(w625_exe_path_lookup_fraction "$s" "$e")
    echo "  $frac"
    if [ "$base" = "collect-6.2.4" ]; then
        if [ "$frac" = "resolved=6118 unresolved=348 total=6466 unresolved_pct=5.38" ]; then
            echo "  OK: 6.2.5.15 воспроизводит архивные числа находки №261 (unresolved 348 из 6466)"
        else
            echo "  ПРОВАЛ: 6.2.5.15 ожидало 'resolved=6118 unresolved=348 total=6466 unresolved_pct=5.38', получено '$frac'"; rc=1
        fi
    fi

    echo "=== №268 (item 5, критерий 6.2.5.1 подпункт 2): двойники №253 по обоим исключениям ==="
    local twin_out
    twin_out=$(w625_daemon_twin_exceptions "$s" "$e")
    echo "$twin_out" | sed 's/^/    /'
    if [ "$base" = "collect-6.2.4" ]; then
        # Архив 6.2.4 предшествует item 1 волны 6.2.5 — verified-daemon-lineage
        # в нём отсутствует по построению (lineage=0 у всех четырёх), это не
        # провал сторожа, это факт истории волны, зафиксированный явно.
        local want
        want=$(printf 'sigma_passwd_shadow_read_daemon image=763 lineage=0 total=763\nsigma_log_deletion_daemon image=314 lineage=0 total=314\nsigma_utmp_wtmp_modified_daemon image=157 lineage=0 total=157\nsensitive_file_read_daemon image=18 lineage=0 total=18')
        if [ "$twin_out" = "$want" ]; then
            echo "  OK: все четыре двойника №253 дали ненулевой срез (image+lineage), lineage=0 ожидаемо (архив ДО item 1)"
        else
            echo "  ПРОВАЛ: разбивка двойников не совпала с ожидаемой"; rc=1
        fi
        local zero_twin
        zero_twin=$(echo "$twin_out" | awk '$NF ~ /total=0$/' | grep -c . || true)
        [ "${zero_twin:-0}" -eq 0 ] || { echo "  ПРОВАЛ: сторож нуля на двойниках — хотя бы одно правило дало total=0 (ось выключена на нём)"; rc=1; }
    fi

    echo "=== №267 (item 5, критерий 6.2.5.11): _w625_metric_sum с фильтром по comm — синтетический сторож ==="
    # Синтетический срез, где и w625sig, и bash дали приращение
    # signature_cap_reached_total — ровно форма архива №267 (страж на срезе,
    # где bash тоже вырос, требование постановки item 5).
    local synA synB syn_all syn_comm m=ebpf_guard_drift_baseline_signature_cap_reached_total
    synA=$(mktemp); synB=$(mktemp)
    printf 'ebpf_guard_drift_baseline_signature_cap_reached_total{comm="w625sig"} 5\nebpf_guard_drift_baseline_signature_cap_reached_total{comm="bash"} 5\n' > "$synA"
    printf 'ebpf_guard_drift_baseline_signature_cap_reached_total{comm="w625sig"} 7\nebpf_guard_drift_baseline_signature_cap_reached_total{comm="bash"} 12\n' > "$synB"
    # Считается ТОЙ ЖЕ функцией, которой считает прогон (w625_metric_sum_file —
    # ядро _w625_metric_sum), а не переписанным здесь awk: сторож обязан
    # судить код, а не свою копию кода.
    syn_all=$(( $(w625_metric_sum_file "$m" "" "$synB") - $(w625_metric_sum_file "$m" "" "$synA") ))
    syn_comm=$(( $(w625_metric_sum_file "$m" "w625sig" "$synB") - $(w625_metric_sum_file "$m" "w625sig" "$synA") ))
    rm -f "$synA" "$synB"
    echo "  без фильтра (пустой аргумент, дефект №267): Δ=$syn_all (это bash+w625sig вместе — 2+7=9)"
    echo "  с фильтром по comm=\"w625sig\" (item 5 чинит): Δ=$syn_comm (только w625sig — 2)"
    if [ "$syn_all" -eq 9 ] && [ "$syn_comm" -eq 2 ]; then
        echo "  OK: непустой comm-фильтр отделяет w625sig от bash — фикс №267 воспроизводим офлайн, без стенда"
    else
        echo "  ПРОВАЛ: ожидалось Δ_без_фильтра=9, Δ_с_фильтром=2 — получено $syn_all / $syn_comm"; rc=1
    fi

    # === №262/№263 (item 2/item 3, критерии 6.2.4.6 и 6.2.5.16): инцидентный
    # слой на архиве. Сторож включается только там, где архив несёт снимок
    # инцидентов (collect-6.2.4 — первый такой), и проверяет ДВЕ вещи разом:
    #   (1) обе лжи архива названы поимённо (containerd-shim и k3s-server) —
    #       то есть счёт по классу "node" видит именно их;
    #   (2) вычитание окна стартов подов (item 3) НИЧЕГО НЕ ТЕРЯЕТ: что
    #       уходит из вердикта 6.2.4.6, обязано попасть в половину «окно
    #       стартов подов» критерия 6.2.5.16.
    local inc="$archive/controls/artifacts/alerts-incidents.json"
    if [ -s "$inc" ]; then
        echo "=== №262/№263 (критерии 6.2.4.6/6.2.5.16): инцидентный слой на архиве ==="
        local instr="bash sh curl jq awk grep sed cat dirname pgrep date kubectl go ld cut wc find tr head tail sleep setsid dd printf"
        local actors="k3s-server kubelet containerd containerd-shim containerd-shim-runc-v2 runc runc:[1:CHILD] runc:[2:INIT] coredns local-path-prov kube-proxy pause iptables ip6tables kubectl flannel bridge loopback"
        local all_roots podstart_roots out_roots
        all_roots=$(w625_incident_roots "$inc" node all 0 0 0 0 0 0 "$instr" "$actors" | jq -r 'unique|join(" ")')
        echo "    корни класса «нодовый актор» за архив: ${all_roots:-нет}"
        if [ "$base" = "collect-6.2.4" ]; then
            if [ "$all_roots" = "containerd-shim k3s-server" ]; then
                echo "  OK: обе лжи архива 6.2.4 названы поимённо (containerd-shim, k3s-server) — счёт видит ровно их"
            else
                echo "  ПРОВАЛ: ожидались «containerd-shim k3s-server», получено «${all_roots:-нет}»"; rc=1
            fi
            # Окно стартов подов прогона 6.2.4: churn шёл между 6.2.1.2b и
            # 6.2.1.8, обе лжи (20:35:36/37Z) лежат внутри него.
            podstart_roots=$(w625_incident_roots "$inc" node podstart 0 0 0 0 1788813300 1788813390 "$instr" "$actors" | jq 'length')
            out_roots=$(w625_incident_roots "$inc" node outpodstart 0 0 0 0 1788813300 1788813390 "$instr" "$actors" | jq 'length')
            echo "    item 3: внутри окна стартов подов $podstart_roots, вне его (вердикт 6.2.4.6) $out_roots"
            if [ "$podstart_roots" -eq 2 ] && [ "$out_roots" -eq 0 ]; then
                echo "  OK: вычитание окна стартов подов (item 3) переносит обе лжи в половину 6.2.5.16, а не теряет их"
            else
                echo "  ПРОВАЛ: ожидалось «внутри 2, вне 0» — получено «внутри $podstart_roots, вне $out_roots»"; rc=1
            fi
            # Пустое окно (ce==0) не имеет права вычитать ничего.
            out_roots=$(w625_incident_roots "$inc" node outpodstart 0 0 0 0 0 0 "$instr" "$actors" | jq 'length')
            if [ "$out_roots" -eq 2 ]; then
                echo "  OK: при пустом окне стартов подов (контроль churn не исполнялся) вердикт 6.2.4.6 считает обе лжи"
            else
                echo "  ПРОВАЛ: пустое окно стартов подов вычло что-то из вердикта — получено $out_roots вместо 2"; rc=1
            fi
        fi
    fi

    [ "$rc" -eq 0 ] && echo "СТОРОЖ ПРОЙДЕН ($base)" || echo "СТОРОЖ ПРОВАЛЕН ($base)"
    return "$rc"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    case "${1:-}" in
        --self-test) shift; w625_self_test "${1:-}" ;;
        *) echo "использование: $0 --self-test <каталог архива, collect-6.2.2-run1 или collect-6.2.2>"; exit 2 ;;
    esac
fi
