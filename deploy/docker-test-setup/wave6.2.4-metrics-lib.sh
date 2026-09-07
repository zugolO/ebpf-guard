#!/usr/bin/env bash
# wave6.2.4-metrics-lib.sh — измерительная половина волны 6.2.3. Форк
# wave6.2.2-metrics-lib.sh: функции w624_ratelimited_by_rule/w624_volume_by_rule
# и их офлайн-сторож на collect-6.2.1 перенесены БЕЗ ИЗМЕНЕНИЙ (№238/№239,
# item, унаследованный из 6.2.2); добавлены три новые функции для item 2
# постановки волны 6.2.3 (№248 + решение 1):
#
#   w624_dedup_dropped_by_rule  — четвёртый слой (дедуп), по метрике;
#   w624_value_v_by_rule        — величина (в) поимённо: (а)-разбивка + срез
#                                  лимитера + срез дедупа на каждый rule_id,
#                                  ранжировано по СУММЕ, а не по остатку
#                                  после лимитера (это и есть критерий
#                                  6.2.4.2, отличие от 6.2.2.3);
#   w624_value_v_total           — та же сумма, одним числом, для сверки с
#                                  прямой дельтой в контролях.
#
# Файл самопроверяем: запуск
#
#   ./wave6.2.4-metrics-lib.sh --self-test ../../server-logs/collect-6.2.2-run1
#   ./wave6.2.4-metrics-lib.sh --self-test ../../server-logs/collect-6.2.2
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
# №238: поимённый список правил со срезом лимитера ЗА ОКНО — по МЕТРИКЕ.
#
# Перебираются rule_id из объединения имён в ОБОИХ срезах
# ebpf_guard_alerts_ratelimited_by_rule_total, а не из сторового списка.
# Печатает строки "rule_id +delta", по убыванию дельты; молчит, только если
# ни одно правило не срезано.
# ---------------------------------------------------------------------------
w624_ratelimited_by_rule() { # $1=срез-начало $2=срез-конец
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
w624_volume_by_rule() { # $1=срез-начало $2=срез-конец
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
w624_volume_delta() { # $1=срез-начало $2=срез-конец
    awk '
        /^ebpf_guard_alerts_total[{ ]/ || /^ebpf_guard_alerts_filtered_total[{ ]/ {
            if (FILENAME == ARGV[1]) a += $NF; else b += $NF
        }
        END { printf "%d", (b+0) - (a+0) }' "$1" "$2"
}

# ---------------------------------------------------------------------------
# ITEM 2 (№248 + решение 1). Четвёртый слой: срез дедупа, поимённо — по
# МЕТРИКЕ, симметрично w624_ratelimited_by_rule.
# ---------------------------------------------------------------------------
w624_dedup_dropped_by_rule() { # $1=срез-начало $2=срез-конец
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
# №248 + РЕШЕНИЕ 1: величина (в) поимённо — критерий 6.2.4.2.
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
w624_value_v_by_rule() { # $1=срез-начало $2=срез-конец
    {
        w624_volume_by_rule "$1" "$2"
        w624_ratelimited_by_rule "$1" "$2" | awk '$2 != "RESET"'
        w624_dedup_dropped_by_rule "$1" "$2" | awk '$2 != "RESET"'
    } | awk '{ s[$1] += $2 } END { for (r in s) printf "%s %d\n", r, s[r] }' | sort -k2 -rn
}

# Прямая сумма величины (в) — для сверки разбивки с самой собой в контролях.
w624_value_v_total() { # $1=срез-начало $2=срез-конец
    local vol rl dd
    vol=$(w624_volume_delta "$1" "$2")
    rl=$(w624_ratelimited_by_rule "$1" "$2" | awk '$2 != "RESET" {s+=$2} END{printf "%d", s+0}')
    dd=$(w624_dedup_dropped_by_rule "$1" "$2" | awk '$2 != "RESET" {s+=$2} END{printf "%d", s+0}')
    printf "%d" "$(( vol + rl + dd ))"
}

# ---------------------------------------------------------------------------
# Офлайн-сторож. Принимает ЛЮБОЙ из двух архивов 6.2.2 и знает ожидаемые
# числа для каждого по имени каталога (память gate-offline-replay-on-mac:
# правка проверяется на ОБОИХ архивах ДО стенда, поэтому числа — не одна
# пара, а таблица на два имени).
# ---------------------------------------------------------------------------
w624_self_test() { # $1=каталог архива (…/collect-6.2.2-run1 или …/collect-6.2.2)
    local archive="${1:?путь к архиву, например server-logs/collect-6.2.2-run1}"
    local s="$archive/controls/artifacts/metrics-window-start.txt"
    local e="$archive/controls/artifacts/metrics-window-end.txt"
    local rc=0
    local base; base=$(basename "$archive")

    for f in "$s" "$e"; do
        [ -s "$f" ] || { echo "СТОРОЖ ПРОВАЛЕН: нет среза $f"; return 1; }
    done

    echo "=== №238: правила со срезом лимитера за окно (по метрике) ==="
    local rl
    rl=$(w624_ratelimited_by_rule "$s" "$e")
    echo "$rl" | sed 's/^/    /'
    [ -n "$rl" ] || { echo "  ПРОВАЛ: пустой список при ненулевом срезе — это и есть дефект №238"; rc=1; }

    echo "=== №239: разбивка величины (а) по правилам (по метрике) — 6.2.2.3, унаследовано ==="
    local vol sum pct
    vol=$(w624_volume_delta "$s" "$e")
    sum=$(w624_volume_by_rule "$s" "$e" | awk '{s+=$2} END{printf "%d", s+0}')
    w624_volume_by_rule "$s" "$e" | head -8 | sed 's/^/    /'
    echo "  прямая дельта объёма (а): $vol; сумма разбивки: $sum"
    if [ "$vol" -le 0 ]; then
        echo "  ПРОВАЛ: прямая дельта объёма не положительна — архив не тот"; rc=1
    else
        pct=$(awk -v s="$sum" -v v="$vol" 'BEGIN{printf "%.1f", 100.0*s/v}')
        echo "  покрытие разбивки: $pct% (критерий 6.2.2.3 требует ≥ 95%)"
        awk -v s="$sum" -v v="$vol" 'BEGIN{exit !(s >= 0.95*v)}' || { echo "  ПРОВАЛ: разбивка (а) не покрывает величину"; rc=1; }
    fi

    echo "=== №248 + решение 1: величина (в) поимённо — критерий 6.2.4.2 ==="
    local v_total v_sum v_top v_second
    v_total=$(w624_value_v_total "$s" "$e")
    v_sum=$(w624_value_v_by_rule "$s" "$e" | awk '{s+=$2} END{printf "%d", s+0}')
    w624_value_v_by_rule "$s" "$e" | head -8 | sed 's/^/    /'
    v_top=$(w624_value_v_by_rule "$s" "$e" | awk 'NR==1{print $1}')
    v_second=$(w624_value_v_by_rule "$s" "$e" | awk 'NR==2{print $1}')
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
            echo "  (архив «$base» не в таблице ожидаемых чисел — печатаю без сверки)"
            want_v=""; want_top=""; want_second="" ;;
    esac

    if [ -n "$want_v" ]; then
        if [ "$v_total" = "$want_v" ]; then
            echo "  OK: величина (в) = $v_total (ожидалось $want_v, $(awk -v v="$v_total" 'BEGIN{printf "%.0f", v*6}')/ч)"
        else
            echo "  ПРОВАЛ: величина (в) = $v_total, ожидалось $want_v"; rc=1
        fi
        local top_line second_line top_v second_v
        top_line=$(w624_value_v_by_rule "$s" "$e" | awk -v r="$want_top" '$1==r{print $2}')
        second_line=$(w624_value_v_by_rule "$s" "$e" | awk -v r="$want_second" '$1==r{print $2}')
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
        beacon_v=$(w624_value_v_by_rule "$s" "$e" | awk '$1=="c2_periodic_beacon_pattern"{print $2}')
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
        echo "  покрытие разбивки (в): $pct% (критерий 6.2.4.2 требует ≥ 95%)"
        awk -v s="$v_sum" -v v="$v_total" 'BEGIN{exit !(s >= 0.95*v)}' || { echo "  ПРОВАЛ: разбивка (в) не покрывает величину"; rc=1; }
    fi

    [ "$rc" -eq 0 ] && echo "СТОРОЖ ПРОЙДЕН ($base)" || echo "СТОРОЖ ПРОВАЛЕН ($base)"
    return "$rc"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    case "${1:-}" in
        --self-test) shift; w624_self_test "${1:-}" ;;
        *) echo "использование: $0 --self-test <каталог архива, collect-6.2.2-run1 или collect-6.2.2>"; exit 2 ;;
    esac
fi
