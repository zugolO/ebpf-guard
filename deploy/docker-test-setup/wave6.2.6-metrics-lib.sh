#!/usr/bin/env bash
# wave6.2.6-metrics-lib.sh — измерительная половина волны 6.2.3. Форк
# wave6.2.2-metrics-lib.sh: функции w626_ratelimited_by_rule/w626_volume_by_rule
# и их офлайн-сторож на collect-6.2.1 перенесены БЕЗ ИЗМЕНЕНИЙ (№238/№239,
# item, унаследованный из 6.2.2); добавлены три новые функции для item 2
# постановки волны 6.2.3 (№248 + решение 1):
#
#   w626_dedup_dropped_by_rule  — четвёртый слой (дедуп), по метрике;
#   w626_value_v_by_rule        — величина (в) поимённо: (а)-разбивка + срез
#                                  лимитера + срез дедупа на каждый rule_id,
#                                  ранжировано по СУММЕ, а не по остатку
#                                  после лимитера (это и есть критерий
#                                  6.2.6.2, отличие от 6.2.2.3);
#   w626_value_v_total           — та же сумма, одним числом, для сверки с
#                                  прямой дельтой в контролях.
#
# Файл самопроверяем: запуск
#
#   ./wave6.2.6-metrics-lib.sh --self-test ../../server-logs/collect-6.2.2-run1
#   ./wave6.2.6-metrics-lib.sh --self-test ../../server-logs/collect-6.2.2
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
# №267 (item 5, волна 6.2.6). ЯДРО ФИЛЬТРА _w626_metric_sum ЖИВЁТ ЗДЕСЬ, а не
# в контролях, и по одной причине: офлайн-сторож обязан звать ТУ САМУЮ
# функцию, которой пользуется прогон. Первая редакция item 5 проверяла
# comm-фильтр синтетическим awk, переписанным внутри --self-test, — то есть
# доказывала концепцию, а не код (тот же класс, что находка №267 и весь item
# 6: «сторож судит не то, что напечатано»). wave6.2.6-controls.sh берёт эту
# функцию source'ом и делегирует ей, добавляя лишь чтение живого /metrics.
#
# Фильтр совпадает по ЗНАЧЕНИЮ любого лейбла в кавычках (rule_id, comm,
# exception_name…), а не только rule_id: метрика заморозки
# ebpf_guard_drift_baseline_signature_cap_reached_total лейблится comm, и без
# этого 6.2.6.11 вынужден звать сумму с пустым фильтром (архивный «+2» =
# 1×bash + 1×w624sig, вердикт совпал со счётом случайно).
# ---------------------------------------------------------------------------
w626_metric_sum_file() { # $1=метрика $2=значения лейблов через пробел (пусто = все) $3=файл среза ("-" или пусто = stdin)
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
w626_ratelimited_by_rule() { # $1=срез-начало $2=срез-конец
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
w626_volume_by_rule() { # $1=срез-начало $2=срез-конец
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
w626_volume_delta() { # $1=срез-начало $2=срез-конец
    awk '
        /^ebpf_guard_alerts_total[{ ]/ || /^ebpf_guard_alerts_filtered_total[{ ]/ {
            if (FILENAME == ARGV[1]) a += $NF; else b += $NF
        }
        END { printf "%d", (b+0) - (a+0) }' "$1" "$2"
}

# ---------------------------------------------------------------------------
# ITEM 2 (№248 + решение 1). Четвёртый слой: срез дедупа, поимённо — по
# МЕТРИКЕ, симметрично w626_ratelimited_by_rule.
# ---------------------------------------------------------------------------
w626_dedup_dropped_by_rule() { # $1=срез-начало $2=срез-конец
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
# №248 + РЕШЕНИЕ 1: величина (в) поимённо — критерий 6.2.6.2.
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
w626_value_v_by_rule() { # $1=срез-начало $2=срез-конец
    {
        w626_volume_by_rule "$1" "$2"
        w626_ratelimited_by_rule "$1" "$2" | awk '$2 != "RESET"'
        w626_dedup_dropped_by_rule "$1" "$2" | awk '$2 != "RESET"'
    } | awk '{ s[$1] += $2 } END { for (r in s) printf "%s %d\n", r, s[r] }' | sort -k2 -rn
}

# Прямая сумма величины (в) — для сверки разбивки с самой собой в контролях.
w626_value_v_total() { # $1=срез-начало $2=срез-конец
    local vol rl dd
    vol=$(w626_volume_delta "$1" "$2")
    rl=$(w626_ratelimited_by_rule "$1" "$2" | awk '$2 != "RESET" {s+=$2} END{printf "%d", s+0}')
    dd=$(w626_dedup_dropped_by_rule "$1" "$2" | awk '$2 != "RESET" {s+=$2} END{printf "%d", s+0}')
    printf "%d" "$(( vol + rl + dd ))"
}

# ---------------------------------------------------------------------------
# ИНЦИДЕНТНЫЙ СЛОЙ (критерии 6.2.4.6 / 6.2.6.16, item 3 волны 6.2.6). ЯДРО
# СЧЁТА ЖИВЁТ ЗДЕСЬ — по той же причине, что и w626_metric_sum_file: критерий
# инцидентного слоя переписывался в каждой из четырёх волн подряд (6.2.2.9 →
# 6.2.3.7 → 6.2.4.6) и каждый раз проверялся ТОЛЬКО на стенде, постфактум.
# Здесь он получает офлайн-сторож на архиве collect-6.2.4, где обе лжи
# известны поимённо (containerd-shim и k3s-server).
#
# Классы корня судятся по-разному (см. комментарий в контролях):
#   instr — дерево измерителя, ложь только внутри тихого окна [t0,t1];
#   node  — нодовый актор, ложь за прогон, МИНУС окно стартов подов 6.2.6.10
#           (item 3, №263: цена старта пода — предмет своего критерия с
#           порогом, а не повод простить весь прогон).
# Режимы: win|outwin (тихое окно), phase|outphase (фаза атак),
#         podstart|outpodstart (окно стартов подов), all.
# ---------------------------------------------------------------------------
w626_incident_roots() { # $1=alerts.json $2=класс $3=режим $4=t0 $5=t1 $6=ps $7=pe $8=cs $9=ce $10=instr-comms $11=node-actors
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
# ITEM 7 (№280, критерий 6.2.4.6, ТРЕТЬЯ ось — по ДЕРЕВУ, а не по корню).
#
# w626_incident_roots выше судит только КОРЕНЬ цепочки (.details.root_comm),
# и промахивается мимо инцидентов, чей корень — родовой процесс сессии
# (sshd/sh/bash), но чья РАБОТА целиком — фон ноды. Архивный образец (№280,
# collect-6.2.5, 19:46:18Z, score=59, verdict=attack):
#
#   sshd → sshd → sh → run-parts → 00-header → uname
#
# Это вход MOTD при интерактивном логине (/etc/update-motd.d/*, запускаемый
# pam_motd через run-parts) — учебный образец фона ноды. Корень sshd не
# входит ни в W626_NODE_ACTORS (там k3s-server и т.п.), ни в comm измерителя,
# и старая (по корню) классификация инцидент не увидела ВООБЩЕ — он не попал
# ни в одну корзину вердикта.
#
# Определение "целиком состоит из фоновых акторов ноды" (plan.md §6.2.6, item
# 7): не требует, чтобы КАЖДЫЙ элемент цепочки поимённо входил в реестр —
# архивный образец несёт "uname" листом (00-header печатает версию ядра), и
# следующий MOTD-плагин с тем же успехом позовёт date/grep/cat/hostname;
# перечислять каждый возможный лист значило бы гоняться за находкой №280
# бесконечно. Вместо этого действует ТОТ ЖЕ принцип, что уже применяется к
# КОРНЮ в W626_NODE_ACTORS (например root=k3s-server прощает ВЕСЬ хвост
# containerd→flannel→bridge→host-local без разбора листьев): один узел
# дерева — W626_TREE_BG_ACTORS (run-parts, update-motd.d-скрипты по
# конвенции имени NN-*, landscape-sysin, unattended-upgr) ГДЕ УГОДНО в
# цепочке — маркер фоновой работы ноды, и всё, что под ним, наследует эту
# классификацию. Судит НЕЗАВИСИМО от корня: sshd/sh/bash в начале цепочки
# (сессионная обвязка логина, W626_TREE_PLUMBING) не топит и не оправдывает
# инцидент сам по себе — важен только факт присутствия названного актора.
# ---------------------------------------------------------------------------
W626_TREE_PLUMBING="sshd sh bash"
W626_TREE_BG_ACTORS="run-parts landscape-sysin unattended-upgr"
_w626_tree_is_bg_actor() { # $1=comm
    local c="$1"
    case " $W626_TREE_BG_ACTORS " in *" $c "*) return 0 ;; esac
    # /etc/update-motd.d/* — конвенция имени NN-название (00-header,
    # 10-help-text, 50-motd-news, …); comm обрезан ядром до 15 байт.
    case "$c" in [0-9][0-9]-*) return 0 ;; esac
    return 1
}
# $1=alerts.json $2=exclude-roots (корни, уже посчитанные классами
# node/instr — не дублировать) $3=cs (окно стартов подов, начало, 0=нет)
# $4=ce (окно стартов подов, конец). Как и node-класс, ложь считается за
# прогон ЦЕЛИКОМ, минус окно собственных стартов подов контроля 6.2.6.10
# (item 3) — MOTD на входе пода той же природы, что и churn других акторов.
w626_incident_tree_bg() { # $1=alerts.json $2=exclude-roots $3=cs $4=ce
    local exclude="${2:-}" cs="${3:-0}" ce="${4:-0}"
    jq -r '[.[]|select(.rule_id=="incident_confirmed_attack")]
      | to_entries[] | "\(.key)\t\((.value.details.root_comm // .value.comm))\t\((.value.details.process_chain // [])|join(","))\t\(.value.timestamp)"' \
        "$1" 2>/dev/null | while IFS=$'\t' read -r _idx _root _chain_csv _ts; do
        [ -z "$_chain_csv" ] && continue
        case " $exclude " in *" $_root "*) continue ;; esac
        local _saw_bg=0 _c
        IFS=',' read -ra _chain_arr <<< "$_chain_csv"
        for _c in "${_chain_arr[@]}"; do
            _w626_tree_is_bg_actor "$_c" && _saw_bg=1
        done
        [ "$_saw_bg" -eq 1 ] || continue
        if [ "$ce" != "0" ]; then
            local _tepoch
            _tepoch=$(date -d "$_ts" +%s 2>/dev/null || echo -1)
            if [ "$_tepoch" -ge "$cs" ] && [ "$_tepoch" -le "$ce" ]; then continue; fi
        fi
        printf '%s\t%s\t%s\n' "$_root" "$_chain_csv" "$_ts"
    done
}

# ---------------------------------------------------------------------------
# ITEM 7 (№279, критерий 6.2.6.A, продолжение — потери пролога поимённо).
#
# `ebpf_guard_events_dropped_total{collector,reason}` минус `path_denylist`
# (тот же законный фильтр, что исключает `_w626_real_drops`), по каждой
# паре {collector,reason} отдельно. Печатает "collector/reason +delta",
# по убыванию — постановка требует РАЗБИВКУ, а не только сумму: архив 6.2.4
# потерял 1014 файловых событий в `fileaccess/ringbuf_to_router`, и одно это
# имя называет причину точнее, чем итоговое число.
# ---------------------------------------------------------------------------
w626_drops_by_reason() { # $1=срез-начало $2=срез-конец
    awk '
        function label(line,   m, c, r) {
            c = "?"; r = "?"
            if (match(line, /collector="[^"]*"/)) c = substr(line, RSTART+11, RLENGTH-12)
            if (match(line, /reason="[^"]*"/)) r = substr(line, RSTART+8, RLENGTH-9)
            return c "/" r
        }
        /^ebpf_guard_events_dropped_total\{/ && !/reason="path_denylist"/ {
            k = label($0)
            if (FILENAME == ARGV[1]) a[k] += $NF; else { b[k] += $NF; seen[k] = 1 }
        }
        END {
            for (k in seen) { d = b[k] - (k in a ? a[k] : 0); if (d > 0) printf "%s %d\n", k, d }
        }' "$1" "$2" | sort -k2 -rn
}

# ---------------------------------------------------------------------------
# РЕЕСТР ВЫНЕСЕННЫХ ВЕРДИКТОВ — КЛЮЧ И ЧТЕНИЕ. Живут здесь по той же причине,
# что и ядро _w626_metric_sum: у реестра ДВА читателя (6.2.6.14 и 6.2.6.21,
# последний решает судьбу всего куста 6.2.x), и оба обязаны читать ТУ САМУЮ
# функцию, которая пишет, а не свою копию grep'а.
#
# ЧТО ЛЕЧИТ КЛЮЧ. Критерий 6.2.6.1 выносит ЧЕТЫРЕ подпунктных вердикта до
# своего главного («6.2.6.1 подпункт (3) ДОСТИГНУТО»), и все они писались в
# реестр строкой «6.2.6.1 OK». Условие 1 критерия 6.2.6.21 читает реестр
# буквально — и при ПРОВАЛЕННОМ гейте нашло бы OK подпункта, объявив условие
# взятым. Подпункт теперь получает ключ «<метка>/подпункт».
# ---------------------------------------------------------------------------
w626_label_key() { # $1=текст вердикта → ключ реестра ("" если метки в тексте нет
    local lbl
    lbl=$(printf '%s' "$1" | grep -oE '6\.2\.[123456]\.[A-Za-z0-9]+' | head -1)
    [ -n "${lbl:-}" ] || return 0
    # ТОЛЬКО «подпункт». Слово «половина» намеренно НЕ перехватывается: у
    # 6.2.4.5/6.2.6.22 ГЛАВНЫЙ вердикт сам звучит как «половины: …», и
    # переименование ключа по нему увело бы из реестра главную метку.
    case "$1" in
        *подпункт*) printf '%s/подпункт' "$lbl" ;;
        *)          printf '%s' "$lbl" ;;
    esac
}

# Метка ВЗЯТА, только если у неё есть строка OK и НЕТ строки FAIL. Одного
# grep'а по OK мало: метка может вынести оба вердикта (контроль исполнился
# дважды, ветка die сработала после pass) — тогда взятой она не является.
w626_label_taken() { # $1=метка $2=файл реестра
    local esc="${1//./\\.}"
    grep -qE "^${esc} OK$" "${2:-/dev/null}" 2>/dev/null || return 1
    grep -qE "^${esc} FAIL$" "${2:-/dev/null}" 2>/dev/null && return 1
    return 0
}

# ---------------------------------------------------------------------------
# ITEM 5 (№267/№268/№277/№286, критерий 6.2.6.15). Доля величины на
# нерезолвленном образе — по МЕТРИКЕ ebpf_guard_exe_path_lookups_total.
#
# ТРИ ОСИ, А НЕ ОДНА СМЕСЬ. До item 3 волны 6.2.6 у метрики был ровно один
# лейбл (result), и «unresolved=375» на архиве 6.2.5 складывало две РАЗНЫЕ
# гонки с разными причинами и разными починками (№277). После item 3 лейблов
# два: {result, field}, field ∈ {exe_path, parent_exe_path, ancestor_exe_path}.
#
# ВАЖНО ПРО ФОРМУ СТРОКИ. client_golang печатает лейблы В АЛФАВИТНОМ ПОРЯДКЕ,
# то есть после item 3 строка выглядит как
#   ebpf_guard_exe_path_lookups_total{field="exe_path",result="resolved"} N
# — прежний якорь `{result="resolved"}` не совпадает с ней НИ РАЗУ. Разбор,
# оставленный в форме до item 3, дал бы не «старую величину», а ЧЕСТНЫЙ НОЛЬ
# по всем осям и ложное ИЗМЕРЕНО (тот же класс, что [[agent-logs-json-not-logfmt]]).
# Поэтому совпадение здесь идёт по ЗНАЧЕНИЯМ лейблов, а не по их порядку, и
# отсутствие лейбла field выражается отдельной строкой field=НЕТ_ЛЕЙБЛА —
# это не ноль, это «item 3 не задеплоен», и вердикт по нему выносит контроль.
#
# Печатает по строке на ось:
#   field=<ось> resolved=<Δ> unresolved=<Δ> total=<Δ> unresolved_pct=<X.YZ>
# Порог не назначается (5.9.6, диагностика гонки №261).
# ---------------------------------------------------------------------------
W626_EXE_PATH_FIELDS="exe_path parent_exe_path ancestor_exe_path"
w626_exe_path_lookup_fraction() { # $1=срез-начало $2=срез-конец
    local fld rd ud total pct any=0
    _w626_exe_cell() { # $1=файл $2=result $3=field ("" = строка без лейбла field)
        awk -v res="$2" -v fld="$3" '
            $0 !~ /^ebpf_guard_exe_path_lookups_total\{/ { next }
            index($0, "result=\"" res "\"") == 0 { next }
            fld == "" { if (index($0, "field=\"") == 0) { s += $NF; f = 1 } ; next }
            index($0, "field=\"" fld "\"") { s += $NF; f = 1 }
            END { if (f) printf "%d", s+0; else printf "" }' "$1" 2>/dev/null
    }
    for fld in $W626_EXE_PATH_FIELDS; do
        local r0 r1 u0 u1
        r0=$(_w626_exe_cell "$1" resolved "$fld");   r1=$(_w626_exe_cell "$2" resolved "$fld")
        u0=$(_w626_exe_cell "$1" unresolved "$fld"); u1=$(_w626_exe_cell "$2" unresolved "$fld")
        # Ось, которой нет НИ НА ОДНОЙ границе, — не ноль, а отсутствие серии.
        if [ -z "${r1:-}" ] && [ -z "${u1:-}" ]; then
            printf "field=%s ОТСУТСТВУЕТ (серии нет в срезе закрытия)\n" "$fld"
            continue
        fi
        any=1
        rd=$(( ${r1:-0} - ${r0:-0} )); ud=$(( ${u1:-0} - ${u0:-0} )); total=$(( rd + ud ))
        if [ "$total" -gt 0 ]; then
            pct=$(awk -v u="$ud" -v t="$total" 'BEGIN{printf "%.2f", 100.0*u/t}')
        else
            pct="0.00"
        fi
        printf "field=%s resolved=%d unresolved=%d total=%d unresolved_pct=%s\n" "$fld" "$rd" "$ud" "$total" "$pct"
    done
    # Форма ДО item 3: лейбла field нет вовсе. Печатается ЯВНО и отдельной
    # осью — контроль обязан объявить критерий НЕИЗМЕРИМЫМ, а не прочитать
    # три нуля как измерение.
    local n0 n1 nu0 nu1
    n0=$(_w626_exe_cell "$1" resolved "");   n1=$(_w626_exe_cell "$2" resolved "")
    nu0=$(_w626_exe_cell "$1" unresolved ""); nu1=$(_w626_exe_cell "$2" unresolved "")
    if [ -n "${n1:-}" ] || [ -n "${nu1:-}" ]; then
        rd=$(( ${n1:-0} - ${n0:-0} )); ud=$(( ${nu1:-0} - ${nu0:-0} )); total=$(( rd + ud ))
        if [ "$total" -gt 0 ]; then
            pct=$(awk -v u="$ud" -v t="$total" 'BEGIN{printf "%.2f", 100.0*u/t}')
        else
            pct="0.00"
        fi
        printf "field=НЕТ_ЛЕЙБЛА resolved=%d unresolved=%d total=%d unresolved_pct=%s\n" "$rd" "$ud" "$total" "$pct"
    elif [ "$any" -eq 0 ]; then
        printf "field=НЕТ_МЕТРИКИ серия ebpf_guard_exe_path_lookups_total отсутствует в срезе закрытия\n"
    fi
}

# ---------------------------------------------------------------------------
# ITEM 5 (№286, критерий 6.2.6.22, половина (б)). Разбивка обходов
# родословной по ИСХОДУ: ebpf_guard_exe_path_ancestor_walk_total{outcome}.
#
# Пять исходов, каждый печатается ВСЕГДА (даже нулевым): именно нули здесь
# несут вердикт — ancestor=0 при ненулевых прочих означает «правка
# задеплоена и НЕ СРАБОТАЛА», а отсутствие серии целиком — «правка не
# задеплоена». Эти два состояния обязаны быть различимы, поэтому
# отсутствующая серия печатается словом, а не нулём.
# ---------------------------------------------------------------------------
W626_ANCESTOR_OUTCOMES="parent ancestor no_lineage comm_break exhausted"
w626_ancestor_walk_by_outcome() { # $1=срез-начало $2=срез-конец
    local oc v0 v1
    for oc in $W626_ANCESTOR_OUTCOMES; do
        v0=$(awk -v o="$oc" '$0 ~ /^ebpf_guard_exe_path_ancestor_walk_total\{/ && index($0, "outcome=\"" o "\"") {print $NF; f=1} END{if(!f) print ""}' "$1" 2>/dev/null)
        v1=$(awk -v o="$oc" '$0 ~ /^ebpf_guard_exe_path_ancestor_walk_total\{/ && index($0, "outcome=\"" o "\"") {print $NF; f=1} END{if(!f) print ""}' "$2" 2>/dev/null)
        if [ -z "${v1:-}" ]; then
            printf "outcome=%s ОТСУТСТВУЕТ\n" "$oc"
        else
            printf "outcome=%s delta=%d открытие=%s закрытие=%s\n" "$oc" "$(( ${v1:-0} - ${v0:-0} ))" "${v0:-нет}" "${v1:-0}"
        fi
    done
}

# ---------------------------------------------------------------------------
# ITEM 1 (№282, критерии 6.2.6.2/6.2.6.22(в)). Разбивка объёма по паре
# {rule_id, comm} — счётчик ebpf_guard_alert_volume_by_source_total, ось,
# которой у alerts_total нет и метрикой не восстановима.
#
# Печатает "<rule_id> <comm> <Δ>" по убыванию. Фильтры необязательны: $3 —
# список rule_id через пробел, $4 — comm (точное значение).
# ---------------------------------------------------------------------------
w626_volume_by_source() { # $1=срез-начало $2=срез-конец [$3=rule_id…] [$4=comm]
    awk -v ids="${3:-}" -v want_comm="${4:-}" '
        function val(line, name,   p) {
            if (match(line, name "=\"[^\"]*\"")) {
                p = substr(line, RSTART, RLENGTH)
                sub(name "=\"", "", p); sub("\"$", "", p)
                return p
            }
            return ""
        }
        BEGIN { n = split(ids, want, " ") }
        /^ebpf_guard_alert_volume_by_source_total\{/ {
            r = val($0, "rule_id"); c = val($0, "comm")
            if (r == "") next
            if (want_comm != "" && c != want_comm) next
            if (n > 0) { ok = 0; for (i = 1; i <= n; i++) if (want[i] == r) ok = 1; if (!ok) next }
            k = r " " c
            if (FILENAME == ARGV[1]) a[k] += $NF; else { b[k] += $NF; seen[k] = 1 }
        }
        END { for (k in seen) { d = b[k] - (k in a ? a[k] : 0); if (d > 0) printf "%s %d\n", k, d } }
    ' "$1" "$2" | sort -k3 -rn
}

# ---------------------------------------------------------------------------
# ITEM 6 (№282, открытый вопрос 13, подпункт критерия 6.2.6.1). Приращение
# rule_exceptions_total по КАЖДОЙ из восьми пар (rule_id, exception_name),
# заведённых item 6 по идиоме node-host-daemon.
#
# ПОЧЕМУ БЕЗ ПОРОГА. Имена, по которым сделаны сужения, взяты из ПРОЛОГА
# архива 6.2.5 (в границах окна стор не дал по этим правилам ни одной
# строки), поэтому ноль здесь — НЕ провал правки, а провал её АДРЕСНОСТИ:
# оконные алерты подняли другие comm. Различить эти два исхода можно только
# напечатав счётчик по каждому имени отдельно, что здесь и делается.
# ---------------------------------------------------------------------------
W626_ITEM6_EXCEPTIONS="sigma_cpu_info_access:node-motd-sysinfo
mitre_sandbox_detect_proc_read:node-motd-sysinfo
mitre_sandbox_detect_proc_read:systemd-logind-session-cgroup
container_escape_init_proc:node-motd-sysinfo
container_escape_init_proc:systemd-logind-session-cgroup
container_escape_init_proc:sshd-session-limits
container_escape_init_proc:k3s-server-node-netdev-poll
drift_new_file_dir_sensitive:sshd-authorized-keys"
w626_item6_exceptions() { # $1=срез-начало $2=срез-конец
    local pair rid name v0 v1
    for pair in $W626_ITEM6_EXCEPTIONS; do
        rid=${pair%%:*}; name=${pair##*:}
        v0=$(awk -v r="$rid" -v n="$name" '$0 ~ /^ebpf_guard_rule_exceptions_total\{/ && index($0, "rule_id=\"" r "\"") && index($0, "exception_name=\"" n "\"") {print $NF; f=1} END{if(!f) print 0}' "$1" 2>/dev/null)
        v1=$(awk -v r="$rid" -v n="$name" '$0 ~ /^ebpf_guard_rule_exceptions_total\{/ && index($0, "rule_id=\"" r "\"") && index($0, "exception_name=\"" n "\"") {print $NF; f=1} END{if(!f) print 0}' "$2" 2>/dev/null)
        printf "%s %s delta=%d\n" "$rid" "$name" "$(( ${v1:-0} - ${v0:-0} ))"
    done
}

# ---------------------------------------------------------------------------
# ITEM 4 (№283, критерий 6.2.6.20). Подавление синтетического правила
# anomaly_detection — приращение rule_exceptions_total{rule_id=
# "anomaly_detection"} ПО КАЖДОМУ имени исключения (verified-daemon-image /
# verified-daemon-lineage) плюс суммарная строка.
# ---------------------------------------------------------------------------
W626_ANOMALY_EXCEPTIONS="verified-daemon-image verified-daemon-lineage"
w626_anomaly_exceptions() { # $1=срез-начало $2=срез-конец
    local name v0 v1 sum=0 d
    for name in $W626_ANOMALY_EXCEPTIONS; do
        v0=$(awk -v n="$name" '$0 ~ /^ebpf_guard_rule_exceptions_total\{/ && index($0, "rule_id=\"anomaly_detection\"") && index($0, "exception_name=\"" n "\"") {print $NF; f=1} END{if(!f) print 0}' "$1" 2>/dev/null)
        v1=$(awk -v n="$name" '$0 ~ /^ebpf_guard_rule_exceptions_total\{/ && index($0, "rule_id=\"anomaly_detection\"") && index($0, "exception_name=\"" n "\"") {print $NF; f=1} END{if(!f) print 0}' "$2" 2>/dev/null)
        d=$(( ${v1:-0} - ${v0:-0} ))
        sum=$(( sum + d ))
        printf "%s delta=%d\n" "$name" "$d"
    done
    printf "ИТОГО delta=%d\n" "$sum"
}

# ---------------------------------------------------------------------------
# ITEM 5 (№268, критерий 6.2.6.1 подпункт 2). Приращение
# rule_exceptions_total ПО КАЖДОМУ из четырёх правил-двойников №253, ПО
# ОБОИМ именованным исключениям (verified-daemon-image — исход развилки
# №253; verified-daemon-lineage — исход развилки №261, item 1 волны 6.2.6).
# Печатает "rule_id image=<Δ> lineage=<Δ> total=<Δ>" на каждое правило,
# отсутствующая серия читается как 0 (архив ДО item 1 не знает lineage —
# это не провал самопроверки, а факт истории волны).
# ---------------------------------------------------------------------------
W626_TWIN_RULES="sigma_passwd_shadow_read_daemon sigma_log_deletion_daemon sigma_utmp_wtmp_modified_daemon sensitive_file_read_daemon"
w626_daemon_twin_exceptions() { # $1=срез-начало $2=срез-конец
    local rid image0 image1 lineage0 lineage1 id imd lnd tot
    for rid in $W626_TWIN_RULES; do
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
w626_self_test() { # $1=каталог архива (…/collect-6.2.2-run1 или …/collect-6.2.2)
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
    rl=$(w626_ratelimited_by_rule "$s" "$e")
    echo "$rl" | sed 's/^/    /'
    # Сторож №238 — это СОГЛАСОВАННОСТЬ списка с суммой, а не «список обязан
    # быть непуст». Первая редакция требовала непустоты безусловно и потому
    # ложно проваливалась на архиве, где срез лимитера ЧЕСТНО нулевой
    # (collect-6.2.4: срез 0 второй прогон подряд — см. plan.md §6.2.4). Тот
    # же дефект, который лечит сам критерий 6.2.2.2 в контролях: пустой
    # список при НЕНУЛЕВОЙ сумме — находка №238; пустой список при нулевой
    # сумме — верное измерение.
    rl_sum=$(w626_metric_sum_file ebpf_guard_alerts_ratelimited_by_rule_total "" "$e")
    rl_sum=$(( rl_sum - $(w626_metric_sum_file ebpf_guard_alerts_ratelimited_by_rule_total "" "$s") ))
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
    vol=$(w626_volume_delta "$s" "$e")
    sum=$(w626_volume_by_rule "$s" "$e" | awk '{s+=$2} END{printf "%d", s+0}')
    w626_volume_by_rule "$s" "$e" | head -8 | sed 's/^/    /'
    echo "  прямая дельта объёма (а): $vol; сумма разбивки: $sum"
    if [ "$vol" -le 0 ]; then
        echo "  ПРОВАЛ: прямая дельта объёма не положительна — архив не тот"; rc=1
    else
        pct=$(awk -v s="$sum" -v v="$vol" 'BEGIN{printf "%.1f", 100.0*s/v}')
        echo "  покрытие разбивки: $pct% (критерий 6.2.2.3 требует ≥ 95%)"
        awk -v s="$sum" -v v="$vol" 'BEGIN{exit !(s >= 0.95*v)}' || { echo "  ПРОВАЛ: разбивка (а) не покрывает величину"; rc=1; }
    fi

    echo "=== №248 + решение 1: величина (в) поимённо — критерий 6.2.6.2 ==="
    local v_total v_sum v_top v_second
    v_total=$(w626_value_v_total "$s" "$e")
    v_sum=$(w626_value_v_by_rule "$s" "$e" | awk '{s+=$2} END{printf "%d", s+0}')
    w626_value_v_by_rule "$s" "$e" | head -8 | sed 's/^/    /'
    v_top=$(w626_value_v_by_rule "$s" "$e" | awk 'NR==1{print $1}')
    v_second=$(w626_value_v_by_rule "$s" "$e" | awk 'NR==2{print $1}')
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
        top_line=$(w626_value_v_by_rule "$s" "$e" | awk -v r="$want_top" '$1==r{print $2}')
        second_line=$(w626_value_v_by_rule "$s" "$e" | awk -v r="$want_second" '$1==r{print $2}')
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
        beacon_v=$(w626_value_v_by_rule "$s" "$e" | awk '$1=="c2_periodic_beacon_pattern"{print $2}')
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
        echo "  покрытие разбивки (в): $pct% (критерий 6.2.6.2 требует ≥ 95%)"
        awk -v s="$v_sum" -v v="$v_total" 'BEGIN{exit !(s >= 0.95*v)}' || { echo "  ПРОВАЛ: разбивка (в) не покрывает величину"; rc=1; }
    fi

    echo "=== №267/№268 (item 5, критерий 6.2.6.15): доля величины на нерезолвленном образе ==="
    # ФОРМА ОТВЕТА СМЕНИЛАСЬ ВМЕСТЕ С МЕТРИКОЙ (item 3, №277): функция теперь
    # печатает СТРОКУ НА ОСЬ. Архивы 6.2.2/6.2.4/6.2.5 сняты ДО item 3 и
    # лейбла field не несут — их числа обязаны воспроизводиться под осью
    # «НЕТ_ЛЕЙБЛА», и именно она сверяется здесь. Ожидание в СТАРОЙ форме
    # («resolved=… unresolved=…» без имени оси) означало бы, что сторож
    # проверяет форму, которой продукт больше не производит.
    local frac frac_legacy
    frac=$(w626_exe_path_lookup_fraction "$s" "$e")
    printf '%s\n' "$frac" | sed 's/^/  /'
    frac_legacy=$(printf '%s\n' "$frac" | sed -n 's/^field=НЕТ_ЛЕЙБЛА //p')
    if [ "$base" = "collect-6.2.4" ]; then
        if [ "$frac_legacy" = "resolved=6118 unresolved=348 total=6466 unresolved_pct=5.38" ]; then
            echo "  OK: 6.2.6.15 воспроизводит архивные числа находки №261 (unresolved 348 из 6466) под осью НЕТ_ЛЕЙБЛА — архив снят до item 3"
        else
            echo "  ПРОВАЛ: 6.2.6.15 ожидало по оси НЕТ_ЛЕЙБЛА 'resolved=6118 unresolved=348 total=6466 unresolved_pct=5.38', получено '$frac_legacy'"; rc=1
        fi
    fi
    if [ "$base" = "collect-6.2.5" ] && [ "$frac_legacy" != "resolved=5976 unresolved=375 total=6351 unresolved_pct=5.90" ]; then
        echo "  ПРОВАЛ: на collect-6.2.5 ожидалось 'resolved=5976 unresolved=375 total=6351 unresolved_pct=5.90' (база постановки 6.2.6.15), получено '$frac_legacy'"; rc=1
    fi

    echo "=== №268 (item 5, критерий 6.2.6.1 подпункт 2): двойники №253 по обоим исключениям ==="
    local twin_out
    twin_out=$(w626_daemon_twin_exceptions "$s" "$e")
    echo "$twin_out" | sed 's/^/    /'
    if [ "$base" = "collect-6.2.4" ]; then
        # Архив 6.2.4 предшествует item 1 волны 6.2.6 — verified-daemon-lineage
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

    echo "=== №267 (item 5, критерий 6.2.6.11): _w626_metric_sum с фильтром по comm — синтетический сторож ==="
    # Синтетический срез, где и w626sig, и bash дали приращение
    # signature_cap_reached_total — ровно форма архива №267 (страж на срезе,
    # где bash тоже вырос, требование постановки item 5).
    local synA synB syn_all syn_comm m=ebpf_guard_drift_baseline_signature_cap_reached_total
    synA=$(mktemp); synB=$(mktemp)
    printf 'ebpf_guard_drift_baseline_signature_cap_reached_total{comm="w626sig"} 5\nebpf_guard_drift_baseline_signature_cap_reached_total{comm="bash"} 5\n' > "$synA"
    printf 'ebpf_guard_drift_baseline_signature_cap_reached_total{comm="w626sig"} 7\nebpf_guard_drift_baseline_signature_cap_reached_total{comm="bash"} 12\n' > "$synB"
    # Считается ТОЙ ЖЕ функцией, которой считает прогон (w626_metric_sum_file —
    # ядро _w626_metric_sum), а не переписанным здесь awk: сторож обязан
    # судить код, а не свою копию кода.
    syn_all=$(( $(w626_metric_sum_file "$m" "" "$synB") - $(w626_metric_sum_file "$m" "" "$synA") ))
    syn_comm=$(( $(w626_metric_sum_file "$m" "w626sig" "$synB") - $(w626_metric_sum_file "$m" "w626sig" "$synA") ))
    rm -f "$synA" "$synB"
    echo "  без фильтра (пустой аргумент, дефект №267): Δ=$syn_all (это bash+w626sig вместе — 2+7=9)"
    echo "  с фильтром по comm=\"w626sig\" (item 5 чинит): Δ=$syn_comm (только w626sig — 2)"
    if [ "$syn_all" -eq 9 ] && [ "$syn_comm" -eq 2 ]; then
        echo "  OK: непустой comm-фильтр отделяет w626sig от bash — фикс №267 воспроизводим офлайн, без стенда"
    else
        echo "  ПРОВАЛ: ожидалось Δ_без_фильтра=9, Δ_с_фильтром=2 — получено $syn_all / $syn_comm"; rc=1
    fi

    # === №262/№263 (item 2/item 3, критерии 6.2.4.6 и 6.2.6.16): инцидентный
    # слой на архиве. Сторож включается только там, где архив несёт снимок
    # инцидентов (collect-6.2.4 — первый такой), и проверяет ДВЕ вещи разом:
    #   (1) обе лжи архива названы поимённо (containerd-shim и k3s-server) —
    #       то есть счёт по классу "node" видит именно их;
    #   (2) вычитание окна стартов подов (item 3) НИЧЕГО НЕ ТЕРЯЕТ: что
    #       уходит из вердикта 6.2.4.6, обязано попасть в половину «окно
    #       стартов подов» критерия 6.2.6.16.
    local inc="$archive/controls/artifacts/alerts-incidents.json"
    if [ -s "$inc" ]; then
        echo "=== №262/№263 (критерии 6.2.4.6/6.2.6.16): инцидентный слой на архиве ==="
        local instr="bash sh curl jq awk grep sed cat dirname pgrep date kubectl go ld cut wc find tr head tail sleep setsid dd printf"
        local actors="k3s-server kubelet containerd containerd-shim containerd-shim-runc-v2 runc runc:[1:CHILD] runc:[2:INIT] coredns local-path-prov kube-proxy pause iptables ip6tables kubectl flannel bridge loopback"
        local all_roots podstart_roots out_roots
        all_roots=$(w626_incident_roots "$inc" node all 0 0 0 0 0 0 "$instr" "$actors" | jq -r 'unique|join(" ")')
        echo "    корни класса «нодовый актор» за архив: ${all_roots:-нет}"
        if [ "$base" = "collect-6.2.4" ]; then
            if [ "$all_roots" = "containerd-shim k3s-server" ]; then
                echo "  OK: обе лжи архива 6.2.4 названы поимённо (containerd-shim, k3s-server) — счёт видит ровно их"
            else
                echo "  ПРОВАЛ: ожидались «containerd-shim k3s-server», получено «${all_roots:-нет}»"; rc=1
            fi
            # Окно стартов подов прогона 6.2.4: churn шёл между 6.2.1.2b и
            # 6.2.1.8, обе лжи (20:35:36/37Z) лежат внутри него.
            podstart_roots=$(w626_incident_roots "$inc" node podstart 0 0 0 0 1788813300 1788813390 "$instr" "$actors" | jq 'length')
            out_roots=$(w626_incident_roots "$inc" node outpodstart 0 0 0 0 1788813300 1788813390 "$instr" "$actors" | jq 'length')
            echo "    item 3: внутри окна стартов подов $podstart_roots, вне его (вердикт 6.2.4.6) $out_roots"
            if [ "$podstart_roots" -eq 2 ] && [ "$out_roots" -eq 0 ]; then
                echo "  OK: вычитание окна стартов подов (item 3) переносит обе лжи в половину 6.2.6.16, а не теряет их"
            else
                echo "  ПРОВАЛ: ожидалось «внутри 2, вне 0» — получено «внутри $podstart_roots, вне $out_roots»"; rc=1
            fi
            # Пустое окно (ce==0) не имеет права вычитать ничего.
            out_roots=$(w626_incident_roots "$inc" node outpodstart 0 0 0 0 0 0 "$instr" "$actors" | jq 'length')
            if [ "$out_roots" -eq 2 ]; then
                echo "  OK: при пустом окне стартов подов (контроль churn не исполнялся) вердикт 6.2.4.6 считает обе лжи"
            else
                echo "  ПРОВАЛ: пустое окно стартов подов вычло что-то из вердикта — получено $out_roots вместо 2"; rc=1
            fi
        fi

        # === ITEM 7 (№280, критерий 6.2.4.6, ТРЕТИЙ КЛАСС — по дереву) ===
        # Архив collect-6.2.5 несёт ровно образец находки №280: инцидент
        # 19:46:18Z, корень sshd, цепочка sshd→sshd→sh→run-parts→00-header→
        # uname. Ни root-класс "node", ни "instr" его не видят (корень sshd
        # не входит ни в один список) — до item 7 критерий 6.2.4.6 проходил
        # бы МИМО этой лжи молча.
        if [ "$base" = "collect-6.2.5" ]; then
            echo "=== №280 (item 7, критерий 6.2.4.6, класс «по дереву»): MOTD-инцидент с корнем sshd ==="
            local tree_out tree_count
            tree_out=$(w626_incident_tree_bg "$inc" "$actors $instr" 0 0)
            tree_count=$(printf '%s\n' "$tree_out" | grep -c . || true)
            echo "$tree_out" | sed 's/^/    /'
            if [ "${tree_count:-0}" -eq 1 ] && printf '%s' "$tree_out" | grep -q '^sshd	sshd,sshd,sh,run-parts,00-header,uname	'; then
                echo "  OK: инцидент 19:46:18Z (корень sshd, run-parts/00-header в цепочке) пойман классом «по дереву» — до item 7 не был виден ни одним классом"
            else
                echo "  ПРОВАЛ: ожидался ровно один инцидент «sshd,sshd,sh,run-parts,00-header,uname» — получено «$tree_out»"; rc=1
            fi
            # Отрицательный контроль: k3s-server/bash/cron-корни (уже
            # посчитанные классами node/instr) НЕ ДОЛЖНЫ задваиваться классом
            # «по дереву», даже если исключить их явно не удалось бы —
            # ни один из них не несёт W626_TREE_BG_ACTORS в цепочке.
            local tree_noexclude
            tree_noexclude=$(w626_incident_tree_bg "$inc" "" 0 0 | grep -c . || true)
            if [ "${tree_noexclude:-0}" -eq 1 ]; then
                echo "  OK: без списка исключений класс «по дереву» всё равно даёт ровно 1 — k3s-server/bash/cron не несут фонового актора в цепочке, задвоения нет"
            else
                echo "  ПРОВАЛ: без исключений ожидался 1 инцидент класса «по дереву», получено $tree_noexclude"; rc=1
            fi
        fi
    fi

    # === ITEM 7 (№279, критерий 6.2.6.A, половина 2): разбивка потерь пролога
    #     по {collector,reason}. Архив collect-6.2.5 — точный образец находки
    #     №279 (1014 файловых событий, fileaccess/ringbuf_to_router).
    local prologue="$archive/metrics-prologue-start-${base#collect-}.txt"
    if [ -s "$prologue" ] && [ -s "$e" ]; then
        echo "=== №279 (item 7, критерий 6.2.6.A половина 2): разбивка потерь пролога по {collector,reason} ==="
        local dr
        dr=$(w626_drops_by_reason "$prologue" "$s")
        echo "$dr" | sed 's/^/    /'
        if [ "$base" = "collect-6.2.5" ]; then
            if [ "$dr" = "fileaccess/ringbuf_to_router 1014" ]; then
                echo "  OK: разбивка воспроизводит архивную находку №279 поимённо (fileaccess/ringbuf_to_router +1014)"
            else
                echo "  ПРОВАЛ: ожидалось 'fileaccess/ringbuf_to_router 1014', получено '$dr'"; rc=1
            fi
        fi
    fi

    # === ITEM 3/5/4/6 (№277/№286/№283/№282): оси, которых в архиве 6.2.5 нет
    #     по построению — правки этих items задеплоены ПОСЛЕ него. Проверяются
    #     двумя способами сразу:
    #       1) на самом архиве — разбор ОБЯЗАН честно сказать «нет лейбла /
    #          нет серии», а не напечатать нули (это и есть ложное ИЗМЕРЕНО,
    #          которым волна 6.2.5 уже платила прогоном);
    #       2) на синтетическом срезе — в ОБОИХ порядках лейблов, потому что
    #          порядок в экспозиции задаётся клиентской библиотекой, а не нами,
    #          и якорь, зависящий от порядка, ломается молча.
    echo "=== №277 (item 3, критерий 6.2.6.15): разбор осей exe_path_lookups_total ==="
    local axes_arch
    axes_arch=$(w626_exe_path_lookup_fraction "$s" "$e")
    echo "$axes_arch" | sed 's/^/    /'
    if printf '%s' "$axes_arch" | grep -q 'field=НЕТ_ЛЕЙБЛА'; then
        echo "  OK: архив ДО item 3 распознан как «лейбла field нет» — контроль обязан объявить 6.2.6.15 НЕИЗМЕРИМЫМ, а не прочитать нули"
    else
        echo "  ПРОВАЛ: архив 6.2.5 несёт метрику БЕЗ лейбла field, а разбор этого не сказал: $axes_arch"; rc=1
    fi
    # Вердикт синтетической части возвращается КОДОМ ВОЗВРАТА, а не stdout:
    # функция печатает отчёт, и $( ) съел бы его целиком, подставив весь
    # отчёт в rc (арифметика молча получила бы мусор).
    w626_synthetic_axes_test || rc=1

    [ "$rc" -eq 0 ] && echo "СТОРОЖ ПРОЙДЕН ($base)" || echo "СТОРОЖ ПРОВАЛЕН ($base)"
    return "$rc"
}

# ---------------------------------------------------------------------------
# Синтетические срезы для осей, появившихся ПОСЛЕ архива collect-6.2.5.
# Отчёт идёт в stdout, вердикт — КОДОМ ВОЗВРАТА (0 = пройдено). Вызывается и
# из w626_self_test, и отдельно (--axes-test) без стенда и без архива.
# ---------------------------------------------------------------------------
w626_synthetic_axes_test() {
    local rc=0 tmp s e out
    tmp=$(mktemp -d)
    s="$tmp/start.txt"; e="$tmp/end.txt"

    # Порядок лейблов НАМЕРЕННО разный в двух срезах: client_golang печатает
    # их по алфавиту (field раньше result), но контракт разбора — совпадение
    # по ЗНАЧЕНИЮ, а не по позиции. Срез открытия написан «наоборот».
    cat > "$s" <<'EOF'
ebpf_guard_exe_path_lookups_total{result="resolved",field="exe_path"} 100
ebpf_guard_exe_path_lookups_total{result="unresolved",field="exe_path"} 10
ebpf_guard_exe_path_lookups_total{result="resolved",field="parent_exe_path"} 5
ebpf_guard_exe_path_lookups_total{result="unresolved",field="parent_exe_path"} 1
ebpf_guard_exe_path_lookups_total{result="resolved",field="ancestor_exe_path"} 40
ebpf_guard_exe_path_lookups_total{result="unresolved",field="ancestor_exe_path"} 4
ebpf_guard_exe_path_ancestor_walk_total{outcome="parent"} 300
ebpf_guard_exe_path_ancestor_walk_total{outcome="ancestor"} 20
ebpf_guard_exe_path_ancestor_walk_total{outcome="no_lineage"} 0
ebpf_guard_exe_path_ancestor_walk_total{outcome="comm_break"} 7
ebpf_guard_exe_path_ancestor_walk_total{outcome="exhausted"} 0
ebpf_guard_alert_volume_by_source_total{comm="cron",rule_id="sigma_passwd_shadow_read_daemon"} 10
ebpf_guard_alert_volume_by_source_total{comm="sshd",rule_id="sigma_passwd_shadow_read_daemon"} 3
ebpf_guard_rule_exceptions_total{exception_name="verified-daemon-image",rule_id="anomaly_detection"} 2
ebpf_guard_rule_exceptions_total{exception_name="node-motd-sysinfo",rule_id="sigma_cpu_info_access"} 1
EOF
    cat > "$e" <<'EOF'
ebpf_guard_exe_path_lookups_total{field="exe_path",result="resolved"} 180
ebpf_guard_exe_path_lookups_total{field="exe_path",result="unresolved"} 30
ebpf_guard_exe_path_lookups_total{field="parent_exe_path",result="resolved"} 5
ebpf_guard_exe_path_lookups_total{field="parent_exe_path",result="unresolved"} 1
ebpf_guard_exe_path_lookups_total{field="ancestor_exe_path",result="resolved"} 90
ebpf_guard_exe_path_lookups_total{field="ancestor_exe_path",result="unresolved"} 4
ebpf_guard_exe_path_ancestor_walk_total{outcome="parent"} 700
ebpf_guard_exe_path_ancestor_walk_total{outcome="ancestor"} 63
ebpf_guard_exe_path_ancestor_walk_total{outcome="no_lineage"} 0
ebpf_guard_exe_path_ancestor_walk_total{outcome="comm_break"} 12
ebpf_guard_exe_path_ancestor_walk_total{outcome="exhausted"} 0
ebpf_guard_alert_volume_by_source_total{comm="cron",rule_id="sigma_passwd_shadow_read_daemon"} 10
ebpf_guard_alert_volume_by_source_total{comm="sshd",rule_id="sigma_passwd_shadow_read_daemon"} 9
ebpf_guard_rule_exceptions_total{exception_name="verified-daemon-image",rule_id="anomaly_detection"} 9
ebpf_guard_rule_exceptions_total{exception_name="node-motd-sysinfo",rule_id="sigma_cpu_info_access"} 4
EOF

    echo "=== синтетика: ключ реестра вердиктов и чтение «метка взята» (вход условий 1/2 критерия 6.2.6.21) ==="
    local reg="$tmp/emitted.txt"
    {
        echo "$(w626_label_key '6.2.6.1 подпункт (3) ДОСТИГНУТО (№268): напечатан обеими границами') OK"
        echo "$(w626_label_key '6.2.6.1 подпункт (4) ИЗМЕРЕНО (№282): 3 из 8 имён') OK"
        echo "$(w626_label_key '6.2.6.1 ПРОВАЛЕН (величина — НИЖНЯЯ оценка): цена ноды 186 алертов/ч') FAIL"
        echo "$(w626_label_key '6.2.4.6 ДОСТИГНУТО: ложных incident_confirmed_attack ноль') OK"
        echo "$(w626_label_key '6.2.4.5 ДОСТИГНУТО: все четыре половины') OK"
    } > "$reg"
    sed 's/^/    /' "$reg"
    if w626_label_taken 6.2.6.1 "$reg"; then
        echo "  ПРОВАЛ: 6.2.6.1 прочитана ВЗЯТОЙ при провале гейта — подпунктный OK утёк в главный ключ (ложный PASS условия 1 критерия 6.2.6.21)"; rc=1
    else
        echo "  OK: провал гейта не перекрыт двумя подпунктными OK — условие 1 читается верно"
    fi
    if w626_label_taken 6.2.4.6 "$reg" && w626_label_taken 6.2.4.5 "$reg"; then
        echo "  OK: главные вердикты (в том числе «все четыре половины») остались под СВОИМ ключом и читаются взятыми"
    else
        echo "  ПРОВАЛ: главная метка не читается взятой — ключ увёл её в сторону"; rc=1
    fi
    if w626_label_taken 6.2.6.99 "$reg"; then
        echo "  ПРОВАЛ: метка, которой в реестре нет, прочитана взятой"; rc=1
    else
        echo "  OK: отсутствующая метка взятой не считается"
    fi

    echo "=== синтетика: три оси exe_path_lookups_total, лейблы в РАЗНОМ порядке на границах ==="
    out=$(w626_exe_path_lookup_fraction "$s" "$e")
    echo "$out" | sed 's/^/    /'
    if [ "$(printf '%s' "$out" | grep -c '^field=')" -eq 3 ] \
       && printf '%s' "$out" | grep -q '^field=exe_path resolved=80 unresolved=20 total=100 unresolved_pct=20.00$' \
       && printf '%s' "$out" | grep -q '^field=parent_exe_path resolved=0 unresolved=0 total=0 unresolved_pct=0.00$' \
       && printf '%s' "$out" | grep -q '^field=ancestor_exe_path resolved=50 unresolved=0 total=50 unresolved_pct=0.00$'; then
        echo "  OK: три оси разобраны раздельно и независимо от порядка лейблов; нулевая ось parent_exe_path — штатный исход (открытый вопрос 12), а не потеря"
    else
        echo "  ПРОВАЛ: разбор трёх осей не совпал с ожидаемым"; rc=1
    fi

    echo "=== синтетика: разбивка обходов родословной по исходу (6.2.6.22 половина б) ==="
    out=$(w626_ancestor_walk_by_outcome "$s" "$e")
    echo "$out" | sed 's/^/    /'
    if printf '%s' "$out" | grep -q '^outcome=ancestor delta=43 ' && printf '%s' "$out" | grep -q '^outcome=comm_break delta=5 '; then
        echo "  OK: ancestor=43 и comm_break=5 прочитаны прямой дельтой"
    else
        echo "  ПРОВАЛ: разбивка обходов не совпала с ожидаемой"; rc=1
    fi
    out=$(w626_ancestor_walk_by_outcome "$e" "$e")
    if [ "$(printf '%s' "$out" | grep -c 'delta=0')" -eq 5 ]; then
        echo "  OK: на одинаковых срезах все пять исходов дают 0 (а не «серии нет»)"
    else
        echo "  ПРОВАЛ: нулевая дельта не отличена от отсутствия серии"; rc=1
    fi
    out=$(w626_ancestor_walk_by_outcome "$tmp/../nonexistent-start" "$s" 2>/dev/null; w626_ancestor_walk_by_outcome "$s" /dev/null)
    if printf '%s' "$out" | grep -q 'outcome=ancestor ОТСУТСТВУЕТ'; then
        echo "  OK: отсутствие серии в срезе закрытия названо словом, а не нулём (item 5 не задеплоен ≠ item 5 не сработал)"
    else
        echo "  ПРОВАЛ: отсутствие серии прочитано как ноль — два разных состояния слиты"; rc=1
    fi

    echo "=== синтетика: объём по паре {rule_id, comm} (item 1, 6.2.6.2/6.2.6.22в) ==="
    out=$(w626_volume_by_source "$s" "$e")
    echo "$out" | sed 's/^/    /'
    if [ "$(printf '%s' "$out" | grep -c .)" -eq 1 ] && printf '%s' "$out" | grep -q '^sigma_passwd_shadow_read_daemon sshd 6$'; then
        echo "  OK: пара с нулевой дельтой (comm=cron) не печатается, ненулевая — печатается числом"
    else
        echo "  ПРОВАЛ: разбивка по {rule_id, comm} не совпала с ожидаемой"; rc=1
    fi
    out=$(w626_volume_by_source "$s" "$e" "sigma_passwd_shadow_read_daemon" "cron")
    if [ -z "$out" ]; then
        echo "  OK: фильтр по comm=cron даёт пусто — утечка двойников с comm=cron за окно = 0 (форма вердикта 6.2.6.22в)"
    else
        echo "  ПРОВАЛ: фильтр по comm вернул строки при нулевой дельте: $out"; rc=1
    fi

    echo "=== синтетика: исключения item 6 и item 4 поимённо ==="
    out=$(w626_item6_exceptions "$s" "$e")
    echo "$out" | sed 's/^/    /'
    if [ "$(printf '%s' "$out" | grep -c .)" -eq 8 ] && printf '%s' "$out" | grep -q '^sigma_cpu_info_access node-motd-sysinfo delta=3$'; then
        echo "  OK: все восемь пар (rule_id, exception_name) напечатаны, отсутствующие серии читаются нулём ЯВНО"
    else
        echo "  ПРОВАЛ: разбор восьми исключений item 6 не совпал с ожидаемым"; rc=1
    fi
    out=$(w626_anomaly_exceptions "$s" "$e")
    echo "$out" | sed 's/^/    /'
    if printf '%s' "$out" | grep -q '^ИТОГО delta=7$'; then
        echo "  OK: переезд объёма anomaly_detection в исключения читается суммой по именам"
    else
        echo "  ПРОВАЛ: сумма исключений anomaly_detection не совпала"; rc=1
    fi

    rm -rf "$tmp"
    [ "$rc" -eq 0 ] && echo "СИНТЕТИЧЕСКАЯ ЧАСТЬ ПРОЙДЕНА" || echo "СИНТЕТИЧЕСКАЯ ЧАСТЬ ПРОВАЛЕНА"
    return "$rc"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    case "${1:-}" in
        --self-test) shift; w626_self_test "${1:-}" ;;
        --axes-test) w626_synthetic_axes_test ;;
        *) echo "использование: $0 --self-test <каталог архива, collect-6.2.2-run1 или collect-6.2.2> | --axes-test"; exit 2 ;;
    esac
fi
