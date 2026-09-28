#!/bin/bash
# wave6.4-item5-item6-tls-controls.sh — items 5/6 постановки волны 6.4
# (plan.md §6.4 TLS-коллектор): положительный plaintext-контроль
# долгоживущим процессом (item 5) и контейнерный случай в mount-ns пода
# (item 6, находка №380). Пишет сторожевые файлы, которые читают эмиттеры
# 6.4.3/6.4.4 в run-6.4-pipeline.sh — САМ НИЧЕГО не решает про класс
# ДОСТИГНУТО/ПРОВАЛЕН, только измеряет и называет класс неизмеримости, где
# он есть (никогда не гадает нулём — [[verdict-zero-needs-its-class-presented]]).
#
# МЕСТО В ПОРЯДКЕ: зовётся из run-6.4-pipeline.sh ПОСЛЕ снятия журнала окна
# (после Шага 4 контролей волны 6.3), тем же приёмом, что и опорный набор
# item 3 волны 6.3.9.F — оба контроля здесь подают НАСТОЯЩИЙ TLS-обмен и
# внутри окна вошли бы в измеряемую цену события ноды, ради которой прогон и
# делается. Артефакты пишутся в $W64_ART (НЕ в /root/ — там висит
# drift-правило, и собственные файлы контроля создали бы алерты на самих
# себя, [[control-artifacts-must-live-outside-root]]).
#
# СЦЕНАРИЙ ЖЁСТКИЙ (постановка item 5): держатель — процесс, слинкованный с
# libssl, СТАРТУЕТ и ждёт БОЛЬШЕ collectors.tls.scan_interval (умолчание 30с,
# internal/config/config.go:2278) ПЕРЕД обменом, подтверждая
# ebpf_guard_tls_tracked_pids_total>=1 СВОИМ прибором (не слепым sleep — тот
# же класс дефекта, что [[control-payload-must-outlive-its-readlink]]), и
# ТОЛЬКО ПОТОМ начинает обмен. curl НЕ годится: живёт < 1с, периодический
# сканер процессов его не увидит НИКОГДА, и ноль прочитался бы как «детект
# мёртв», а не как «контроль неверно поставлен».
#
# Вход: W64_ART (обязателен, каталог для артефактов — уже вне /root/, тот же
# каталог, что и остальные контроли прогона), W64_API (http://host:port, без
# завершающего /), W64_TOKEN (bearer), W64_NS (k8s-неймспейс item 6,
# умолчание w64), W64_CONTROLS=on|off (умолчание off — тот же логический
# тумблер, что W63_BASELINE_CONTROLS у item 3, стар архив без этой правки не
# ломается).
#
# Выход: $W64_ART/tls-control-plaintext.txt (events_delta=/manifest_alerts=/
# manifest_alerts_delta=/manifest_alerts_since=/cut_epoch=/dedup_delta=/
# ratelimit_delta= ЛИБО class=; три последние — ось подавления, №493), $W64_ART/tls-control-container.txt (bound=/identity_match=/
# event= ЛИБО class=) — формат, который уже читают 6.4.3/6.4.4.

set +e +o pipefail
set -u

W64_ART="${W64_ART:?W64_ART обязателен}"
W64_API="${W64_API:?W64_API обязателен}"
W64_TOKEN="${W64_TOKEN:-}"
W64_NS="${W64_NS:-w64}"
W64_CONTROLS="${W64_CONTROLS:-off}"
W64_SCAN_INTERVAL_S="${W64_SCAN_INTERVAL_S:-30}"
# Журнал агента — единственный источник ПОИМЁННОЙ привязки (№453). Имя юнита
# передаёт пайплайн; умолчание совпадает с его собственным.
W64_SVC="${W64_SVC:-ebpf-guard-test.service}"

if [ "$W64_CONTROLS" = "off" ]; then
    echo "--- items 5/6 волны 6.4: W64_CONTROLS=off — контроли не поставлены, 6.4.3/6.4.4 назовут класс сами ---"
    exit 0
fi

echo "--- items 5/6 волны 6.4: plaintext-контроль долгоживущим процессом (item 5) и контейнерный случай (item 6) — ПОСЛЕ снятия журнала окна ---"

_w64_metrics() { curl -s --max-time 10 -H "Authorization: Bearer $W64_TOKEN" "$W64_API/metrics" 2>/dev/null; }

_w64_is_num() { case "${1:-}" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac; }

# Метрика ebpf_guard_tls_tracked_pids_total; печатает НЕИЗМЕРИМ отдельно от
# нуля ([[gated-metric-cannot-carry-product-verdict]] — нет серии ≠ ноль).
_w64_tracked() { _w64_metrics | awk '$1=="ebpf_guard_tls_tracked_pids_total"{print $2+0; f=1} END{if(!f) print ""}'; }
_w64_mismatch_failures() { _w64_metrics | awk '/^ebpf_guard_tls_attach_failures_total\{/ && /reason="libssl_mismatch"/{s+=$NF; f=1} END{print (f? s+0 : "")}'; }

# Дедуп по правилу (№455). Дедуп стоит ПЕРЕД лимитером и ключуется
# {rule_id,pid,comm}: два обмена одного правила с РАЗНЫХ pid не схлопываются,
# но повторы одного pid — схлопываются. Контроль обязан читать этот срез, иначе
# «алертов 0» неотличимо от «алерт был и подавлен слоем»
# ([[control-after-attacks-hits-filled-limiter]], [[dedup-is-third-suppression-layer]]).
_w64_dedup_rule() { _w64_metrics | awk -v r="$1" '$0 ~ /^ebpf_guard_alerts_dedup_dropped_by_rule_total\{/ && index($0, "rule_id=\"" r "\"") {print $NF+0; f=1} END{if(!f) print 0}'; }
# №456: СУММА по сериям, а не печать каждой. Серия events_total расщепляется
# лейблами {namespace,node,pod}: пока пода нет — одна строка, как только под
# отдал событие — ДВЕ, и прежняя форма печатала два числа, из которых
# _w64_is_num делал НЕИЗМЕРИМО. Дефект латентный: у item 5 (до пода) помощник
# работал, у item 6 (после) — нет, то есть он ломался ровно на том контроле,
# ради которого заведён ([[metric-label-added-breaks-awk-anchors]] в форме
# «выросло ЧИСЛО серий, а не порядок лейблов»).
_w64_events_tls() { _w64_metrics | awk '/^ebpf_guard_events_total\{/ && /type="tls"/{s+=$NF; f=1} END{if(f) printf "%d", s+0; else print 0}'; }

# События TLS, атрибутированные К ПОДУ. Это и есть «событие» метки 6.4.4 по
# постановке волны («привязка + тождество библиотеки + СОБЫТИЕ»), и это
# САМЫЙ устойчивый из доступных приборов: держатель в поде долгоживущий,
# поэтому резолв pid→pod успевает; у короткоживущего s_client он проигрывает
# гонку и алерт приезжает с pod=null (№456).
_w64_events_tls_pod() { _w64_metrics | awk -v p="$1" '$0 ~ /^ebpf_guard_events_total\{/ && /type="tls"/ && index($0, "pod=\"" p "\"") {s+=$NF; f=1} END{if(f) printf "%d", s+0; else print 0}'; }

# Алерты правила за весь стор — по rule_id, БЕЗ требования атрибуции к поду.
_w64_alerts_rule() {
    local j
    j=$(curl -s --max-time 30 -H "Authorization: Bearer $W64_TOKEN" "$W64_API/api/v1/alerts?limit=200000" 2>/dev/null)
    printf '%s' "$j" | jq -e . >/dev/null 2>&1 || { echo ""; return; }
    printf '%s' "$j" | jq --arg r "$1" '[.[] | select(.rule_id==$r or (.details.base_rule_id? == $r))] | length' 2>/dev/null
}

# Лимитер по правилу (№493). Третий слой подавления после дедупа: 10 алертов
# на правило за 60 с ([[per-rule-rate-limit-ceiling]]). Контроль ставится ПОСЛЕ
# окна атак, то есть в уже наполненный лимитер
# ([[control-after-attacks-hits-filled-limiter]]), и без этого среза «алертов 0»
# неотличимо от «алерт был и срезан потолком».
_w64_ratelimited_rule() { _w64_metrics | awk -v r="$1" '$0 ~ /^ebpf_guard_alerts_ratelimited_by_rule_total\{/ && index($0, "rule_id=\"" r "\"") {print $NF+0; f=1} END{if(!f) print 0}'; }

# Ось ПРОДЮСЕРА (№496, разбор №493). Четыре величины одной серии
# ebpf_guard_tls_payload_capture_total{direction,result}: событие, у которого
# захват нагрузки не удался (result="empty"), доезжает до слоя правил с ПУСТОЙ
# нагрузкой, но считается в events_total как полноценное — и «нагрузка пришла,
# ни одно правило не подошло» читается снаружи ровно так же, как «нагрузки не
# было вовсе». Снимается ОДНИМ проходом по одному снимку: четыре отдельных
# curl'а дали бы четыре разных момента. Пустая строка = серии нет вовсе
# (бинарь до №496), и это НЕ ноль ([[gated-metric-cannot-carry-product-verdict]]).
# №504: шесть величин вместо четырёх. result="empty" распался на две причины
# РАЗНОГО КЛАССА, и ровно на этом различии стоял ложный продуктовый вердикт
# 6.4.3 на архиве w7A:
#   empty_zero_len    — SSL_write(num<=0): вызову НЕЧЕГО было нести. Замер
#                       bpftrace на ebaka2 28.09.2026 по тому же обмену: из
#                       пяти вызовов SSL_write четыре с num=0 и один с num=53.
#                       Такое событие — НЕ дефект;
#   empty_read_failed — ядро видело num>0 и захватило ноль: отказ
#                       bpf_probe_read_user. ТОЛЬКО это даёт продуктовый класс.
# Старое значение result="empty" читается как zero_len: архив/бинарь до №504
# не различал причин, а подавляющее большинство тех «empty» и были num=0.
# Молча складывать его с read_failed нельзя — вердикт перевернётся.
_w64_payload_sextet() {
    _w64_metrics | awk '
        /^ebpf_guard_tls_payload_capture_total\{/ {
            f = 1; v = $NF + 0
            d = index($0, "direction=\"write\"") ? "w" : (index($0, "direction=\"read\"") ? "r" : "")
            if (d == "") next
            if (index($0, "result=\"captured\"")) c[d] += v
            else if (index($0, "result=\"empty_zero_len\"")) z[d] += v
            else if (index($0, "result=\"empty_read_failed\"")) x[d] += v
            else if (index($0, "result=\"empty\"")) z[d] += v
        }
        END { if (f) printf "%d %d %d %d %d %d", c["w"], z["w"], x["w"], c["r"], z["r"], x["r"]; else print "" }'
}

# Алерты правила СТРОГО ПОСЛЕ момента $2 (эпоха с дробной частью). Граница —
# тот же предикат `w626ts`, что у 6.2.6/6.2.9.F.3: точное сравнение с дробными
# секундами, без усечения до секунды ([[store-window-jq-truncates-to-second]] —
# усечение втянуло бы в отсечку алерты той же секунды ДО обмена).
_w64_alerts_rule_since() {
    local j
    j=$(curl -s --max-time 30 -H "Authorization: Bearer $W64_TOKEN" "$W64_API/api/v1/alerts?limit=200000" 2>/dev/null)
    printf '%s' "$j" | jq -e . >/dev/null 2>&1 || { echo ""; return; }
    printf '%s' "$j" | jq --arg r "$1" --argjson t "$2" '
        def w626ts: (.timestamp | capture("^(?<i>[^.]+)(\\.(?<f>[0-9]+))?Z$")) as $c
            | ($c.i + "Z" | fromdateiso8601) + (($c.f // "0") | ("0." + .) | tonumber);
        [.[] | select((.rule_id == $r or (.details.base_rule_id? == $r)) and (w626ts >= $t))] | length' 2>/dev/null
}

# Эпоха с дробной частью. GNU date умеет %N; на дате без %N (busybox) строка
# приходит с буквальным «N», и тогда берётся целая секунда МИНУС 1 — отсечка
# смещается НАЗАД, то есть в худшую для вердикта сторону (лишний алерт может
# войти), но никогда не отрезает свой собственный.
_w64_epoch_frac() {
    local e
    e=$(date -u +%s.%N 2>/dev/null)
    case "$e" in
        *N*|'') printf '%s' "$(( $(date -u +%s) - 1 ))" ;;
        *) printf '%s' "$e" ;;
    esac
}

# ── ПОИМЁННАЯ ПРИВЯЗКА (№453). Оба контроля судили себя ГЛОБАЛЬНЫМ гейджем
#    tls_tracked_pids_total, и это неверно дважды:
#    (а) гейдж не нулевой на любой живой ноде — здесь 2 процесса с libssl
#        (sshd и systemd) привязаны с первой секунды, поэтому проверка
#        «tracked >= 1» выходила из цикла ожидания МГНОВЕННО с waited=0, и
#        собственное же условие «waited >= scan_interval» объявляло контроль
#        НЕИЗМЕРИМЫМ. На этом стенде контроль не мог пройти НИКОГДА;
#    (б) дельта гейджа неатрибутируема: нода под постоянным ssh-брутфорсом
#        (732–1885 соединений/час) даёт привязки sshd непрерывно, а
#        cleanupDeadPIDs одновременно снимает вышедшие PID — рост на «свой»
#        и падение на «чужой» схлопываются в ноль
#        ([[generic-comm-attribution-is-node-background]], №449 на другом
#        уровне: гейдж вместо монотонной величины).
#    Журнал агента печатает привязку С PID'ом, и это единственная
#    неподделываемая атрибуция, доступная внешнему скрипту.
_w64_journal_since() { journalctl -u "$W64_SVC" --since "@${1}" --no-pager 2>/dev/null; }

# Привязался ли агент К ЭТОМУ pid после эпохи $2.
_w64_attached_pid() {
    _w64_journal_since "$2" | grep -a 'attached TLS uprobes' | grep -aq "\"pid\":${1}[,}]"
}

# Привязался ли агент к libssl, которой НА ХОСТЕ НЕТ, после эпохи $2 —
# доказательство привязки в чужом mount-ns (№380). Путь берётся из журнала и
# проверяется на существование здесь же: alpine-под несёт /lib/libssl.so.3,
# которой на этом хосте не существует, и подделать это изнутри пода нельзя.
_w64_attached_foreign_libssl() {
    local line pathv
    while IFS= read -r line; do
        pathv=$(printf '%s' "$line" | sed -n 's/.*"libssl":"\([^"]*\)".*/\1/p')
        [ -n "$pathv" ] || continue
        if [ ! -e "$pathv" ]; then
            printf '%s' "$pathv"
            return 0
        fi
    done <<EOF_FOREIGN
$(_w64_journal_since "$1" | grep -a 'attached TLS uprobes')
EOF_FOREIGN
    return 1
}

# ─── ITEM 5: plaintext-контроль долгоживущим процессом ────────────────────
_w64_item5() {
    local out="$W64_ART/tls-control-plaintext.txt"
    local work="$W64_ART/tls-control-plaintext.d"
    rm -rf "$work"; mkdir -p "$work"
    local port=18443

    if ! openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
            -keyout "$work/key.pem" -out "$work/cert.pem" \
            -subj "/CN=w64-item5-tls-control" >"$work/certgen.log" 2>&1; then
        echo "class=сертификат не сгенерирован (openssl req упал, см. $work/certgen.log)" > "$out"
        echo "  item5: НЕИЗМЕРИМ — генерация сертификата не удалась"
        return
    fi

    # Держатель — процесс с libssl (openssl s_server сам слинкован с libssl,
    # это ровно та библиотека, на которую ставится uprobe). -naccept 1:
    # ровно ОДИН accept, после которого процесс сам завершается — держатель
    # переживает окно ожидания привязки, но не висит бесконечно, если обмен
    # почему-то не случится (страховка от осиротевшего процесса, тот же
    # приём, что таймаут `exec sleep N` у положительного контроля бэкфилла
    # №340).
    # Эпоха ДО старта держателя: окно журнала, в котором ищется привязка
    # именно к нему (№453). Секунда назад — страховка от того, что привязка
    # попадёт в ту же секунду, что и запуск.
    local t_hold0=$(( $(date -u +%s) - 1 ))
    openssl s_server -quiet -naccept 1 -accept "$port" \
        -cert "$work/cert.pem" -key "$work/key.pem" \
        >"$work/server.log" 2>&1 &
    local srv_pid=$!
    sleep 1
    if ! kill -0 "$srv_pid" 2>/dev/null; then
        echo "class=держатель (openssl s_server) не поднялся, см. $work/server.log" > "$out"
        echo "  item5: НЕИЗМЕРИМ — s_server не стартовал"
        return
    fi
    echo "  item5: держатель поднят (pid=$srv_pid, порт $port), жду > ${W64_SCAN_INTERVAL_S}с (scan_interval) с подтверждением tls_tracked_pids_total"

    # №453: ждём привязку К СВОЕМУ pid по журналу, а не роста глобального
    # гейджа. Условие «waited >= scan_interval» сохранено: сценарий постановки
    # требует, чтобы держатель ПЕРЕЖИЛ интервал сканирования, — но теперь оно
    # ДОПОЛНЯЕТ доказательство привязки, а не заменяет его.
    local waited=0 tries=0 max_tries=$(( (W64_SCAN_INTERVAL_S * 3) / 3 + 10 ))
    local attached="no"
    while [ "$tries" -lt "$max_tries" ]; do
        sleep 3
        waited=$(( waited + 3 ))
        tries=$(( tries + 1 ))
        if [ "$waited" -ge "$W64_SCAN_INTERVAL_S" ] && _w64_attached_pid "$srv_pid" "$t_hold0"; then
            attached="yes"
            break
        fi
    done
    if [ "$attached" != "yes" ]; then
        kill "$srv_pid" 2>/dev/null
        echo "class=привязка К ДЕРЖАТЕЛЮ pid=$srv_pid не подтверждена за ${waited}с ожидания (порог >${W64_SCAN_INTERVAL_S}с; в журнале $W64_SVC нет строки «attached TLS uprobes» с этим pid) — сканер не взял держателя до обмена. Глобальный tls_tracked_pids_total=$(_w64_tracked) к вердикту НЕ относится: на живой ноде он не нулевой и без нашего держателя (№453)" > "$out"
        echo "  item5: НЕИЗМЕРИМ — привязка к своему pid не подтверждена за ${waited}с"
        return
    fi
    echo "  item5: привязка К СВОЕМУ держателю подтверждена за ${waited}с (журнал: attached TLS uprobes pid=$srv_pid)"

    # №493: контроль печатает ПЯТЬ величин, а не две. Прежние две (рост
    # событий и алерты манифеста ЗА ВЕСЬ СТОР) не различали «детекта нет» и
    # «детект был и подавлен»: у соседнего item 6 эта ось есть с №455, а здесь
    # её не было, и 6 событий при нуле алертов читались как продуктовый провал
    # ([[control-643-has-no-suppression-axis]], [[dedup-is-third-suppression-layer]]).
    local ev0 ev1 dd0 dd1 rl0 rl1 al0 al1 t_ex
    ev0=$(_w64_events_tls)
    local pc0 pc1
    pc0=$(_w64_payload_sextet)
    dd0=$(_w64_dedup_rule tls_http_basic_auth)
    rl0=$(_w64_ratelimited_rule tls_http_basic_auth)
    al0=$(_w64_alerts_rule tls_http_basic_auth)
    # Отсечка берётся ДО обмена: изолированная дельта стора считается по ней, а
    # не по «всему стору» ([[metric-window-lower-bound-leaks-launcher]]).
    t_ex=$(_w64_epoch_frac)

    # Обмен: платит manifest-правило tls_http_basic_auth
    # (rules/tls-patterns.yaml:19..29) — предикат "содержит 'Authorization:
    # Basic '" в РАСШИФРОВАННОМ тексте, тот же текст, что видит SSL_read/
    # SSL_write через uprobe независимо от TLS-провода.
    #
    # №504: ОБМЕН ФЛАПАЕТ, И ЭТО ИЗМЕРЕНО, А НЕ ПРЕДПОЛОЖЕНО. На ebaka2
    # 28.09.2026 одна и та же команда шесть раз подряд: в трёх заходах
    # openssl s_client отдал свои 53 байта (bpftrace: W num=53), в трёх —
    # НЕ отдал ни одного, завершив рукопожатие и закрыв соединение. Ровно
    # это, а не продюсер, развело w7B (нагрузка захвачена) и w7A (не
    # захвачена) и подсунуло 6.4.3 продуктовый вердикт.
    #
    # Починка — ПОВТОР, а не удлинение таймаута: величина, по которой
    # повторяем, — та же ось продюсера, которую печатает контроль, то есть
    # прибор судит сам себя своим же числом. Потолок 3: выше него отсутствие
    # нагрузки перестаёт быть флапом и становится величиной, которую эмиттер
    # обязан увидеть (attempts печатается в файл).
    #
    # ВАРИАНТ С УДЕРЖАНИЕМ stdin ОТВЕРГНУТ ЧИСЛОМ: `{ printf …; sleep 3; } |
    # openssl s_client -ign_eof` дал 1 успех из 3 против 3 из 3 у простого
    # пайпа. Идиома НЕ виновата — виновата гонка, и лечится она повтором.
    local attempts=0 max_attempts=3
    local _wc_a _zw_a _xw_a _rc_a _zr_a _xr_a
    while [ "$attempts" -lt "$max_attempts" ]; do
        attempts=$(( attempts + 1 ))
        printf 'GET / HTTP/1.0\r\nAuthorization: Basic dGVzdDp0ZXN0\r\n\r\n' \
            | openssl s_client -quiet -connect "127.0.0.1:$port" >"$work/client-$attempts.log" 2>&1
        sleep 5
        pc1=$(_w64_payload_sextet)
        # Повторяем, только если ось продюсера читается и нагрузку не донёс
        # НИ ОДИН вызов. Нечитаемая ось — не повод крутить обмен: это другой
        # класс, и его назовёт разбор ниже.
        [ -n "$pc0" ] && [ -n "$pc1" ] || break
        # shellcheck disable=SC2086
        set -- $pc0; _wc_a=$1 _zw_a=$2 _xw_a=$3 _rc_a=$4 _zr_a=$5 _xr_a=$6
        # shellcheck disable=SC2086
        set -- $pc1
        [ $(( ($1 - _wc_a) + ($4 - _rc_a) )) -gt 0 ] && break
        [ "$attempts" -lt "$max_attempts" ] && \
            echo "  item5: попытка $attempts не донесла нагрузку (все вызовы SSL_write пусты) — повтор обмена (№504)"
        # Держатель поднят с -naccept 1 и уже израсходован первым обменом:
        # на повтор нужен новый accept, иначе вторая попытка стучится в
        # закрытый порт и «ноль» станет приборным, а не измеренным.
        if ! kill -0 "$srv_pid" 2>/dev/null; then
            openssl s_server -quiet -naccept 1 -accept "$port" \
                -cert "$work/cert.pem" -key "$work/key.pem" \
                >>"$work/server.log" 2>&1 &
            srv_pid=$!
            sleep 1
        fi
    done
    ev1=$(_w64_events_tls)
    kill "$srv_pid" 2>/dev/null

    if ! _w64_is_num "$ev0" || ! _w64_is_num "$ev1"; then
        echo "class=events_total{type=\"tls\"} не читается числом до/после обмена (ev0=${ev0:-?}, ev1=${ev1:-?})" > "$out"
        echo "  item5: НЕИЗМЕРИМ — счётчик событий не число"
        return
    fi
    local ev_delta=$(( ev1 - ev0 ))

    local alerts_json=""
    if command -v jq >/dev/null 2>&1; then
        alerts_json=$(curl -s --max-time 30 -H "Authorization: Bearer $W64_TOKEN" "$W64_API/api/v1/alerts?limit=200000" 2>/dev/null)
        printf '%s' "$alerts_json" | jq -e . >/dev/null 2>&1 || alerts_json=""
    fi
    if [ -z "$alerts_json" ]; then
        echo "class=jq недоступен либо /api/v1/alerts не опросить/не JSON — сверка манифеста невозможна (events_delta=$ev_delta известен, но алерт манифеста не сверен)" > "$out"
        echo "  item5: НЕИЗМЕРИМ — сверка манифеста невозможна"
        return
    fi
    # `$a | ...` без пайпа ЧЕРЕЗ index() ([[jq-pipe-into-index-reassigns-dot]]):
    # здесь простой select по двум полям одного объекта, дефект не применим,
    # но приём сохранён явным `.[] | .` захватом для единообразия с 6.3r.2.
    local hit
    hit=$(printf '%s' "$alerts_json" | jq '[.[] | select(.rule_id=="tls_http_basic_auth" or (.details.base_rule_id? == "tls_http_basic_auth"))] | length' 2>/dev/null)
    if ! _w64_is_num "$hit"; then
        echo "class=jq-запрос по манифесту (tls_http_basic_auth) не отдал число (результат: '${hit:-пусто}')" > "$out"
        echo "  item5: НЕИЗМЕРИМ — jq-запрос не дал числа"
        return
    fi

    # ── ОСЬ ПОДАВЛЕНИЯ (№493). Три величины, каждая — свой слой:
    #    dedup_delta   — дедуп {rule_id,pid,comm}, стоит ПЕРЕД лимитером;
    #    ratelimit_delta — потолок 10 алертов/правило/60 с;
    #    manifest_alerts_since — изолированная дельта стора ПО ОТСЕЧКЕ, а не
    #    «весь стор»: именно она отвечает на вопрос постановки «дал ли ЭТОТ
    #    обмен алерт», и именно её читает эмиттер 6.4.3.
    dd1=$(_w64_dedup_rule tls_http_basic_auth)
    rl1=$(_w64_ratelimited_rule tls_http_basic_auth)
    local since dd_delta rl_delta al_delta
    since=$(_w64_alerts_rule_since tls_http_basic_auth "$t_ex")
    _w64_is_num "$dd0" && _w64_is_num "$dd1" && dd_delta=$(( dd1 - dd0 ))
    _w64_is_num "$rl0" && _w64_is_num "$rl1" && rl_delta=$(( rl1 - rl0 ))
    _w64_is_num "$al0" && al_delta=$(( hit - al0 ))

    # №496: ось продюсера считается ТОЛЬКО когда обе стороны — числа; иначе
    # печатается класс, а не ноль.
    local pay_axis="НЕТ_СЕРИИ" pay_cap="НЕИЗМЕРИМО" pay_empty="НЕИЗМЕРИМО" pay_detail="НЕИЗМЕРИМО"
    local pay_zero="НЕИЗМЕРИМО" pay_rdfail="НЕИЗМЕРИМО"
    if [ -n "$pc0" ] && [ -n "$pc1" ]; then
        # shellcheck disable=SC2086
        set -- $pc0; local wc0=$1 zw0=$2 xw0=$3 rc0=$4 zr0=$5 xr0=$6
        # shellcheck disable=SC2086
        set -- $pc1; local wc1=$1 zw1=$2 xw1=$3 rc1=$4 zr1=$5 xr1=$6
        pay_axis="есть"
        pay_cap=$(( (wc1 - wc0) + (rc1 - rc0) ))
        # №504: ДВЕ причины пустоты считаются врозь, а payload_empty_delta
        # остаётся их суммой — прежнее имя, прежняя величина: его читают
        # эмиттеры старых архивов, и переопределять смысл имени нельзя.
        pay_zero=$(( (zw1 - zw0) + (zr1 - zr0) ))
        pay_rdfail=$(( (xw1 - xw0) + (xr1 - xr0) ))
        pay_empty=$(( pay_zero + pay_rdfail ))
        pay_detail="write_captured=$(( wc1 - wc0 )),write_zero_len=$(( zw1 - zw0 )),write_read_failed=$(( xw1 - xw0 )),read_captured=$(( rc1 - rc0 )),read_zero_len=$(( zr1 - zr0 )),read_read_failed=$(( xr1 - xr0 ))"
    fi

    {
        echo "events_delta=$ev_delta"
        # manifest_alerts — ПРЕЖНИЙ ключ и прежняя величина (весь стор): его
        # читают эмиттеры старых архивов, и переопределять смысл имени нельзя
        # ([[f6b-table-indexed-by-limiter-cut]] — то же про «одно имя, две
        # величины»). Изолированная величина приходит ПОД СВОИМ именем.
        echo "manifest_alerts=$hit"
        echo "manifest_alerts_delta=${al_delta:-НЕИЗМЕРИМО}"
        echo "manifest_alerts_since=${since:-НЕИЗМЕРИМО}"
        echo "cut_epoch=$t_ex"
        echo "dedup_delta=${dd_delta:-НЕИЗМЕРИМО}"
        echo "ratelimit_delta=${rl_delta:-НЕИЗМЕРИМО}"
        # Ось ПРОДЮСЕРА (№496): сколько событий обмена донесли до слоя правил
        # хоть один байт нагрузки, и сколько пришли пустыми. Без неё «событие
        # есть, детекта нет» имеет две причины, неразличимые снаружи.
        echo "payload_axis=$pay_axis"
        echo "payload_captured_delta=$pay_cap"
        echo "payload_empty_delta=$pay_empty"
        echo "payload_detail=$pay_detail"
        # №504: две причины пустоты — врозь и ПОД СВОИМИ ИМЕНАМИ. Эмиттер
        # 6.4.3 обязан объявлять продуктовый дефект продюсера ТОЛЬКО по
        # payload_read_failed_delta; payload_zero_len_delta — это вызовы, у
        # которых нагрузки не было вовсе, и по ним продуктового вердикта нет.
        echo "payload_zero_len_delta=$pay_zero"
        echo "payload_read_failed_delta=$pay_rdfail"
        # Сколько раз пришлось повторять обмен, чтобы нагрузка вообще пошла.
        # attempts>1 — это про КОНТРОЛЬ, а не про продукт.
        echo "exchange_attempts=${attempts:-1}"
        echo "exchange_max_attempts=${max_attempts:-1}"
    } > "$out"
    echo "  item5: events_delta=$ev_delta, manifest_alerts(весь стор)=$hit, за обмен по отсечке=${since:-НЕИЗМЕРИМО}, дельта стора=${al_delta:-НЕИЗМЕРИМО}, срез дедупа=${dd_delta:-НЕИЗМЕРИМО}, срез лимитера=${rl_delta:-НЕИЗМЕРИМО}, нагрузка захвачена=${pay_cap}/пусто=${pay_empty} (из них нечего нести=${pay_zero}, отказ чтения=${pay_rdfail}; ось: $pay_axis), попыток обмена=${attempts:-1}"
}

# ─── ITEM 6: контейнерный случай (mount-ns пода, находка №380) ────────────
_w64_item6() {
    local out="$W64_ART/tls-control-container.txt"
    local pod="w64-item6-tls"
    local port=18444

    if ! command -v kubectl >/dev/null 2>&1; then
        echo "class=kubectl недоступен — контейнерный случай не подать" > "$out"
        echo "  item6: НЕИЗМЕРИМ — kubectl недоступен"
        return
    fi

    # Неймспейс — идемпотентно: run-6.4-pipeline.sh его не создаёт (только
    # чистит поды на Шаге 1, `kubectl -n "$NS" delete pod --all`), и на
    # свежем стенде его может не быть вовсе.
    kubectl get ns "$W64_NS" >/dev/null 2>&1 || kubectl create ns "$W64_NS" >/dev/null 2>&1

    kubectl -n "$W64_NS" delete pod "$pod" --ignore-not-found --wait=true >/dev/null 2>&1

    if ! kubectl -n "$W64_NS" run "$pod" --image=alpine:3.19 --restart=Never \
            --labels="w64-role=item6-tls-control" \
            -- sh -c "apk add --no-cache openssl >/tmp/apk.log 2>&1 && sleep 3600" \
            >/dev/null 2>&1; then
        echo "class=kubectl run не создал под $pod в неймспейсе $W64_NS" > "$out"
        echo "  item6: НЕИЗМЕРИМ — под не создан"
        return
    fi

    local ready_tries=0
    while [ "$ready_tries" -lt 30 ]; do
        [ "$(kubectl -n "$W64_NS" get pod "$pod" -o jsonpath='{.status.phase}' 2>/dev/null)" = "Running" ] && break
        sleep 2
        ready_tries=$(( ready_tries + 1 ))
    done
    if [ "$(kubectl -n "$W64_NS" get pod "$pod" -o jsonpath='{.status.phase}' 2>/dev/null)" != "Running" ]; then
        echo "class=под $pod не перешёл в Running за $(( ready_tries * 2 ))с" > "$out"
        echo "  item6: НЕИЗМЕРИМ — под не поднялся"
        kubectl -n "$W64_NS" delete pod "$pod" --ignore-not-found --wait=false >/dev/null 2>&1
        return
    fi
    # apk install идёт внутри того же sh -c до sleep 3600 — ждать, пока
    # openssl появится в PATH контейнера, иначе следующий exec упадёт на
    # пустом месте и назовётся привязкой, а не установкой пакета.
    local apk_tries=0
    while [ "$apk_tries" -lt 30 ]; do
        kubectl -n "$W64_NS" exec "$pod" -- sh -c 'command -v openssl' >/dev/null 2>&1 && break
        sleep 2
        apk_tries=$(( apk_tries + 1 ))
    done
    if ! kubectl -n "$W64_NS" exec "$pod" -- sh -c 'command -v openssl' >/dev/null 2>&1; then
        echo "class=openssl не появился в поде $pod за $(( apk_tries * 2 ))с (apk add не завершился — см. /tmp/apk.log в поде)" > "$out"
        echo "  item6: НЕИЗМЕРИМ — openssl не установлен в поде"
        kubectl -n "$W64_NS" delete pod "$pod" --ignore-not-found --wait=false >/dev/null 2>&1
        return
    fi

    kubectl -n "$W64_NS" exec "$pod" -- sh -c \
        "openssl req -x509 -newkey rsa:2048 -nodes -days 1 -keyout /tmp/key.pem -out /tmp/cert.pem -subj /CN=w64-item6-tls-control >/tmp/certgen.log 2>&1" \
        >/dev/null 2>&1

    # Держатель ВНУТРИ пода — тот же приём item 5 (naccept 1), запущенный
    # через nohup/setsid, чтобы пережить конец exec-сессии (сама
    # exec-сессия не PID 1 контейнера, процесс без отвязки от неё умер бы
    # вместе с ней).
    # Эпоха ДО старта держателя в поде — окно журнала для сторожа привязки
    # в чужом mount-ns (№453).
    local t_pod0=$(( $(date -u +%s) - 1 ))
    kubectl -n "$W64_NS" exec "$pod" -- sh -c \
        "setsid openssl s_server -quiet -naccept 1 -accept $port -cert /tmp/cert.pem -key /tmp/key.pem >/tmp/server.log 2>&1 < /dev/null &" \
        >/dev/null 2>&1
    sleep 2

    local mm0
    mm0=$(_w64_mismatch_failures)

    # №453: привязка в mount-ns пода доказывается ПУТЁМ БИБЛИОТЕКИ, которого
    # НА ХОСТЕ НЕ СУЩЕСТВУЕТ. Под — alpine (musl), его libssl лежит в
    # /lib/libssl.so.3; на этом хосте такого файла нет вовсе (хостовая —
    # /usr/lib/x86_64-linux-gnu/libssl.so.3). Строка журнала «attached TLS
    # uprobes» с несуществующим на хосте путём не может возникнуть ни от
    # одного хостового процесса — это ровно то, что item 6 и обязан
    # предъявить, и подделать её изнутри пода нельзя.
    #
    # Прежний прибор — рост ГЛОБАЛЬНОГО гейджа tracked_pids — не годился
    # дважды: он неатрибутируем (нода под ssh-брутфорсом привязывает sshd
    # непрерывно, а cleanupDeadPIDs одновременно снимает вышедшие PID, и
    # «+1 свой / −1 чужой» схлопывается в ноль) и на смоке 24.09.2026 дал
    # «tracked до=3, после=3» при том, что привязка К ПОДУ в журнале БЫЛА
    # (pid=1287186 libssl=/lib/libssl.so.3) — то есть контроль провалил
    # успешный продукт. Окно ожидания расширено до трёх интервалов
    # сканирования: держатель в поде появляется после `apk add`, и двух
    # интервалов на медленной сети не хватало.
    local waited=0 tries=0 max_tries=$(( (W64_SCAN_INTERVAL_S * 3) / 3 + 10 ))
    local foreign=""
    while [ "$tries" -lt "$max_tries" ]; do
        sleep 3
        waited=$(( waited + 3 ))
        tries=$(( tries + 1 ))
        if [ "$waited" -ge "$W64_SCAN_INTERVAL_S" ]; then
            foreign=$(_w64_attached_foreign_libssl "$t_pod0") && break
            foreign=""
        fi
    done

    local bound="no" identity="no"
    if [ -n "$foreign" ]; then
        bound="yes"
        echo "  item6: привязка в mount-ns пода подтверждена — libssl=$foreign, которой на хосте НЕТ (ожидание ${waited}с)"
        local mm1
        mm1=$(_w64_mismatch_failures)
        # identity_match: сторож тождества (verifyLibraryIdentity,
        # internal/collector/tls.go:561) НЕ провалился за то же ожидание —
        # счётчик отказов reason="libssl_mismatch" не вырос. Косвенный
        # прибор (внешний скрипт не может пересчитать device/inode сам), но
        # он же — единственный внешний симптом, который продукт публикует
        # (tlsAttachFailuresCounter, tls.go:467).
        if _w64_is_num "$mm0" && _w64_is_num "$mm1" && [ "$mm1" -le "$mm0" ]; then
            identity="yes"
        elif ! _w64_is_num "$mm0" || ! _w64_is_num "$mm1"; then
            identity="неизмерим_нет_серии_отказов"
        else
            identity="no"
        fi
    fi

    local event="no" pod_ev_delta="" pod_dedup_delta="" pod_ev_labeled="" alert_rule_delta=""
    if [ "$bound" = "yes" ]; then
        # №455/№456: контроль печатает ЧЕТЫРЕ величины, а не одну.
        #
        # «event» метки 6.4.4 — это СОБЫТИЕ по постановке волны («привязка в
        # mount-ns пода + тождество библиотеки + событие»), и мерится оно
        # серией events_total С ЛЕЙБЛОМ ПОДА. Прежняя реализация требовала
        # АЛЕРТ с атрибуцией к поду — величину строго сильнее той, что просит
        # постановка, и структурно недостижимую: uprobe встаёт на INODE
        # библиотеки, а не на процесс, поэтому заголовок Authorization платит
        # короткоживущий s_client, чей резолв pid→pod проигрывает гонку с его
        # собственным выходом, и алерт приезжает с pod=null. Держатель в поде
        # долгоживущий, его события размечены правильно — этим и судим.
        #
        # Алерт правила остаётся ДОПОЛНИТЕЛЬНОЙ величиной (alert_rule_delta),
        # но вердикта не гейтит: он уже предъявлен меткой 6.4.3 на хосте.
        local ev0_pod ev1_pod dd0_pod dd1_pod al0 al1
        ev0_pod=$(_w64_events_tls)
        dd0_pod=$(_w64_dedup_rule tls_http_basic_auth)
        al0=$(_w64_alerts_rule tls_http_basic_auth)
        kubectl -n "$W64_NS" exec "$pod" -- sh -c \
            "printf 'GET /item6 HTTP/1.0\r\nAuthorization: Basic dzY0aXRlbTY6cG9k\r\n\r\n' | openssl s_client -quiet -connect 127.0.0.1:$port >/tmp/client.log 2>&1" \
            >/dev/null 2>&1
        sleep 5
        ev1_pod=$(_w64_events_tls)
        dd1_pod=$(_w64_dedup_rule tls_http_basic_auth)
        al1=$(_w64_alerts_rule tls_http_basic_auth)
        pod_ev_labeled=$(_w64_events_tls_pod "$pod")
        if _w64_is_num "$ev0_pod" && _w64_is_num "$ev1_pod"; then
            pod_ev_delta=$(( ev1_pod - ev0_pod ))
        fi
        if _w64_is_num "$dd0_pod" && _w64_is_num "$dd1_pod"; then
            pod_dedup_delta=$(( dd1_pod - dd0_pod ))
        fi
        if _w64_is_num "$al0" && _w64_is_num "$al1"; then
            alert_rule_delta=$(( al1 - al0 ))
        fi
        if _w64_is_num "$pod_ev_labeled" && [ "$pod_ev_labeled" -ge 1 ]; then
            event="yes"
        elif _w64_is_num "$pod_ev_labeled" ; then
            event="no"
        else
            event="неизмерим_серии_с_лейблом_пода_нет"
        fi
        echo "  item6: обмен проведён — события TLS с лейблом пода: ${pod_ev_labeled:-НЕИЗМЕРИМО}, события TLS всего за обмен: ${pod_ev_delta:-НЕИЗМЕРИМО}, алертов правила за обмен: ${alert_rule_delta:-НЕИЗМЕРИМО}, срез дедупа: ${pod_dedup_delta:-НЕИЗМЕРИМО}"
    fi

    kubectl -n "$W64_NS" delete pod "$pod" --ignore-not-found --wait=false >/dev/null 2>&1

    if [ "$bound" != "yes" ]; then
        echo "class=привязка в mount-ns пода не подтверждена за ${waited}с ожидания (порог >${W64_SCAN_INTERVAL_S}с; в журнале $W64_SVC нет строки «attached TLS uprobes» с путём libssl, отсутствующим на хосте) — сканер не взял держателя в поде $pod до обмена. Глобальный tracked_pids к вердикту НЕ относится (№453)" > "$out"
        echo "  item6: НЕИЗМЕРИМ — привязка не подтверждена"
        return
    fi

    case "$identity" in
        yes|no) ;;
        *)
            echo "class=тождество библиотеки НЕИЗМЕРИМО (${identity}) — серии ebpf_guard_tls_attach_failures_total{reason=\"libssl_mismatch\"} нет в /metrics" > "$out"
            echo "  item6: НЕИЗМЕРИМ — серии отказов привязки нет"
            return
            ;;
    esac
    case "$event" in
        yes|no) ;;
        *)
            echo "class=событие НЕИЗМЕРИМО (${event})" > "$out"
            echo "  item6: НЕИЗМЕРИМ — событие не сверено"
            return
            ;;
    esac

    {
        echo "bound=$bound"
        echo "identity_match=$identity"
        echo "event=$event"
        echo "pod_events=${pod_ev_labeled:-НЕИЗМЕРИМО}"
        echo "events_delta=${pod_ev_delta:-НЕИЗМЕРИМО}"
        echo "alert_delta=${alert_rule_delta:-НЕИЗМЕРИМО}"
        echo "dedup_delta=${pod_dedup_delta:-НЕИЗМЕРИМО}"
    } > "$out"
    echo "  item6: bound=$bound, identity_match=$identity, event=$event (под $pod, неймспейс $W64_NS)"
}

_w64_item5
_w64_item6
