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
# Выход: $W64_ART/tls-control-plaintext.txt (events_delta=/manifest_alerts=
# ЛИБО class=), $W64_ART/tls-control-container.txt (bound=/identity_match=/
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
_w64_events_tls() { _w64_metrics | awk '/^ebpf_guard_events_total\{/ && /type="tls"/{print $NF; f=1} END{if(!f) print 0}'; }

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

    local ev0 ev1
    ev0=$(_w64_events_tls)

    # Обмен: платит manifest-правило tls_http_basic_auth
    # (rules/tls-patterns.yaml:19..29) — предикат "содержит 'Authorization:
    # Basic '" в РАСШИФРОВАННОМ тексте, тот же текст, что видит SSL_read/
    # SSL_write через uprobe независимо от TLS-провода.
    printf 'GET / HTTP/1.0\r\nAuthorization: Basic dGVzdDp0ZXN0\r\n\r\n' \
        | openssl s_client -quiet -connect "127.0.0.1:$port" >"$work/client.log" 2>&1
    sleep 5
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

    {
        echo "events_delta=$ev_delta"
        echo "manifest_alerts=$hit"
    } > "$out"
    echo "  item5: events_delta=$ev_delta, manifest_alerts(tls_http_basic_auth)=$hit"
    echo "  ⚠ item5 сверяет манифест ЗА ВЕСЬ СТОР, без отсечки по времени начала обмена — при повторном запуске контроля в том же архиве старые срабатывания tls_http_basic_auth (если были) считаются тоже; на одиночном заходе это не занижает и не завышает вердикт 6.4.3, но не читать эту величину как строго изолированную дельту"
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

    local event="no"
    if [ "$bound" = "yes" ]; then
        kubectl -n "$W64_NS" exec "$pod" -- sh -c \
            "printf 'GET / HTTP/1.0\r\nAuthorization: Basic dGVzdDp0ZXN0\r\n\r\n' | openssl s_client -quiet -connect 127.0.0.1:$port >/tmp/client.log 2>&1" \
            >/dev/null 2>&1
        sleep 5
        if command -v jq >/dev/null 2>&1; then
            local alerts_json hit
            alerts_json=$(curl -s --max-time 30 -H "Authorization: Bearer $W64_TOKEN" "$W64_API/api/v1/alerts?limit=200000" 2>/dev/null)
            if printf '%s' "$alerts_json" | jq -e . >/dev/null 2>&1; then
                hit=$(printf '%s' "$alerts_json" | jq --arg pod "$pod" \
                    '[.[] | select(.pod == $pod) | select(.rule_id=="tls_http_basic_auth" or (.details.base_rule_id? == "tls_http_basic_auth"))] | length' 2>/dev/null)
                if _w64_is_num "$hit" && [ "$hit" -ge 1 ]; then
                    event="yes"
                elif _w64_is_num "$hit"; then
                    event="no"
                else
                    event="неизмерим_jq_не_число"
                fi
            else
                event="неизмерим_alerts_api"
            fi
        else
            event="неизмерим_jq_недоступен"
        fi
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
    } > "$out"
    echo "  item6: bound=$bound, identity_match=$identity, event=$event (под $pod, неймспейс $W64_NS)"
}

_w64_item5
_w64_item6
