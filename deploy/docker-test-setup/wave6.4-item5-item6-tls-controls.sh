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

    local waited=0 tracked="" tries=0 max_tries=$(( (W64_SCAN_INTERVAL_S + 30) / 3 + 5 ))
    while [ "$tries" -lt "$max_tries" ]; do
        tracked=$(_w64_tracked)
        if _w64_is_num "$tracked" && [ "$tracked" -ge 1 ]; then
            break
        fi
        sleep 3
        waited=$(( waited + 3 ))
        tries=$(( tries + 1 ))
    done
    if [ "$waited" -lt "$W64_SCAN_INTERVAL_S" ] || ! _w64_is_num "$tracked" || [ "$tracked" -lt 1 ]; then
        kill "$srv_pid" 2>/dev/null
        echo "class=привязка не подтверждена за ${waited}с ожидания (tls_tracked_pids_total=${tracked:-НЕТ}, порог >${W64_SCAN_INTERVAL_S}с) — сканер не взял держателя pid=$srv_pid до обмена" > "$out"
        echo "  item5: НЕИЗМЕРИМ — привязка не подтверждена за ${waited}с"
        return
    fi
    echo "  item5: привязка подтверждена за ${waited}с (tls_tracked_pids_total=$tracked)"

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
    kubectl -n "$W64_NS" exec "$pod" -- sh -c \
        "setsid openssl s_server -quiet -naccept 1 -accept $port -cert /tmp/cert.pem -key /tmp/key.pem >/tmp/server.log 2>&1 < /dev/null &" \
        >/dev/null 2>&1
    sleep 2

    local mm0 tracked0
    mm0=$(_w64_mismatch_failures)
    tracked0=$(_w64_tracked)

    local waited=0 tracked="" tries=0 max_tries=$(( (W64_SCAN_INTERVAL_S + 30) / 3 + 5 ))
    while [ "$tries" -lt "$max_tries" ]; do
        tracked=$(_w64_tracked)
        if _w64_is_num "$tracked" && _w64_is_num "$tracked0" && [ "$tracked" -gt "$tracked0" ]; then
            break
        fi
        sleep 3
        waited=$(( waited + 3 ))
        tries=$(( tries + 1 ))
    done

    local bound="no" identity="no"
    if [ "$waited" -ge "$W64_SCAN_INTERVAL_S" ] && _w64_is_num "$tracked" && _w64_is_num "$tracked0" && [ "$tracked" -gt "$tracked0" ]; then
        bound="yes"
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
        echo "class=привязка не подтверждена за ${waited}с ожидания (tracked до=${tracked0:-НЕТ}, после=${tracked:-НЕТ}, порог >${W64_SCAN_INTERVAL_S}с) — сканер не взял держателя в поде $pod до обмена" > "$out"
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
