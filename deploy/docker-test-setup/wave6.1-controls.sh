#!/bin/bash
# wave6.1-controls.sh — контроли волны 6.1 (контейнерная ось на Q9-правилах).
#
# ПОЧЕМУ ЭТОТ ФАЙЛ СУЩЕСТВУЕТ. Волна 6.1 внесла в код две вещи: фолбэк
# обогащения на голый cgroup-ID и клаузулу `container.id neq ""` в пять
# Q9-правил. Обе проверены ТОЛЬКО юнит-тестами. Юнит-тест доказывает логику
# условия; он не доказывает, что на живом стенде агент вообще получает
# непустой container.id. Пока это не доказано отдельно, любой ноль Q9 на
# стенде неотличим от приборного (память positive-control-needs-result-sentinel).
#
# Ровно этот разрыв уже дал две находки при разборе:
#   №216 — фолбэк внесён в internal/k8s/enricher.go, а стенд идёт с
#          kubernetes.enabled: false (config-test.yaml), и k8s-энричер на нём
#          вообще не конструируется (cmd/ebpf-guard/main.go). Правка на стенде
#          не исполнялась НИ РАЗУ и читалась как исполненная.
#   №217 — ось на стенде держит internal/runtime.Enricher, и в нём был тот же
#          дефект: cgroup-ID добывался и выбрасывался, если рантайм-сокет не
#          ответил; при отсутствии сокета энричер не поднимался вовсе.
# Оба дефекта починены в коде; ниже — контроль, который не даёт им (и их
# классу) вернуться молча.
#
# ПОРЯДОК ЧТЕНИЯ ВЕРДИКТОВ. 6.1.0 — сторож приборности. Если он не взят,
# критерии 6.1.1/6.1.2 НЕ ЧИТАЮТСЯ ВООБЩЕ: ни ноль, ни единица там ничего не
# измеряют.
#
# ЗАПУСК. Скрипт не самостоятелен: нужен живой агент, поднятый compose-стенд
# (juice-shop) и те же переменные, что у пайплайна. Волна 6.0m: провал
# контроля НЕ убивает чужой прогон (память die-only-for-unmeasurable-run).
#   W61_API   — база HTTP API агента (http://<host>:19090)
#   W61_TOKEN — bearer-токен
#   W61_CTR   — имя контейнера-цели (по умолчанию juice-shop)
set -u

VPS_IP="${VPS_IP:-localhost}"
W61_API="${W61_API:-${DRIFT_PC_API:-http://${VPS_IP}:19090}}"
W61_TOKEN="${W61_TOKEN:-${DRIFT_PC_TOKEN:-${EBPF_GUARD_TOKEN:-$(grep '^admin=' /var/lib/ebpf-guard/token 2>/dev/null | cut -d= -f2)}}}"
W61_CTR="${W61_CTR:-juice-shop}"
W61_SETUP="${W61_SETUP:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
W61_SETTLE="${W61_SETTLE:-15}"

WAVE61_FAILS=0
WAVE61_VERDICTS="${WAVE61_VERDICTS:-/root/wave6.1-controls-verdicts.txt}"
die() {
    echo "=== КОНТРОЛЬ ПРОВАЛЕН (прогон НЕ прерывается — волна 6.0m): $* ==="
    WAVE61_FAILS=$((WAVE61_FAILS + 1))
    {
        echo "критерий=$(printf '%s' "$*" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)+' | head -1)"
        echo "время_UTC=$(date -u +%FT%TZ)"
        echo "причина: $*"
        echo "---"
    } >> "$WAVE61_VERDICTS" 2>/dev/null || true
    return 0
}

: > "$WAVE61_VERDICTS" 2>/dev/null || true
echo "# wave6.1-controls.sh, прогон от $(date -u +%FT%TZ)" >> "$WAVE61_VERDICTS"
echo "=== КОНТРОЛИ ВОЛНЫ 6.1 (контейнерная ось Q9) ==="

# Пять правил, получивших клаузулу container.id. Порядок фиксирован: он же
# порядок печати величин.
W61_RULES="owasp_path_traversal owasp_web_sensitive_file_read appexploit_lfi_passwd_access appexploit_xxe_file_read webshell_sensitive_file_read"
# Четыре из пяти матчатся на голом чтении /etc/passwd; owasp_path_traversal
# требует "../" в пути и на этом примитиве не поднимается по построению.
W61_PASSWD_RULES="owasp_web_sensitive_file_read appexploit_lfi_passwd_access appexploit_xxe_file_read webshell_sensitive_file_read"

_w61_alerts() {
    curl -s --max-time 15 -H "Authorization: Bearer $W61_TOKEN" "$W61_API/api/v1/alerts" 2>/dev/null
}

_w61_metrics() {
    curl -s --max-time 15 -H "Authorization: Bearer $W61_TOKEN" "$W61_API/metrics" 2>/dev/null
}

# Число алертов по списку правил. $1 = список id через пробел.
_w61_count() {
    _w61_alerts | jq --arg ids "$1" '[.[]|select(.rule_id as $r | ($ids|split(" "))|index($r))]|length' 2>/dev/null || echo 0
}

# Число алертов по списку правил, У КОТОРЫХ НЕПУСТ container_id. Это и есть
# «подтверждено container-полем, а не совпадением comm» из критерия 6.1.
_w61_count_with_container() {
    _w61_alerts | jq --arg ids "$1" '[.[]|select((.rule_id as $r | ($ids|split(" "))|index($r)) and ((.enrichment.container_id // "") != ""))]|length' 2>/dev/null || echo 0
}

# Число алертов по списку правил, У КОТОРЫХ container_id ПУСТ, то есть
# ХОСТОВЫХ. Ровно это меряет негативный контроль 6.1.2: утверждение «чтение с
# хоста не поднимает правило» — про хостовые алерты, а не про все подряд.
# Считать там всё подряд нельзя (найдено на прогоне 03.09.2026): любой
# контейнер стенда, читающий /etc/passwd в то же 15-секундное окно
# (grafana/prometheus, да хоть runc:[N:INIT] от соседнего docker exec),
# даёт +N и роняет 6.1.2 с вердиктом «клаузула матчит там, где контейнера
# нет» — выводом ПРЯМО ПРОТИВОПОЛОЖНЫМ тому, что произошло.
_w61_count_host() {
    _w61_alerts | jq --arg ids "$1" '[.[]|select((.rule_id as $r | ($ids|split(" "))|index($r)) and ((.enrichment.container_id // "") == ""))]|length' 2>/dev/null || echo 0
}

# Сумма метрики по списку правил (объём, а не срез лимитера — память
# f6b-table-indexed-by-limiter-cut).
_w61_metric_sum() { # $1=metric $2=список rule_id
    local metric="$1" ids="$2"
    _w61_metrics | awk -v m="$metric" -v ids="$ids" '
        BEGIN { n = split(ids, a, " ") }
        $0 ~ "^"m"\\{" {
            for (i = 1; i <= n; i++) if (index($0, "rule_id=\"" a[i] "\"")) { s += $NF; next }
        }
        END { printf "%d", s+0 }'
}

# Объём = собственная дельта двух метрик (экспортированные + срезанные
# min_severity), а не строка какой-либо таблицы.
_w61_volume() { # $1=список rule_id
    echo "$(( $(_w61_metric_sum ebpf_guard_alerts_total "$1") + $(_w61_metric_sum ebpf_guard_alerts_filtered_total "$1") ))"
}

# ─────────────────────────────────────────────────────────────────────────────
# ПРЕFLIGHT. Три сторожа против возврата находок №216/№217 и против немого
# правила. Исполняются ДО подачи входа: провал здесь означает, что величины
# ниже нечем читать.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.1 преflight: конфигурация оси ---"

_w61_cfg="${W61_CONFIG:-$W61_SETUP/config-test.yaml}"
if [ ! -s "$_w61_cfg" ]; then
    die "6.1 преflight ПРОВАЛЕН: конфиг стенда $_w61_cfg не найден — нечем доказать, что ось обогащения вообще включена; все величины 6.1 ниже неизмеримы"
else
    # (а) runtime.enrichment: off убивает ось целиком и молча. Отсутствие
    # секции — законно: значение по умолчанию "auto" (internal/config/config.go).
    if grep -A4 '^runtime:' "$_w61_cfg" 2>/dev/null | grep -qE '^\s*enrichment:\s*"?off"?\s*$'; then
        die "6.1 преflight ПРОВАЛЕН: в $_w61_cfg стоит runtime.enrichment: off — container.id пуст на КАЖДОМ событии по построению, и все пять Q9-правил обездвижены их же новой клаузулой. Любой ноль ниже будет приборным"
    fi
    # (б) находка №216 напрямую: при kubernetes.enabled: false фолбэк в
    # internal/k8s/enricher.go не исполняется вовсе (k8sEnricher == nil в
    # cmd/ebpf-guard/main.go). Это не провал — это запись о том, ЧТО именно
    # проверяет прогон, чтобы правка k8s-энричера снова не прочиталась как
    # исполненная на стенде, где её не звали ни разу.
    if grep -A2 '^kubernetes:' "$_w61_cfg" 2>/dev/null | grep -qE '^\s*enabled:\s*false\s*$'; then
        echo "  6.1 преflight: kubernetes.enabled=false — ось на этом стенде держит ТОЛЬКО internal/runtime.Enricher (cgroup -> docker/CRI, при недоступном сокете -> голый cgroup-ID). Фолбэк k8s-энричера здесь НЕ исполняется и этим прогоном НЕ проверяется (находка №216)"
    else
        echo "  6.1 преflight: kubernetes.enabled=true — ось могут держать оба энричера; k8s идёт первым, runtime дозаполняет пустые поля"
    fi
fi

# (в) клаузула на месте во всех пяти правилах. Переименование правила или
# потеря subgroups даст ноль, неотличимый от продуктового (память
# rule-rename-breaks-replays).
_w61_rules_dir="${W61_RULES_DIR:-$(cd "$W61_SETUP/../.." 2>/dev/null && pwd)/rules}"
_w61_missing=""
for _r in $W61_RULES; do
    if ! grep -rl "id: $_r\$" "$_w61_rules_dir" >/dev/null 2>&1; then
        _w61_missing="$_w61_missing $_r(нет правила)"
        continue
    fi
    _f=$(grep -rl "id: $_r\$" "$_w61_rules_dir" 2>/dev/null | head -1)
    # Клаузула ищется в блоке правила: от его id до следующего "  - id:".
    if ! awk -v r="id: $_r" '$0 ~ r {inb=1} inb && /^  - id:/ && $0 !~ r {exit} inb' "$_f" 2>/dev/null | grep -q 'container.id'; then
        _w61_missing="$_w61_missing $_r(нет container.id)"
    fi
done
if [ -n "$_w61_missing" ]; then
    die "6.1 преflight ПРОВАЛЕН: клаузула container.id отсутствует у правил:$_w61_missing (искали в $_w61_rules_dir) — либо правила переименованы, либо клаузула волны 6.1 потеряна. Ноль величин 6.1.1 ниже будет означать отсутствие правила, а не отсутствие детекта"
else
    echo "  6.1 преflight: клаузула container.id на месте у всех пяти правил ($_w61_rules_dir)"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.1.0 — СТОРОЖ ПРИБОРНОСТИ. Агент обязан отдавать непустой container.id
# хотя бы на одном живом алерте. Без этого 6.1.1/6.1.2 не читаются.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.1.0: сторож приборности — container.id непуст на живом событии ---"

_w61_any_ctr=$(_w61_alerts | jq '[.[]|select((.enrichment.container_id // "") != "")]|length' 2>/dev/null || echo 0)
_w61_src=$(_w61_alerts | jq -r 'first(.[]|select((.enrichment.container_id // "") != "")|.enrichment.runtime_source // "<источник не проставлен>") // "<алертов с container_id нет>"' 2>/dev/null || echo "<не прочитано>")
_w61_cache=$(_w61_metrics | awk '$1 == "ebpf_guard_runtime_cache_size" { printf "%d", $2+0; f=1 } END { if (!f) printf "" }')
# ВНИМАНИЕ ЧИТАТЕЛЮ ВЕРДИКТА (найдено прогоном 03.09.2026): пустой
# runtime_source НЕ является признаком деградации оси. SQLite-стор кладёт из
# EnrichmentInfo только pod_name/namespace/container_id/labels
# (internal/store/sqlite.go, alertSelectColumns) — container_name,
# container_image и runtime_source теряются НА ЗАПИСИ и через /api/v1/alerts
# не возвращаются никогда, каким бы живым ни был энричер. Настоящий источник
# читать в логе агента: "runtime enricher active" source=docker|containerd|
# crio|cgroup.
echo "  6.1.0: алертов с непустым enrichment.container_id в сторе: ${_w61_any_ctr:-0}; runtime_source из стора: ${_w61_src} (стор его НЕ хранит — см. комментарий выше, судить по логу агента); фактический источник по логу: $(journalctl -u ebpf-guard-test.service --since "-24h" --no-pager 2>/dev/null | grep -o 'runtime enricher active.*' | tail -1 | grep -oE '"source":"[a-z]+"' || echo '<в логе не найдено>'); ebpf_guard_runtime_cache_size: ${_w61_cache:-<серии нет>} ($(date -u +%H:%M:%S) UTC)"

W61_INSTRUMENTED=1
if [ "${_w61_any_ctr:-0}" -lt 1 ] && [ "${_w61_cache:-0}" -lt 1 ]; then
    W61_INSTRUMENTED=0
    die "6.1.0 ПРОВАЛЕН: ни одного алерта с непустым container_id и пустой кэш рантайм-энричера (ebpf_guard_runtime_cache_size=${_w61_cache:-<серии нет>}) — контейнерная ось на этом стенде МЕРТВА. Читать в порядке: (1) поднят ли runtime-энричер вообще (в логе агента 'runtime enricher active' с source=docker|containerd|crio|cgroup); (2) видит ли агент /proc целевых контейнеров (общий PID-namespace, hostPID); (3) не исключено ли дерево контейнеров фильтром наблюдателя (память observer-exclusion-blinds-controls). Величины 6.1.1/6.1.2 ниже НЕ ЧИТАЮТСЯ: их ноль приборный"
else
    echo "6.1.0 доказан живьём в $(date -u +%H:%M:%S) UTC: агент отдаёт контейнерную атрибуцию, ось приборно жива"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.1.1 — ПОЗИТИВНЫЙ. Чтение /etc/passwd ВНУТРИ контейнера под comm, которого
# нет в comm-списке правил (cat), обязано поднять хотя бы одно из четырёх
# passwd-правил, и алерт обязан нести непустой container_id. Именно это
# формулирует критерий 6.1: подтверждено container-полем, а не совпадением comm.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.1.1: позитивный контроль — /etc/passwd из контейнера под comm=cat ---"

_w61_pos_before=$(_w61_count_with_container "$W61_PASSWD_RULES")
_w61_vol_before=$(_w61_volume "$W61_PASSWD_RULES")

# Сторож результата входа (память positive-control-needs-result-sentinel):
# засчитываем подачу ТОЛЬКО если exec реально прочитал файл. Отсутствующий
# `cat` в образе или остановленный контейнер иначе дадут ложный ноль.
#
# ПОЧЕМУ НЕ ПРОСТО `docker exec $W61_CTR cat` (прогон на ebaka2 03.09.2026).
# Образ bkimminich/juice-shop:latest — DISTROLESS: entrypoint /nodejs/bin/node,
# в нём нет ни `cat`, ни `sh` («exec: "cat": executable file not found in
# $PATH», rc=126). Прежняя редакция контроля не могла подать вход НИ РАЗУ на
# штатной цели волны, то есть 6.1.1 всегда печатал «НЕ ИСПОЛНЕН», а критерий
# 6.1 оставался неизмеримым по механике контроля, а не по продукту.
# Подменять цель на образ с шеллом нельзя: тогда контроль перестаёт проверять
# ту самую цель, через которую волна собирается гонять атаки.
# Решение: подкладываем в контейнер СТАТИЧЕСКИЙ busybox с хоста (без libc
# внутри distroless динамический бинарь не поднимется) и читаем им. comm при
# этом — `busybox`/`runc:[N:INIT]`, и то и другое ВНЕ comm-списка правил, то
# есть смысл позитивного контроля («поднять могла только контейнерная ось»)
# сохранён полностью.
_w61_read_in_ctr() {
    # (1) штатный cat, если образ не distroless
    _w61_exec_out=$(docker exec "$W61_CTR" cat /etc/passwd 2>&1)
    _w61_exec_rc=$?
    case "$_w61_exec_out" in *root:*) W61_INPUT_HOW="docker exec $W61_CTR cat /etc/passwd"; return 0 ;; esac
    # (2) distroless: кладём статический busybox и читаем им
    for _bb in ${W61_BUSYBOX:-} /bin/busybox /usr/bin/busybox /usr/local/bin/busybox; do
        [ -n "$_bb" ] && [ -x "$_bb" ] || continue
        # статичность обязательна: динамический busybox в distroless не стартует
        if command -v file >/dev/null 2>&1 && ! file -L "$_bb" 2>/dev/null | grep -q "statically linked"; then
            continue
        fi
        # ИМЯ ФАЙЛА ЗНАЧИМО: busybox выбирает апплет по basename(argv[0]).
        # Под чужим именем он падает с «applet not found» ещё до разбора
        # аргументов (найдено прогоном 03.09.2026) — класть только как busybox.
        docker cp "$_bb" "$W61_CTR:/busybox" >/dev/null 2>&1 || continue
        _w61_exec_out=$(docker exec -u 0 "$W61_CTR" /busybox cat /etc/passwd 2>&1)
        _w61_exec_rc=$?
        case "$_w61_exec_out" in
            *root:*)
                W61_INPUT_HOW="docker cp $_bb -> $W61_CTR:/busybox; docker exec -u 0 $W61_CTR /busybox cat /etc/passwd"
                W61_BB_PLANTED=1
                return 0 ;;
        esac
    done
    return 1
}

W61_INPUT_HOW="docker exec $W61_CTR cat /etc/passwd"
W61_BB_PLANTED=0
_w61_exec_ok=0
_w61_read_in_ctr && _w61_exec_ok=1
echo "  6.1.1 вход: $W61_INPUT_HOW -> rc=$_w61_exec_rc, строка root: $( [ "$_w61_exec_ok" = 1 ] && echo 'найдена' || echo 'НЕ НАЙДЕНА' ) ($(date -u +%H:%M:%S) UTC)"

if [ "$_w61_exec_ok" != 1 ]; then
    die "6.1.1 НЕ ИСПОЛНЕН: вход не подан — docker exec $W61_CTR cat /etc/passwd вернул rc=$_w61_exec_rc без строки root: (вывод: $(printf '%.200s' "$_w61_exec_out")). Это отказ механики контроля, а не вердикт по продукту: нулей ниже не существует, критерий 6.1 остаётся НЕ ИЗМЕРЕННЫМ. Чинить: поднят ли контейнер ($W61_CTR); есть ли на ХОСТЕ статический busybox (пакет busybox-static, /bin/busybox) — для distroless-образов вроде juice-shop это единственный путь подачи, задать явно через W61_BUSYBOX=/путь"
else
    sleep "$W61_SETTLE"
    _w61_pos_after=$(_w61_count_with_container "$W61_PASSWD_RULES")
    _w61_vol_after=$(_w61_volume "$W61_PASSWD_RULES")
    _w61_pos_delta=$(( ${_w61_pos_after:-0} - ${_w61_pos_before:-0} ))
    _w61_vol_delta=$(( ${_w61_vol_after:-0} - ${_w61_vol_before:-0} ))
    # comm поднявшего алерта печатается всегда: он и есть доказательство того,
    # что сработала контейнерная ось, а не совпадение с comm-списком.
    _w61_pos_comm=$(_w61_alerts | jq -r --arg ids "$W61_PASSWD_RULES" '[.[]|select((.rule_id as $r | ($ids|split(" "))|index($r)) and ((.enrichment.container_id // "") != ""))]|sort_by(.timestamp)|if length==0 then "<таких алертов нет>" else (.[-1].rule_id + " comm=" + (.[-1].comm // "?") + " container_id=" + ((.[-1].enrichment.container_id // "")[0:12])) end' 2>/dev/null || echo "<не прочитано>")
    echo "  6.1.1 величина: алертов Q9 с непустым container_id ${_w61_pos_before:-0} -> ${_w61_pos_after:-0} (дельта $_w61_pos_delta); объём тех же правил (alerts_total+alerts_filtered_total) ${_w61_vol_before:-0} -> ${_w61_vol_after:-0} (дельта $_w61_vol_delta); последний: $_w61_pos_comm"

    if [ "$_w61_pos_delta" -lt 1 ]; then
        if [ "$_w61_vol_delta" -gt 0 ]; then
            die "6.1.1 ПРОВАЛЕН (ось не подтверждена, детект есть): правила поднялись (объём +$_w61_vol_delta), но НИ ОДИН алерт не нёс непустой container_id. Значит сработала не контейнерная ось, а что-то другое — и критерий 6.1 ('подтверждено container-полем, а не совпадением comm') НЕ ВЗЯТ этим прогоном. Читать обогащение НЕ по стору (runtime_source туда не пишется), а по логу агента: source= у 'runtime enricher active', и по ebpf_guard_runtime_cache_size/miss-счётчику"
        elif [ "$W61_INSTRUMENTED" = 0 ]; then
            die "6.1.1 НЕ ИЗМЕРЕН: ноль при проваленном стороже 6.1.0 — приборный ноль, вердикта по продукту нет"
        else
            die "6.1.1 ПРОВАЛЕН: чтение /etc/passwd внутри контейнера $W61_CTR под comm=cat не подняло ни одного из четырёх passwd-правил ($W61_PASSWD_RULES), объём тех же правил тоже не сдвинулся (+$_w61_vol_delta) — при живой оси (6.1.0 взят). Это продуктовый ноль: клаузула container.id внесена, но до правил не доходит. Читать в порядке: (1) крутит ли агент новые правила (рестарт после правки rules/); (2) доходит ли обогащение до оценки правил (enrichment ставится ДО correlate в cmd/ebpf-guard/main.go); (3) виден ли агенту сам file-event из контейнера"
        fi
    else
        echo "6.1.1 PASS $(date -u +%FT%TZ)" >> "$WAVE61_VERDICTS" 2>/dev/null || true
        echo "6.1.1 доказан живьём в $(date -u +%H:%M:%S) UTC: контейнерное чтение /etc/passwd под comm вне comm-списка поднимает Q9-правило, и алерт несёт container_id — критерий 6.1 взят по позитивной стороне"
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.1.2 — НЕГАТИВНЫЙ. Тот же файл, тот же comm, но С ХОСТА: container.id пуст,
# comm=cat вне списка — ни одно из четырёх правил не смеет подняться. Это
# вторая сторона проверки из постановки («тот же файл, читаемый sshd, — не
# поднимает»), исполненная без интерактивного sshd, чтобы не пачкать idle-час
# (память 6.0.10).
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.1.2: негативный контроль — тот же /etc/passwd с ХОСТА ---"

_w61_neg_before=$(_w61_count_host "$W61_PASSWD_RULES")
_w61_neg_all_before=$(_w61_count "$W61_PASSWD_RULES")
_w61_neg_lim_before=$(_w61_metric_sum ebpf_guard_alerts_filtered_total "$W61_PASSWD_RULES")
_w61_host_out=$(cat /etc/passwd 2>&1)
_w61_host_ok=0
case "$_w61_host_out" in
    *root:*) _w61_host_ok=1 ;;
esac
sleep "$W61_SETTLE"
_w61_neg_after=$(_w61_count_host "$W61_PASSWD_RULES")
_w61_neg_all_after=$(_w61_count "$W61_PASSWD_RULES")
_w61_neg_lim_after=$(_w61_metric_sum ebpf_guard_alerts_filtered_total "$W61_PASSWD_RULES")
_w61_neg_delta=$(( ${_w61_neg_after:-0} - ${_w61_neg_before:-0} ))
_w61_neg_lim_delta=$(( ${_w61_neg_lim_after:-0} - ${_w61_neg_lim_before:-0} ))
_w61_neg_all_delta=$(( ${_w61_neg_all_after:-0} - ${_w61_neg_all_before:-0} ))
echo "  6.1.2 вход: cat /etc/passwd с хоста, строка root: $( [ "$_w61_host_ok" = 1 ] && echo 'найдена' || echo 'НЕ НАЙДЕНА' ); ХОСТОВЫХ алертов Q9 (container_id пуст) ${_w61_neg_before:-0} -> ${_w61_neg_after:-0} (дельта $_w61_neg_delta); для контекста всех Q9, включая контейнерные: дельта $_w61_neg_all_delta; срезано min_severity за то же окно +$_w61_neg_lim_delta ($(date -u +%H:%M:%S) UTC)"

if [ "$_w61_host_ok" != 1 ]; then
    die "6.1.2 НЕ ИСПОЛНЕН: вход не подан — cat /etc/passwd на хосте не вернул строку root:. Ноль ниже не читается"
elif [ "$_w61_neg_delta" -ne 0 ]; then
    die "6.1.2 ПРОВАЛЕН: чтение /etc/passwd С ХОСТА под comm=cat подняло +$_w61_neg_delta ХОСТОВЫХ (container_id пуст) алертов Q9-правил ($W61_PASSWD_RULES) — клаузула container.id матчит там, где контейнера нет. Это возврат ровно того FP, ради устранения которого Q9-сужение и заводилось: 92% алертов LFI-правила были sshd/cron. Читать: непуст ли container.id у ХОСТОВЫХ процессов на этом стенде (агент в контейнере с общим cgroup-неймспейсом даст непустой ID всему, что видит) — тогда ось нужно сузить, а не расширять"
else
    echo "6.1.2 PASS $(date -u +%FT%TZ)" >> "$WAVE61_VERDICTS" 2>/dev/null || true
    echo "6.1.2 доказан живьём в $(date -u +%H:%M:%S) UTC: тот же файл под тем же comm с хоста молчит — расширение оси не вернуло хостовой FP"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.1.3 — ОБЪЁМ. Клаузула `container.id neq ""` открывает четыре passwd-правила
# ДЛЯ ЛЮБОГО контейнера, читающего /etc/passwd, а на стенде в контейнерах
# крутятся grafana/prometheus/containerd. Волна 6.1 обязана предъявить цену
# расширения величиной, а не обещанием (пункт А «Перенос в 6.1…6.4»: 6.1
# двигает ту же idle-базу). Пол — память drift-volume-criterion-needs-a-floor:
# нулевой объём засчитывается ТОЛЬКО если правило вообще видело вход за то же
# окно, иначе это молчание сломанного детектора.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.1.3: объём пяти расширенных правил за окно ---"

W61_VOL_WINDOW="${W61_VOL_WINDOW:-600}"
_w61_v3_start=$(_w61_volume "$W61_RULES")
_w61_v3_files_start=$(_w61_metrics | awk '$0 ~ /^ebpf_guard_events_total\{/ && index($0, "type=\"file\"") { s += $NF } END { printf "%d", s+0 }')
echo "  6.1.3: окно ${W61_VOL_WINDOW}с открыто в $(date -u +%H:%M:%S) UTC (объём на старте ${_w61_v3_start})"
sleep "$W61_VOL_WINDOW"
_w61_v3_end=$(_w61_volume "$W61_RULES")
_w61_v3_files_end=$(_w61_metrics | awk '$0 ~ /^ebpf_guard_events_total\{/ && index($0, "type=\"file\"") { s += $NF } END { printf "%d", s+0 }')
_w61_v3_delta=$(( ${_w61_v3_end:-0} - ${_w61_v3_start:-0} ))
_w61_v3_floor=$(( ${_w61_v3_files_end:-0} - ${_w61_v3_files_start:-0} ))
_w61_v3_hour=$(( _w61_v3_delta * 3600 / W61_VOL_WINDOW ))
echo "  6.1.3 величина: объём пяти правил за ${W61_VOL_WINDOW}с = $_w61_v3_delta (в пересчёте $_w61_v3_hour/ч), пол за то же окно (file-события) = $_w61_v3_floor"
if [ "$_w61_v3_delta" -eq 0 ] && [ "$_w61_v3_floor" -eq 0 ]; then
    die "6.1.3 НЕ ИЗМЕРЕН: объём 0 при НУЛЕВОМ поле — за окно не было ни одного file-события вообще, то есть молчание правил не отличимо от слепоты коллектора. Повторить окно на живой нагрузке"
else
    echo "6.1.3 измерен в $(date -u +%H:%M:%S) UTC: $_w61_v3_hour/ч при поле $_w61_v3_floor file-событий — это цена расширения оси, её надо сложить с idle-базой замера (потолок idle-часа волны 6.0 — 23 алерта/ч)"
fi

# Уборка подложенного busybox. СТРОГО в самом конце, а не сразу после 6.1.1:
# `docker exec` для удаления сам порождает контейнерное чтение /etc/passwd
# (runc:[N:INIT] резолвит пользователя), то есть внутри окон 6.1.2/6.1.3 он
# подмешал бы собственные алерты в измеряемые величины.
if [ "${W61_BB_PLANTED:-0}" = 1 ]; then
    docker exec -u 0 "$W61_CTR" /busybox rm -f /busybox >/dev/null 2>&1 \
        && echo "  уборка: /busybox удалён из $W61_CTR" \
        || echo "  уборка: НЕ УДАЛОСЬ удалить /busybox из $W61_CTR — снять руками (docker exec -u 0 $W61_CTR /busybox rm -f /busybox), иначе он останется в цели атак следующего прогона"
fi

echo "=== wave6.1-controls.sh завершён: проваленных контролей $WAVE61_FAILS, вердикты в $WAVE61_VERDICTS ==="
exit 0
