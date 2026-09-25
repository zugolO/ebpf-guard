#!/bin/bash
# wave6.5-item5-http-control.sh — положительный контроль item 5 волны 6.5:
# ЖИВОЕ событие http_plaintext. Пишет сторожевой файл, который читает эмиттер
# метки 6.5.1 в run-6.4-pipeline.sh — САМ про класс ДОСТИГНУТО/ПРОВАЛЕН ничего
# не решает, только измеряет и НАЗЫВАЕТ класс неизмеримости, где он есть
# ([[verdict-zero-needs-its-class-presented]]).
#
# ЗАЧЕМ. `http_plaintext` не измерялся живьём НИ РАЗУ за всю историю проекта:
# загрузчик в бинаре есть (метка 6.4B.4 предъявляла http_plaintext_loader=true),
# объекты скомпилированы, коллектор выключен конфигом. Это ровно пара «код
# есть, прогона нет», которая четыре волны прятала №436, а №436 прятал №452
# ([[stub-loader-hides-verifier-rejects]]).
#
# ПОЧЕМУ ДЕРЖАТЕЛЬ СВОЙ, А НЕ «ЧТО НАЙДЁТСЯ НА НОДЕ». Коллектор привязывается
# ПЕРИОДИЧЕСКИМ сканом /proc (scanAndAttach, умолчание 30с) к процессам, чей
# comm входит в defaultHTTPServerComms, и вешает uprobe на libc read/recv. То
# есть держатель обязан (1) иметь comm из списка, (2) ЖИТЬ дольше интервала
# скана, (3) читать запрос через libc. `python3 -m http.server` выполняет все
# три: comm=python3 из встроенного списка (http_uprobe.go:40), процесс
# долгоживущий, CPython читает сокет через recv(2). curl не годится по той же
# причине, что и в контроле item 5 волны 6.4: живёт < 1с, скан его не увидит
# НИКОГДА, и ноль прочитался бы как «детект мёртв», а не как «контроль неверно
# поставлен» ([[control-payload-must-outlive-its-readlink]]).
#
# ЧТО ИМЕННО ПРЕДЪЯВЛЯЕТСЯ, А НЕ ПРЕДПОЛАГАЕТСЯ:
#   - коллектор зарегистрирован и поднят — по collector_up{http_plaintext};
#   - порт держателя реально слушает — по успешному запросу, а не по sleep;
#   - привязка состоялась — по ebpf_guard_http_plaintext_tracked_pids_total>=1,
#     СВОИМ прибором, а не слепым ожиданием интервала скана (№453);
#   - запросы дошли — по кодам ответа (requests_ok), иначе «событий 0» было бы
#     неотличимо от «запросов не было» ([[positive-control-needs-result-sentinel]]).
#
# МЕСТО В ПОРЯДКЕ: зовётся ПОСЛЕ снятия журнала и метрик окна, как и контроли
# items 5/6 волны 6.4 — обмен контроля не имеет права входить в измеряемую
# цену окна ([[metric-window-lower-bound-leaks-launcher]]).
#
# Артефакты — в $W65_ART, НЕ в /root/: там висит drift-правило, и файлы
# контроля создавали бы алерты на самих себя
# ([[control-artifacts-must-live-outside-root]]).
#
# Вход: W65_ART (обязателен), W65_API (http://host:port без завершающего /),
# W65_TOKEN, W65_CONTROL=on|off (умолчание off — старый прогон без этой правки
# не ломается и метка 6.5.1 честно печатает НЕ ЗАПРОШЕН),
# W65_SCAN_INTERVAL_S (умолчание 30 — collectors.http_plaintext.scan_interval),
# W65_PORT (умолчание 18085), W65_REQUESTS (умолчание 3).
#
# Выход: $W65_ART/http-control-plaintext.txt — либо ОДНА строка `class=<имя>`
# (неизмеримо, класс назван), либо строки
# events_delta=/tracked_pids=/requests_ok=/holder_pid=/holder_comm=.

set +e +o pipefail
set -u

W65_ART="${W65_ART:?W65_ART обязателен}"
W65_API="${W65_API:?W65_API обязателен}"
W65_TOKEN="${W65_TOKEN:-}"
W65_CONTROL="${W65_CONTROL:-off}"
W65_SCAN_INTERVAL_S="${W65_SCAN_INTERVAL_S:-30}"
W65_PORT="${W65_PORT:-18085}"
W65_REQUESTS="${W65_REQUESTS:-3}"

_W65_OUT="$W65_ART/http-control-plaintext.txt"

if [ "$W65_CONTROL" = "off" ]; then
    echo "--- item 5 волны 6.5: W65_CONTROL=off — контроль не поставлен, 6.5.1 назовёт класс сам ---"
    exit 0
fi

mkdir -p "$W65_ART" 2>/dev/null

_w65_metrics() { curl -s --max-time 10 -H "Authorization: Bearer $W65_TOKEN" "$W65_API/metrics" 2>/dev/null; }

# Одна величина — один разбор (item 1 волны 6.5): и текст, и решение читают
# ровно то, что вернул этот разбор. Отсутствие серии и её ноль различаются
# СЛОВОМ: пусто = серии нет ([[metric-anchor-must-carry-full-series-name]]).
_w65_series() { # $1 = снимок, $2 = полное имя серии (с «{» для серии с лейблами), $3 = подстрока-селектор
    printf '%s\n' "$1" | awk -v sel="${3:-}" -v series="$2" '
        # Якорь — ПОЛНОЕ имя серии с префиксом ebpf_guard_, иначе «серии нет»
        # неотличимо от опечатки в имени ([[metric-anchor-must-carry-full-series-name]]).
        index($1, series) == 1 {
            if (sel == "" || index($0, sel) > 0) { print $NF; exit }
        }'
}

_w65_class() { # $1 = имя класса неизмеримости
    printf 'class=%s\n' "$1" > "$_W65_OUT"
    echo "  item 5 волны 6.5: КЛАСС НАЗВАН — $1 (6.5.1 напечатает НЕИЗМЕРИМ с этим классом)"
    exit 0
}

echo "--- item 5 волны 6.5: положительный контроль ЖИВОГО события http_plaintext (ПОСЛЕ окна) ---"

_w65_snap=$(_w65_metrics)
if [ -z "$_w65_snap" ]; then
    _w65_class "снимок_метрик_не_взят"
fi

# (1) Коллектор зарегистрирован? Отсутствие серии — это ВЫКЛЮЧЕН КОНФИГОМ, а не
#     ноль: main конструирует http_plaintext только внутри
#     `if cfg.Collectors.HTTPPlaintext.Enabled`.
_w65_up=$(_w65_series "$_w65_snap" "ebpf_guard_collector_up{" 'collector="http_plaintext"')
case "${_w65_up:-}" in
    '')  _w65_class "коллектор_выключен_конфигом_серии_нет" ;;
    0|0.0) _w65_class "коллектор_включён_но_НЕ_поднялся_up=0" ;;
esac

# (2) Держатель. python3 — первый из defaultHTTPServerComms, который есть на
#     любом стенде; comm процесса и есть имя, по которому идёт отбор.
if ! command -v python3 >/dev/null 2>&1; then
    _w65_class "держатель_недоступен_python3_нет"
fi
_w65_root="$W65_ART/http-holder-root"
mkdir -p "$_w65_root" 2>/dev/null
printf 'ebpf-guard item 5 wave 6.5 holder\n' > "$_w65_root/index.html" 2>/dev/null

python3 -m http.server "$W65_PORT" --bind 127.0.0.1 --directory "$_w65_root" \
    > "$W65_ART/http-holder.log" 2>&1 &
_w65_pid=$!
# Убираем держателя на любом выходе: транзиентный процесс, переживший прогон,
# блокирует следующий запуск по порту ([[transient-unit-survives-and-blocks-next-run]]).
trap 'kill "$_w65_pid" 2>/dev/null; wait "$_w65_pid" 2>/dev/null' EXIT

_w65_comm=$(cat "/proc/$_w65_pid/comm" 2>/dev/null)
echo "  держатель поднят: pid=$_w65_pid comm=${_w65_comm:-?} порт=$W65_PORT (comm обязан входить в defaultHTTPServerComms)"

# (3) Порт слушает — предъявляется запросом, а не sleep.
_w65_listen=0
for _ in $(seq 1 20); do
    if curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$W65_PORT/"; then _w65_listen=1; break; fi
    sleep 1
done
[ "$_w65_listen" -eq 1 ] || _w65_class "держатель_не_начал_слушать"

# (4) Привязка подтверждается СВОИМ прибором (№453): tracked_pids>=1. Ждём с
#     запасом в два интервала скана — меньше значит судить детект по фазе
#     таймера, а не по детекту ([[gate-value-is-node-timer-phase]]).
_w65_wait=$(( W65_SCAN_INTERVAL_S * 2 + 15 ))
_w65_tracked=""
for _ in $(seq 1 "$_w65_wait"); do
    _w65_tracked=$(_w65_series "$(_w65_metrics)" "ebpf_guard_http_plaintext_tracked_pids_total" "")
    case "${_w65_tracked:-}" in
        ''|0|0.0) : ;;
        *) break ;;
    esac
    sleep 1
done
case "${_w65_tracked:-}" in
    '')    _w65_class "серии_tracked_pids_нет_бинарь_без_счётчика" ;;
    0|0.0) _w65_class "привязка_НЕ_подтверждена_tracked_pids=0_за_${_w65_wait}с" ;;
esac
echo "  привязка подтверждена прибором коллектора: tracked_pids=$_w65_tracked"

# (5) Обмен и дельта. Снимок ДО — уже после подтверждения привязки, иначе в
#     дельту вошли бы события чужих процессов за время ожидания.
# №472 (25.09.2026). Здесь стояло `_w65_v0="${_w65_v0:-0}"` МОЛЧА: отсутствие
# серии выдавалось за её ноль — ровно то, что репозиторий уже записал
# ([[metric-anchor-must-carry-full-series-name]], [[empty-metric-snapshot-is-silently-zero]]).
# Для СНИМКА ДО отсутствие законно: `events_total{type=…}` — счётчик с
# лейблами, он создаётся первым принятым событием, и до первого события серии
# нет по построению. Поэтому ноль подставляется, но НАЗЫВАЕТСЯ словом, а не
# подменяет показание тихо.
_w65_v0=$(_w65_series "$(_w65_metrics)" "ebpf_guard_events_total{" 'type="http_plaintext"')
if [ -z "${_w65_v0:-}" ]; then
    echo "  снимок ДО: серии ebpf_guard_events_total{type=\"http_plaintext\"} нет — законно, счётчик с лейблами создаётся ПЕРВЫМ принятым событием; принято за 0"
    _w65_v0=0
fi
# №472, вторая половина. Ноль в events_total НЕ РАЗЛИЧАЕТ «хук слеп» и «события
# доходят, а разбор их отбивает». Второй случай виден только в
# events_dropped_total{collector="http_plaintext"} — и именно он оказался
# правдой на смоке 25.09 (reason=parse_error, №471). Дельта отбраковки
# снимается тем же аппаратом и в те же две точки, что и дельта событий.
_w65_drops() {
    printf '%s\n' "$1" | awk '
        index($0, "ebpf_guard_events_dropped_total{") == 1 && index($0, "collector=\"http_plaintext\"") > 0 {
            n = split($0, f, " "); sum += f[n] + 0
            if (match($0, /reason="[^"]+"/)) {
                r = substr($0, RSTART + 8, RLENGTH - 9)
                if (!(r in seen)) { seen[r] = 1; names = names (names == "" ? "" : "+") r }
            }
        }
        END { printf "%d %s", sum, (names == "" ? "-" : names) }'
}
_w65_d0=$(_w65_drops "$(_w65_metrics)")
_w65_d0_sum=${_w65_d0%% *}
_w65_ok=0
for _ in $(seq 1 "$W65_REQUESTS"); do
    _w65_code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:$W65_PORT/index.html")
    [ "$_w65_code" = "200" ] && _w65_ok=$(( _w65_ok + 1 ))
done
sleep 3
_w65_m1=$(_w65_metrics)
_w65_v1=$(_w65_series "$_w65_m1" "ebpf_guard_events_total{" 'type="http_plaintext"')
if [ -z "${_w65_v1:-}" ]; then
    echo "  снимок ПОСЛЕ: серии ebpf_guard_events_total{type=\"http_plaintext\"} по-прежнему НЕТ — ни одно событие не было ПРИНЯТО (это показание, не пропуск); принято за 0"
    _w65_v1=0
fi
_w65_delta=$(awk -v a="$_w65_v0" -v b="$_w65_v1" 'BEGIN{ d = b - a; printf "%d", (d > 0 ? d : 0) }')
_w65_d1=$(_w65_drops "$_w65_m1")
_w65_d1_sum=${_w65_d1%% *}
_w65_d1_names=${_w65_d1#* }
_w65_drops_delta=$(awk -v a="$_w65_d0_sum" -v b="$_w65_d1_sum" 'BEGIN{ d = b - a; printf "%d", (d > 0 ? d : 0) }')

{
    echo "events_delta=$_w65_delta"
    echo "drops_delta=$_w65_drops_delta"
    echo "drop_reasons=${_w65_d1_names:--}"
    echo "events_before=$_w65_v0"
    echo "events_after=$_w65_v1"
    echo "tracked_pids=$_w65_tracked"
    echo "requests_ok=$_w65_ok"
    echo "requests_sent=$W65_REQUESTS"
    echo "holder_pid=$_w65_pid"
    echo "holder_comm=${_w65_comm:-?}"
} > "$_W65_OUT"

echo "  item 5 волны 6.5: events_delta=$_w65_delta (было $_w65_v0, стало $_w65_v1), отбраковано за обмен $_w65_drops_delta (причины: ${_w65_d1_names:--}), запросов 200 = $_w65_ok из $W65_REQUESTS, tracked_pids=$_w65_tracked"
echo "  сторожевой файл: $_W65_OUT (класс вердикта выносит эмиттер 6.5.1, не контроль)"
exit 0
