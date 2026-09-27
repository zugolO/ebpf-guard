#!/bin/bash
# wave6.6-ja3-probe.sh — ЗОНД №488 (упакованная раскладка
# struct tls_clienthello_event) КАК АРХИВИРУЕМЫЙ КОНТРОЛЬ.
#
# ЗАЧЕМ ЭТОТ СКРИПТ ВООБЩЕ. Приёмка №488 на заходе 27.09.2026 состоялась, но
# её свидетели — дельта семейства ja3 0→3, pid=2099987 на всех трёх событиях,
# отпечатки ja3/ja4 — существуют ТОЛЬКО как текст, переписанный в plan.md
# рукой. Ни один из них не пересчитывается из архива, то есть приёмка
# неповторима и непроверяема: ровно тот класс, против которого заведено
# [[verdict-input-must-be-computed-by-emitter]]. Зонд делает то же самое
# скриптом и оставляет ФАЙЛЫ, по которым эмиттер метки 6.6.6 считает вердикт
# сам — и на стенде, и при офлайн-реплее архива.
#
# ПОЧЕМУ НЕ «curl https». Приборный ноль по построению (№491/№381):
# ClientHello у OpenSSL уходит через write(2), а kprobe висит на
# __x64_sys_sendto. Нагрузка подаётся ИМЕННО sendto(2) — той осью, на которой
# стоит зонд, — и это единственный способ довести байты до парсера.
#
# ЧТО ДОКАЗЫВАЕТСЯ И ЧТО НЕТ. Доказывается ПАРСЕР (упакованная раскладка), а
# НЕ покрытие коллектора: развилка №381 не переоткрывается, цена коллектору не
# назначается. Зонд НЕ поднимает коллектор сам — он читает РАНТАЙМ
# ([[entry-guard-must-read-runtime-not-config]]) и, если tlsfingerprint не
# поднят, НАЗЫВАЕТ класс. Рестарт ради тумблера обнулил бы счётчики и сделал
# дельты бессмысленными ([[ab-toggle-measures-the-restart]],
# [[empty-metric-snapshot-is-silently-zero]]).
#
# НАГРУЗКА ФИКСИРОВАНА (wave6.6-ja3-probe.clienthello.hex), поэтому
# отпечатки ДЕТЕРМИНИРОВАНЫ и сверяются с ожидаемыми
# (wave6.6-ja3-probe.expect, пересчитываются офлайн-тестом
# internal/collector/ja3_probe_payload_test.go). Это сверка ПОБАЙТОВАЯ: сдвиг
# data на 4 байта — дефект №488 — даёт либо пустой JA3, либо другой хеш, но
# никогда ожидаемый.
#
# Вход: W66_ART, W66_API, W66_TOKEN, W66_JA3_PROBE=on|off (умолчание off),
#       W66_SVC (юнит для журнала), W66_SETTLE_S (умолчание 5),
#       W66_JA3_SENDS (умолчание 3).
# Выход: $W66_ART/ja3-probe.txt — ЛИБО одна строка class=<имя>, ЛИБО ключи
#       sender_pid=/sent=/settle_s=/journal_lines=/journal_pids=/ja3_observed=/
#       ja4_observed=; плюс архивируемые входы эмиттера:
#       ja3-probe-expect.txt (копия ожиданий), metrics-ja3-probe-before.txt,
#       metrics-ja3-probe-after.txt, ja3-probe-journal.txt.
# ВСЕ дельты считает ЭМИТТЕР по двум снимкам — здесь их сознательно нет.

set +e +o pipefail
set -u

W66_ART="${W66_ART:?W66_ART обязателен}"
W66_API="${W66_API:?W66_API обязателен}"
W66_TOKEN="${W66_TOKEN:-}"
W66_JA3_PROBE="${W66_JA3_PROBE:-off}"
W66_SVC="${W66_SVC:-ebpf-guard-test.service}"
W66_SETTLE_S="${W66_SETTLE_S:-5}"
W66_JA3_SENDS="${W66_JA3_SENDS:-3}"

_SELF_DIR=$(cd "$(dirname "$0")" && pwd)
_HEX="$_SELF_DIR/wave6.6-ja3-probe.clienthello.hex"
_EXPECT="$_SELF_DIR/wave6.6-ja3-probe.expect"
_OUT="$W66_ART/ja3-probe.txt"

if [ "$W66_JA3_PROBE" = "off" ]; then
    echo "--- зонд №488: W66_JA3_PROBE=off — не поставлен, 6.6.6 назовёт класс сам ---"
    exit 0
fi
mkdir -p "$W66_ART" 2>/dev/null

_metrics() { curl -s --max-time 10 -H "Authorization: Bearer $W66_TOKEN" "$W66_API/metrics" 2>/dev/null; }
_class() { printf 'class=%s\n' "$1" > "$_OUT"; echo "  зонд №488: КЛАСС НАЗВАН — $1"; exit 0; }

echo "--- зонд №488: упакованная раскладка tls_clienthello_event, нагрузка sendto(2) (ПОСЛЕ окна) ---"

[ -r "$_HEX" ]    || _class "нагрузка_не_найдена_${_HEX##*/}_рядом_со_скриптом_нет"
[ -r "$_EXPECT" ] || _class "ожидания_не_найдены_${_EXPECT##*/}_рядом_со_скриптом_нет"
command -v python3 >/dev/null 2>&1 || _class "нагрузка_недоступна_python3_нет"
[ "$(uname -m)" = "x86_64" ] || _class "архитектура_$(uname -m)_kprobe___x64_sys_sendto_только_x86_64"

# Ожидания КОПИРУЮТСЯ в архив: при офлайн-реплее каталога deploy/ рядом с
# архивом нет, а сверять эмиттер обязан ровно с теми числами, что действовали
# на прогоне ([[archive-carries-its-own-guard-copy]] в применении к ожиданиям).
cp "$_EXPECT" "$W66_ART/ja3-probe-expect.txt" 2>/dev/null

_snap_before=$(_metrics)
[ -n "$_snap_before" ] || _class "снимок_метрик_до_зонда_не_взят"
printf '%s\n' "$_snap_before" > "$W66_ART/metrics-ja3-probe-before.txt"

# Коллектор обязан быть поднят ДО зонда. Отсутствие серии и ноль в ней — два
# РАЗНЫХ случая, и оба называются классом, а не молчанием
# ([[gated-metric-cannot-carry-product-verdict]],
# [[metric-anchor-must-carry-full-series-name]]).
_up=$(printf '%s\n' "$_snap_before" | awk 'index($1,"ebpf_guard_collector_up{")==1 && index($0,"collector=\"tlsfingerprint\"")>0 {print $NF; exit}')
[ -n "$_up" ] || _class "серии_collector_up_tlsfingerprint_нет_коллектор_не_поднят_на_этом_прогоне_зонд_не_ставится"
[ "$_up" = "1" ] || _class "collector_up_tlsfingerprint=${_up}_коллектор_выключен_зонд_дал_бы_приборный_ноль"

# Эпоха окна журнала — на секунду раньше отправки (привязка может лечь в ту же
# секунду, тот же приём, что у контролей items 5/6 волны 6.4).
_t0=$(( $(date -u +%s) - 1 ))

# Отправка: sendto(2) на loopback:9 (discard), UDP — адресат не нужен и
# слушателя не требует. Нагрузка ЖИВЁТ до чтения /proc/self/comm, иначе
# атрибуция читалась бы с уже вышедшего процесса
# ([[control-payload-must-outlive-its-readlink]]).
_res=$(HEXFILE="$_HEX" SENDS="$W66_JA3_SENDS" python3 - <<'PY' 2>&1
import os, socket, hashlib
payload = bytes.fromhex("".join(
    l.strip() for l in open(os.environ["HEXFILE"]) if l.strip() and not l.startswith("#")))
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
n = 0
for _ in range(int(os.environ["SENDS"])):
    # sendto с адресом — РОВНО тот syscall, на котором висит kprobe; send() на
    # неподключённом сокете его не даёт.
    s.sendto(payload, ("127.0.0.1", 9))
    n += 1
comm = open("/proc/self/comm").read().strip()
print("pid=%d sent=%d comm=%s len=%d sha256=%s" % (
    os.getpid(), n, comm, len(payload), hashlib.sha256(payload).hexdigest()))
PY
)
echo "  нагрузка: $_res"
_pid=$(printf '%s' "$_res" | sed -n 's/.*pid=\([0-9]*\).*/\1/p')
_sent=$(printf '%s' "$_res" | sed -n 's/.*sent=\([0-9]*\).*/\1/p')
_comm=$(printf '%s' "$_res" | sed -n 's/.*comm=\([^ ]*\).*/\1/p')
_plen=$(printf '%s' "$_res" | sed -n 's/.*len=\([0-9]*\).*/\1/p')
_psha=$(printf '%s' "$_res" | sed -n 's/.*sha256=\([0-9a-f]*\).*/\1/p')
[ -n "$_pid" ] || _class "нагрузка_не_напечатала_pid_отправка_не_состоялась"
[ "${_sent:-0}" = "$W66_JA3_SENDS" ] || _class "отправлено_${_sent:-0}_из_${W66_JA3_SENDS}_нагрузка_не_доиграла"

sleep "$W66_SETTLE_S"

_snap_after=$(_metrics)
[ -n "$_snap_after" ] || _class "снимок_метрик_после_зонда_не_взят_дельты_считать_не_из_чего"
printf '%s\n' "$_snap_after" > "$W66_ART/metrics-ja3-probe-after.txt"

# Отпечатки и pid события печатает САМ агент строкой debug «tlsfingerprint
# event» (internal/collector/tlsfingerprint.go). Журнал — JSON, не logfmt
# ([[agent-logs-json-not-logfmt]]), и -a обязателен: лог может быть невалиден в
# UTF-8 ([[archive-log-invalid-utf8-blinds-grep]]).
journalctl -u "$W66_SVC" --since "@${_t0}" --no-pager 2>/dev/null \
    | grep -a 'tlsfingerprint event' > "$W66_ART/ja3-probe-journal.txt"
_jl=$(wc -l < "$W66_ART/ja3-probe-journal.txt" 2>/dev/null | tr -d ' ')
_jpids=$(sed -n 's/.*"pid":\([0-9]*\).*/\1/p' "$W66_ART/ja3-probe-journal.txt" 2>/dev/null | sort -un | tr '\n' ',' | sed 's/,$//')
_ja3=$(sed -n 's/.*"ja3":"\([^"]*\)".*/\1/p' "$W66_ART/ja3-probe-journal.txt" 2>/dev/null | sort -u | tr '\n' ',' | sed 's/,$//')
_ja4=$(sed -n 's/.*"ja4":"\([^"]*\)".*/\1/p' "$W66_ART/ja3-probe-journal.txt" 2>/dev/null | sort -u | tr '\n' ',' | sed 's/,$//')

{
    echo "sender_pid=$_pid"
    echo "sender_comm=${_comm:-?}"
    echo "sent=$_sent"
    echo "payload_len=${_plen:-?}"
    echo "payload_sha256=${_psha:-?}"
    echo "settle_s=$W66_SETTLE_S"
    echo "collector_up=$_up"
    echo "journal_lines=${_jl:-0}"
    echo "journal_pids=${_jpids:--}"
    echo "ja3_observed=${_ja3:--}"
    echo "ja4_observed=${_ja4:--}"
} > "$_OUT"
echo "  зонд №488: отправлено $_sent записей от pid=$_pid (${_comm:-?}), строк журнала ${_jl:-0}, pid событий ${_jpids:--}, ja3 ${_ja3:--}"
exit 0
