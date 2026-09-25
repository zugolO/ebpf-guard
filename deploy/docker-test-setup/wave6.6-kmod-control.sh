#!/bin/bash
# wave6.6-kmod-control.sh — item 7 волны 6.6 (№478): положительный контроль
# ЖИВОГО ДВОЙНИКА инертного kmod. Пишет сторожевой файл, который читает эмиттер
# метки 6.6.5 в run-6.4-pipeline.sh; САМ про класс ДОСТИГНУТО/ПРОВАЛЕН ничего
# не решает ([[verdict-zero-needs-its-class-presented]]).
#
# ДВЕ ПОЛОВИНЫ (без (б) метка — декларация, а не предъявление):
#   (а) collector_up{collector="kmod"} — читается из РАНТАЙМА (/metrics), не из
#       конфига ([[entry-guard-must-read-runtime-not-config]]);
#   (б) finit_module(-1, "", 0), nr 313 (x86_64): ядро отказывает EBADF, модуль
#       НЕ грузится, а sys_enter срабатывает — и rootkit_init_module_syscall
#       обязано дать алерт. Контроль ПЕЧАТАЕТ errno: без него приборный ноль
#       (вызов не дошёл до ядра) неотличим от мёртвого детекта
#       ([[positive-control-needs-result-sentinel]]).
# Нагрузка — python3 (comm=python3 вне исключений insmod/modprobe/kmod/…), она
# живёт, пока вызов не вернулся и пока не прочитан /proc/self/comm
# ([[control-payload-must-outlive-its-readlink]]).
#
# ПОСЛЕ окна, как и остальные контроли (обмен не входит в измеряемую цену).
# Артефакты — в $W66_ART, не в /root/ ([[control-artifacts-must-live-outside-root]]).
#
# Вход: W66_ART, W66_API, W66_TOKEN, W66_KMOD_CONTROL=on|off (умолчание off),
# W66_SETTLE_S (умолчание 8 — осадка алерта до чтения стора).
# Выход: $W66_ART/kmod-control.txt — ЛИБО одна строка class=<имя>, ЛИБО
# kmod_up=/errno=/errno_name=/comm=/alerts_before=/alerts_after=/alerts_delta=/rule=.

set +e +o pipefail
set -u

W66_ART="${W66_ART:?W66_ART обязателен}"
W66_API="${W66_API:?W66_API обязателен}"
W66_TOKEN="${W66_TOKEN:-}"
W66_KMOD_CONTROL="${W66_KMOD_CONTROL:-off}"
W66_SETTLE_S="${W66_SETTLE_S:-8}"
_OUT="$W66_ART/kmod-control.txt"
_RULE=rootkit_init_module_syscall

if [ "$W66_KMOD_CONTROL" = "off" ]; then
    echo "--- item 7 волны 6.6: W66_KMOD_CONTROL=off — контроль не поставлен, 6.6.5 назовёт класс сам ---"
    exit 0
fi
mkdir -p "$W66_ART" 2>/dev/null

_metrics() { curl -s --max-time 10 -H "Authorization: Bearer $W66_TOKEN" "$W66_API/metrics" 2>/dev/null; }
_class() { printf 'class=%s\n' "$1" > "$_OUT"; echo "  item 7 волны 6.6: КЛАСС НАЗВАН — $1"; exit 0; }
_count() { # алерты правила в сторе (по rule_id либо base_rule_id после Rego-переименования №400)
    curl -s --max-time 30 -H "Authorization: Bearer $W66_TOKEN" "$W66_API/api/v1/alerts?limit=200000" 2>/dev/null \
      | jq --arg r "$_RULE" '[.[] | select(.rule_id==$r or (.details.base_rule_id? == $r))] | length' 2>/dev/null
}

echo "--- item 7 волны 6.6: живой двойник kmod на syscall-оси (ПОСЛЕ окна) ---"
_snap=$(_metrics)
[ -n "$_snap" ] || _class "снимок_метрик_не_взят"
# ebpf_guard_-префикс обязателен ([[metric-anchor-must-carry-full-series-name]]).
_up=$(printf '%s\n' "$_snap" | awk 'index($1,"ebpf_guard_collector_up{")==1 && index($0,"collector=\"kmod\"")>0 {print $NF; exit}')
[ -n "$_up" ] || _class "серии_collector_up_kmod_нет_коллектор_не_зарегистрирован"
# Список LSM ядра — свойство МИРА (а не флаг): «нет bpf в списке» и есть
# причина, по которой kmod законно мёртв ([[run-intent-must-be-declared]]).
_lsm=$(cat /sys/kernel/security/lsm 2>/dev/null)
# Нечитаемый список — НЕ «bpf в нём нет». Эмиттер судит половину (а) именно
# сравнением collector_up{kmod} со списком, и пустое значение он прочитал бы как
# «bpf отсутствует», то есть вынес бы вердикт о лжи серии, не имея свойства мира
# на руках ([[verdict-zero-needs-its-class-presented]]). securityfs может быть
# не смонтирован — это класс контроля, а не показание продукта.
[ -n "$_lsm" ] || _class "список_LSM_ядра_не_прочитан_sys_kernel_security_lsm_недоступен"
command -v python3 >/dev/null 2>&1 || _class "нагрузка_недоступна_python3_нет"
command -v jq >/dev/null 2>&1 || _class "jq_недоступен_стор_не_прочитать"
[ "$(uname -m)" = "x86_64" ] || _class "архитектура_$(uname -m)_nr313_только_x86_64"

_before=$(_count)
case "${_before:-}" in ''|*[!0-9]*) _class "стор_алертов_не_прочитан_до_вызова" ;; esac

_res=$(python3 - <<'PY' 2>&1
import ctypes, os
libc = ctypes.CDLL(None, use_errno=True)
rc = libc.syscall(313, -1, b"", 0)      # finit_module(-1, "", 0)
e = ctypes.get_errno()
comm = open("/proc/self/comm").read().strip()
print("rc=%d errno=%d name=%s comm=%s" % (rc, e, os.strerror(e).replace(" ", "_"), comm))
PY
)
echo "  нагрузка: $_res"
_rc=$(printf '%s' "$_res" | sed -n 's/.*rc=\(-\?[0-9]*\).*/\1/p')
_errno=$(printf '%s' "$_res" | sed -n 's/.*errno=\([0-9]*\).*/\1/p')
_name=$(printf '%s' "$_res" | sed -n 's/.*name=\([^ ]*\).*/\1/p')
_comm=$(printf '%s' "$_res" | sed -n 's/.*comm=\([^ ]*\).*/\1/p')
[ -n "$_errno" ] || _class "нагрузка_не_напечатала_errno_вызов_не_дошёл_до_ядра"
# EBADF=9: любой другой errno значит, что вызов не тот, что задуман (EPERM —
# нет CAP_SYS_MODULE, ENOSYS — nr не тот); на ЭТОТ вызов правило тоже сработало
# бы по sys_enter, но контроль не подтверждён — класс назван, а не проглочен.
[ "$_errno" = "9" ] || _class "errno_${_errno}_${_name}_вместо_EBADF_нагрузка_не_та_что_задумана"

sleep "$W66_SETTLE_S"
_after=$(_count)
case "${_after:-}" in ''|*[!0-9]*) _class "стор_алертов_не_прочитан_после_вызова" ;; esac
_delta=$(( _after - _before ))
{
    echo "kmod_up=$_up"
    echo "lsm=${_lsm:-?}"
    echo "errno=$_errno"
    echo "errno_name=$_name"
    echo "rc=$_rc"
    echo "comm=${_comm:-?}"
    echo "rule=$_RULE"
    echo "alerts_before=$_before"
    echo "alerts_after=$_after"
    echo "alerts_delta=$_delta"
} > "$_OUT"
echo "  item 7 волны 6.6: kmod_up=$_up errno=$_errno($_name) comm=${_comm:-?} алертов $_RULE: $_before→$_after (дельта $_delta)"
exit 0
