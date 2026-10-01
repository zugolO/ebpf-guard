#!/bin/bash
# wave7-bought-rules-controls.sh — положительные контроли на КУПЛЕННЫЕ правила
# оси `nr` (задача П волны 7). Пишет сторожевой файл, который читает эмиттер
# метки 6.7.1 в run-6.4-pipeline.sh; САМ про ДОСТИГНУТО/ПРОВАЛЕН ничего не решает,
# а только измеряет и НАЗЫВАЕТ класс каждого правила.
#
# ЗАЧЕМ. Пары порций снимали цену (события, алерты) и падение немоты по реестру.
# Они не отвечали на вопрос условия волны: «купленное правило ВЫСТРЕЛИТ, если
# сделать то, о чём оно написано». Из 10 купленных правил детектом предъявлено
# одно, и ноль по остальным девяти НЕ ЧИТАЕТСЯ ни как «мёртвое», ни как «живое»:
# аттак-шага на них не ставилось. Ноль по правилу БЕЗ контроля и ноль по правилу
# ПОД контролем — разные классы, и этот файл их разводит поимённо.
#
# КЛАССЫ ПРАВИЛА (поле class=), каждый называет, ЧТО именно не измерено:
#   SHOWN       алерт с pid нашей нагрузки под правилом (или его Rego-переименованием)
#               найден в сторе. Детект ЖИВ.
#   SWALLOWED   алерта в сторе нет, но счётчики лимитера/дедупа по правилу выросли:
#               правило, скорее всего, сработало, и его съели подавляющие слои
#               ([[dedup-is-third-suppression-layer]]). Не вердикт ни в одну сторону.
#   SILENT      событие нашей нагрузки ДОШЛО до продукта (ось nr выросла), а алерта
#               нет ни в сторе, ни в слоях подавления: правило куплено, номер открыт,
#               нагрузка соответствует написанному — и правило молчит. Продуктовая
#               находка, не приборная.
#   NO_EVENT    ось nr по номеру нагрузки НЕ выросла: событие в продукт не доехало
#               (ядерный фильтр, сэмплинг, дерево измерителя). Прибор, не детект.
#   NOT_OPEN    номера нагрузки нет в аллоулисте РАНТАЙМА ([[entry-guard-must-read-runtime-not-config]]).
#   INSTRUMENT  нагрузка не доказала себя сама (результатный сторож: comm не тот,
#               отказ запуска) — ноль в файле НЕ ЕСТЬ снятие
#               ([[positive-control-needs-result-sentinel]]).
#
# ЛОВУШКИ, КОТОРЫЕ УЖЕ СТОИЛИ ЗАМЕРА, И ГДЕ ОНИ ЗАКРЫТЫ:
#   - дерево измерителя режется в ядре и ослепляет контроль: файл
#     observer-root-pid проверяется ДО нагрузки, при наличии — class=observer_tree_armed;
#   - нагрузка обязана пережить свой readlink: каждая живёт ещё секунды после вызова;
#   - шебанг даёт comm=интерпретатор: нагрузки — python3 -c, comm печатает /proc/self/comm;
#   - номер вызова задан СЫРЫМ syscall(): обёртка glibc выбирает nr сама
#     (mkdir→83 или mkdirat→258 — зависит от версии) и мерила бы не то;
#   - контроль на новизне ОДНОРАЗОВ: FAIL при повторе в том же окне ≠ потеря детекта,
#     поэтому класс печатается вместе со счётчиками слоёв, а не одним словом;
#   - артефакты — в $W7B_DIR и $W7B_ART, НЕ в /root/ (там drift-правило).
#
# МЕСТО В ПОРЯДКЕ: после снятия журнала и метрик окна, как все контроли волн 6.4–6.6:
# обмен контроля не входит в измеряемую цену окна.
#
# Вход: W7B_ART (обязателен), W7B_API, W7B_TOKEN, W7B_CONTROL=on|off (умолчание off),
#       W7B_DIR (умолчание /var/lib/w7-bought), W7B_SETTLE_S (умолчание 25),
#       W7B_MODE=run|analyze (analyze — только разбор готовых файлов; для фикстур и реплея).
# Выход: $W7B_ART/bought-rules-controls.txt — либо ОДНА строка `class=<имя>`
# (неизмеримо, класс назван), либо по строке `rule=… class=…` на правило.

set +e +o pipefail
set -u

W7B_ART="${W7B_ART:?W7B_ART обязателен}"
W7B_API="${W7B_API:-http://localhost:19090}"
W7B_TOKEN="${W7B_TOKEN:-}"
W7B_CONTROL="${W7B_CONTROL:-off}"
W7B_DIR="${W7B_DIR:-/var/lib/w7-bought}"
W7B_SETTLE_S="${W7B_SETTLE_S:-25}"
W7B_MODE="${W7B_MODE:-run}"
W7B_ORPF="${W7B_ORPF:-/var/lib/ebpf-guard/observer-root-pid}"

_OUT="$W7B_ART/bought-rules-controls.txt"
_PAY="$W7B_ART/bought-payloads.txt"
_M0="$W7B_ART/bought-metrics-before.txt"
_M1="$W7B_ART/bought-metrics-after.txt"
_AL="$W7B_ART/bought-alerts-after.json"

if [ "$W7B_CONTROL" = "off" ]; then
    echo "--- задача П волны 7: W7B_CONTROL=off — контроли не поставлены, 6.7.1 назовёт класс сама ---"
    exit 0
fi
mkdir -p "$W7B_ART" 2>/dev/null

# ── ТАБЛИЦА: <rule_id>|<nr нагрузки>|<ожидаемый comm>|<функция нагрузки>
# Правила — РОВНО те, что манифест порций называет купленными (строки RULE);
# эмиттер сверяет состав, и правило без строки здесь получит класс БЕЗ КОНТРОЛЯ.
_TABLE="evasion_auditd_stop|62|python3|_p_kill
ransomware_backup_tool_kill|62|python3|_p_kill
evasion_timestamp_modify|280|python3|_p_utimensat
impact_fork_bomb_pattern|57|python3|_p_fork_nonroot
mitre_sandbox_detect_cpuid|135|python3|_p_personality
sigma_seccomp_filter_install|317|python3|_p_seccomp
sigma_world_writable_dir_created|258|python3|_p_mkdirat_ww
web_blind_sqli_heuristic|162|python3|_p_sync_under_nginx
sigma_prctl_dumpable|157|python3|_p_prctl_dumpable
sigma_mprotect_exec_heap|10|python3|_p_mprotect_exec
exfil_raw_socket_by_non_root|41|python3|_p_rawsock_nonroot
c2_raw_socket_shell|41|python3|_p_rawsock_root
mitre_arp_spoof_raw_socket|41|python3|_p_packet_socket
ransomware_mass_rename|82|python3|_p_rename
evasion_self_delete|87|python3|_p_unlink
ransomware_backup_delete|87|python3|_p_unlink
rootkit_kexec_load|246|python3|_p_kexec_nonroot
rootkit_userfaultfd_create|323|python3|_p_userfaultfd_nonroot
rootkit_anonymous_exec_memory|9|python3|_p_mmap_anon_exec"

# Общая шапка python-нагрузки: печатает ОДНУ строку-результат, по которой работает
# результатный сторож (pid, comm из /proc/self/comm, rc, errno). Нагрузка пишется
# в ФАЙЛ и зовётся `python3 файл`: так comm процесса — python3 (не интерпретатор
# шебанга) и нет вложенных кавычек в `nginx -c`.
export W7B_DIR
_PYHEAD='import os, sys, time, ctypes
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
def sc(n, *a):
    args = [ctypes.c_long(x) if isinstance(x, int) else x for x in a]
    ctypes.set_errno(0)
    r = libc.syscall(ctypes.c_long(n), *args)
    return r, ctypes.get_errno()
def comm():
    return open("/proc/self/comm").read().strip()
def done(rc, en):
    print("RESULT pid=%d comm=%s rc=%d errno=%d" % (os.getpid(), comm(), rc, en)); sys.stdout.flush()
    time.sleep(3)
D = os.environ["W7B_DIR"]
'
# _pyfile <имя> <тело> — пишет нагрузку, печатает путь.
_pyfile() { local f="$W7B_DIR/pl-$1.py"; printf '%s\n%s\n' "$_PYHEAD" "$2" > "$f"; echo "$f"; }

_p_kill() { python3 "$(_pyfile kill 'rc, en = sc(62, os.getpid(), 0)
done(rc, en)')"; }
_p_utimensat() { python3 "$(_pyfile utimensat 'f = D + "/ts-%d" % os.getpid(); open(f, "w").close()
rc, en = sc(280, -100, f.encode(), None, 0)
done(rc, en)')"; }
# Не-root обязателен: условие правила — uid not_in [0]. Сырой fork(57); потомок
# выходит немедленно, родитель дожидается и печатает результат.
_p_fork_nonroot() { python3 "$(_pyfile fork 'os.setgroups([]); os.setgid(65534); os.setuid(65534)
rc, en = sc(57)
if rc == 0:
    os._exit(0)
if rc > 0:
    os.waitpid(rc, 0)
done(rc, en)')"; }
# Условие правила — arg0 in [4113, 4114] при nr=135, а это personality(2), не
# arch_prctl(2): правило названо про cpuid, а ловит только такое persona-значение.
# Нагрузка предъявляет то, что написано в УСЛОВИИ.
_p_personality() { python3 "$(_pyfile personality 'rc, en = sc(135, 4113)
done(rc, en)')"; }
_p_seccomp() { python3 "$(_pyfile seccomp 'class F(ctypes.Structure): _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]
class P(ctypes.Structure): _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(F))]
sc(157, 38, 1, 0, 0, 0)
ins = (F * 1)(F(0x06, 0, 0, 0x7fff0000))
prog = P(1, ins)
rc, en = sc(317, 1, 0, ctypes.byref(prog))
done(rc, en)')"; }
_p_mkdirat_ww() { python3 "$(_pyfile mkdirat 'd = D + "/ww-%d" % os.getpid()
rc, en = sc(258, -100, d.encode(), 0o777)
done(rc, en)')"; }
# parent_comm=nginx достигается копией bash под именем nginx: comm ребёнка —
# python3, а родителя — nginx. Хвост `; exit $?` не даёт bash заменить себя на
# единственную команду (exec-оптимизация убрала бы родителя).
_p_sync_under_nginx() {
    cp "$(command -v bash)" "$W7B_DIR/nginx" 2>/dev/null || { echo "RESULT pid=0 comm=- rc=-1 errno=-1 reason=copy_bash_failed"; return; }
    local f; f=$(_pyfile sync 'rc, en = sc(162)
done(rc, en)')
    "$W7B_DIR/nginx" -c "python3 $f; exit \$?"
}
_p_prctl_dumpable() { python3 "$(_pyfile prctl 'rc, en = sc(157, 4, 0, 0, 0, 0)
done(rc, en)')"; }
_p_mprotect_exec() { python3 "$(_pyfile mprotect 'import mmap
m = mmap.mmap(-1, 4096)
addr = ctypes.addressof(ctypes.c_char.from_buffer(m))
rc, en = sc(10, addr, 4096, 5)
done(rc, en)')"; }

# Порция 4 (socket 41). Нагрузки предъявляют ТО, ЧТО ПРОВЕРЯЕТ УСЛОВИЕ после №516:
# тип сокета SOCK_RAW (arg1=3) и семейство AF_PACKET (arg0=17). Отказ ядра
# (EPERM у не-root) не мешает: правило срабатывает на входе в вызов, а сторож
# результата — «процесс дошёл до печати», а не «вызов удался».
_p_rawsock_nonroot() { python3 "$(_pyfile rawsock_nonroot 'os.setgroups([]); os.setgid(65534); os.setuid(65534)
rc, en = sc(41, 2, 3, 255)
done(rc, en)')"; }
_p_rawsock_root() { python3 "$(_pyfile rawsock_root 'rc, en = sc(41, 2, 3, 255)
done(rc, en)')"; }
_p_packet_socket() { python3 "$(_pyfile packet_socket 'rc, en = sc(41, 17, 3, 768)
done(rc, en)')"; }

# Порции 4 и 5. kexec_load и userfaultfd — ОТ НЕ-ROOT: kexec_load первым делом проверяет
# CAP_SYS_BOOT и отвечает EPERM, ничего не трогая (от root вызов с нулём сегментов
# выгрузил бы поставленный образ kexec), а userfaultfd у не-root безвреден. Правила
# срабатывают на входе в вызов, поэтому отказ ядра нагрузке не мешает.
_p_rename() { python3 "$(_pyfile rename 'a = D + "/rn-%d.txt" % os.getpid(); open(a, "w").close()
rc, en = sc(82, a.encode(), (a + ".bak").encode())
done(rc, en)')"; }
_p_unlink() { python3 "$(_pyfile unlink 'a = D + "/ul-%d.txt" % os.getpid(); open(a, "w").close()
rc, en = sc(87, a.encode())
done(rc, en)')"; }
_p_kexec_nonroot() { python3 "$(_pyfile kexec 'os.setgroups([]); os.setgid(65534); os.setuid(65534)
rc, en = sc(246, 0, 0, None, 0)
done(rc, en)')"; }
_p_userfaultfd_nonroot() { python3 "$(_pyfile userfaultfd 'os.setgroups([]); os.setgid(65534); os.setuid(65534)
rc, en = sc(323, 0)
done(rc, en)')"; }
# PROT_READ|PROT_WRITE|PROT_EXEC=7, MAP_PRIVATE|MAP_ANONYMOUS=0x22, fd=-1 (arg4 = 2^64-1).
_p_mmap_anon_exec() { python3 "$(_pyfile mmap 'rc, en = sc(9, 0, 4096, 7, 0x22, -1, 0)
done(rc, en)')"; }

_metrics() { curl -s --max-time 15 -H "Authorization: Bearer $W7B_TOKEN" "$W7B_API/metrics" 2>/dev/null; }
_alerts()  { curl -s --max-time 60 -H "Authorization: Bearer $W7B_TOKEN" "$W7B_API/api/v1/alerts?limit=200000" 2>/dev/null; }

# _sumrule <файл> <метрика> "<rule_id rule_id …>" — сумма серий метрики по набору rule_id.
_sumrule() {
    awk -v m="$2" -v set="$3" '
        BEGIN { n = split(set, a, " "); for (i = 1; i <= n; i++) s[a[i]] = 1 }
        index($1, m "{") == 1 {
            r = $1; sub(/.*rule_id="/, "", r); sub(/".*/, "", r)
            if (r in s) t += $NF
        }
        END { printf "%d", t + 0 }' "$1" 2>/dev/null
}
# _nrval <файл> <nr> — значение серии оси nr; пусто, если серии нет (отсутствие ≠ ноль).
_nrval() {
    awk -v nr="$2" 'index($1, "ebpf_guard_syscall_events_by_nr_total{nr=\"" nr "\"}") == 1 { print $NF + 0; f = 1; exit } END { if (!f) exit 1 }' "$1" 2>/dev/null
}
# _ruleset <файл метрик> <rule_id> — rule_id и все его Rego-переименования
# (серия alert_rule_id_renamed_total{base_rule_id=…,rule_id=…}, №400/№401).
_ruleset() {
    local out
    out=$(awk -v b="$2" '
        index($1, "ebpf_guard_alert_rule_id_renamed_total{") == 1 {
            x = $1; sub(/.*base_rule_id="/, "", x); sub(/".*/, "", x)
            r = $1; sub(/.*,rule_id="/, "", r); sub(/".*/, "", r)
            if (x == b && r != "") print r
        }' "$1" 2>/dev/null | sort -u | tr '\n' ' ')
    echo "$2 $out"
}

if [ "$W7B_MODE" = "run" ]; then
    : > "$_PAY"
    # ── глобальные предусловия: каждое — ОДНА строка class=…, неизмеримо целиком.
    _gcls=""
    # Файл МОЖЕТ существовать и быть выключенным: на стенде он стоит с 02.09 и
    # содержит «0» (нет корня дерева — срезать нечего). Взведён он только при
    # положительном pid; существование файла — не доказательство ([[observer-exclusion-blinds-controls]]).
    if [ -e "$W7B_ORPF" ]; then
        _orp=$(tr -dc '0-9' < "$W7B_ORPF" 2>/dev/null)
        [ -n "$_orp" ] && [ "$_orp" -gt 0 ] 2>/dev/null && _gcls="observer_tree_armed"
        [ -z "$_orp" ] && _gcls="observer_tree_file_unreadable"
    fi
    [ -z "$_gcls" ] && [ "$(uname -m)" != "x86_64" ] && _gcls="arch_not_x86_64_nr_table_is_x86_64"
    [ -z "$_gcls" ] && ! command -v python3 >/dev/null 2>&1 && _gcls="python3_missing"
    if [ -z "$_gcls" ]; then
        _metrics > "$_M0"
        [ -s "$_M0" ] || _gcls="metrics_unreachable"
    fi
    [ -z "$_gcls" ] && ! grep -aq 'ebpf_guard_syscall_events_by_nr_total{nr="' "$_M0" && _gcls="nr_axis_absent_binary_before_item_b3"
    mkdir -p "$W7B_DIR" 2>/dev/null || _gcls="${_gcls:-payload_dir_unwritable}"
    if [ -n "$_gcls" ]; then
        echo "class=$_gcls" > "$_OUT"
        echo "  П: контроли купленных правил НЕ поставлены — class=$_gcls"
        exit 0
    fi
    while IFS='|' read -r _rule _nr _expc _fn; do
        [ -n "$_rule" ] || continue
        _t=$(date +%s)
        # номер нагрузки обязан быть в оси РАНТАЙМА до вызова
        if ! _nrval "$_M0" "$_nr" >/dev/null; then
            echo "rule=$_rule payload_nr=$_nr t=$_t pids=- comm=- res=skipped open=no" >> "$_PAY"
            echo "  П: $_rule — nr $_nr НЕ объявлен рантаймом, нагрузка не запускается"
            continue
        fi
        _res=$($_fn 2>&1 | grep -a '^RESULT ' | tail -1)
        [ -n "$_res" ] || _res="RESULT pid=0 comm=- rc=-1 errno=-1 reason=no_result_line"
        _pid=$(printf '%s' "$_res" | sed -n 's/.*pid=\([0-9]*\).*/\1/p')
        _cm=$(printf '%s' "$_res" | sed -n 's/.*comm=\([^ ]*\).*/\1/p')
        _rc=$(printf '%s' "$_res" | sed -n 's/.* rc=\(-\{0,1\}[0-9]*\).*/\1/p')
        _en=$(printf '%s' "$_res" | sed -n 's/.*errno=\(-\{0,1\}[0-9]*\).*/\1/p')
        echo "rule=$_rule payload_nr=$_nr t=$_t pids=${_pid:-0} comm=${_cm:--} expect_comm=$_expc rc=${_rc:--9} errno=${_en:--9} open=yes" >> "$_PAY"
        echo "  П: $_rule — нагрузка: $_res"
        sleep 1
    done <<< "$_TABLE"
    echo "  П: осадка ${W7B_SETTLE_S}s (агрегат приходит только после Reap, порог вердикта — после неё)"
    sleep "$W7B_SETTLE_S"
    _metrics > "$_M1"
    _alerts  > "$_AL"
fi

# ── РАЗБОР. Читает ТОЛЬКО файлы, лежащие в $W7B_ART: тем же кодом его гоняют
# фикстуры и офлайн-реплей архива. Ничего не берёт у живого рантайма.
for _f in "$_PAY" "$_M0" "$_M1" "$_AL"; do
    if [ ! -s "$_f" ]; then
        echo "class=input_missing_$(basename "$_f")" > "$_OUT"
        echo "  П: нет входа разбора $_f — class=input_missing_$(basename "$_f")"
        exit 0
    fi
done
{
    while IFS= read -r _line; do
        _rule=$(printf '%s' "$_line" | sed -n 's/^rule=\([^ ]*\).*/\1/p')
        _nr=$(printf '%s' "$_line" | sed -n 's/.* payload_nr=\([0-9]*\).*/\1/p')
        _t=$(printf '%s' "$_line" | sed -n 's/.* t=\([0-9]*\).*/\1/p')
        _pid=$(printf '%s' "$_line" | sed -n 's/.* pids=\([0-9]*\).*/\1/p')
        _cm=$(printf '%s' "$_line" | sed -n 's/.* comm=\([^ ]*\).*/\1/p')
        _expc=$(printf '%s' "$_line" | sed -n 's/.* expect_comm=\([^ ]*\).*/\1/p')
        _rc=$(printf '%s' "$_line" | sed -n 's/.* rc=\(-\{0,1\}[0-9]*\).*/\1/p')
        _open=$(printf '%s' "$_line" | sed -n 's/.* open=\([a-z]*\).*/\1/p')
        _set=$(_ruleset "$_M1" "$_rule")
        _swal=$(( $(_sumrule "$_M1" ebpf_guard_alerts_ratelimited_by_rule_total "$_set") - $(_sumrule "$_M0" ebpf_guard_alerts_ratelimited_by_rule_total "$_set") \
                + $(_sumrule "$_M1" ebpf_guard_alerts_dedup_dropped_by_rule_total "$_set") - $(_sumrule "$_M0" ebpf_guard_alerts_dedup_dropped_by_rule_total "$_set") ))
        _e0=$(_nrval "$_M0" "$_nr"); _e1=$(_nrval "$_M1" "$_nr")
        if [ -n "$_e0" ] && [ -n "$_e1" ]; then _ed=$(( _e1 - _e0 )); else _ed="?"; fi
        _shown=$(jq --argjson pid "${_pid:-0}" --argjson t "${_t:-0}" --arg set "$_set" '
            ($set | split(" ") | map(select(. != ""))) as $S
            | [ .[] | select(.pid == $pid) | select(.rule_id as $r | $S | index($r))
                | select( try ((.timestamp | sub("\\.[0-9]+"; "") | sub("\\+00:00$"; "Z") | fromdateiso8601) >= ($t - 2)) catch true ) ] | length' "$_AL" 2>/dev/null)
        [ -n "$_shown" ] || _shown="?"
        # Порядок решения: сначала — доказал ли себя прибор, потом — что сказал детект.
        if [ "$_open" = "no" ]; then
            _cls=NOT_OPEN
        elif [ "${_pid:-0}" = 0 ] || [ "$_cm" != "$_expc" ] || [ "${_rc:--9}" = "-9" ]; then
            _cls=INSTRUMENT
        elif [ "$_shown" = "?" ]; then
            _cls=INSTRUMENT
        elif [ "$_shown" -gt 0 ]; then
            _cls=SHOWN
        elif [ "$_swal" -gt 0 ]; then
            _cls=SWALLOWED
        elif [ "$_ed" = "?" ] || [ "$_ed" -le 0 ]; then
            _cls=NO_EVENT
        else
            _cls=SILENT
        fi
        echo "rule=$_rule class=$_cls payload_nr=$_nr pids=${_pid:-0} comm=$_cm shown=$_shown swallowed=$_swal events_nr_delta=$_ed rc=${_rc:-?}"
    done < "$_PAY"
} > "$_OUT.tmp" && mv -f "$_OUT.tmp" "$_OUT"
echo "  П: сторожевой файл $_OUT:"
sed 's/^/    /' "$_OUT"
exit 0
