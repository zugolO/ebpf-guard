#!/bin/bash
# wave7-controls.sh — контроли ЧУЖИХ находок, вынесенные из пайплайна 6.0
# волной 6.0m (2026-09-03).
#
# ПОЧЕМУ ЭТОТ ФАЙЛ СУЩЕСТВУЕТ. Пункт 6.0 (базовая линия дрейфа) стартовал с
# четырёх критериев и к прогону №6.0j нёс девятнадцать. Прирост — находки,
# обнаруженные ВО ВРЕМЯ измерения 6.0 и прицепленные к тому же пайплайну:
#   №200  — impact_raw_disk_write_from_container / container_escape_host_device
#   №205  — container_escape_proc_write
#   №210  — спуф argv[0], актуальность proc.args
#   №211  — хостовой container_escape_host_device_from_host
# Ни одна из них не про базовую линию дрейфа. Правило, по которому их цепляли,
# верное («правка правила без контроля есть заведение немого правила»), но
# МЕСТО было выбрано неверно: шаги стояли в окне атак, ПОСЛЕ idle-часа, и
# каждый die'ил весь прогон. Три аборта подряд (6.0f, 6.0f2, 6.0j) — все на
# механике контроля, ни один на дефекте продукта; каждый стоил двух часов
# стенда и обнулял уже собранные величины 6.0.
#
# Здесь лежат ровно те три шага, построчно, без правок логики:
#   6.0h -> критерии 6.0.13 / 6.0.14 / 6.0.15
#   6.0k -> критерии 6.0.16 / 6.0.17
#   6.0l -> критерий  6.0.18
#
# ИЗВЕСТНЫЙ ДЕФЕКТ, КОТОРЫЙ ОБЯЗАН БЫТЬ ПОЧИНЕН ДО ПЕРВОГО ЗАПУСКА (находка
# №215): у 6.0.14 НЕТ СТОРОЖА РЕЗУЛЬТАТА. Он подаёт
#   dd if=/dev/zero of=/dev/vda1 bs=512 count=0
# и требует критикала impact_raw_disk_write_from_container. Правило требует
# file.op == "write", а FILE_OP_WRITE ставится ТОЛЬКО в хуке sys_enter_write
# (bpf/fileaccess.bpf.c:426); из флагов открытия write не выводится нигде.
# `dd count=0` открывает устройство и не делает ни одного write(2) — события
# с op=write в потоке не существует, и ноль контроля не измеряет ничего.
# Именно на нём умер замер №6.0j.
#   Честный вход: count=1 — но он затрёт первые 512 байт устройства. На
#   /dev/vda1 это суперблок рабочего раздела стенда, поэтому в фикстуре и
#   стоял count=0. Чинить так: свой узел mknod на loop-устройство под теми же
#   префиксами правила (/dev/sd|nvme|xvd|vd), плюс сторож ФАКТА write(2)
#   (например сверка счётчика записей устройства или strace-сентинел), а не
#   только счётчика алертов. Ниже, у 6.0.18, образец такого сторожа уже стоит
#   («6.0.18 НЕ ИСПОЛНЕН: dumpe2fs вернул rc=...»).
#
# ЗАПУСК. Скрипт не самостоятелен: он требует живого агента и тех же двух
# переменных, что и пайплайн. Зовётся из своего окна, ПОСЛЕ снятия снимков
# замера, и его провал не имеет права убивать чужой прогон.
#   DRIFT_PC_API   — база HTTP API агента (http://<host>:19090)
#   DRIFT_PC_TOKEN — bearer-токен
# По умолчанию берутся так же, как в пайплайне.
set -u

VPS_IP="${VPS_IP:-localhost}"
DRIFT_PC_API="${DRIFT_PC_API:-http://${VPS_IP}:19090}"
DRIFT_PC_TOKEN="${DRIFT_PC_TOKEN:-${EBPF_GUARD_TOKEN:-$(grep '^admin=' /var/lib/ebpf-guard/token 2>/dev/null | cut -d= -f2)}}"

# Волна 6.0m: у этого скрипта НЕТ права убивать прогон. die() здесь — не
# останов цепочки, а запись вердикта: контроль, провалившийся на своей
# механике, оставляет свой критерий неизмеренным, но не обнуляет чужие
# величины. Ровно то разведение, ради которого шаги сюда и вынесены.
WAVE7_FAILS=0
WAVE7_VERDICTS="${WAVE7_VERDICTS:-/root/wave7-controls-verdicts.txt}"
die() {
    echo "=== КОНТРОЛЬ ПРОВАЛЕН (прогон НЕ прерывается — волна 6.0m): $* ==="
    WAVE7_FAILS=$((WAVE7_FAILS + 1))
    {
        echo "критерий=$(printf '%s' "$*" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)+' | head -1)"
        echo "время_UTC=$(date -u +%FT%TZ)"
        echo "причина: $*"
        echo "---"
    } >> "$WAVE7_VERDICTS" 2>/dev/null || true
    return 0
}

: > "$WAVE7_VERDICTS" 2>/dev/null || true
echo "# wave7-controls.sh, прогон от $(date -u +%FT%TZ)" >> "$WAVE7_VERDICTS"
echo "=== КОНТРОЛИ ВОЛНЫ 7 (вынесены из пайплайна 6.0 волной 6.0m) ==="

echo "--- 6.0h: позитивный контроль импакт-правил №200 и подмножества (б) на container_escape_proc_write (критерии 6.0.13/6.0.14/6.0.15, №200/№205) ---"
# 6.0.13 — негативный, по ОБОИМ правилам №200. dumpe2fs -h на смонтированное
# устройство раньше был false positive обоих: impact_raw_disk_write_from_container
# матчило на op=open/filename-регулярку без предиката на comm/тип операции;
# container_escape_host_device матчило на голый filename-регэксп без
# различения container/host. После правки: impact_raw_disk_write_from_container
# сужено до op=write ∧ comm в списке инструментов записи — dumpe2fs делает
# open(O_RDONLY), не матчит вовсе. container_escape_host_device разведено на
# container-случай (critical, тот же id) и host-случай (новый id, warning) —
# этот пайплайн исполняется НА ХОСТЕ (нет container.id/pod_name на событии),
# поэтому dumpe2fs здесь может поднять только новый warning-id, а критикал
# по container_escape_host_device остаётся ровно тем, что было ДО правки: 0.
_impact_critical_count() { # $1=rule_id
    curl -s --max-time 15 -H "Authorization: Bearer $DRIFT_PC_TOKEN" "$DRIFT_PC_API/api/v1/alerts" 2>/dev/null \
        | jq --arg r "$1" '[.[]|select(.rule_id==$r and .severity=="critical")]|length' 2>/dev/null || echo 0
}
_impact_neg_before1=$(_impact_critical_count impact_raw_disk_write_from_container)
_impact_neg_before2=$(_impact_critical_count container_escape_host_device)
dumpe2fs -h /dev/vda1 >/dev/null 2>&1 || true
sleep 15
_impact_neg_after1=$(_impact_critical_count impact_raw_disk_write_from_container)
_impact_neg_after2=$(_impact_critical_count container_escape_host_device)
echo "  6.0.13 негативный контроль: dumpe2fs -h /dev/vda1 -> impact_raw_disk_write_from_container критикалов: ${_impact_neg_before1:-0} -> ${_impact_neg_after1:-0}, container_escape_host_device критикалов: ${_impact_neg_before2:-0} -> ${_impact_neg_after2:-0} ($(date -u +%H:%M:%S) UTC)"
if [ "$((${_impact_neg_after1:-0} - ${_impact_neg_before1:-0}))" -ne 0 ] \
   || [ "$((${_impact_neg_after2:-0} - ${_impact_neg_before2:-0}))" -ne 0 ]; then
    die "6.0.13 ПРОВАЛЕН: dumpe2fs -h /dev/vda1 (read-only open, с хоста) подняло новых критикалов: impact_raw_disk_write_from_container +$((${_impact_neg_after1:-0} - ${_impact_neg_before1:-0})), container_escape_host_device +$((${_impact_neg_after2:-0} - ${_impact_neg_before2:-0})) — правка №200 не сузила хотя бы одно из двух правил, либо агент крутит старые правила (проверить рестарт [5/14]), либо container.id/k8s.pod ошибочно непусты на этом хосте (проверить enrichment)"
fi
echo "6.0.13 PASS $(date -u +%FT%TZ)" >> /root/drift-controls-6.0.txt 2>/dev/null || true
echo "6.0.13 доказан живьём в $(date -u +%H:%M:%S) UTC: штатный dumpe2fs -h не поднимает критикал ни по одному из двух правил №200"

# 6.0.14 — позитивный: count=0 — устройство открывается на запись, ни один
# байт не пишется физически, откат не нужен по построению.
_impact_pos_before=$(_impact_critical_count impact_raw_disk_write_from_container)
dd if=/dev/zero of=/dev/vda1 bs=512 count=0 >/dev/null 2>&1 || true
sleep 15
_impact_pos_after=$(_impact_critical_count impact_raw_disk_write_from_container)
echo "  6.0.14 позитивный контроль: dd if=/dev/zero of=/dev/vda1 bs=512 count=0 -> impact_raw_disk_write_from_container критикалов: ${_impact_pos_before:-0} -> ${_impact_pos_after:-0} ($(date -u +%H:%M:%S) UTC)"
if [ "$((${_impact_pos_after:-0} - ${_impact_pos_before:-0}))" -lt 1 ]; then
    die "6.0.14 ПРОВАЛЕН: dd (comm=dd, op=write, count=0) на /dev/vda1 не подняло ни одного критикала impact_raw_disk_write_from_container (было ${_impact_pos_before:-0}, стало ${_impact_pos_after:-0}) — правка №200 сузила правило до немоты вместо сужения FP, находка №200 не закрыта"
fi
echo "6.0.14 PASS $(date -u +%FT%TZ)" >> /root/drift-controls-6.0.txt 2>/dev/null || true
echo "6.0.14 доказан живьём в $(date -u +%H:%M:%S) UTC: dd на raw-устройство по-прежнему поднимает критикал"

# 6.0.15 — позитивный контроль подмножества (б) на container_escape_proc_write
# (№205, находка №193). sysctl -w того же значения — идемпотентно по
# построению, откат не нужен. comm=sysctl не входит в список исключений
# правила (systemd, systemd-sysctl, irqbalance).
_procwrite_count() {
    curl -s --max-time 15 -H "Authorization: Bearer $DRIFT_PC_TOKEN" "$DRIFT_PC_API/api/v1/alerts" 2>/dev/null \
        | jq '[.[]|select(.rule_id=="container_escape_proc_write")]|length' 2>/dev/null || echo 0
}
_procwrite_before=$(_procwrite_count)
_pid_max_current=$(cat /proc/sys/kernel/pid_max 2>/dev/null || echo "")
if [ -n "$_pid_max_current" ]; then
    sysctl -w kernel.pid_max="$_pid_max_current" >/dev/null 2>&1 || true
fi
sleep 15
_procwrite_after=$(_procwrite_count)
echo "  6.0.15 позитивный контроль: sysctl -w kernel.pid_max=$_pid_max_current -> container_escape_proc_write алертов: ${_procwrite_before:-0} -> ${_procwrite_after:-0} ($(date -u +%H:%M:%S) UTC)"
if [ -z "$_pid_max_current" ]; then
    die "6.0.15 НЕ ИСПОЛНИМ: /proc/sys/kernel/pid_max не читается на этом стенде — контроль нечем исполнить. Постановка требует либо 6.0.15 ДОСТИГНУТО, либо явный вывод container_escape_proc_write из подмножества (б) с записью причины в plan.md — третьего исхода нет"
fi
if [ "$((${_procwrite_after:-0} - ${_procwrite_before:-0}))" -lt 1 ]; then
    echo "6.0.15 FAIL $(date -u +%FT%TZ)" >> /root/drift-controls-6.0.txt 2>/dev/null || true
    die "6.0.15 ПРОВАЛЕН: sysctl -w kernel.pid_max=<текущее значение> (comm=sysctl, op=write, filename=/proc/sys/kernel/pid_max) не подняло ни одного алерта container_escape_proc_write (было ${_procwrite_before:-0}, стало ${_procwrite_after:-0}) — проводка флага drift_novel_workload:alert на этом правиле мертва, находка №193 закрыта только на drift_dangerous_syscall"
fi
echo "6.0.15 PASS $(date -u +%FT%TZ)" >> /root/drift-controls-6.0.txt 2>/dev/null || true
echo "6.0.15 доказан живьём в $(date -u +%H:%M:%S) UTC: sysctl -w поднимает container_escape_proc_write"

echo "--- 6.0k: контроли находки №210 — детект под спуфом argv[0] и ровно один алерт на обычный exec (критерии 6.0.16 и 6.0.17) ---"
# Буквы i и j пропущены: `6.0i` — метка шага-таблицы выше, `6.0j` — имя ВОЛНЫ,
# а файл грепается буквально (тот же разбор, что у пропущенных d и f).
#
# Что меряется. Находка №210: execve не требует, чтобы argv[0] называл образ,
# а коллектор до правки 6.0j решал «эта запись про новый образ или про
# вызывающего» ровно по совпадению comm с basename(argv[0])
# (commMatchesArgv0) и при несовпадении ОБНУЛЯЛ proc.args. Под это попадали
# весь класс правил `field: proc.args` (68 условий в дереве на 02.09),
# штатный login-shell (argv[0]="-bash", comm="bash") и маскирующийся дроппер
# T1036.003 — то есть техника, ради детекта которой правила и заведены,
# выключала детект целиком.
#
# Правка: `struct proc_args` несёт `exec_ts` (bpf_ktime_get_ns() в
# trace_sched_process_exec), и userspace прикрепляет argv тогда и только
# тогда, когда exec_ts СТАРШЕ метки самого события — то есть на записи
# sys_exit и не на записи sys_enter. Дискриминатор перестал зависеть от
# argv[0] вовсе. Резервный путь (/proc/PID/cmdline) метки времени не имеет и
# сохраняет старую эвристику; его слепота теперь измерима счётчиком
# ebpf_guard_proc_args_dropped_total{reason="argv0_mismatch"}.
#
# Пара контролей неразделима: 6.0.16 без 6.0.17 означал бы, что слепота снята
# ценой двойного алерта на каждый exec (ровно то, ради чего сверка
# commMatchesArgv0 вводилась), то есть обмен одного дефекта на другой.
#
# Оба контроля отбирают алерты ПО САМОМУ proc.args, а не по comm: под спуфом
# comm и argv[0] по построению разъезжаются, и отбор по comm мерил бы не то
# исполнение. Приём 6.0.17 («ровно 1») тем же отбором становится прямым: обе
# записи одного execve несут ОДИН И ТОТ ЖЕ argv, поэтому двойной алерт виден
# как 2, независимо от того, под каким comm приехал второй.
SP_TOUCH=""
for _sp_cand in /usr/bin/touch /bin/touch; do
    if [ -f "$_sp_cand" ] && [ -x "$_sp_cand" ]; then SP_TOUCH="$_sp_cand"; break; fi
done
[ -n "$SP_TOUCH" ] \
    || die "6.0k: ни /usr/bin/touch, ни /bin/touch не оказались исполняемым обычным файлом — примитив обоих контролей нечем собрать. Брать builtin нельзя (находка №176), и брать «true» тоже нельзя: у него нет наблюдаемого результата, а контроль без сторожа результата даёт ложный ноль при execve ENOENT (память «позитивный контроль по результату»)"
SP_WORKDIR=/usr/local/bin/sp-work
SP_SEEDDIR=/usr/local/bin/sp-seed
mkdir -p "$SP_WORKDIR" "$SP_SEEDDIR" 2>/dev/null || die "6.0k: не удалось создать $SP_WORKDIR/$SP_SEEDDIR"

_sp_count_args() { # $1=префикс proc.args -> число алертов правила с таким proc.args
    curl -s --max-time 15 -H "Authorization: Bearer $DRIFT_PC_TOKEN" "$DRIFT_PC_API/api/v1/alerts" 2>/dev/null \
        | jq --arg a "$1" '[.[]|select(.rule_id=="drift_exec_from_system_bin" and ((.details["proc.args"] // "") | startswith($a)))]|length' 2>/dev/null \
        || echo 0
}
_sp_args_of() { # $1=comm -> proc.args последнего алерта правила под этим comm (сторож п.2 волны 6.0j)
    curl -s --max-time 15 -H "Authorization: Bearer $DRIFT_PC_TOKEN" "$DRIFT_PC_API/api/v1/alerts" 2>/dev/null \
        | jq -r --arg c "$1" '[.[]|select(.rule_id=="drift_exec_from_system_bin" and .comm==$c)] | if length == 0 then "<алертов правила под этим comm нет>" else (sort_by(.timestamp) | .[-1].details["proc.args"] // "<поля нет в алерте>") end' 2>/dev/null \
        || echo "<не удалось прочитать /api/v1/alerts>"
}
_sp_limited() {
    curl -s --max-time 15 -H "Authorization: Bearer $DRIFT_PC_TOKEN" "$DRIFT_PC_API/metrics" 2>/dev/null \
        | awk '/^ebpf_guard_alerts_ratelimited_by_rule_total\{/ && /rule_id="drift_exec_from_system_bin"/ { s += $NF } END { printf "%d", s+0 }'
}
_sp_dropped() { # $1=reason -> ebpf_guard_proc_args_dropped_total{reason=...}
    curl -s --max-time 15 -H "Authorization: Bearer $DRIFT_PC_TOKEN" "$DRIFT_PC_API/metrics" 2>/dev/null \
        | awk -v r="reason=\"$1\"" '/^ebpf_guard_proc_args_dropped_total\{/ && index($0, r) { s += $NF } END { printf "%d", s+0 }'
}

# --- 6.0.16: позитивный, закрывает №210 -------------------------------------
# Каждая попытка берёт СВЕЖИЙ hex: повтор той же сигнатуры после среза
# лимитера был бы подавлен базовой линией как already_reported, и ложный ноль
# сменился бы другим ложным нулём (память «потолок rate-limiter'а»).
_sp16_attempt() { # заполняет _sp16_{comm,spoof,sentinel,before,after,lim_before,lim_after}
    local hex; hex=$(head -c 4 /dev/urandom 2>/dev/null | od -An -tx1 | tr -d ' \n')
    _sp16_comm="sp-$hex"
    [ "${#_sp16_comm}" -le 15 ] || die "6.0k: сгенерированный comm '$_sp16_comm' длиннее 15 символов — ядро усечёт его"
    local bin="$SP_WORKDIR/$_sp16_comm"
    _sp16_spoof="$SP_SEEDDIR/$hex"
    _sp16_sentinel="/tmp/sp-ran-$hex"
    cp "$SP_TOUCH" "$bin" 2>/dev/null || die "6.0.16: не удалось подготовить $bin из $SP_TOUCH"
    chmod +x "$bin" || die "6.0.16: не удалось сделать $bin исполняемым"
    [ -x "$bin" ] || die "6.0.16: $bin не исполняем после chmod (noexec на /usr/local?) — execve упадёт с EACCES ДО смены comm, и контроль получит ложный ноль (класс находки №176)"
    rm -f "$_sp16_sentinel"
    _sp16_before=$(_sp_count_args "$_sp16_spoof")
    _sp16_lim_before=$(_sp_limited)
    # ARGV0-SPOOF-BY-DESIGN (№210)
    # Единственное место пайплайна, где подмена argv[0] разрешена преflight'ом
    # 6.0j/№210: здесь она и есть ПРЕДМЕТ измерения. argv[0] — путь в
    # $SP_SEEDDIR (префикс /usr/local/bin/ обязателен: без него правило с
    # `op: prefix` по proc.args не сматчит вовсе), исполняемый файл — другой,
    # в $SP_WORKDIR, и comm=$_sp16_comm равен его имени, а не basename(argv[0]).
    # До правки №210 commMatchesArgv0 обнулял бы proc.args на ОБЕИХ записях
    # execve, и контроль давал бы ровно ноль.
    bash -c "exec -a '$_sp16_spoof' '$bin' '$_sp16_sentinel'" >/dev/null 2>&1 || true
    # Сторож результата (память «позитивный контроль по результату»): без него
    # ENOENT/EACCES на execve выглядят как «детект не сработал».
    [ -e "$_sp16_sentinel" ] \
        || die "6.0.16 НЕ ИСПОЛНЕН: подменённый вызов не создал $_sp16_sentinel — сам execve не состоялся (ENOENT/EACCES/усечённый argv), и ноль алертов ниже был бы приборным. Проверить $bin и права на /usr/local/bin"
    sleep 20
    _sp16_after=$(_sp_count_args "$_sp16_spoof")
    _sp16_lim_after=$(_sp_limited)
    rm -f "$bin" "$_sp16_sentinel"
}
_sp16_dropped_before=$(_sp_dropped argv0_mismatch)
_sp16_attempt
echo "  6.0.16 позитивный контроль: argv[0]=$_sp16_spoof подменён у реального образа comm=$_sp16_comm -> алертов drift_exec_from_system_bin с этим proc.args: ${_sp16_before:-0} -> ${_sp16_after:-0}, срез лимитера ${_sp16_lim_before:-0} -> ${_sp16_lim_after:-0} ($(date -u +%H:%M:%S) UTC)"
if [ "$((${_sp16_after:-0} - ${_sp16_before:-0}))" -lt 1 ] \
   && [ "$(( ${_sp16_lim_after:-0} - ${_sp16_lim_before:-0} ))" -gt 0 ]; then
    echo "  6.0.16: ноль алертов ПРИ выросшем срезе лимитера (+$(( ${_sp16_lim_after:-0} - ${_sp16_lim_before:-0} ))) — приборный ноль. Даём окну лимитера (60с) стечь и повторяем один раз, со свежей сигнатурой"
    sleep 70
    _sp16_attempt
    echo "  6.0.16 повтор после стекания окна лимитера: argv[0]=$_sp16_spoof, алертов ${_sp16_before:-0} -> ${_sp16_after:-0}, срез ${_sp16_lim_before:-0} -> ${_sp16_lim_after:-0} ($(date -u +%H:%M:%S) UTC)"
fi
_sp16_args=$(_sp_args_of "$_sp16_comm")
echo "  6.0.16 proc.args последнего алерта под comm=$_sp16_comm: $_sp16_args (ожидается начало с $_sp16_spoof — сторож п.2 волны 6.0j/№209)"
echo "  6.0.16 счётчик слепоты резервного пути: ebpf_guard_proc_args_dropped_total{reason=\"argv0_mismatch\"} ${_sp16_dropped_before:-0} -> $(_sp_dropped argv0_mismatch), {reason=\"stale_exec\"} = $(_sp_dropped stale_exec)"
if [ "$((${_sp16_after:-0} - ${_sp16_before:-0}))" -lt 1 ]; then
    echo "6.0.16 FAIL $(date -u +%FT%TZ) comm=$_sp16_comm" >> /root/drift-controls-6.0.txt 2>/dev/null || true
    rm -rf "$SP_WORKDIR" "$SP_SEEDDIR"
    die "6.0.16 ПРОВАЛЕН: execve с подменённым argv[0]=$_sp16_spoof (реальный образ — другой файл, comm=$_sp16_comm) не дал ни одного алерта drift_exec_from_system_bin с этим proc.args (было ${_sp16_before:-0}, стало ${_sp16_after:-0}); сам вызов состоялся — сторож результата выше зелёный. Читать в порядке: срез лимитера за попытку +$(( ${_sp16_lim_after:-0} - ${_sp16_lim_before:-0} )) (ненулевой после повтора = причина приборная); прирост proc_args_dropped_total{reason=\"argv0_mismatch\"} = проводка идёт резервным путём (/proc/PID/cmdline, ядро без BTF), где эвристика argv[0] сохранена сознательно и слепота остаётся известным ограничением; прирост {reason=\"stale_exec\"} без алертов = exec_ts прикрепил argv не к той записи; ноль по обоим счётчикам и ноль алертов = правка №210 не в ядре, то есть `make generate` на шаге [3/14] собрал bpf/common.h без поля exec_ts, и контроль мерит старый бинарь"
fi
echo "6.0.16 PASS $(date -u +%FT%TZ) comm=$_sp16_comm" >> /root/drift-controls-6.0.txt 2>/dev/null || true
echo "6.0.16 доказан живьём в $(date -u +%H:%M:%S) UTC: детект класса proc.args пережил подмену argv[0] (находка №210 закрыта)"

# --- 6.0.17: негативный, антирегресс ----------------------------------------
# Ровно один алерт на один обычный execve. Именно это обеспечивала сверка
# commMatchesArgv0, снятая правкой №210 с основного пути: без дискриминатора
# argv вызываемого приезжает и на запись sys_enter, и правило поднимается
# дважды за exec, второй раз — под comm вызывающего. Отбор по самому
# proc.args ловит обе записи, потому что argv у них общий.
_sp17_attempt() {
    local hex; hex=$(head -c 4 /dev/urandom 2>/dev/null | od -An -tx1 | tr -d ' \n')
    _sp17_comm="sp2-$hex"
    [ "${#_sp17_comm}" -le 15 ] || die "6.0k: сгенерированный comm '$_sp17_comm' длиннее 15 символов — ядро усечёт его"
    _sp17_dir="/usr/local/bin/sp-plain-$hex"
    mkdir -p "$_sp17_dir" 2>/dev/null || die "6.0.17: не удалось создать $_sp17_dir"
    _sp17_bin="$_sp17_dir/$_sp17_comm"
    _sp17_sentinel="/tmp/sp2-ran-$hex"
    cp "$SP_TOUCH" "$_sp17_bin" 2>/dev/null || die "6.0.17: не удалось подготовить $_sp17_bin из $SP_TOUCH"
    chmod +x "$_sp17_bin" || die "6.0.17: не удалось сделать $_sp17_bin исполняемым"
    [ -x "$_sp17_bin" ] || die "6.0.17: $_sp17_bin не исполняем после chmod (noexec на /usr/local?)"
    rm -f "$_sp17_sentinel"
    _sp17_before=$(_sp_count_args "$_sp17_bin")
    _sp17_lim_before=$(_sp_limited)
    "$_sp17_bin" "$_sp17_sentinel" >/dev/null 2>&1 || true
    [ -e "$_sp17_sentinel" ] \
        || die "6.0.17 НЕ ИСПОЛНЕН: обычный вызов не создал $_sp17_sentinel — execve не состоялся, и любое число алертов ниже относится не к нему"
    sleep 20
    _sp17_after=$(_sp_count_args "$_sp17_bin")
    _sp17_lim_after=$(_sp_limited)
    rm -rf "$_sp17_dir"
    rm -f "$_sp17_sentinel"
}
_sp17_attempt
echo "  6.0.17 негативный контроль: один обычный execve $_sp17_bin (comm=$_sp17_comm, невиданный каталог, argv[0] равен пути) -> алертов drift_exec_from_system_bin с этим proc.args: ${_sp17_before:-0} -> ${_sp17_after:-0}, срез лимитера ${_sp17_lim_before:-0} -> ${_sp17_lim_after:-0} ($(date -u +%H:%M:%S) UTC)"
echo "  6.0.17 proc.args последнего алерта под comm=$_sp17_comm: $(_sp_args_of "$_sp17_comm") (сторож п.2 волны 6.0j/№209)"
if [ "$((${_sp17_after:-0} - ${_sp17_before:-0}))" -eq 0 ] \
   || [ "$(( ${_sp17_lim_after:-0} - ${_sp17_lim_before:-0} ))" -gt 0 ]; then
    echo "  6.0.17: попытка непригодна для вердикта (ноль алертов либо ненулевой срез лимитера — «ровно 1» тогда может быть срезанной двойкой). Даём окну лимитера (60с) стечь и повторяем один раз, со свежей сигнатурой"
    sleep 70
    _sp17_attempt
    echo "  6.0.17 повтор: $_sp17_bin -> алертов ${_sp17_before:-0} -> ${_sp17_after:-0}, срез ${_sp17_lim_before:-0} -> ${_sp17_lim_after:-0} ($(date -u +%H:%M:%S) UTC)"
fi
if [ "$((${_sp17_after:-0} - ${_sp17_before:-0}))" -ne 1 ]; then
    echo "6.0.17 FAIL $(date -u +%FT%TZ) comm=$_sp17_comm" >> /root/drift-controls-6.0.txt 2>/dev/null || true
    rm -rf "$SP_WORKDIR" "$SP_SEEDDIR"
    die "6.0.17 ПРОВАЛЕН: один execve $_sp17_bin дал $((${_sp17_after:-0} - ${_sp17_before:-0})) алертов drift_exec_from_system_bin с этим proc.args вместо ровно 1, срез лимитера за попытку +$(( ${_sp17_lim_after:-0} - ${_sp17_lim_before:-0} )). Читать так: 2 и больше = снятие сверки commMatchesArgv0 с основного пути вернуло алерт на записи sys_enter, то есть exec_ts прикрепляет argv к обеим записям (проверить, что bpf/common.h собран с полем exec_ts и что userspace сравнивает его с меткой события, а не с нулём) — слепота снята ценой двойного алерта на КАЖДЫЙ exec, и это обмен одного дефекта на другой, а не исправление; 0 при нулевом срезе лимитера = правило не сматчило вовсе, и 6.0.16 выше засчитан по чужому алерту"
fi
echo "6.0.17 PASS $(date -u +%FT%TZ) comm=$_sp17_comm" >> /root/drift-controls-6.0.txt 2>/dev/null || true
echo "6.0.17 доказан живьём в $(date -u +%H:%M:%S) UTC: один exec — ровно один алерт, двойного срабатывания за execve нет"
rm -rf "$SP_WORKDIR" "$SP_SEEDDIR"

echo "--- 6.0l: позитивный контроль container_escape_host_device_from_host (критерий 6.0.18, №211) ---"
# Буква l — следующая свободная за k (i занята шагом-таблицей, j — именем
# ВОЛНЫ, а файл грепается буквально).
#
# Что меряется. Волна 6.0f развела container_escape_host_device на два
# правила: контейнерный случай (тот же id, critical) и хостовой (новый id
# container_escape_host_device_from_host, warning). Контроль получил только
# ПЕРВЫЙ: 6.0.13 негативный и считает исключительно КРИТИКАЛЫ обоих id,
# тогда как хостовое правило — warning, и ни один его алерт в вердикт 6.0.13
# не входит по построению. Правило было заведено без собственного контроля —
# ровно то «заведение немого правила», которое сторож преflight'а п.9 волны
# 6.0f и должен был запретить; он прошёл ложно-зелёным, потому что грепал
# префикс `_impact_critical_count container_escape_host_device`, матчащийся
# на контейнерное правило (сторож якорен на полный id правкой п.5 волны 6.0j).
#
# Цена немоты — два FAIL гейта замера №6.0f2: «состав детекта: потеряно 1
# типов вне intentional-loss.txt» и «1 правило немо за весь аптайм без строки
# в silent-rules.txt (категория (в))». Оба воспроизвелись бы и на этом
# прогоне: реестр new-rules.txt вычитает правило только на архивах СТАРШЕ
# даты заведения (20260901), а это прогон своей волны.
#
# Записи в silent-rules.txt НЕ заводится сознательно: она утверждала бы, что
# стенд не воспроизводит сценарий правила, а это ложь — сценарий
# воспроизводится ниже, в этом же пайплайне.
#
# Один примитив закрывает обе стороны разведения и совместим с 6.0.13:
# 6.0.13 утверждает «критикалов нет», 6.0.18 — «детект не потерян». Поэтому
# критикалы обоих id проверяются здесь ЕЩЁ РАЗ, на своём собственном
# примитиве: позитивный контроль, поднявший заодно критикал, означал бы, что
# разведение не состоялось, а не что детект жив.
_hd_dev=/dev/vda1
[ -b "$_hd_dev" ] \
    || die "6.0.18 НЕ ИСПОЛНИМ: $_hd_dev не блочное устройство — примитив контроля нечем исполнить. Репетиция [6/14] обязана была поймать это ДО idle-часа (сторож 6.0h/6.0l), и если прогон дошёл сюда, значит репетиция не покрывает того, что печатает (6.0.19 признаётся не покрывающей, см. постановку волны 6.0j)"
command -v dumpe2fs >/dev/null 2>&1 \
    || die "6.0.18 НЕ ИСПОЛНИМ: dumpe2fs(8) (e2fsprogs) не установлен — тот же примитив, что у 6.0.13, и та же претензия к репетиции [6/14]"
_hd_count() { # $1=rule_id, $2=severity -> число алертов правила этой строгости
    curl -s --max-time 15 -H "Authorization: Bearer $DRIFT_PC_TOKEN" "$DRIFT_PC_API/api/v1/alerts" 2>/dev/null \
        | jq --arg r "$1" --arg s "$2" '[.[]|select(.rule_id==$r and .severity==$s)]|length' 2>/dev/null || echo 0
}
_hd_limited() { # срез лимитера по хостовому правилу (сторож ложного нуля)
    curl -s --max-time 15 -H "Authorization: Bearer $DRIFT_PC_TOKEN" "$DRIFT_PC_API/metrics" 2>/dev/null \
        | awk '/^ebpf_guard_alerts_ratelimited_by_rule_total\{/ && /rule_id="container_escape_host_device_from_host"/ { s += $NF } END { printf "%d", s+0 }'
}
# Сторож результата (память «позитивный контроль по результату», comm=tar
# 20/20 при execve ENOENT): без кода возврата самого dumpe2fs ноль алертов
# ниже неотличим от «устройство не открывалось вовсе» — не ext-раздел, нет
# прав, устройство занято. rc проверяется ДО того, как контроль посмотрит на
# алерты.
_hd18_attempt() { # заполняет _hd18_{warn_before,warn_after,c1_before,c1_after,c2_before,c2_after,lim_before,lim_after,rc}
    _hd18_warn_before=$(_hd_count container_escape_host_device_from_host warning)
    _hd18_c1_before=$(_hd_count container_escape_host_device critical)
    _hd18_c2_before=$(_hd_count container_escape_host_device_from_host critical)
    _hd18_lim_before=$(_hd_limited)
    dumpe2fs -h "$_hd_dev" >/dev/null 2>&1
    _hd18_rc=$?
    [ "$_hd18_rc" -eq 0 ] \
        || die "6.0.18 НЕ ИСПОЛНЕН: dumpe2fs -h $_hd_dev вернул rc=$_hd18_rc — устройство не было прочитано, и любое число алертов ниже относится не к этому вызову. Ноль здесь был бы приборным (класс находки №176), а не вердиктом о правиле"
    sleep 20
    _hd18_warn_after=$(_hd_count container_escape_host_device_from_host warning)
    _hd18_c1_after=$(_hd_count container_escape_host_device critical)
    _hd18_c2_after=$(_hd_count container_escape_host_device_from_host critical)
    _hd18_lim_after=$(_hd_limited)
}
_hd18_attempt
echo "  6.0.18 позитивный контроль: dumpe2fs -h $_hd_dev с хоста (rc=$_hd18_rc) -> container_escape_host_device_from_host warning: ${_hd18_warn_before:-0} -> ${_hd18_warn_after:-0}; критикалы container_escape_host_device: ${_hd18_c1_before:-0} -> ${_hd18_c1_after:-0}, container_escape_host_device_from_host: ${_hd18_c2_before:-0} -> ${_hd18_c2_after:-0}; срез лимитера ${_hd18_lim_before:-0} -> ${_hd18_lim_after:-0} ($(date -u +%H:%M:%S) UTC)"
# Сторож ложного нуля, общий с 6.0.6/6.0.12/6.0.16/6.0.17. Шаг стоит ПОСЛЕ
# окна атак, где лимитер уже мог набрать своё (память «контроль после атак и
# лимитер»): ноль при выросшем срезе — это срез, а не вердикт.
if [ "$(( ${_hd18_warn_after:-0} - ${_hd18_warn_before:-0} ))" -lt 1 ] \
   && [ "$(( ${_hd18_lim_after:-0} - ${_hd18_lim_before:-0} ))" -gt 0 ]; then
    echo "  6.0.18: ноль алертов ПРИ выросшем срезе лимитера (+$(( ${_hd18_lim_after:-0} - ${_hd18_lim_before:-0} ))) — приборный ноль. Даём окну лимитера (60с) стечь и повторяем один раз"
    sleep 70
    _hd18_attempt
    echo "  6.0.18 повтор после стекания окна лимитера: warning ${_hd18_warn_before:-0} -> ${_hd18_warn_after:-0}, срез ${_hd18_lim_before:-0} -> ${_hd18_lim_after:-0} ($(date -u +%H:%M:%S) UTC)"
fi
if [ "$(( ${_hd18_warn_after:-0} - ${_hd18_warn_before:-0} ))" -lt 1 ]; then
    echo "6.0.18 FAIL $(date -u +%FT%TZ)" >> /root/drift-controls-6.0.txt 2>/dev/null || true
    die "6.0.18 ПРОВАЛЕН: dumpe2fs -h $_hd_dev с хоста (rc=0, устройство прочитано) не подняло ни одного алерта container_escape_host_device_from_host уровня warning (было ${_hd18_warn_before:-0}, стало ${_hd18_warn_after:-0}), срез лимитера за попытку +$(( ${_hd18_lim_after:-0} - ${_hd18_lim_before:-0} )). Читать в порядке: ненулевой срез после повтора = причина приборная; нулевой срез = хостовая половина разведения №200 нема продуктово, то есть волна 6.0f завела правило, которое не поднимается на СВОЁМ сценарии — проверить предикаты container.id/k8s.pod (op: eq, values: [\"\"]) против обогащения этого хоста и то, что агент крутит новые правила (рестарт [5/14]). Третьего исхода у 6.0.18 нет: правило без исполнившегося контроля возвращается в состояние, из-за которого волна 6.0j и заведена"
fi
# Вторая сторона разведения: тот же примитив не смеет поднять критикал НИ ПО
# ОДНОМУ из двух id. Это не дубль 6.0.13 (он мерил свой собственный вызов
# dumpe2fs на шаге 6.0h): здесь проверяется, что критикал не пришёл ИМЕННО
# от того вызова, который дал warning, — иначе «детект не потерян» было бы
# куплено ценой возврата ложного критикала, ради устранения которого №200 и
# разводило правило.
if [ "$(( ${_hd18_c1_after:-0} - ${_hd18_c1_before:-0} ))" -ne 0 ] \
   || [ "$(( ${_hd18_c2_after:-0} - ${_hd18_c2_before:-0} ))" -ne 0 ]; then
    echo "6.0.18 FAIL $(date -u +%FT%TZ) (критикал на позитивном примитиве)" >> /root/drift-controls-6.0.txt 2>/dev/null || true
    die "6.0.18 ПРОВАЛЕН: тот же dumpe2fs -h $_hd_dev, что дал warning хостового правила, поднял и критикал: container_escape_host_device +$(( ${_hd18_c1_after:-0} - ${_hd18_c1_before:-0} )), container_escape_host_device_from_host +$(( ${_hd18_c2_after:-0} - ${_hd18_c2_before:-0} )). Разведение №200 не состоялось: хостовой случай снова критикал-first, и 6.0.13 на шаге 6.0h выше засчитан по случайности, а не по сужению. Правило _from_host обязано быть severity: warning (rules/container-escape.yaml), контейнерное — обязано требовать непустой container.id/k8s.pod"
fi
echo "6.0.18 PASS $(date -u +%FT%TZ)" >> /root/drift-controls-6.0.txt 2>/dev/null || true
echo "6.0.18 доказан живьём в $(date -u +%H:%M:%S) UTC: container_escape_host_device_from_host поднимается на своём сценарии (warning, без критикалов) — правило перестало быть немым, оба FAIL гейта №6.0f2 закрыты продуктом, а не реестром"

echo "=== wave7-controls.sh завершён: проваленных контролей $WAVE7_FAILS, вердикты в $WAVE7_VERDICTS ==="
exit 0
