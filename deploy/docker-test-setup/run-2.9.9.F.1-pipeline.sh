#!/usr/bin/env bash
# ЗАМЕР №2.9.9.F.1 — приёмка волны 5.9.9.F.1, вход в волну 6 (plan.md, "ЗАМЕР №2.9.9.F.1").
# Структура унаследована от №2.9.9 дословно; отличия — пятый архив реплея
# (collect-2.9.9, реплей 6/6 волны 5.9.9.Fe) и имена артефактов.
#
# Структура унаследована от №2.9.8 дословно (преflight -> реплеи -> сборка ->
# P0-3 -> очистка -> SMOKE -> контроли вне окна -> пауза -> idle-час -> атаки
# -> гейт -> отчёт, ОДНИМ detached-процессом) — 5.9.9 не трогает bpf/*.bpf.c,
# поэтому в отличие от 5.9.8 копия этого файла не обязана менять шаги
# [1/14]/[3/14]/[6/14]/[7/14] по существу, только номер замера в путях/логах
# (5.9.9f, №104) и smoke_sum() (5.9.9f, №103, см. ниже).
#
# 5.9.9f (№104, ЭТА ПРАВКА): ниже сделаны ровно два исправления, которые и
# были её содержанием — smoke_sum() переведён на ENVIRON (та же правка, что
# уже стоит в run-gate.sh/run-all-attacks.sh: -v assignments запускают
# unescaped-sequence обработку строки и портят вывод предупреждением на
# каждый вызов "\{"), и заголовок отчёта передаётся через REPORT_LABEL, а не
# зашивается литералом run-2.9.5-report.sh.
#
# Пятый жёсткий стоп преflight'а (5.9.9a, №99) — ЗДЕСЬ, в шаге [1/14]:
# replay-gate.sh получил четвёртый архив (collect-2.9.8) и пятый реплей,
# который требует ОБА исхода механизма «база брошена» — молчание при
# повторном вызове гейта за тот же замер и WARN при чужом TIMESTAMP в файле
# состояния. Оба проверяются здесь поимённо, отдельно от кода возврата
# реплея: механизм, разучившийся печатать WARN, вернул бы 0 и прошёл бы.
#
# Запуск (обязательно detached, иначе обрыв ssh убивает замер):
#   setsid nohup bash /opt/ebpf-guard/deploy/docker-test-setup/run-2.9.9.F.1-pipeline.sh >/dev/null 2>&1 &
# Готовность: файл /root/PIPELINE-2.9.9.F.1-DONE. Полный лог: /root/run-2.9.9.F.1-pipeline.log
#
# ПРЕДУПРЕЖДЕНИЕ (риск №2 постановки 5.9.5, дожил без изменений):
# run_kill_scenario намеренно доводит энфорсер до разрушительного действия
# против одноразового дочернего процесса харнесса. Жертва одноразовая и шаг
# стоит ПОСЛЕ окна атак — сломанный предохранитель (dry_run не погасил kill)
# портит один шаг замера, а не весь прогон, но убивает реальный процесс.
exec > /root/run-2.9.9.F.1-pipeline.log 2>&1
set -x
SETUP=/opt/ebpf-guard/deploy/docker-test-setup
IDLE_OUT=$SETUP/idle-results/idle-2.9.9.F.1
P0_OUT=$SETUP/idle-results/p0-3-2.9.9.F.1
export PATH="$PATH:/usr/local/go/bin"

die() {
    echo "=== СТОП: $* ==="
    echo "=== ЗАМЕР №2.9.9.F.1 НЕ НАЧАТ. $(date -u +%H:%M:%S) UTC ==="
    touch /root/PIPELINE-2.9.9.F.1-DONE
    exit 1
}

# Параметры волны объявлены ЗДЕСЬ и печатаются в преflight (п.4 порядка
# работы): величина, влияющая на критерий, обязана лежать в артефактах
# замера, а не восстанавливаться потом чтением кода.
export COUNTING_CONTROL_N="${COUNTING_CONTROL_N:-10000}"
export COUNTING_CONTROL_DROP_N="${COUNTING_CONTROL_DROP_N:-300000}"
export INDUCED_DROP_MAX_FILES="${INDUCED_DROP_MAX_FILES:-20000}"
export RINGBUF_OVERFLOW_N="${RINGBUF_OVERFLOW_N:-300000}"
export RINGBUF_OVERFLOW_SERVICE="${RINGBUF_OVERFLOW_SERVICE:-ebpf-guard-test.service}"
# 5.9.8a: число межпоточных резолвов позитивного контроля. Маленькое
# намеренно — контроль отвечает на вопрос «видит ли коллектор межпоточный
# fd вообще», а не мерит пропускную способность.
export DNS_CROSS_THREAD_N="${DNS_CROSS_THREAD_N:-8}"

echo "=== [0/14] преflight: что именно меряется ==="
cd /opt/ebpf-guard || die "нет /opt/ebpf-guard"
git log -1 --format='коммит замера: %H %s (%ci)'
git status --porcelain | sed 's/^/  локальная правка: /'
./build/ebpf-guard version 2>&1 | sed 's/^/  бинарь (до пересборки): /' || true
./build/ebpf-guard rules check tests/rules/ 2>&1 | tail -5

echo "--- преflight: интерпретатор ---"
echo "  bash: ${BASH_VERSION}"
[ "${BASH_VERSINFO[0]}" -ge 4 ] || die "bash ${BASH_VERSION} — run-gate.sh требует 4+ (declare -A, секция 19)"

echo "--- преflight: go-тесты волн 5.9.4/5.9.5 ---"
go test -count=1 ./internal/enforcer/ -run 'DryRunSentinel|TestExecuteKill_DryRun|TestExecuteThrottle_DryRun' 2>&1 | tail -3
go test -count=1 -v ./internal/correlator/ -run 'TestDestructiveRulesInventory_RepoRules|TestExclusionsCollidingWithAttackerComms_RepoRules|TestRootkitBPFRules_MatchCommandNotCaller|TestKillScenarioControlRule_ActionIsKill' 2>&1 \
    | grep -E 'разрушительных|правил проверено|^(ok|FAIL|--- )' | sed 's/^/  /'

echo "--- преflight: go-тесты волны 5.9.6 ---"
go test -count=1 ./internal/bpf/ -run 'SumPerCPU' 2>&1 | tail -3
go test -count=1 ./internal/collector/ -run 'DNS|Malformed' 2>&1 | tail -3

echo "--- преflight: go-тесты волны 5.9.7 (риск №3: сужение != ослепление) ---"
go test -count=1 -v ./internal/correlator/ -run 'TestWave597' 2>&1 | grep -E '^(=== RUN|--- |ok|FAIL)' | sed 's/^/  /'
go test -count=1 ./internal/correlator/ -run 'TestWave597' >/dev/null 2>&1 \
    || die "юнит-тесты 5.9.7e/f красные — сужение rootkit_ssh_authorized_keys_modified/sigma_sensitive_dir_listing не доказано как не-ослепление (риск №3)"

# Волна 5.9.8. Два независимых набора, оба обязательны:
#   - парсер DNS-заголовка (5.9.8a): TLS-ClientHello не становится DNS-событием
#     НИ ПРИ КАКОЙ причине отказа, валидный заголовок не отвергается;
#   - сужение webshell_script_write_via_web_process по comm (5.9.8g) вместе с
#     его позитивной половиной — тот же риск №3 в третий раз.
echo "--- преflight: go-тесты волны 5.9.8 ---"
go test -count=1 -v ./internal/collector/ -run 'TestParseDNSWireMessage' 2>&1 | grep -E '^(--- |ok|FAIL)' | sed 's/^/  /'
go test -count=1 ./internal/collector/ -run 'TestParseDNSWireMessage' >/dev/null 2>&1 \
    || die "юнит-тесты разбора DNS-заголовка (5.9.8a) красные — второй заслон против TLS в DNS-пути не доказан"
go test -count=1 -v ./internal/correlator/ -run 'TestWave598' 2>&1 | grep -E '^(=== RUN|--- |ok|FAIL)' | sed 's/^/  /'
go test -count=1 ./internal/correlator/ -run 'TestWave598' >/dev/null 2>&1 \
    || die "юнит-тесты 5.9.8g красные — сужение webshell_script_write_via_web_process не доказано как не-ослепление (риск №3)"

# Волна 5.9.9. Сужение webshell_crontab_modification по comm (5.9.9b,
# находка №98) — тот же риск №3 в четвёртый раз, и его юнит-половина обязана
# стоять здесь по той же причине, что 5.9.7e и 5.9.8g: сужение, ослепившее
# правило, красит преflight, а не идёт в отчёт после idle-часа.
echo "--- преflight: go-тесты волны 5.9.9 ---"
go test -count=1 -v ./internal/correlator/ -run 'TestWave599' 2>&1 | grep -E '^(=== RUN|--- |ok|FAIL)' | sed 's/^/  /'
go test -count=1 ./internal/correlator/ -run 'TestWave599' >/dev/null 2>&1 \
    || die "юнит-тесты 5.9.9b красные — сужение webshell_crontab_modification не доказано как не-ослепление (риск №3)"

echo "--- преflight: синтаксис харнесса ---"
bash -n $SETUP/attacks/run-all-attacks.sh || die "run-all-attacks.sh: синтаксическая ошибка"
bash -n $SETUP/attacks/run-gate.sh         || die "run-gate.sh: синтаксическая ошибка"
bash -n $SETUP/attacks/replay-gate.sh      || die "replay-gate.sh: синтаксическая ошибка"
bash -n $SETUP/idle-run.sh                 || die "idle-run.sh: синтаксическая ошибка"
echo "  синтаксис всех четырёх скриптов ок"

# СТОРОЖ НАХОДКИ №86 (P0), без изменений с №2.9.7: корень наблюдателя не
# шире пролога, иначе observer_should_drop() уронит все атаки прогона.
echo "--- преflight: сторож находки №86 (корень наблюдателя не шире пролога) ---"
grep -q 'run_measurement_prologue()' $SETUP/attacks/run-all-attacks.sh \
    || die "находка №86: run_measurement_prologue отсутствует — регистрация observer_root не сужена до пролога"
top_level_reg=$(grep -nE '^(observer_root_register[[:space:]]*$|echo[[:space:]]+"?\$\$"?[[:space:]]*>)' $SETUP/attacks/run-all-attacks.sh || true)
if [ -n "$top_level_reg" ]; then
    echo "$top_level_reg" | sed 's/^/  регистрация на верхнем уровне: /'
    die "находка №86: регистрация observer_root вызвана на верхнем уровне run-all-attacks.sh — все атаки прогона будут отброшены в ядре, recall станет 0/6"
fi
echo "  ок: корень наблюдателя регистрируется только внутри пролога"

# 5.9.9.Fg (находка №112, ЭТА ПРАВКА): все сторожа «определён и вызывается»
# ниже искали вызов ПО ВСЕМУ файлу — а вызовы шагов есть ещё и в
# interactive_mode (пункты меню 1 и 6), который на замере не исполняется
# никогда. Поэтому сторож проходил на функции, отсутствующей в full_run(), —
# ровно то, что он обязан ловить, и ровно это и случилось с
# run_cred_proc_maps_positive_control (её не было в full_run(); исправлено
# той же правкой). Проверяем ТЕЛО full_run(), а не файл.
# Шаги волны делятся на два класса, и оба законны:
#   - внутри full_run() — окно замера (крит. 7 читает их по манифесту);
#   - внутри своей ветки main() (--dns-fd-reuse-controls, --counting-control,
#     --ringbuf-overflow, --cred-proc-maps-control) — вне окна, по запрету №3.
# Незаконен ровно один случай: вызов ТОЛЬКО из interactive_mode, который на
# замере не исполняется никогда. Поэтому ищем вызов в файле БЕЗ тела
# interactive_mode.
calls_outside_menu() {
    sed '/^interactive_mode() {/,/^}/d' $SETUP/attacks/run-all-attacks.sh | grep -qE "^[[:space:]]+$1[[:space:]]*$"
}
calls_in_full_run() {
    sed -n '/^full_run() {/,/^}/p' $SETUP/attacks/run-all-attacks.sh | grep -qE "^[[:space:]]+$1[[:space:]]*$"
}

echo "--- преflight: позитивный контроль 5.9.7e присутствует в цепочке (риск №3) ---"
grep -q 'run_ssh_keys_positive_control()' $SETUP/attacks/run-all-attacks.sh || die "риск №3: run_ssh_keys_positive_control отсутствует"
calls_in_full_run run_ssh_keys_positive_control || die "риск №3: run_ssh_keys_positive_control определён, но не вызывается из full_run()"
echo "  ок: позитивный контроль 5.9.7e в цепочке"

# То же требование, но для волны 5.9.8: три шага харнесса, без которых три
# пункта постановки остаются без входа. Проверяется И определение, И вызов —
# «определён, но не вызывается» уже случалось (5.9.7e).
echo "--- преflight: шаги волны 5.9.8 присутствуют в цепочке ---"
for fn in run_dns_fd_reuse_negative_control run_dns_cross_thread_positive_control run_webshell_script_write_positive_control; do
    grep -q "^$fn()" $SETUP/attacks/run-all-attacks.sh || die "5.9.8: $fn отсутствует в run-all-attacks.sh — соответствующий пункт постановки без входа"
    calls_outside_menu "$fn" || die "5.9.8: $fn вызывается только из interactive_mode — на замере шаг не исполнится (находка №112)"
    echo "  ок: $fn определён и вызывается"
done

# То же для волны 5.9.9: позитивная половина сужения (5.9.9b) и сценарий
# container_escape_cap_sys_admin (5.9.9c, находка №101). Обе категории
# читает крит. 7 (recall) — функция, определённая, но не вызванная, дала бы
# не «контроль не исполнился», а тихое отсутствие категории в манифесте.
echo "--- преflight: шаги волны 5.9.9 присутствуют в цепочке ---"
for fn in run_webshell_crontab_positive_control run_container_escape_positive_control; do
    grep -q "^$fn()" $SETUP/attacks/run-all-attacks.sh || die "5.9.9: $fn отсутствует в run-all-attacks.sh — соответствующий пункт постановки без входа"
    calls_in_full_run "$fn" || die "5.9.9: $fn определён, но не вызывается из full_run() — шаг не исполнится"
    echo "  ок: $fn определён и вызывается"
done

# То же для волны 5.9.9.F: позитивный контроль cred_proc_maps_mass_read
# (5.9.9.Fa, находка №107). Стоит отдельным блоком, а не строкой в цикле
# выше, потому что у него две половины, и без второй сужение правила
# недоказуемо: шаг в цепочке И юнит-тесты на оба исхода. Ревизия волны
# 5.9.9.F: постановка считала этот контроль уже существующим — его не было,
# и правило, суженное без него, дало бы 0 алертов за прогон при живом
# detection-baseline.txt, то есть красный крит. 6 с формулировкой «регресс
# детекта».
echo "--- преflight: шаг и юнит-тесты волны 5.9.9.F присутствуют (5.9.9.Fa, №107) ---"
grep -q "^run_cred_proc_maps_positive_control()" $SETUP/attacks/run-all-attacks.sh     || die "5.9.9.Fa: run_cred_proc_maps_positive_control отсутствует — суженное cred_proc_maps_mass_read остаётся без единого входа (находка №57)"
calls_in_full_run run_cred_proc_maps_positive_control     || die "5.9.9.Fa: run_cred_proc_maps_positive_control определён, но не вызывается из full_run() — шаг не исполнится (находка №112)"
grep -q '\^/proc/\[0-9\]+/(task/\[0-9\]+/)?(maps|mem|environ)\$' rules/credential-access.yaml     || die "5.9.9.Fa: numeric-PID предикат отсутствует в rules/credential-access.yaml — правка №107 не в дереве"
go test -count=1 -v ./internal/correlator/ -run 'TestP1_17_CredProcMapsMassRead_NumericPID|TestP1_17_ProcSelfNarrowingIsRuleLocal' 2>&1     | grep -E '^(=== RUN|--- |ok|FAIL)' | sed 's/^/  /'
go test -count=1 ./internal/correlator/ -run 'TestP1_17_CredProcMapsMassRead_NumericPID|TestP1_17_ProcSelfNarrowingIsRuleLocal' >/dev/null 2>&1     || die "5.9.9.Fa: юнит-тесты красные — либо сужение не доказано как не-ослепление, либо нарушен запрет волны (/proc/self у owasp_web_sensitive_file_read)"
echo "  ок: шаг вызывается из full_run(), оба юнит-теста зелёные"

# Сторож 5.9.8a на уровне ИСХОДНИКА BPF: ключ dns_socket_map обязан быть
# процессным (tgid), а не потоковым. Проверяется здесь, а не только в
# контролях [7/14], потому что здесь это стоит секунду, а там — минуты.
echo "--- преflight: ключ dns_socket_map процессный, а не потоковый (5.9.8a) ---"
grep -q '__u32 tgid;' bpf/dns.bpf.c || die "5.9.8a: struct dns_socket_key не несёт поля tgid — правка №94 не в дереве, замер измерил бы старый ключ"
grep -q 'key.pid_tgid = bpf_get_current_pid_tgid();' bpf/dns.bpf.c \
    && die "5.9.8a: в bpf/dns.bpf.c остался потоковый ключ (key.pid_tgid = …) — правка №94 откачена частично"
echo "  ок: ключ строится из current_tgid()"

echo "--- преflight: реестры ---"
for f in dns-decode-reasons.txt detection-baseline.txt silent-rules.txt intentional-loss.txt criteria-index.txt dns-idle-fp.txt; do
    if [ -f "$SETUP/attacks/$f" ]; then
        echo "  $f: $(grep -cv '^[[:space:]]*\(#\|$\)' "$SETUP/attacks/$f") значащих строк"
    else
        echo "  $f: ОТСУТСТВУЕТ — соответствующий критерий будет нечитаем"
    fi
done
[ -s "$SETUP/attacks/criteria-index.txt" ] \
    || die "criteria-index.txt отсутствует или пуст — run-gate.sh обрушится преflight'ом (exit 3), 5.9.7h не проверяем"

# 5.9.8h: WARN «база брошена» второй замер подряд означал, что сигнатура
# прошлого прогона осталась от прогона на АРХИВЕ (шаг [2/14] снимает её за
# собой, но старая могла дожить с прошлых сессий). Печатается явно.
ls -l "$SETUP/attacks/detection-baseline-diff-state.txt" 2>/dev/null | sed 's/^/  сигнатура прошлого прогона: /' \
    || echo "  сигнатуры прошлого прогона нет — предупреждение «база брошена» на этом замере невозможно по построению"

if command -v python3 >/dev/null 2>&1; then
    echo "  python3: $(python3 --version 2>&1) — 5.9.7a/5.9.7b/5.9.8a исполнимы"
else
    die "python3 не найден — контроль счётности (5.9.7a), run_ringbuf_overflow (5.9.7b) и оба контроля DNS (5.9.8a) без входа"
fi
command -v jq >/dev/null 2>&1 || die "jq не найден — гейт и разбивки по comm непроверяемы"

echo "  параметры волны 5.9.8: COUNTING_CONTROL_N=$COUNTING_CONTROL_N COUNTING_CONTROL_DROP_N=$COUNTING_CONTROL_DROP_N INDUCED_DROP_MAX_FILES=$INDUCED_DROP_MAX_FILES RINGBUF_OVERFLOW_N=$RINGBUF_OVERFLOW_N DNS_CROSS_THREAD_N=$DNS_CROSS_THREAD_N"

grep -n -A7 '^enforcement:' "$SETUP/config-test.yaml" | sed 's/^/  конфиг enforcement: /'
grep -n 'track_write' "$SETUP/config-test.yaml" | sed 's/^/  конфиг file_ops: /'
grep -q 'track_write:[[:space:]]*true' "$SETUP/config-test.yaml" \
    || die "track_write выключен — rootkit_ssh_authorized_keys_modified (5.9.7e) немо по построению"
echo "преflight завершён в $(date -u +%H:%M:%S) UTC"

echo "=== [1/14] ЖЁСТКИЙ СТОП №1: replay-gate.sh на ПЯТИ архивах (5.9.7c/5.9.8e/5.9.9a/5.9.9.Fe) ==="
# collect-2.9.5 — тождество умеет SKIP по отсутствующей левой части;
# collect-2.9.6 — сходится там, где сходилось, и новая формула фона проходит
# там, где старая валила; синтетическая потеря 1000 событий — тождество умеет
# падать; collect-2.9.7 (5.9.8e) — крит. 9 даёт 88.6/мин, а не SKIP;
# collect-2.9.8 (НОВОЕ, 5.9.9a, №99) — «база брошена» обязана дать ОБА исхода:
# молчать при повторном вызове гейта за тот же замер и печатать WARN при чужом
# TIMESTAMP. collect-2.9.9 (НОВОЕ, 5.9.9.Fe, разбор №111) — вторая и третья
# ветки спасения фонового правила обязаны напечататься РАЗНЫМИ формулировками
# на одном прогоне: «выросло за idle-час» (anomaly_detection) и «срабатывало
# до окна» (container_escape_init_proc). Это пятый жёсткий стоп преflight'а по
# постановке №2.9.9.F.1; реплей, давший только один из двух исходов в любой из
# двух пар, останавливает цепочку здесь.
find_archive() {
    local name="$1" d
    for d in "/opt/ebpf-guard/server-logs/$name" "/root/$name" "/tmp/$name" "$SETUP/../../server-logs/$name"; do
        [ -d "$d/attacks" ] && { echo "$d"; return 0; }
    done
    return 1
}
C295_DIR="${REPLAY_C295_DIR:-$(find_archive collect-2.9.5 || true)}"
C296_DIR="${REPLAY_C296_DIR:-$(find_archive collect-2.9.6 || true)}"
C297_DIR="${REPLAY_C297_DIR:-$(find_archive collect-2.9.7 || true)}"
C298_DIR="${REPLAY_C298_DIR:-$(find_archive collect-2.9.8 || true)}"
C299_DIR="${REPLAY_C299_DIR:-$(find_archive collect-2.9.9 || true)}"
# 5.9.9.F.1a/5.9.9.F.1c: шестой архив. collect-2.9.9.F — единственный, где
# дерево измерителя дало алерт в слепом окне и где рядом лежит маркер
# observer-root-register-*.txt; без него ни крит. 16 (реплей 7/8), ни
# ветка реестра для нулевого web_sql_injection_files (реплей 8/8) не
# воспроизводятся ни на чём.
C299F_DIR="${REPLAY_C299F_DIR:-$(find_archive collect-2.9.9.F || true)}"
echo "  архив 2.9.5: ${C295_DIR:-НЕ НАЙДЕН}"
echo "  архив 2.9.6: ${C296_DIR:-НЕ НАЙДЕН}"
echo "  архив 2.9.7: ${C297_DIR:-НЕ НАЙДЕН}"
echo "  архив 2.9.8: ${C298_DIR:-НЕ НАЙДЕН}"
echo "  архив 2.9.9: ${C299_DIR:-НЕ НАЙДЕН}"
echo "  архив 2.9.9.F: ${C299F_DIR:-НЕ НАЙДЕН}"
if [ -z "$C295_DIR" ] || [ -z "$C296_DIR" ] || [ -z "$C297_DIR" ] || [ -z "$C298_DIR" ] || [ -z "$C299_DIR" ] || [ -z "$C299F_DIR" ]; then
    die "архивы collect-2.9.5/2.9.6/2.9.7/2.9.8/2.9.9/2.9.9.F не найдены на стенде. Скопировать (например в /root/) либо задать REPLAY_C295_DIR/REPLAY_C296_DIR/REPLAY_C297_DIR/REPLAY_C298_DIR/REPLAY_C299_DIR/REPLAY_C299F_DIR. Пропуск реплея — это находка №85, повторённая восьмой раз"
fi
bash $SETUP/attacks/replay-gate.sh "$C295_DIR" "$C296_DIR" "$C297_DIR" "$C298_DIR" "$C299_DIR" "$C299F_DIR" 2>&1 | tee /root/replay-2.9.9.F.1.txt
replay_rc=${PIPESTATUS[0]}
echo "  replay-gate вернул $replay_rc"
[ "$replay_rc" -eq 4 ] && die "replay-gate: неподходящий bash (находка №88) — цепочка зовёт старый интерпретатор"
[ "$replay_rc" -eq 0 ] \
    || die "REPLAY-GATE красный (код $replay_rc) — известные ответы на архивах не воспроизводятся. Риск №1 постановки материализовался: правки гейта 5.9.8b/c/e меняют вердикт на уже снятых данных"
grep -q '88\.6/мин' /root/replay-2.9.9.F.1.txt \
    || die "реплей 4/8 не напечатал 88.6/мин — крит. 9 на collect-2.9.7 не воспроизвёл известный ответ (5.9.8e, №90)"
# 5.9.9a (№99): оба исхода проверяются ПОИМЁННО, а не одним кодом возврата
# реплея. Реплей, который дал бы только «молчит», вернул бы 0 и здесь — а
# механизм, разучившийся печатать WARN, это не починка №99, а её ослепление
# (тот же класс, что находка №57: сужение, неотличимое от немоты).
grep -q 'повторный вызов за тот же замер молчит' /root/replay-2.9.9.F.1.txt \
    || die "реплей 5/8: повторный вызов гейта за тот же замер не промолчал — самонаведение №99 не починено (5.9.9a)"
grep -q 'умеет падать, а не только молчать (5.9.9a)' /root/replay-2.9.9.F.1.txt \
    || die "реплей 5/8: с подменённым TIMESTAMP WARN «база брошена» не напечатан — механизм 5.9.6f ослеплён правкой 5.9.9a"
# 5.9.9.Fe (разбор №111): третья ветка спасения (idle_prewindow_list) до этой
# волны не применялась ни на одном прогоне — то есть её поломка была бы
# невидима. Проверяется поимённо обеими формулировками, а не кодом возврата:
# реплей, у которого обе ветки печатают ОДИН текст, вернул бы 0.
grep -q 'выросло за idle-час' /root/replay-2.9.9.F.1.txt \
    || die "реплей 6/8: вторая ветка спасения фонового правила («выросло за idle-час») не напечатана (5.9.9.Fe)"
grep -q 'напечатаны разными формулировками' /root/replay-2.9.9.F.1.txt \
    || die "реплей 6/8: вторая и третья ветки спасения не различены на одном прогоне — ветка idle_prewindow_list не проверена (5.9.9.Fe, №111)"
# 5.9.9.F.1a (№116): крит. 16 обязан уметь ОБА исхода. Реплей, у которого
# критерий только пропускает, вернул бы 0 — и правка была бы неотличима от
# «критерий больше никогда не падает», то есть от ослепления.
grep -q 'случай 1 (алерт старше регистрации корня) и PASS с названным случаем' /root/replay-2.9.9.F.1.txt \
    || die "реплей 7/8: крит. 16 не вынес PASS на структурно неизбежном случае 1 — либо классификация не отработала (проверить iso_to_epoch на этом стенде), либо находка №116 не починена"
grep -q 'критерий 16 умеет падать, а не только пропускать' /root/replay-2.9.9.F.1.txt \
    || die "реплей 7/8: с алертом за confirm_epoch крит. 16 НЕ упал — правка 5.9.9.F.1a ослепила критерий, что хуже находки №116 (тихо, а не шумно)"
# 5.9.9.F.1c (№114): у правки нет позитивного контроля по построению —
# приёмка идёт ВЕТКОЙ РЕЕСТРА, и обе её стороны проверяются поимённо.
grep -q 'ноль 5.9.9.F.1c объясняется печатью, а не допущением' /root/replay-2.9.9.F.1.txt \
    || die "реплей 8/8: нулевой web_sql_injection_files не отнесён реестром — приёмка 5.9.9.F.1c осталась бы допущением, а не проверкой"
grep -q 'ветка реестра различает объяснённый ноль и регресс детекта' /root/replay-2.9.9.F.1.txt \
    || die "реплей 8/8: крит. 6 не упал на правиле вне реестров — значит первый исход реплея 8 не доказывает ничего (критерий не различает объяснённый ноль и потерю)"
echo "реплей 8/8 пройден в $(date -u +%H:%M:%S) UTC"

echo "=== [2/14] ЖЁСТКИЙ СТОП №2: сверка criteria-index.txt (5.9.7h/5.9.8h) ==="
c296_ts=$(ls "$C296_DIR"/attacks/baseline-state-*.json 2>/dev/null | head -1 | sed 's/.*baseline-state-\(.*\)\.json/\1/')
[ -n "$c296_ts" ] || die "не удалось определить TIMESTAMP архива 2.9.6 для сверки criteria-index.txt"
# Побочный эффект run-gate.sh (detection-baseline-diff-state.txt, 5.9.6f)
# снимается здесь же: прогон на архиве не является «прошлым замером», иначе
# шаг [13/14] сравнит настоящий замер с сигнатурой архива и напечатает WARN
# «база брошена» третий замер подряд (5.9.8h).
DIFF_STATE="$SETUP/attacks/detection-baseline-diff-state.txt"
DIFF_BAK=""
if [ -f "$DIFF_STATE" ]; then DIFF_BAK=$(mktemp); cp "$DIFF_STATE" "$DIFF_BAK"; fi
ci_out=$(EBPF_GUARD_API="http://127.0.0.1:1" EBPF_GUARD_TOKEN="" \
    bash $SETUP/attacks/run-gate.sh "$C296_DIR/attacks" "$c296_ts" 2>&1 | head -8)
if [ -n "$DIFF_BAK" ]; then cp "$DIFF_BAK" "$DIFF_STATE"; rm -f "$DIFF_BAK"; else rm -f "$DIFF_STATE"; fi
echo "$ci_out" | sed 's/^/  /'
echo "$ci_out" | grep -q 'непокрытых пунктов постановки: 0' \
    || die "criteria-index.txt: у пункта постановки нет машинной печати в гейте (5.9.7h) — это находка №83, повторённая"
echo "сверка пройдена в $(date -u +%H:%M:%S) UTC"

echo "=== [3/14] make generate && make build (жёстко: 5.9.8a правит bpf/dns.bpf.c) ==="
cd /opt/ebpf-guard
make generate || die "make generate упал"
echo "--- generate: карты волны 5.9.6 живы в сгенерированных биндингах ---"
gen_maps_missing=0
for c in syscall network fileaccess privesc; do
    gf=$(ls internal/bpf/${c}_*_bpfe*.go 2>/dev/null | head -1)
    if [ -z "$gf" ]; then
        echo "  $c: сгенерированных биндингов нет — bpf2go не выдал объект"
        gen_maps_missing=1
        continue
    fi
    n=$(grep -c 'RingbufFullCounters\|EventsEmittedCounters' "$gf")
    echo "  $c ($gf): полей карт = $n"
    [ "$n" -eq 0 ] && gen_maps_missing=1
done
[ "$gen_maps_missing" -eq 0 ] || echo "ВНИМАНИЕ: карты 5.9.6 отсутствуют хотя бы в одном объекте — SMOKE-гейт [6/14] обязан это подтвердить красным"
# 5.9.8a: DNS-объект обязан быть ПЕРЕСОБРАН этим generate, а не взят с полки.
# Проверяется по факту существования свежего .o и биндинга с DnsSocketMap.
dns_gen=$(ls internal/bpf/dns_*_bpfe*.go 2>/dev/null | head -1)
[ -n "$dns_gen" ] || die "5.9.8a: сгенерированных биндингов DNS нет — bpf2go не выдал объект, правка ключа не попала бы в ядро"
grep -q 'DnsSocketMap' "$dns_gen" || die "5.9.8a: в $dns_gen нет DnsSocketMap — биндинг не соответствует правленому bpf/dns.bpf.c"
ls -l internal/bpf/dns_*_bpfe*.o 2>/dev/null | sed 's/^/  DNS-объект: /'
git status --porcelain internal/bpf/ | sed 's/^/  generate изменил: /'
make build || die "make build упал"
./build/ebpf-guard version 2>&1 | sed 's/^/  бинарь (после пересборки): /' || true
ls -l build/ebpf-guard | sed 's/^/  /'
echo "сборка завершена в $(date -u +%H:%M:%S) UTC"

echo "=== [4/14] риск №3 (5.9.4): отдельный короткий прогон P0-3 ДО замера ==="
cd $SETUP
OUT_DIR=$P0_OUT DURATION=120 INTERVAL=60 NO_RESTART=0 bash ./idle-run.sh
echo "P0-3 прогон завершён в $(date -u +%H:%M:%S) UTC"
grep -h "before:\|after:\|P0-3" $P0_OUT/idle-run.log

echo "=== [5/14] очистка стора + рестарт агента (уже с новым бинарём) ==="
systemctl stop ebpf-guard-test.service
rm -f /var/lib/ebpf-guard/test-events.db /var/lib/ebpf-guard/test-events.db-shm /var/lib/ebpf-guard/test-events.db-wal
echo 0 > /var/lib/ebpf-guard/observer-root-pid
systemctl start ebpf-guard-test.service
echo "рестарт в $(date -u +%H:%M:%S) UTC"
date -u +"%Y-%m-%d %H:%M:%S" > /root/agent-start-2.9.9.F.1.txt
systemctl show ebpf-guard-test.service -p ExecMainStartTimestamp | sed 's/^/  /'

echo "=== [6/14] SMOKE-гейт: коллекторы грузятся, поток не пуст, серии волны на месте ==="
SMOKE_TOKEN="${EBPF_GUARD_TOKEN:-$(grep '^admin=' /var/lib/ebpf-guard/token 2>/dev/null | cut -d= -f2)}"
SMOKE_API="http://${VPS_IP:-localhost}:19090"
smoke_fail=0

sleep 20
echo "--- smoke: журнал загрузки BPF ---"
smoke_journal=$(journalctl -u ebpf-guard-test.service --no-pager -n 400 2>/dev/null || true)
echo "$smoke_journal" | grep -iE 'verifier|failed to load|load program|permission denied|collector .* (started|failed)|watchdog started' | tail -20 | sed 's/^/  /'
if echo "$smoke_journal" | grep -qiE 'verifier|failed to load'; then
    echo "SMOKE FAIL: в журнале есть ошибка загрузки/верификатора"
    smoke_fail=1
fi

smoke_health=$(curl -s --max-time 10 -H "Authorization: Bearer $SMOKE_TOKEN" "$SMOKE_API/health" 2>/dev/null)
echo "  /health: $smoke_health"
echo "$smoke_health" | grep -q '"status"' || { echo "SMOKE FAIL: агент не отвечает на /health"; smoke_fail=1; }

smoke_metrics() { curl -s --max-time 10 -H "Authorization: Bearer $SMOKE_TOKEN" "$SMOKE_API/metrics" 2>/dev/null; }
# 5.9.9f (№103): ENVIRON, не -v — то же обоснование, что у run-gate.sh
# sum_metric_delta()/run-all-attacks.sh sum_metric(): -v запускает
# unescaped-sequence разбор строки, и \{ в паттерне печатал предупреждение
# "escape sequence `\{' treated as plain `{'" на stderr при каждом вызове.
# Эта копия smoke_sum() кочевала из run-2.9.6-pipeline.sh в 2.9.7 и в 2.9.8
# без правки — третья непочиненная копия одного и того же дефекта.
smoke_sum() { P="$1" awk -F'} ' '$0 ~ ENVIRON["P"] {s+=$2} END{printf "%.0f", s+0}'; }

smoke_before=$(smoke_metrics)
python3 -c "
import os
p='/tmp/ebpf-guard-smoke-canary'
open(p,'w').close()
for _ in range(20000):
    fd=os.open(p, os.O_RDONLY); os.close(fd)
" || echo "  smoke: генератор не отработал, полагаемся на фоновую активность"
sleep 8
smoke_after=$(smoke_metrics)
rm -f /tmp/ebpf-guard-smoke-canary

for c in syscall network fileaccess; do
    em_a=$(echo "$smoke_before" | smoke_sum "ebpf_guard_events_emitted_kernel_total\{collector=\"$c\"\}")
    em_b=$(echo "$smoke_after"  | smoke_sum "ebpf_guard_events_emitted_kernel_total\{collector=\"$c\"\}")
    rf_present=$(echo "$smoke_after" | grep -c "reason=\"ringbuf_full\".*collector=\"$c\"\|collector=\"$c\".*reason=\"ringbuf_full\"" || true)
    echo "  $c: emitted_kernel $em_a -> $em_b (Δ$((em_b - em_a))), серия ringbuf_full присутствует: $rf_present"
    if [ "$rf_present" -eq 0 ]; then
        echo "SMOKE FAIL: $c — серия events_dropped_total{reason=\"ringbuf_full\"} отсутствует (5.9.6a не доехала до /metrics)"
        smoke_fail=1
    fi
done

fa_a=$(echo "$smoke_before" | smoke_sum 'ebpf_guard_events_emitted_kernel_total\{collector="fileaccess"\}')
fa_b=$(echo "$smoke_after"  | smoke_sum 'ebpf_guard_events_emitted_kernel_total\{collector="fileaccess"\}')
ev_a=$(echo "$smoke_before" | smoke_sum '^ebpf_guard_events_total\{.*type="file"')
ev_b=$(echo "$smoke_after"  | smoke_sum '^ebpf_guard_events_total\{.*type="file"')
echo "  fileaccess: Δemitted_kernel=$((fa_b - fa_a)), Δevents_total{file}=$((ev_b - ev_a))"
[ "$((fa_b - fa_a))" -gt 0 ] || { echo "SMOKE FAIL: emitted_kernel{fileaccess} не вырос под заведомой нагрузкой"; smoke_fail=1; }
[ "$((ev_b - ev_a))" -gt 0 ] || { echo "SMOKE FAIL: events_total{type=file} не вырос — события не доходят до userspace"; smoke_fail=1; }

hb=$(echo "$smoke_after" | grep -c '^ebpf_guard_heartbeat_timestamp_seconds' || true)
echo "  watchdog: серий ebpf_guard_heartbeat_timestamp_seconds = $hb"
if [ "$hb" -eq 0 ]; then
    echo "SMOKE FAIL: heartbeat отсутствует — watchdog.Start не выполнен, bpf_lost_events_total останется нулём (5.9.7b недоказуем)"
    smoke_fail=1
fi

# 5.9.8b: канареечная серия материализована нулём в init() — её отсутствие
# означает старый бинарь, и крит. 20 молча свалился бы в путь с вычетом фона
# (тот же провал, что 5.9.8b и чинит), напечатав SKIP вместо вердикта.
canary_series=$(echo "$smoke_after" | grep -c '^ebpf_guard_counting_canary_total' || true)
echo "  5.9.8b: серий ebpf_guard_counting_canary_total = $canary_series (ожидается 2: events, dropped)"
if [ "$canary_series" -lt 2 ]; then
    echo "SMOKE FAIL: канареечная серия отсутствует или неполна — бинарь старее 5.9.8b, критерий 20 будет считать по старому пути с вычетом фона"
    smoke_fail=1
fi
# Та же логика для нового reason DNS (5.9.8a): материализован нулём в
# RegisterMetrics, отсутствует только у старого бинаря.
bad_header_series=$(echo "$smoke_after" | grep -c 'ebpf_guard_dns_decode_errors_total{reason="bad_header"}' || true)
echo "  5.9.8a: серия dns_decode_errors_total{reason=\"bad_header\"} присутствует: $bad_header_series"
if [ "$bad_header_series" -eq 0 ]; then
    echo "SMOKE FAIL: reason=bad_header отсутствует — бинарь старее 5.9.8a, второй заслон DNS не в прогоне"
    smoke_fail=1
fi

if [ "$smoke_fail" -ne 0 ]; then
    die "SMOKE-гейт красный. Полтора часа на прогон, который не сможет отличить исправную систему от ослепшей, тратить нельзя"
fi
echo "SMOKE OK: коллекторы живы, watchdog запущен, серии волны 5.9.8 на месте. $(date -u +%H:%M:%S) UTC"

echo "=== [7/14] ЖЁСТКИЙ СТОП №4 (НОВЫЙ): оба контроля DNS ВНЕ окна замера (5.9.8a, запрет №6) ==="
# Риск №2 постановки: «0 long-label за idle-час» выглядит одинаково при
# починке и при полностью ослепшем DNS-коллекторе. Отсюда порядок: контроли
# в преflight, idle-час — потом. Слепой коллектор на idle-час не едет.
cd $SETUP/attacks
# 5.9.9g (находка №105, ЭТА ПРАВКА): шаг повторяем до трёх раз. На преflight'е
# №2.9.9 позитивный контроль дал Δdns=7 при N=8 и убил цепочку на 15-й минуте;
# три немедленных повтора подряд дали 8/8, а волна 5.9.9 не трогает ни
# bpf/dns.bpf.c, ни коллектор — то есть остановкой была потеря ОДНОГО UDP-пакета,
# а не ослепление. Различить их можно только повтором: ослепший коллектор даёт
# недосчёт КАЖДЫЙ раз, потерянный пакет — один раз из четырёх. Порог не ослаблен
# (последняя попытка обязана дать Δdns >= N ровно как раньше), ослаблена только
# цена единичного промаха. Повторяются лишь исходы «сценарий не воспроизведён»
# (в их формулировках и раньше стояло «повторить шаг»); Δdns > 0 у негатива —
# это находка №94, она валит цепочку с первой попытки без повторов.
DNS_CTL_ATTEMPTS="${DNS_CTL_ATTEMPTS:-3}"
dns_ctl_ok=0
for dns_try in $(seq 1 "$DNS_CTL_ATTEMPTS"); do
    echo "--- контроли DNS: попытка $dns_try из $DNS_CTL_ATTEMPTS ---"
    bash ./run-all-attacks.sh --dns-fd-reuse-controls 2>&1 | tee /root/dns-controls-2.9.9.F.1-$dns_try.txt
    dns_neg=$(ls -t $SETUP/attacks/attack-results/dns-negative-control-*.txt 2>/dev/null | head -1)
    dns_pos=$(ls -t $SETUP/attacks/attack-results/dns-positive-control-*.txt 2>/dev/null | head -1)
    [ -n "$dns_neg" ] || die "негативный контроль DNS не оставил маркера — 5.9.8a без входа"
    [ -n "$dns_pos" ] || die "позитивный контроль DNS не оставил маркера — 5.9.8a без входа"
    cat "$dns_neg" | sed 's/^/  негативный: /'
    cat "$dns_pos" | sed 's/^/  позитивный: /'
    grep -q '^skipped=1' "$dns_neg" && die "негативный контроль DNS пропущен харнессом — правка dns_socket_map не проверена (запрет №6)"
    grep -q '^skipped=1' "$dns_pos" && die "позитивный контроль DNS пропущен харнессом — правка dns_socket_map не проверена (запрет №6)"

    neg_xthread=$(awk -F= '$1=="cross_thread_close"{print $2+0}' "$dns_neg")
    neg_reused=$(awk -F= '$1=="reused_fd"{print $2+0}' "$dns_neg")
    neg_delta=$(awk -F= '$1=="events_dns_delta"{print $2+0}' "$dns_neg")
    pos_n=$(awk -F= '$1=="n"{print $2+0}' "$dns_pos")
    pos_delta=$(awk -F= '$1=="events_dns_delta"{print $2+0}' "$dns_pos")
    echo "  негативный: cross_thread_close=$neg_xthread reused_fd=$neg_reused Δdns=$neg_delta"
    echo "  позитивный: N=$pos_n Δdns=$pos_delta"

    # Негатив: Δdns > 0 — это сама находка №94, повтор её не исправит.
    [ "${neg_delta:-0}" -eq 0 ] || die "негативный контроль ПРОВАЛЕН: Δevents_total{type=dns}=$neg_delta > 0 — dns_socket_map всё ещё принимает переиспользованный fd за DNS, находка №94 не закрыта"
    # Генератор не отработал вовсе — повтор бессмыслен, вторая половина
    # запрета №6 осталась бы без входа при любом числе попыток.
    [ "${pos_n:-0}" -gt 0 ] || die "позитивный контроль: N=0 — генератор не отработал, вторая половина запрета №6 без входа"

    # Три исхода «сценарий не воспроизведён» — повторяемые.
    if [ "${neg_xthread:-0}" -ne 1 ]; then
        echo "ВНИМАНИЕ: попытка $dns_try: close() с чужого потока не удался — сценарий №94 не воспроизведён, повтор"
    elif [ "${neg_reused:-0}" -ne 1 ]; then
        echo "ВНИМАНИЕ: попытка $dns_try: fd не переиспользован (reused_fd=0) — сценарий №94 не воспроизведён, повтор"
    elif [ "${pos_delta:-0}" -lt "${pos_n:-0}" ]; then
        echo "ВНИМАНИЕ: попытка $dns_try: Δevents_total{type=dns}=$pos_delta < N=$pos_n — межпоточный резолв недосчитан, повтор (стабильный недосчёт остановит цепочку ниже)"
    else
        dns_ctl_ok=1
        [ "$dns_try" -gt 1 ] && echo "ВНИМАНИЕ: контроли DNS сошлись с попытки $dns_try, а не с первой — единичные промахи предыдущих попыток выше в логе"
        break
    fi
    sleep 10
done
[ "$dns_ctl_ok" -eq 1 ] \
    || die "контроли DNS не сошлись за $DNS_CTL_ATTEMPTS попыток (последняя: cross_thread_close=$neg_xthread reused_fd=$neg_reused N=$pos_n Δdns=$pos_delta) — недосчёт устойчив, это ослепление коллектора, а не потеря пакета (риск №2)"
echo "5.9.8a доказан живьём в $(date -u +%H:%M:%S) UTC: TLS по reused fd не даёт DNS-событий, межпоточный резолв даёт"

echo "=== [8/14] контроль счётности вне окна замера: канареечная серия оживает (5.9.8b) ==="
# Второй P0 волны после DNS. Без этого шага канареечная серия впервые
# считается только на минуте ~95 полного замера, внутри окна атак — то есть
# ошибка в ней (серия не растёт, префикс ловит лишнее) находилась бы там же,
# где и раньше находились все ошибки измерителя: после того, как час уже
# потрачен.
#
# ВЕРДИКТА ЗДЕСЬ НЕТ, и это осознанно: остаток считает ОДНА функция
# (counting_control_residual, run-gate.sh, 5.9.8c), переписывать её копию в
# пайплайне — ровно то, что 5.9.8c запретила. Проверяются только два
# инварианта, которым формула не нужна и которые ловят обе слепые ветки:
#   - null: канареечная серия строго 0 (иначе префикс ловит фон стенда);
#   - idle: канареечная серия выросла вообще (иначе счётчик мёртв, и крит. 20
#     на замере дал бы «остаток = -N» с диагнозом «непосчитанная потеря»).
# Маркеры пишутся со своим TIMESTAMP и в вердикт замера не попадают (секция
# 20 ищет их по таймстампу основного прогона) — запрет №3 соблюдён.
cd $SETUP/attacks
bash ./run-all-attacks.sh --counting-control 2>&1 | tee /root/counting-control-2.9.9.F.1.txt
cc_null=$(ls -t $SETUP/attacks/attack-results/counting-control-null-*.txt 2>/dev/null | head -1)
cc_idle=$(ls -t $SETUP/attacks/attack-results/counting-control-idle-*.txt 2>/dev/null | head -1)
cc_drop=$(ls -t $SETUP/attacks/attack-results/counting-control-drop-*.txt 2>/dev/null | head -1)
for m in "$cc_null" "$cc_idle" "$cc_drop"; do
    [ -n "$m" ] && { echo "  --- $(basename "$m")"; sed 's/^/    /' "$m"; }
done
[ -n "$cc_null" ] || die "контроль счётности: маркер null отсутствует — шаг не исполнен, 5.9.8b без входа"
[ -n "$cc_idle" ] || die "контроль счётности: маркер idle отсутствует — шаг не исполнен, 5.9.8b без входа"
grep -q '^skipped=1' "$cc_null" && die "контроль счётности пропущен харнессом (null) — python3 недоступен?"
grep -q '^skipped=1' "$cc_idle" && die "контроль счётности пропущен харнессом (idle)"

grep -q '^canary_sum=' "$cc_idle"     || die "5.9.8b: маркер без canary_sum — харнесс или бинарь старее 5.9.8b, крит. 20 на замере посчитает по старому пути с вычетом фона"
cc_null_canary=$(awk -F= '$1=="canary_sum"{print $2+0}' "$cc_null")
cc_idle_canary=$(awk -F= '$1=="canary_sum"{print $2+0}' "$cc_idle")
cc_idle_n=$(awk -F= '$1=="n"{print $2+0}' "$cc_idle")
echo "  null: канареечная серия=$cc_null_canary (обязана быть 0)"
echo "  idle: канареечная серия=$cc_idle_canary из N=$cc_idle_n"
[ "${cc_null_canary:-0}" -eq 0 ]     || die "5.9.8b ПРОВАЛЕН: канареечная серия=$cc_null_canary при N=0 — префикс /tmp/ebpf-guard-counting-canary- ловит события за пределами контроля счётности, крит. 20 будет врать в сторону завышения"
[ "${cc_idle_canary:-0}" -gt 0 ]     || die "5.9.8b ПРОВАЛЕН: канареечная серия=0 при N=$cc_idle_n — счётчик мёртв (RecordCountingCanary не вызывается либо FDPath пуст), крит. 20 на замере дал бы остаток -N с ложным диагнозом «непосчитанная потеря»"
# settle_reason проверяется здесь же — 5.9.8f судит его на замере, но
# «ceiling» на всех трёх маркерах означает дефект самого лупа, а не стенда,
# и чинить его дешевле сейчас, чем после idle-часа.
awk -F= '$1=="settle_reason"{print FILENAME": "$2}' "$cc_null" "$cc_idle" ${cc_drop:+"$cc_drop"} | sed 's/^/  5.9.8f: /'
echo "5.9.8b доказан живьём в $(date -u +%H:%M:%S) UTC: null=0, idle растёт"

echo "=== [9/14] ЖЁСТКИЙ СТОП №3: run_ringbuf_overflow ВНЕ окна замера (5.9.7b/5.9.8c) ==="
cd $SETUP/attacks
bash ./run-all-attacks.sh --ringbuf-overflow 2>&1 | tee /root/ringbuf-overflow-2.9.9.F.1.txt
rb_marker=$(ls -t $SETUP/attacks/attack-results/ringbuf-overflow-*.txt 2>/dev/null | head -1)
[ -n "$rb_marker" ] || die "run_ringbuf_overflow не оставил маркера — шаг не исполнен, 5.9.7b без входа"
cat "$rb_marker" | sed 's/^/  /'
grep -q '^skipped=1' "$rb_marker" && die "run_ringbuf_overflow пропущен харнессом: $(awk -F= '$1=="skip_reason"{$1="";print substr($0,2)}' "$rb_marker")"
rb_full=$(awk -F= '$1=="ringbuf_full_delta"{print $2+0}' "$rb_marker")
rb_lost=$(awk -F= '$1=="bpf_lost_delta"{print $2+0}' "$rb_marker")
rb_canary=$(awk -F= '$1=="canary_sum"{print $2+0}' "$rb_marker")
rb_n=$(awk -F= '$1=="n"{print $2+0}' "$rb_marker")
echo "  ringbuf_full=$rb_full bpf_lost_events_total=$rb_lost канарейка=$rb_canary из N=$rb_n"
[ "${rb_full:-0}" -gt 0 ] \
    || die "ringbuf_full=0 даже с замороженным читателем — переполнение не воспроизведено (поднять RINGBUF_OVERFLOW_N)"
[ "${rb_full:-0}" -eq "${rb_lost:-0}" ] \
    || die "ringbuf_full=$rb_full != bpf_lost_events_total=$rb_lost — проводка watchdog (5.9.7b) не подтверждена живьём"
# 5.9.8c: сам вердикт (остаток той же формулой, что крит. 20) считает гейт в
# секции 22 — здесь только печатается вход, чтобы он лежал в логе замера, а
# не восстанавливался потом из маркера.
grep -q '^canary_sum=' "$rb_marker" \
    || echo "ВНИМАНИЕ: маркер без canary_sum — секция 22 посчитает по запасному пути с вычетом фона (5.9.8c не исполнена этим прогоном)"
echo "5.9.7b/5.9.8c доказан живьём в $(date -u +%H:%M:%S) UTC"

echo "=== [9.5/14] позитивный контроль cred_proc_maps_mass_read живьём (5.9.9.Fg, находка №112) ==="
# Только на предпрогоне. На полном замере шаг стоит ВНУТРИ full_run() (окно
# атак) — там его читает крит. 7, и второй прогон вне окна дал бы правилу
# ненулевой абсолют ДО idle-часа, то есть включил бы ветку спасения фонового
# правила чужой заслугой и замаскировал бы настоящий регресс в крит. 6.
#
# Смысл шага ровно тот же, что у контролей DNS в [7/14]: сужение
# cred_proc_maps_mass_read до numeric-PID (5.9.9.Fa) правит ПРАВИЛО, и
# «сработает ли оно на живом ядре» офлайн-реплеем не проверяется никак —
# юнит-тест судит матчер, а не путь ядро→коллектор→корреляция→стор.
if [ "${SMOKE_ONLY:-0}" = "1" ]; then
    cd $SETUP/attacks
    CRED_API="http://${VPS_IP:-localhost}:19090"
    CRED_TOKEN="${EBPF_GUARD_TOKEN:-$(grep '^admin=' /var/lib/ebpf-guard/token 2>/dev/null | cut -d= -f2)}"
    cred_alerts() { curl -s --max-time 15 -H "Authorization: Bearer $CRED_TOKEN" "$CRED_API/api/v1/alerts" 2>/dev/null; }
    cred_count() { cred_alerts | jq --arg r "$1" '[.[]|select(.rule_id==$r)]|length' 2>/dev/null || echo 0; }

    cred_before=$(cred_count cred_proc_maps_mass_read)
    dump_before=$(cred_count sigma_memory_proc_dump)
    echo "  до контроля: cred_proc_maps_mass_read=$cred_before sigma_memory_proc_dump=$dump_before"

    EBPF_GUARD_API="$CRED_API" EBPF_GUARD_TOKEN="$CRED_TOKEN" \
        bash ./run-all-attacks.sh --cred-proc-maps-control 2>&1 | tee /root/cred-proc-maps-2.9.9.F.1.txt
    cred_marker=$(ls -t $SETUP/attacks/attack-results/cred-proc-maps-control-*.txt 2>/dev/null | head -1)
    [ -n "$cred_marker" ] || die "5.9.9.Fa: позитивный контроль не оставил маркера — шаг не исполнен"
    sed 's/^/  маркер: /' "$cred_marker"
    grep -q '^skipped=1' "$cred_marker" && die "5.9.9.Fa: контроль пропущен харнессом: $(awk -F= '$1=="skip_reason"{$1="";print substr($0,2)}' "$cred_marker") — это дефект стенда, не детекта"
    grep -q '^done=1' "$cred_marker" || die "5.9.9.Fa: контроль не дочитал /proc/<pid>/maps (done!=1) — шаг не состоялся"

    # Порог правила — 5 за 10 с; корреляция и запись в стор идут асинхронно.
    sleep 20
    cred_after=$(cred_count cred_proc_maps_mass_read)
    dump_after=$(cred_count sigma_memory_proc_dump)
    echo "  после контроля: cred_proc_maps_mass_read=$cred_after (Δ$((cred_after - cred_before))) sigma_memory_proc_dump=$dump_after (Δ$((dump_after - dump_before)))"
    cred_alerts | jq -r '.[]|select(.rule_id=="cred_proc_maps_mass_read")|"    \(.rule_id) comm=\(.comm) pid=\(.pid) \(.message)"' 2>/dev/null | tail -5

    [ "$((cred_after - cred_before))" -ge 1 ] \
        || die "5.9.9.Fa ПРОВАЛЕН живьём: 8 чтений /proc/<pid>/maps процессом comm=credscrape не дали НИ ОДНОГО алерта cred_proc_maps_mass_read. Сужение до numeric-PID ослепило правило (находка №57) — полный замер объявил бы это регрессом детекта в крит. 6 после потраченного idle-часа"
    # 5.9.9.F.1b (находка №111): на волне 5.9.9.F этот же контроль для
    # sigma_memory_proc_dump был МЯГКИМ («ВНИМАНИЕ ... цепочку не
    # останавливает»), и это было верно ровно до 5.9.9.F.1b. После неё
    # правило потеряло /proc/[0-9]+/cmdline — то есть потеряло единственный
    # источник, который поднимал его на этом стенде без атаки (18 из 19
    # алертов №2.9.9.F: landscape-sysinfo и dbus-daemon). Теперь ЭТИ восемь
    # чтений /proc/<pid>/maps — единственный вход правила за весь прогон.
    # Ноль здесь означает не «отдельную находку», а ровно то, что постановка
    # назвала главным риском волны: правка неотличима от ослепления по
    # счётчику. Полный замер после этого объявил бы правило потерянным в
    # крит. 6 — после потраченного idle-часа и часа атак.
    [ "$((dump_after - dump_before))" -ge 1 ] \
        || die "5.9.9.F.1b ПРОВАЛЕН живьём: sigma_memory_proc_dump не поднялся на 8 чтениях чужого /proc/<pid>/maps (Δ=0). После снятия предиката cmdline это ЕДИНСТВЕННЫЙ вход правила на стенде — ноль означает ослепление (находка №57), а не тишину. Полный замер потратил бы 1.5 часа, чтобы напечатать это же как регресс детекта в крит. 6"
    echo "5.9.9.Fa/5.9.9.F.1b доказаны живьём в $(date -u +%H:%M:%S) UTC: оба правила видят чтение чужого /proc/<pid>/maps"
    rm -f /tmp/credscrape

    # --- Негативные контроли обеих правок волны 5.9.9.F.1 ------------------
    # Позитивная половина выше доказывает, что правила не ослепли. Негативная
    # половина ниже доказывает, что они СУЗИЛИСЬ — то есть что ожидаемые нули
    # приёмки (19 -> 1 и 10 -> 0) получены правкой условия, а не поломкой
    # загрузки правил. Без неё «0 за прогон» и «правило не загрузилось»
    # неотличимы, и оба дали бы одинаково зелёный крит. 6 через реестры.
    rules_json=$(curl -s --max-time 15 -H "Authorization: Bearer $CRED_TOKEN" "$CRED_API/rules" 2>/dev/null)
    for r in sigma_memory_proc_dump web_sql_injection_files; do
        echo "$rules_json" | jq -e --arg r "$r" '[.. | objects | select(.id? == $r)] | length > 0' >/dev/null 2>&1 \
            || die "5.9.9.F.1: правило $r не найдено в /rules — оно не загрузилось, и его ноль на приёмке означал бы битый YAML, а не сужение (проверить синтаксис правки)"
    done
    echo "  оба правленых правила загружены агентом (не битый YAML)"

    # Негативный контроль 5.9.9.F.1b: чтение чужого cmdline. До правки это
    # поднимало critical (landscape-sysinfo, dbus-daemon, 18 алертов за
    # №2.9.9.F), после — не обязано.
    cp /bin/cat /tmp/cmdlinescan 2>/dev/null || die "не удалось подготовить comm=cmdlinescan для негативного контроля 5.9.9.F.1b"
    dump_neg_before=$(cred_count sigma_memory_proc_dump)
    for _ in $(seq 1 20); do /tmp/cmdlinescan /proc/1/cmdline > /dev/null 2>&1; done
    sleep 20
    dump_neg_after=$(cred_count sigma_memory_proc_dump)
    echo "  негативный 5.9.9.F.1b: 20 чтений /proc/1/cmdline под comm=cmdlinescan -> Δsigma_memory_proc_dump=$((dump_neg_after - dump_neg_before))"
    [ "$((dump_neg_after - dump_neg_before))" -eq 0 ] \
        || die "5.9.9.F.1b ПРОВАЛЕН: чтение /proc/1/cmdline всё ещё поднимает sigma_memory_proc_dump (Δ$((dump_neg_after - dump_neg_before))) — предикат cmdline не убран либо агент крутит старые правила (проверить, что рестарт [5/14] подхватил новый rules/)"
    rm -f /tmp/cmdlinescan

    # Негативный контроль 5.9.9.F.1c: имена файлов с "--", "#", ";". Это
    # ровно те формы, что дали 10 критикалов на №2.9.9.F (session-файлы
    # systemd-logind и man-page git). Ни одна из них больше не SQL-инъекция.
    sql_neg_before=$(cred_count web_sql_injection_files)
    sql_dir=$(mktemp -d)
    for f in 'git-mergetool--lib.1.gz' '.#114376ChHzY' 'report;final.csv' 'libfoo--dev_1.2.3.deb'; do
        printf 'x' > "$sql_dir/$f" 2>/dev/null && cat "$sql_dir/$f" > /dev/null 2>&1
    done
    sleep 20
    sql_neg_after=$(cred_count web_sql_injection_files)
    echo "  негативный 5.9.9.F.1c: 4 имени файла с --/#/; -> Δweb_sql_injection_files=$((sql_neg_after - sql_neg_before))"
    [ "$((sql_neg_after - sql_neg_before))" -eq 0 ] \
        || die "5.9.9.F.1c ПРОВАЛЕН: имя файла с голым --/#/; всё ещё поднимает critical web_sql_injection_files (Δ$((sql_neg_after - sql_neg_before))) — паттерны не убраны либо агент крутит старые правила"
    rm -rf "$sql_dir"
    echo "5.9.9.F.1b/5.9.9.F.1c: негативные контроли пройдены в $(date -u +%H:%M:%S) UTC — сужение доказано, не поломка загрузки"
else
    echo "  пропущено: на полном замере шаг исполняется внутри full_run() (окно атак), крит. 7"
fi

# SMOKE_ONLY=1 — короткий прогон «сборка + живые доказательства», без
# idle-часа и атак (~15 минут вместо ~1ч50м). Именно здесь его место: всё,
# что выше, проверяется машинно и способно провалиться, а всё, что ниже, —
# это время. Смысл ровно один: 5.9.8a правит bpf/dns.bpf.c, и в этом дереве
# BPF ни разу не компилировался ([[bpf-gen-files-are-stubs]]) — отказ
# верификатора или ослепший DNS-коллектор обязаны находиться на 15-й минуте,
# а не на 90-й. Приёмкой волны такой прогон НЕ является: пункты 1, 5-7, 10,
# 16, 20, 23, 24 постановки имеют входом только idle-час.
if [ "${SMOKE_ONLY:-0}" = "1" ]; then
    echo "=== SMOKE_ONLY=1: сборка, SMOKE, оба контроля DNS, контроль счётности, переполнение кольца, позитивный контроль cred_proc_maps и обе пары контролей 5.9.9.F.1b/5.9.9.F.1c пройдены ==="
    echo "=== idle-час, атаки и гейт НЕ запускались — это не приёмка волны 5.9.9.F.1 ==="
    echo "=== ПРЕФИКС №2.9.9.F.1 ЗАВЕРШЁН $(date -u +%H:%M:%S) UTC ==="
    touch /root/PIPELINE-2.9.9.F.1-DONE
    exit 0
fi

echo "=== [10/14] пауза 660с: рестарт, smoke, контроли DNS и переполнение кольца выходят за окно журнала idle-run ==="
sleep 660

echo "=== [11/14] idle-час, NO_RESTART=1 (5.9.1c) — сокращать нельзя ==="
# Час — не запас прочности: FP grafana наблюдался ровно один раз за idle-час
# (период резолва порядка часа, не измерен). Окно короче застало бы «0
# long-label» отсутствием, а не починкой — тот PASS отсутствием, который
# 5.9.6i запретила.
cd $SETUP
OUT_DIR=$IDLE_OUT DURATION=3600 INTERVAL=300 NO_RESTART=1 bash ./idle-run.sh
echo "idle завершён в $(date -u +%H:%M:%S) UTC"

echo "=== [12/14] атаки — без разрыва цепочки, сразу за idle, без ssh между ними ==="
export IDLE_METRICS_START=$IDLE_OUT/metrics-start.txt
export IDLE_STATE_END=$IDLE_OUT/state-end.json
cd $SETUP/attacks
bash ./run-all-attacks.sh || echo "run-all-attacks.sh вернул $? — гейт всё равно считаем"
echo "атаки завершены в $(date -u +%H:%M:%S) UTC"
ls -t $SETUP/attacks/attack-results/attack-window-*.txt 2>/dev/null | head -1 | xargs -r cat | sed 's/^/  окно атаки (5.9.7d): /'

echo "=== [13/14] гейт, один вызов ==="
export IDLE_METRICS_END=$IDLE_OUT/metrics-end.txt
export IDLE_ALERTS_END=$IDLE_OUT/alerts-end.json
export IDLE_ALERTS_START=$IDLE_OUT/alerts-start.json
export AGENT_START_FILE=/root/agent-start-2.9.9.F.1.txt
bash ./run-gate.sh 2>&1 | tee /root/gate-2.9.9.F.1.txt
GATE_RC=${PIPESTATUS[0]}
echo "гейт вернул $GATE_RC"
# Пункты 1-14 постановки №2.9.9.F.1 не подлежат толкованию — вытаскиваем их
# строки отдельно, чтобы приёмка волны читалась без листания всего гейта.
echo "--- пункты 1-12 постановки (обязательные) ---"
grep -E '=== (19|20|22)\.|5\.9\.8a\.|негативный|позитивный|канарейка|null:|idle:|drop:|ringbuf_full|bpf_lost_events_total|events_drain_offset' \
    /root/gate-2.9.9.F.1.txt | sed 's/^/  /'
echo "--- пункты 13-19 (машинная печать: темп, settle, слепое окно, реестры) ---"
grep -E 'окно атаки, 5\.9\.7d|темп алертов|settle_reason|дерева измерителя|фон вне дерева|непокрытых пунктов|база брошена|потеряно вне реестров|dns\.qname|recall' \
    /root/gate-2.9.9.F.1.txt | sed 's/^/  /'

echo "=== [14/14] сводка idle-части + отчёт сверх гейта ==="
cat $IDLE_OUT/SUMMARY.txt 2>/dev/null
# 5.9.9f (№104): REPORT_LABEL передаётся явно в обоих ветках — раньше
# run-2.9.5-report.sh печатал "ОТЧЁТ №2.9.5" литералом независимо от того,
# какой замер его в действительности вызвал (фолбэк использовался на
# №2.9.6…№2.9.8 тоже). REPORT_LABEL=2.9.9.F.1 чинит это для report-2.9.9.F.1.txt;
# если когда-нибудь появится собственный run-2.9.9.F.1-report.sh, ему тоже
# следует читать REPORT_LABEL, а не зашивать номер.
if [ -f "$SETUP/run-2.9.9.F.1-report.sh" ]; then
    IDLE_OUT=$IDLE_OUT AGENT_START_FILE=/root/agent-start-2.9.9.F.1.txt REPORT_LABEL=2.9.9.F.1 \
        bash $SETUP/run-2.9.9.F.1-report.sh 2>&1 | tee /root/report-2.9.9.F.1.txt
else
    echo "ВНИМАНИЕ: run-2.9.9.F.1-report.sh отсутствует — считаем отчётом (сверх гейта) фолбэком run-2.9.5-report.sh."
    echo "ВНИМАНИЕ: п.10 (idle-алерты на метках срезов) он посчитает, величины"
    echo "ВНИМАНИЕ: постановки №2.9.9.F.1 (пп.1-14) — нет; они только в гейте."
    IDLE_OUT=$IDLE_OUT AGENT_START_FILE=/root/agent-start-2.9.9.F.1.txt REPORT_LABEL=2.9.9.F.1 \
        bash $SETUP/run-2.9.5-report.sh 2>&1 | tee /root/report-2.9.9.F.1.txt
fi

echo "=== ПАЙПЛАЙН №2.9.9.F.1 ЗАВЕРШЁН $(date -u +%H:%M:%S) UTC, гейт=$GATE_RC ==="
touch /root/PIPELINE-2.9.9.F.1-DONE
