#!/usr/bin/env bash
# ЗАМЕР №2.9.7 — приёмка волны 5.9.7, окончательный вход в волну 6.
#
# Структура та же, что у №2.9.6 (преflight -> сборка -> P0-3 -> очистка ->
# SMOKE -> пауза -> idle-час -> атаки -> гейт -> отчёт, ОДНИМ detached-
# процессом). Отличий четыре, и все четыре — прямые требования постановки
# №2.9.7, а не улучшения оформления:
#
#   [1/12] ЖЁСТКИЙ СТОП №1 — replay-gate.sh на архивах collect-2.9.5/2.9.6.
#          Риск №1 («дефекты измерителя чинятся тем же кодом, который их
#          меряет») повторялся ТРИ волны подряд и три раза не исполнялся,
#          потому что жил в тексте постановки, а не в цепочке. Теперь он
#          шаг пайплайна, и его провал останавливает замер ДО сборки.
#          Отсутствие архивов на стенде — тоже стоп: «пропустить, раз их
#          нет» — ровно тот способ, которым он пропускался трижды.
#
#   [2/12] ЖЁСТКИЙ СТОП №2 — сверка criteria-index.txt. Выполняется не
#          копией логики, а самим run-gate.sh (его преflight, exit 3) на
#          архиве: пункт постановки без машинной печати обязан обрушить
#          цепочку, а не всплыть ручным разбором через две волны (находка
#          №83).
#
#   [6/12] ЖЁСТКИЙ СТОП №3 — run_ringbuf_overflow ВНЕ окна замера. Шаг
#          SIGSTOP'ит агента и льёт 300 тыс. openat() в замороженное кольцо;
#          это другой режим работы конвейера, и его числа НЕ переносятся на
#          основное окно (риск №2 постановки). Отсюда его место: после
#          рестарта с новым бинарём, до паузы [7/12], то есть далеко за
#          пределами журнального окна idle-часа.
#
#   [9/12] Основное окно получает IDLE_ALERTS_START — новая переменная
#          секции 5.9.7f (DNS-FP на idle). Без неё секция считает прирост,
#          но не может разложить его по comm и честно валит по «разбивка не
#          измерена», а не молчит.
#
# Волна 5.9.7 НЕ трогает BPF C-код (в отличие от 5.9.6), но `make generate`
# остаётся обязательным и жёстким: *_bpf_gen.go в дереве — рукописные
# заглушки, и прогон на них мерил бы не то ядро, которое собрано.
#
# Почему одним процессом — находка №43 (замер №2.9.1): разорванная цепочка
# требует второго ssh-входа между idle и атаками, и этот вход сам становится
# событием внутри измеряемого слепого окна. С волны 5.9.7e у этого правила
# появилась вторая цена: ssh-логин оператора поднимал два правила (одно
# critical) и через 5.9.6f попал в detection-baseline.txt как «детект».
#
# Запуск (обязательно detached, иначе обрыв ssh убивает замер):
#   setsid nohup bash /opt/ebpf-guard/deploy/docker-test-setup/run-2.9.7-pipeline.sh >/dev/null 2>&1 &
# Готовность: файл /root/PIPELINE-2.9.7-DONE. Полный лог: /root/run-2.9.7-pipeline.log
#
# ПРЕДУПРЕЖДЕНИЕ (риск №2 постановки 5.9.5, дожил без изменений):
# run_kill_scenario намеренно доводит энфорсер до разрушительного действия
# против одноразового дочернего процесса харнесса. Жертва одноразовая и шаг
# стоит ПОСЛЕ окна атак — сломанный предохранитель (dry_run не погасил kill)
# портит один шаг замера, а не весь прогон, но убивает реальный процесс.
exec > /root/run-2.9.7-pipeline.log 2>&1
set -x
SETUP=/opt/ebpf-guard/deploy/docker-test-setup
IDLE_OUT=$SETUP/idle-results/idle-2.9.7
P0_OUT=$SETUP/idle-results/p0-3-2.9.7
export PATH="$PATH:/usr/local/go/bin"

die() {
    echo "=== СТОП: $* ==="
    echo "=== ЗАМЕР №2.9.7 НЕ НАЧАТ. $(date -u +%H:%M:%S) UTC ==="
    touch /root/PIPELINE-2.9.7-DONE
    exit 1
}

# Параметры волны, объявленные ЗДЕСЬ и печатаемые в преflight, а не оставленные
# умолчаниями внутри run-all-attacks.sh: п.4 порядка работы требует, чтобы
# величины, влияющие на критерий, были названы ДО прогона и лежали в артефактах
# замера, а не восстанавливались потом чтением кода.
#
# COUNTING_CONTROL_BG_WINDOW больше НЕ объявляется: 5.9.7a удалила оценку фона
# «за N секунд до генератора» целиком и заменила её негативным контролем
# mode=null. Переменная, оставленная здесь по инерции, читалась бы как «фон всё
# ещё оценивается», а он теперь измеряется.
export COUNTING_CONTROL_N="${COUNTING_CONTROL_N:-10000}"
export COUNTING_CONTROL_DROP_N="${COUNTING_CONTROL_DROP_N:-300000}"
export INDUCED_DROP_MAX_FILES="${INDUCED_DROP_MAX_FILES:-20000}"
export RINGBUF_OVERFLOW_N="${RINGBUF_OVERFLOW_N:-300000}"
export RINGBUF_OVERFLOW_SERVICE="${RINGBUF_OVERFLOW_SERVICE:-ebpf-guard-test.service}"

echo "=== [0/12] преflight: что именно меряется ==="
cd /opt/ebpf-guard || die "нет /opt/ebpf-guard"
git log -1 --format='коммит замера: %H %s (%ci)'
git status --porcelain | sed 's/^/  локальная правка: /'
./build/ebpf-guard version 2>&1 | sed 's/^/  бинарь (до пересборки): /' || true
# Декларативные наборы гоняются CLI-чекером, а не `go test` — на 5.9.3f два
# набора были красными с волны 3, и ни один прогон этого не показал.
./build/ebpf-guard rules check tests/rules/ 2>&1 | tail -5

# bash 4+ обязателен: секция 19 гейта использует declare -A, а run-gate.sh и
# replay-gate.sh с волны 5.9.7 сами останавливаются кодом 4 на старом
# интерпретаторе (находка №88). Здесь проверяется тот bash, которым цепочка
# будет их звать, чтобы стоп не случился на 1.5-часовой отметке.
echo "--- преflight: интерпретатор ---"
echo "  bash: ${BASH_VERSION}"
[ "${BASH_VERSINFO[0]}" -ge 4 ] || die "bash ${BASH_VERSION} — run-gate.sh требует 4+ (declare -A, секция 19)"

# Машинные гейты волн 5.9.4/5.9.5. Каждый закрывает находку, которая на
# прошлых замерах доживала до живого прогона: №52 (dry_run не гасил kill),
# №53 (не существовало инвентаря разрушительных правил), №56 (исключение по
# comm слепило собственный позитивный контроль), №62 (kill-сценарий не имел
# защищённого контрольного правила — 5.9.5a). Красный тест здесь — повод не
# начинать замер, а не строка в отчёте после него.
echo "--- преflight: go-тесты волн 5.9.4/5.9.5 ---"
go test -count=1 ./internal/enforcer/ -run 'DryRunSentinel|TestExecuteKill_DryRun|TestExecuteThrottle_DryRun' 2>&1 | tail -3
go test -count=1 -v ./internal/correlator/ -run 'TestDestructiveRulesInventory_RepoRules|TestExclusionsCollidingWithAttackerComms_RepoRules|TestRootkitBPFRules_MatchCommandNotCaller|TestKillScenarioControlRule_ActionIsKill' 2>&1 \
    | grep -E 'разрушительных|правил проверено|^(ok|FAIL|--- )' | sed 's/^/  /'

echo "--- преflight: go-тесты волны 5.9.6 ---"
go test -count=1 ./internal/bpf/ -run 'SumPerCPU' 2>&1 | tail -3
go test -count=1 ./internal/collector/ -run 'DNS|Malformed' 2>&1 | tail -3

# Волна 5.9.7. Юнит-тесты 5.9.7e/f — единственная машинная проверка того, что
# сужение двух правил по ssh НЕ ослепило их (риск №3 постановки: тот же приём
# убил восемь типов на 5.9.3b). Позитивная половина — запись в authorized_keys
# посторонним comm'ом обязана дать алерт — внутри этих же тестов.
echo "--- преflight: go-тесты волны 5.9.7 (риск №3: сужение != ослепление) ---"
# Печать и проверка — двумя командами, а не одной: у `go test | grep | sed`
# статус берётся от sed, то есть `if !` не сработал бы никогда.
go test -count=1 -v ./internal/correlator/ -run 'TestWave597' 2>&1 | grep -E '^(=== RUN|--- |ok|FAIL)' | sed 's/^/  /'
go test -count=1 ./internal/correlator/ -run 'TestWave597' >/dev/null 2>&1 \
    || die "юнит-тесты 5.9.7e/f красные — сужение rootkit_ssh_authorized_keys_modified/sigma_sensitive_dir_listing не доказано как не-ослепление (риск №3)"

# Синтаксис всех трёх скриптов харнесса. Волна 5.9.7 добавила в них ~700 строк
# (секции 20/22/5.9.7f/крит.16 гейта, run_counting_control null, run_ringbuf_
# overflow, mark_attack_window, run_measurement_prologue, весь replay-gate.sh);
# сломанная правка проявилась бы через 1.5 часа, когда прогон уже нельзя
# повторить в тот же день.
echo "--- преflight: синтаксис харнесса ---"
bash -n $SETUP/attacks/run-all-attacks.sh || die "run-all-attacks.sh: синтаксическая ошибка"
bash -n $SETUP/attacks/run-gate.sh         || die "run-gate.sh: синтаксическая ошибка"
bash -n $SETUP/attacks/replay-gate.sh      || die "replay-gate.sh: синтаксическая ошибка"
bash -n $SETUP/idle-run.sh                 || die "idle-run.sh: синтаксическая ошибка"
echo "  синтаксис всех четырёх скриптов ок"

# СТОРОЖ НАХОДКИ №86 (P0). 5.9.7g в первой редакции регистрировала корень
# наблюдателя на ВЕСЬ run-all-attacks.sh — а observer_should_drop() роняет в
# ядре события любого потомка корня, то есть все атаки прогона (sqlmap 202
# алерта, curl 169, chmod 6, tee 5 по архиву №2.9.6) плюс обе канарейки волны.
# Гейт напечатал бы recall 0/6 и это списали бы на регресс продукта. Правка
# сузила корень до сабшелла пролога; здесь проверяется, что она не откачена:
# регистрация обязана вызываться ТОЛЬКО внутри run_measurement_prologue и
# нигде на верхнем уровне.
echo "--- преflight: сторож находки №86 (корень наблюдателя не шире пролога) ---"
grep -q 'run_measurement_prologue()' $SETUP/attacks/run-all-attacks.sh \
    || die "находка №86: run_measurement_prologue отсутствует — регистрация observer_root не сужена до пролога"
# Ищутся ровно две формы отката, обе на ВЕРХНЕМ уровне (без отступа):
# прямая запись `echo "$$" > ...` и голый вызов `observer_root_register` на
# отдельной строке. Определение функции (`observer_root_register() {`) под
# шаблон не подпадает — иначе сторож валил бы исправный файл; правомерный
# вызов внутри сабшелла идёт с отступом и тоже не подпадает.
top_level_reg=$(grep -nE '^(observer_root_register[[:space:]]*$|echo[[:space:]]+"?\$\$"?[[:space:]]*>)' $SETUP/attacks/run-all-attacks.sh || true)
if [ -n "$top_level_reg" ]; then
    echo "$top_level_reg" | sed 's/^/  регистрация на верхнем уровне: /'
    die "находка №86: регистрация observer_root вызвана на верхнем уровне run-all-attacks.sh — все атаки прогона будут отброшены в ядре (sqlmap/curl/chmod/tee), recall станет 0/6"
fi
echo "  ок: корень наблюдателя регистрируется только внутри пролога"

# Реестры, без которых критерии волны не читаются. criteria-index.txt и
# dns-idle-fp.txt — новые: первый обрушивает гейт своим отсутствием (exit 3,
# и это правильно), второй пустой означает «прирост DNS-FP на idle обязан
# быть нулём», что и есть цель 5.9.7f.
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
ls -l "$SETUP/attacks/detection-baseline-diff-state.txt" 2>/dev/null | sed 's/^/  сигнатура прошлого прогона: /' \
    || echo "  сигнатуры прошлого прогона нет — предупреждение «база брошена» на этом замере невозможно по построению"

# python3 — внешняя зависимость трёх шагов: контроль счётности (5.9.7a, оба
# позитивных режима), run_ringbuf_overflow (5.9.7b) и setuid-атака. Без него
# два P0-пункта волны остаются без входа, то есть замер теряет смысл — здесь
# это СТОП, а не предупреждение, как было на №2.9.6.
if command -v python3 >/dev/null 2>&1; then
    echo "  python3: $(python3 --version 2>&1) — 5.9.7a/5.9.7b исполнимы"
else
    die "python3 не найден — контроль счётности (5.9.7a) и run_ringbuf_overflow (5.9.7b) без входа, оба P0-пункта волны непроверяемы"
fi
command -v jq >/dev/null 2>&1 || die "jq не найден — гейт и разбивки по comm непроверяемы"

echo "  параметры волны 5.9.7: COUNTING_CONTROL_N=$COUNTING_CONTROL_N COUNTING_CONTROL_DROP_N=$COUNTING_CONTROL_DROP_N INDUCED_DROP_MAX_FILES=$INDUCED_DROP_MAX_FILES RINGBUF_OVERFLOW_N=$RINGBUF_OVERFLOW_N"

# dry_run обязан быть включён в конфиге замера: критерий 17 (5.9.5a, парность
# enforcement_dryrun_total/enforcement_actions_total) бессмыслен, если dry_run
# выключен, а ноль убийств в таком прогоне ничего не доказывает.
grep -n -A7 '^enforcement:' "$SETUP/config-test.yaml" | sed 's/^/  конфиг enforcement: /'
# 5.9.7e выбрал путь `op: eq write` вместо сужения по comm — правило немо без
# track_write. На стенде он включён; если выключат, правило исчезнет молча.
grep -n 'track_write' "$SETUP/config-test.yaml" | sed 's/^/  конфиг file_ops: /'
grep -q 'track_write:[[:space:]]*true' "$SETUP/config-test.yaml" \
    || die "track_write выключен — rootkit_ssh_authorized_keys_modified (5.9.7e) немо по построению, позитивный контроль риска №3 невозможен"
echo "преflight завершён в $(date -u +%H:%M:%S) UTC"

echo "=== [1/12] ЖЁСТКИЙ СТОП №1: replay-gate.sh на архивах (5.9.7c, №85) ==="
# Архивы прошлых замеров. Реплей обязан быть исполнен на ОБОИХ: collect-2.9.5
# доказывает, что тождество умеет SKIP'ать по отсутствующей левой части,
# collect-2.9.6 — что оно сходится там, где сходилось, и что новая формула
# фона (5.9.7a) проходит там, где старая валила. Третий реплей — синтетическая
# потеря 1000 событий: тождество, которое умеет только сходиться, неотличимо
# от тождества, которое не умеет ничего.
#
# Пути ищутся, а не угадываются; отсутствие — СТОП. «Архивов на стенде нет,
# пропустим» — ровно тот способ, которым риск №1 пропускался три волны подряд.
find_archive() {
    local name="$1" d
    for d in "/opt/ebpf-guard/server-logs/$name" "/root/$name" "/tmp/$name" "$SETUP/../../server-logs/$name"; do
        [ -d "$d/attacks" ] && { echo "$d"; return 0; }
    done
    return 1
}
C295_DIR="${REPLAY_C295_DIR:-$(find_archive collect-2.9.5 || true)}"
C296_DIR="${REPLAY_C296_DIR:-$(find_archive collect-2.9.6 || true)}"
echo "  архив 2.9.5: ${C295_DIR:-НЕ НАЙДЕН}"
echo "  архив 2.9.6: ${C296_DIR:-НЕ НАЙДЕН}"
if [ -z "$C295_DIR" ] || [ -z "$C296_DIR" ]; then
    die "архивы collect-2.9.5/collect-2.9.6 не найдены на стенде. Скопировать их (например в /root/) и повторить, либо задать REPLAY_C295_DIR/REPLAY_C296_DIR. Пропуск реплея — это находка №85, повторённая четвёртый раз"
fi
# PIPESTATUS[0], а не статус конвейера: `cmd | tee` возвращает статус tee,
# который успешен всегда — с прямым `if !` красный реплей проехал бы молча,
# и жёсткий стоп №1 снова оказался бы декорацией.
bash $SETUP/attacks/replay-gate.sh "$C295_DIR" "$C296_DIR" 2>&1 | tee /root/replay-2.9.7.txt
replay_rc=${PIPESTATUS[0]}
echo "  replay-gate вернул $replay_rc"
[ "$replay_rc" -eq 4 ] && die "replay-gate: неподходящий bash (находка №88) — цепочка зовёт старый интерпретатор"
[ "$replay_rc" -eq 0 ] \
    || die "REPLAY-GATE красный (код $replay_rc) — тождество 5.9.6b/счётность 5.9.7a не воспроизводятся на архивах. На стенд такое тождество не едет (5.9.7c)"
echo "реплей пройден в $(date -u +%H:%M:%S) UTC"

echo "=== [2/12] ЖЁСТКИЙ СТОП №2: сверка criteria-index.txt (5.9.7h, №83) ==="
# Проверку делает сам run-gate.sh своим преflight'ом (exit 3) — здесь он
# зовётся на архиве, потому что нужен любой валидный набор снимков, чтобы он
# дошёл до этого блока. Копии логики намеренно нет: реестр обязан сверяться
# ТЕМ кодом, который потом вынесет вердикт, иначе сверяются две разные вещи.
c296_ts=$(ls "$C296_DIR"/attacks/baseline-state-*.json 2>/dev/null | head -1 | sed 's/.*baseline-state-\(.*\)\.json/\1/')
[ -n "$c296_ts" ] || die "не удалось определить TIMESTAMP архива 2.9.6 для сверки criteria-index.txt"
# ПОБОЧНЫЙ ЭФФЕКТ, который обязан быть снят: run-gate.sh пишет рядом с собой
# detection-baseline-diff-state.txt (5.9.6f) — сигнатуру «добавлено/потеряно»
# прошлого прогона, по которой критерий 6 ловит брошенную базу. Прогон на
# архиве не является «прошлым замером» для этого сравнения, и если оставить
# всё как есть, шаг [11/12] сравнит настоящий замер с сигнатурой архива.
# replay-gate.sh снимает/восстанавливает этот файл вокруг каждого своего
# вызова гейта; здесь вызов свой, значит и снимать надо здесь.
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

echo "=== [3/12] make generate && make build ==="
cd /opt/ebpf-guard
# Волна 5.9.7 не правит BPF C-код, но *_bpf_gen.go в дереве — рукописные
# заглушки ([[bpf-gen-files-are-stubs]]); прогон на них мерил бы не тот объект,
# который собран. generate остаётся жёстким.
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
[ "$gen_maps_missing" -eq 0 ] || echo "ВНИМАНИЕ: карты 5.9.6 отсутствуют хотя бы в одном объекте — SMOKE-гейт [5/12] обязан это подтвердить красным"
git status --porcelain internal/bpf/ | sed 's/^/  generate изменил: /'
make build || die "make build упал"
./build/ebpf-guard version 2>&1 | sed 's/^/  бинарь (после пересборки): /' || true
ls -l build/ebpf-guard | sed 's/^/  /'
echo "сборка завершена в $(date -u +%H:%M:%S) UTC"

echo "=== [4/12] риск №3 (5.9.4): отдельный короткий прогон P0-3 ДО замера ==="
# NO_RESTART=1 в основном окне (5.9.1c) отменяет проверку рестарта/5.6d,
# которая на №2.4 поймала настоящий дефект (находка №20). Гоняем её здесь
# отдельно и коротко; её рестарт остаётся далеко за пределами журнального
# окна idle-часа.
cd $SETUP
OUT_DIR=$P0_OUT DURATION=120 INTERVAL=60 NO_RESTART=0 bash ./idle-run.sh
echo "P0-3 прогон завершён в $(date -u +%H:%M:%S) UTC"
grep -h "before:\|after:\|P0-3" $P0_OUT/idle-run.log

echo "=== [5/12] очистка стора + рестарт агента (уже с новым бинарём) ==="
systemctl stop ebpf-guard-test.service
rm -f /var/lib/ebpf-guard/test-events.db /var/lib/ebpf-guard/test-events.db-shm /var/lib/ebpf-guard/test-events.db-wal
# Обнуление корня наблюдателя между прогонами — гигиена, а не механизм:
# агент значение 0 игнорирует (находка №87, поллер main.go делает continue на
# pid==0), так что фактически корень снимается только этим рестартом. Строка
# остаётся, потому что перестанет быть бутафорией, как только №87 починят.
echo 0 > /var/lib/ebpf-guard/observer-root-pid
systemctl start ebpf-guard-test.service
echo "рестарт в $(date -u +%H:%M:%S) UTC"
# Критерии 5.9.4a/17 считаются за ВЕСЬ аптайм агента — точка отсчёта журнала
# фиксируется здесь, а не угадывается потом по времени файлов.
date -u +"%Y-%m-%d %H:%M:%S" > /root/agent-start-2.9.7.txt
systemctl show ebpf-guard-test.service -p ExecMainStartTimestamp | sed 's/^/  /'

echo "=== [6/12] SMOKE-гейт: коллекторы грузятся, поток не пуст, watchdog запущен ==="
SMOKE_TOKEN="${EBPF_GUARD_TOKEN:-$(grep '^admin=' /var/lib/ebpf-guard/token 2>/dev/null | cut -d= -f2)}"
SMOKE_API="http://${VPS_IP:-localhost}:19090"
smoke_fail=0

sleep 20   # дать коллекторам подняться и прицепить программы
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
smoke_sum() { awk -F'} ' -v p="$1" '$0 ~ p {s+=$2} END{printf "%.0f", s+0}'; }

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

# 5.9.7b: watchdog.Watchdog до этой волны НЕ СОЗДАВАЛСЯ вовсе (watchdog.New не
# имел ни одного вызова вне тестов), поэтому bpf_lost_events_total был
# гарантированно нулём на любом стенде с момента, когда 5.9.6a его ввела.
# Дешёвый живой признак того, что проводка на месте: heartbeat-гейдж, который
# публикует тот же Start() и который по той же причине тоже был мёртв. Его
# отсутствие означает, что шаг [8/12] заведомо не сможет доказать 5.9.7b.
hb=$(echo "$smoke_after" | grep -c '^ebpf_guard_heartbeat_timestamp_seconds' || true)
echo "  watchdog: серий ebpf_guard_heartbeat_timestamp_seconds = $hb"
if [ "$hb" -eq 0 ]; then
    echo "SMOKE FAIL: heartbeat отсутствует — watchdog.Start не выполнен, значит runDropTracking тоже не идёт и bpf_lost_events_total останется нулём (5.9.7b недоказуем)"
    smoke_fail=1
fi

if [ "$smoke_fail" -ne 0 ]; then
    die "SMOKE-гейт красный. Полтора часа на прогон, который не сможет отличить исправную систему от ослепшей, тратить нельзя"
fi
echo "SMOKE OK: коллекторы живы, watchdog запущен. $(date -u +%H:%M:%S) UTC"

echo "=== [7/12] ЖЁСТКИЙ СТОП №3: run_ringbuf_overflow ВНЕ окна замера (5.9.7b, №79) ==="
# SIGSTOP всему процессу агента на время генератора: кольцо в ядре продолжает
# принимать bpf_ringbuf_reserve() от каждого openat(), читающий poll-луп
# заморожен, кольцо переполняется. Метод А постановки (узкая карта) не
# исполним — ComputeRingBufSize клэмпит SizeBytes в [4МБ,32МБ].
#
# Шаг стоит ЗДЕСЬ, а не внутри full_run: узкое/переполненное кольцо — другой
# режим работы всего конвейера, и его числа не переносятся на основное окно
# (риск №2 постановки). Пауза [8/12] после него уводит и SIGSTOP, и 300 тыс.
# openat() за пределы журнального окна idle-часа.
cd $SETUP/attacks
bash ./run-all-attacks.sh --ringbuf-overflow 2>&1 | tee /root/ringbuf-overflow-2.9.7.txt
rb_marker=$(ls -t $SETUP/attacks/attack-results/ringbuf-overflow-*.txt 2>/dev/null | head -1)
[ -n "$rb_marker" ] || die "run_ringbuf_overflow не оставил маркера — шаг не исполнен, 5.9.7b без входа"
cat "$rb_marker" | sed 's/^/  /'
grep -q '^skipped=1' "$rb_marker" && die "run_ringbuf_overflow пропущен харнессом: $(awk -F= '$1=="skip_reason"{$1="";print substr($0,2)}' "$rb_marker")"
rb_full=$(awk -F= '$1=="ringbuf_full_delta"{print $2+0}' "$rb_marker")
rb_lost=$(awk -F= '$1=="bpf_lost_delta"{print $2+0}' "$rb_marker")
rb_diff=$(awk -F= '$1=="diff"{print $2+0}' "$rb_marker")
echo "  ringbuf_full=$rb_full bpf_lost_events_total=$rb_lost сумма-N=$rb_diff"
[ "${rb_full:-0}" -gt 0 ] \
    || die "ringbuf_full=0 даже с замороженным читателем — переполнение не воспроизведено, пункт 4 постановки недостижим (поднять RINGBUF_OVERFLOW_N)"
[ "${rb_full:-0}" -eq "${rb_lost:-0}" ] \
    || die "ringbuf_full=$rb_full != bpf_lost_events_total=$rb_lost — проводка watchdog (5.9.7b) не подтверждена живьём, пункт 5 постановки провален до старта окна"
echo "5.9.7b доказан живьём в $(date -u +%H:%M:%S) UTC: кольцо переполнено управляемо, счётчик совпал"

echo "=== [8/12] пауза 660с: рестарт, smoke и переполнение кольца выходят за окно журнала idle-run ==="
sleep 660

echo "=== [9/12] idle-час, NO_RESTART=1 (5.9.1c) ==="
cd $SETUP
OUT_DIR=$IDLE_OUT DURATION=3600 INTERVAL=300 NO_RESTART=1 bash ./idle-run.sh
echo "idle завершён в $(date -u +%H:%M:%S) UTC"

echo "=== [10/12] атаки — без разрыва цепочки, сразу за idle, без ssh между ними ==="
# Переменные экспортируются в ЭТОМ процессе, а не в файл для отдельного входа
# (это и было дефектом №43). run_counting_control (5.9.7a, три режима —
# null первым), run_kill_scenario (5.9.5a) и run_induced_drop (5.9.5b/5.9.6d)
# уже часть full_run() внутри run-all-attacks.sh.
export IDLE_METRICS_START=$IDLE_OUT/metrics-start.txt
# 5.9.5i (находка №70): IDLE_STATE_END должен быть экспортирован ДО
# run-all-attacks.sh, не только до run-gate.sh — get_baseline_metrics сама
# ждёт до 15с перед снятием baseline, если зазор с конца idle-часа меньше 10с.
export IDLE_STATE_END=$IDLE_OUT/state-end.json
cd $SETUP/attacks
bash ./run-all-attacks.sh || echo "run-all-attacks.sh вернул $? — гейт всё равно считаем"
echo "атаки завершены в $(date -u +%H:%M:%S) UTC"
# 5.9.7d: маркер окна атаки пишется самими шагами; печатаем его сразу, чтобы
# знаменатель темпа детекта лежал в логе замера, а не восстанавливался потом.
ls -t $SETUP/attacks/attack-results/attack-window-*.txt 2>/dev/null | head -1 | xargs -r cat | sed 's/^/  окно атаки (5.9.7d): /'

echo "=== [11/12] гейт, один вызов ==="
export IDLE_METRICS_END=$IDLE_OUT/metrics-end.txt
# 5.9.4g (№58): критерий 16 считает объём слепого окна по множеству id снимков
# /api/v1/alerts, а не по кумулятивному счётчику. Эта же переменная кормит
# gap_rule_ids (5.9.6h) и разбор состава окна (5.9.7g).
export IDLE_ALERTS_END=$IDLE_OUT/alerts-end.json
# 5.9.7f (находка №83): НОВАЯ переменная. Секция DNS-FP на idle раскладывает
# прирост четырёх long-label правил по comm вычитанием «comm'ы конца минус
# comm'ы начала»; без неё она честно валит по «разбивка не измерена», а не
# молчит — но и разобрать grafana (риск №4) тогда нечем.
export IDLE_ALERTS_START=$IDLE_OUT/alerts-start.json
# 5.9.5a: критерий 17 читает журнал за ВЕСЬ аптайм от той же точки отсчёта,
# что и отчёт [12/12].
export AGENT_START_FILE=/root/agent-start-2.9.7.txt
bash ./run-gate.sh 2>&1 | tee /root/gate-2.9.7.txt
GATE_RC=${PIPESTATUS[0]}
echo "гейт вернул $GATE_RC"
# Пункты 1-8 постановки №2.9.7 не подлежат толкованию — вытаскиваем их строки
# отдельно, чтобы приёмка волны читалась без листания всего гейта.
echo "--- пункты 1-8 постановки (обязательные: измеритель говорит правду) ---"
grep -E '=== (19|20|22)\.|null:|idle:|drop:|ringbuf_full|bpf_lost_events_total|непокрытых пунктов' \
    /root/gate-2.9.7.txt | sed 's/^/  /'
echo "--- пункты 9-19 (машинная печать: темп, реестры, DNS-FP, слепое окно) ---"
grep -E 'окно атаки, 5\.9\.7d|доля числителя|потеряно вне реестров|немых за аптайм|5\.9\.7f|dns\.qname|состав окна|дерева измерителя|recall' \
    /root/gate-2.9.7.txt | sed 's/^/  /'

echo "=== [12/12] сводка idle-части + отчёт сверх гейта ==="
cat $IDLE_OUT/SUMMARY.txt 2>/dev/null
# Считает только по файлам на диске и по журналу, ни одного сетевого запроса —
# безопасно запускать повторно уже после прогона. run-2.9.7-report.sh пока не
# написан: берём предыдущий и ГОВОРИМ об этом, потому что величины постановки
# №2.9.7 (пп.1-8) в нём отсутствуют и принимать волну по нему нельзя.
if [ -f "$SETUP/run-2.9.7-report.sh" ]; then
    IDLE_OUT=$IDLE_OUT AGENT_START_FILE=/root/agent-start-2.9.7.txt \
        bash $SETUP/run-2.9.7-report.sh 2>&1 | tee /root/report-2.9.7.txt
else
    echo "ВНИМАНИЕ: run-2.9.7-report.sh отсутствует — считаем отчётом №2.9.5."
    echo "ВНИМАНИЕ: п.10 (idle-алерты на метках срезов) он посчитает, величины"
    echo "ВНИМАНИЕ: постановки №2.9.7 (пп.1-8) — нет; они только в гейте."
    IDLE_OUT=$IDLE_OUT AGENT_START_FILE=/root/agent-start-2.9.7.txt \
        bash $SETUP/run-2.9.5-report.sh 2>&1 | tee /root/report-2.9.7.txt
fi

echo "=== ПАЙПЛАЙН №2.9.7 ЗАВЕРШЁН $(date -u +%H:%M:%S) UTC, гейт=$GATE_RC ==="
touch /root/PIPELINE-2.9.7-DONE
