#!/usr/bin/env bash
# ЗАМЕР №2.9.5 — приёмка волны 5.9.5 и вход в волну 6.
# Цепочка та же, что у №2.9.4 (преflight -> сборка -> P0-3 -> очистка ->
# пауза -> idle-час -> атаки -> гейт -> отчёт, ОДНИМ detached-процессом).
# Волна 5.9.5 не трогала сборку/layout — новых обязательных шагов сборки
# нет. Отличия от №2.9.4, все — прямое следствие находки №62 (P0):
#
#   [6/9] run-all-attacks.sh теперь включает run_kill_scenario (5.9.5a) и
#         run_induced_drop (5.9.5b) — оба стоят ПОСЛЕ окна атак и ДО
#         get_final_metrics, чтобы их эффект попал в final-снимок, который
#         читает гейт. Ничего в этом файле для них включать не нужно —
#         они часть full_run() в самом run-all-attacks.sh.
#   [7/9] run-gate.sh получил критерий 17 (парность kill-сценария) и
#         переписанную ветку критерия 3 (SKIP вместо "PASS: проверка
#         неприменима" при нулевых дропах) — обоим нужен AGENT_START_FILE
#         за весь аптайм, экспортируется здесь же, где раньше его читал
#         только отчёт [9/9].
#
# Преflight волны 5.9.4 остаётся (машинные гейты дожили до этого замера
# невредимыми: dry-run sentinel, инвентарь разрушительных правил,
# «исключение × манифест атак», arg0-условия rootkit_bpf_*) и добавляет
# TestKillScenarioControlRule_ActionIsKill (5.9.5a) — если правку
# ebpf_subversion_detach_nonroot когда-нибудь понизят или дадут ей
# comm-условие, критерий 17 перестанет что-либо доказывать, и это обязано
# быть видно за секунды, а не после полутора часов прогона.
#
# Почему одним процессом — находка №43 (замер №2.9.1): разорванная цепочка
# требует второго ssh-входа между idle и атаками, и этот вход сам становится
# событием внутри измеряемого слепого окна.
#
# Запуск (обязательно detached, иначе обрыв ssh убивает замер):
#   setsid nohup bash /opt/ebpf-guard/deploy/docker-test-setup/run-2.9.5-pipeline.sh >/dev/null 2>&1 &
# Готовность: файл /root/PIPELINE-2.9.5-DONE. Полный лог: /root/run-2.9.5-pipeline.log
#
# ПРЕДУПРЕЖДЕНИЕ (риск №2 постановки 5.9.5): run_kill_scenario намеренно
# доводит энфорсер до разрушительного действия против одноразового
# дочернего процесса харнесса. Жертва одноразовая и шаг стоит ПОСЛЕ окна
# атак — сломанный предохранитель (dry_run не погасил kill) портит один
# шаг замера, а не весь прогон, но убивает реальный процесс на стенде.
exec > /root/run-2.9.5-pipeline.log 2>&1
set -x
SETUP=/opt/ebpf-guard/deploy/docker-test-setup
IDLE_OUT=$SETUP/idle-results/idle-2.9.5
P0_OUT=$SETUP/idle-results/p0-3-2.9.5
export PATH="$PATH:/usr/local/go/bin"

echo "=== [0/9] преflight: что именно меряется ==="
cd /opt/ebpf-guard
git log -1 --format='коммит замера: %H %s (%ci)'
git status --porcelain | sed 's/^/  локальная правка: /'
./build/ebpf-guard version 2>&1 | sed 's/^/  бинарь (до пересборки): /' || true
# Декларативные наборы гоняются CLI-чекером, а не `go test` — на 5.9.3f два
# набора были красными с волны 3, и ни один прогон этого не показал.
./build/ebpf-guard rules check tests/rules/ 2>&1 | tail -5

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

# dry_run обязан быть включён в конфиге замера: критерий 17 (5.9.5a, парность
# enforcement_dryrun_total/enforcement_actions_total) бессмыслен, если
# dry_run выключен, а ноль убийств в таком прогоне ничего не доказывает.
# Секция называется enforcement:, не enforcer: — печатаем её целиком, включая
# dry_run/enable_kill.
grep -n -A7 '^enforcement:' "$SETUP/config-test.yaml" | sed 's/^/  конфиг enforcement: /'
echo "преflight завершён в $(date -u +%H:%M:%S) UTC"

echo "=== [1/9] make generate && make build ==="
cd /opt/ebpf-guard
if ! make generate; then
    echo "СТОП: make generate упал — прогон бессмыслен"
    touch /root/PIPELINE-2.9.5-DONE
    exit 1
fi
if ! make build; then
    echo "СТОП: make build упал"
    touch /root/PIPELINE-2.9.5-DONE
    exit 1
fi
./build/ebpf-guard version 2>&1 | sed 's/^/  бинарь (после пересборки): /' || true
ls -l build/ebpf-guard | sed 's/^/  /'
echo "сборка завершена в $(date -u +%H:%M:%S) UTC"

echo "=== [2/9] риск №3 (5.9.4): отдельный короткий прогон P0-3 ДО замера ==="
# NO_RESTART=1 в основном окне (5.9.1c) отменяет проверку рестарта/5.6d,
# которая на №2.4 поймала настоящий дефект (находка №20). Гоняем её здесь
# отдельно и коротко; её рестарт остаётся далеко за пределами журнального
# окна idle-часа.
cd $SETUP
OUT_DIR=$P0_OUT DURATION=120 INTERVAL=60 NO_RESTART=0 bash ./idle-run.sh
echo "P0-3 прогон завершён в $(date -u +%H:%M:%S) UTC"
grep -h "before:\|after:\|P0-3" $P0_OUT/idle-run.log

echo "=== [3/9] очистка стора + рестарт агента (уже с новым бинарём) ==="
systemctl stop ebpf-guard-test.service
rm -f /var/lib/ebpf-guard/test-events.db /var/lib/ebpf-guard/test-events.db-shm /var/lib/ebpf-guard/test-events.db-wal
echo 0 > /var/lib/ebpf-guard/observer-root-pid
systemctl start ebpf-guard-test.service
echo "рестарт в $(date -u +%H:%M:%S) UTC"
# Критерии 5.9.4a/17 считаются за ВЕСЬ аптайм агента — точка отсчёта журнала
# фиксируется здесь, а не угадывается потом по времени файлов.
date -u +"%Y-%m-%d %H:%M:%S" > /root/agent-start-2.9.5.txt
systemctl show ebpf-guard-test.service -p ExecMainStartTimestamp | sed 's/^/  /'

echo "=== [4/9] пауза 660с: deploy-рестарт должен выйти за окно журнала idle-run ==="
sleep 660

echo "=== [5/9] idle-час, NO_RESTART=1 (5.9.1c) ==="
cd $SETUP
OUT_DIR=$IDLE_OUT DURATION=3600 INTERVAL=300 NO_RESTART=1 bash ./idle-run.sh
echo "idle завершён в $(date -u +%H:%M:%S) UTC"

echo "=== [6/9] атаки — без разрыва цепочки, сразу за idle, без ssh между ними ==="
# Переменные экспортируются в ЭТОМ процессе, а не в файл для отдельного
# входа (это и было дефектом №43) — run-all-attacks.sh запускается прямо
# следом, в той же detached-цепочке. run_kill_scenario (5.9.5a) и
# run_induced_drop (5.9.5b) уже часть full_run() внутри run-all-attacks.sh —
# отдельного шага здесь не требуется.
export IDLE_METRICS_START=$IDLE_OUT/metrics-start.txt
# 5.9.5i (находка №70): IDLE_STATE_END должен быть экспортирован ДО
# run-all-attacks.sh, не только до run-gate.sh — get_baseline_metrics теперь
# сама ждёт до 15с перед снятием baseline, если зазор с конца idle-часа
# получился меньше 10с (иначе критерий 16 снова напечатает «не измерялось»,
# как на трёх предыдущих замерах). Экспортируем здесь же, где и
# IDLE_METRICS_START, а не в шаге [7/9] вместе с остальными переменными
# гейта — иначе именно этот перенос воспроизвёл бы дефект.
export IDLE_STATE_END=$IDLE_OUT/state-end.json
cd $SETUP/attacks
bash ./run-all-attacks.sh || echo "run-all-attacks.sh вернул $? — гейт всё равно считаем"
echo "атаки завершены в $(date -u +%H:%M:%S) UTC"

echo "=== [7/9] гейт, один вызов ==="
export IDLE_METRICS_END=$IDLE_OUT/metrics-end.txt
# 5.9.4g (№58): критерий 16 считает объём слепого окна по множеству id снимков
# /api/v1/alerts, а не по кумулятивному счётчику (idle-run.sh рестартует агента
# в конце и обнуляет его). Без этой переменной критерий печатает окно без объёма.
export IDLE_ALERTS_END=$IDLE_OUT/alerts-end.json
# 5.9.5a: критерий 17 читает журнал за ВЕСЬ аптайм от той же точки отсчёта,
# что и отчёт [9/9] — до сих пор эту переменную получал только отчёт,
# гейт падал на --boot. Экспортируем здесь же.
export AGENT_START_FILE=/root/agent-start-2.9.5.txt
bash ./run-gate.sh 2>&1 | tee /root/gate-2.9.5.txt
GATE_RC=${PIPESTATUS[0]}
echo "гейт вернул $GATE_RC"

echo "=== [8/9] сводка idle-части ==="
cat $IDLE_OUT/SUMMARY.txt 2>/dev/null

echo "=== [9/9] отчёт сверх гейта: величины постановки №2.9.5, которых гейт не считает ==="
# Считает только по файлам на диске и по журналу, ни одного сетевого запроса —
# безопасно запускать и повторно, уже после прогона.
IDLE_OUT=$IDLE_OUT AGENT_START_FILE=/root/agent-start-2.9.5.txt \
    bash $SETUP/run-2.9.5-report.sh 2>&1 | tee /root/report-2.9.5.txt

echo "=== ПАЙПЛАЙН №2.9.5 ЗАВЕРШЁН $(date -u +%H:%M:%S) UTC, гейт=$GATE_RC ==="
touch /root/PIPELINE-2.9.5-DONE
