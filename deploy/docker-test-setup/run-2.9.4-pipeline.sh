#!/usr/bin/env bash
# ЗАМЕР №2.9.4 — приёмка волны 5.9.4 и вход в волну 6.
# Цепочка та же, что у №2.9.3 (преflight -> P0-3 -> очистка -> пауза -> idle-час
# -> атаки -> гейт -> отчёт, ОДНИМ detached-процессом), плюс два новых шага,
# оба — следствие того, что волна 5.9.4 трогала не только скрипты:
#
#   [1/9] make generate && make build — ОБЯЗАТЕЛЬНО, не опционально.
#         5.9.4i добавила ppid/parent_comm в `struct dns_event` (bpf/dns.bpf.c):
#         запись выросла с 43 до 63 байт, и `dnsRawEventFixedLen` в
#         internal/collector/dns_parse.go уже ждёт 63. Бинарь, собранный без
#         `make generate`, несёт СТАРЫЙ .o: ядро пишет 43 байта, декодер читает
#         63 — это не «ppid будет нулевой», а разъехавшийся layout на всём
#         DNS-потоке. Поэтому шаг стоит до очистки стора и падает громко.
#   [0/9] преflight гоняет ещё и машинные гейты самой волны 5.9.4 (dry-run
#         sentinel, инвентарь разрушительных правил, «исключение × манифест
#         атак», arg0-условия rootkit_bpf_*). Все четыре — go-тесты, которые
#         должны быть зелёными ДО прогона: если правило сломано, это видно за
#         секунды, а не через полтора часа по пустому составу детекта.
#
# Почему одним процессом — находка №43 (замер №2.9.1): разорванная цепочка
# требует второго ssh-входа между idle и атаками, и этот вход сам становится
# событием внутри измеряемого слепого окна.
#
# Запуск (обязательно detached, иначе обрыв ssh убивает замер):
#   setsid nohup bash /opt/ebpf-guard/deploy/docker-test-setup/run-2.9.4-pipeline.sh >/dev/null 2>&1 &
# Готовность: файл /root/PIPELINE-2.9.4-DONE. Полный лог: /root/run-2.9.4-pipeline.log
exec > /root/run-2.9.4-pipeline.log 2>&1
set -x
SETUP=/opt/ebpf-guard/deploy/docker-test-setup
IDLE_OUT=$SETUP/idle-results/idle-2.9.4
P0_OUT=$SETUP/idle-results/p0-3-2.9.4
export PATH="$PATH:/usr/local/go/bin"

echo "=== [0/9] преflight: что именно меряется ==="
cd /opt/ebpf-guard
git log -1 --format='коммит замера: %H %s (%ci)'
git status --porcelain | sed 's/^/  локальная правка: /'
./build/ebpf-guard version 2>&1 | sed 's/^/  бинарь (до пересборки): /' || true
# Декларативные наборы гоняются CLI-чекером, а не `go test` — на 5.9.3f два
# набора были красными с волны 3, и ни один прогон этого не показал.
./build/ebpf-guard rules check tests/rules/ 2>&1 | tail -5

# Машинные гейты волны 5.9.4. Каждый закрывает находку, которая на прошлых
# замерах доживала до живого прогона: №52 (dry_run не гасил kill), №53 (не
# существовало инвентаря разрушительных правил), №56 (исключение по comm
# слепило собственный позитивный контроль). Красный тест здесь — повод не
# начинать замер, а не строка в отчёте после него.
echo "--- преflight: go-тесты волны 5.9.4 ---"
go test -count=1 ./internal/enforcer/ -run 'DryRunSentinel|TestExecuteKill_DryRun|TestExecuteThrottle_DryRun' 2>&1 | tail -3
go test -count=1 -v ./internal/correlator/ -run 'TestDestructiveRulesInventory_RepoRules|TestExclusionsCollidingWithAttackerComms_RepoRules|TestRootkitBPFRules_MatchCommandNotCaller' 2>&1 \
    | grep -E 'разрушительных|правил проверено|^(ok|FAIL|--- )' | sed 's/^/  /'

# dry_run обязан быть включён в конфиге замера: критерий 5.9.4a («ноль записей
# KILL action executed при dry_run: true») бессмыслен, если dry_run выключен, а
# ноль убийств в таком прогоне ничего не доказывает.
grep -n -A3 '^enforcer:' "$SETUP/config-test.yaml" | sed 's/^/  конфиг enforcer: /'
echo "преflight завершён в $(date -u +%H:%M:%S) UTC"

echo "=== [1/9] make generate && make build (5.9.4i: layout dns_event 43 -> 63 байт) ==="
cd /opt/ebpf-guard
if ! make generate; then
    echo "СТОП: make generate упал — прогон бессмыслен, DNS-события разъедутся по layout"
    touch /root/PIPELINE-2.9.4-DONE
    exit 1
fi
if ! make build; then
    echo "СТОП: make build упал"
    touch /root/PIPELINE-2.9.4-DONE
    exit 1
fi
./build/ebpf-guard version 2>&1 | sed 's/^/  бинарь (после пересборки): /' || true
ls -l build/ebpf-guard bpf/dns.bpf.c | sed 's/^/  /'
echo "сборка завершена в $(date -u +%H:%M:%S) UTC"

echo "=== [2/9] риск №3: отдельный короткий прогон P0-3 ДО замера ==="
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
# Критерий 5.9.4a считается за ВЕСЬ аптайм агента — значит точка отсчёта журнала
# должна быть зафиксирована здесь, а не угадываться потом по времени файлов.
date -u +"%Y-%m-%d %H:%M:%S" > /root/agent-start-2.9.4.txt
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
# следом, в той же detached-цепочке.
export IDLE_METRICS_START=$IDLE_OUT/metrics-start.txt
cd $SETUP/attacks
bash ./run-all-attacks.sh || echo "run-all-attacks.sh вернул $? — гейт всё равно считаем"
echo "атаки завершены в $(date -u +%H:%M:%S) UTC"

echo "=== [7/9] гейт, один вызов ==="
export IDLE_STATE_END=$IDLE_OUT/state-end.json
export IDLE_METRICS_END=$IDLE_OUT/metrics-end.txt
# 5.9.4g (№58): критерий 16 считает объём слепого окна по множеству id снимков
# /api/v1/alerts, а не по кумулятивному счётчику (idle-run.sh рестартует агента
# в конце и обнуляет его). Без этой переменной критерий печатает окно без объёма.
export IDLE_ALERTS_END=$IDLE_OUT/alerts-end.json
bash ./run-gate.sh 2>&1 | tee /root/gate-2.9.4.txt
GATE_RC=${PIPESTATUS[0]}
echo "гейт вернул $GATE_RC"

echo "=== [8/9] сводка idle-части ==="
cat $IDLE_OUT/SUMMARY.txt 2>/dev/null

echo "=== [9/9] отчёт сверх гейта: величины постановки №2.9.4, которых гейт не считает ==="
# Считает только по файлам на диске и по журналу, ни одного сетевого запроса —
# безопасно запускать и повторно, уже после прогона.
IDLE_OUT=$IDLE_OUT AGENT_START_FILE=/root/agent-start-2.9.4.txt \
    bash $SETUP/run-2.9.4-report.sh 2>&1 | tee /root/report-2.9.4.txt

echo "=== ПАЙПЛАЙН №2.9.4 ЗАВЕРШЁН $(date -u +%H:%M:%S) UTC, гейт=$GATE_RC ==="
touch /root/PIPELINE-2.9.4-DONE
