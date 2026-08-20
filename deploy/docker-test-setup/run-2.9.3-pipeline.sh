#!/usr/bin/env bash
# ЗАМЕР №2.9.3 — приёмка волны 5.9.3.
# Цепочка та же, что у №2.9.2: преflight -> P0-3 -> очистка -> пауза ->
# idle-час -> экспорты -> атаки -> гейт -> отчёт, ОДНИМ detached-процессом.
#
# Почему одним процессом — находка №43 (замер №2.9.1): разорванная цепочка
# требует второго ssh-входа между idle и атаками, и этот вход сам становится
# событием внутри измеряемого слепого окна, а гейт без экспортированных
# переменных печатает SKIP по критерию 6. Здесь между последним срезом idle и
# baseline атак не происходит ни одного входа, а гейт вызывается один раз.
#
# Отличие от run-2.9.2-pipeline.sh — два шага, оба следствие постановки
# №2.9.3 (plan.md, «ЗАМЕР №2.9.3»):
#   [0/8] преflight: зафиксировать в логе, ЧТО именно меряется (коммит, версия
#         бинаря, декларативные тесты правил), — на №2.9.2 версия кода в
#         протоколе замера не фиксировалась вовсе, и связь «прогон ↔ коммит»
#         держалась на памяти оператора;
#   [8/8] run-2.9.3-report.sh: четыре величины постановки (п.1-5), которые
#         гейт не считает и которые на №2.9.2 снимались руками уже после
#         прогона. Отдельный скрипт, чтобы его можно было перезапустить на
#         собранных артефактах, ничего не меряя заново.
#
# Запуск (обязательно detached, иначе обрыв ssh убивает замер):
#   setsid nohup bash /opt/ebpf-guard/deploy/docker-test-setup/run-2.9.3-pipeline.sh >/dev/null 2>&1 &
# Готовность: файл /root/PIPELINE-2.9.3-DONE. Полный лог: /root/run-2.9.3-pipeline.log
exec > /root/run-2.9.3-pipeline.log 2>&1
set -x
SETUP=/opt/ebpf-guard/deploy/docker-test-setup
IDLE_OUT=$SETUP/idle-results/idle-2.9.3
P0_OUT=$SETUP/idle-results/p0-3-2.9.3

echo "=== [0/8] преflight: что именно меряется ==="
cd /opt/ebpf-guard
git log -1 --format='коммит замера: %H %s (%ci)'
git status --porcelain | sed 's/^/  локальная правка: /'
./build/ebpf-guard version 2>&1 | sed 's/^/  бинарь: /' || true
# Декларативные наборы гоняются CLI-чекером, а не `go test` — на 5.9.3f два
# набора были красными с волны 3, и ни один прогон этого не показал.
./build/ebpf-guard rules check tests/rules/ 2>&1 | tail -5
echo "преflight завершён в $(date -u +%H:%M:%S) UTC"

echo "=== [1/8] риск №3: отдельный короткий прогон P0-3 ДО замера ==="
# NO_RESTART=1 в основном окне (5.9.1c) отменяет проверку рестарта/5.6d,
# которая на №2.4 поймала настоящий дефект (находка №20). Гоняем её здесь
# отдельно и коротко; её рестарт остаётся далеко за пределами журнального
# окна idle-часа.
cd $SETUP
OUT_DIR=$P0_OUT DURATION=120 INTERVAL=60 NO_RESTART=0 bash ./idle-run.sh
echo "P0-3 прогон завершён в $(date -u +%H:%M:%S) UTC"
grep -h "before:\|after:\|P0-3" $P0_OUT/idle-run.log

echo "=== [2/8] очистка стора + рестарт агента ==="
systemctl stop ebpf-guard-test.service
rm -f /var/lib/ebpf-guard/test-events.db /var/lib/ebpf-guard/test-events.db-shm /var/lib/ebpf-guard/test-events.db-wal
echo 0 > /var/lib/ebpf-guard/observer-root-pid
systemctl start ebpf-guard-test.service
echo "рестарт в $(date -u +%H:%M:%S) UTC"

echo "=== [3/8] пауза 660с: deploy-рестарт должен выйти за окно журнала idle-run ==="
sleep 660

echo "=== [4/8] idle-час, NO_RESTART=1 (5.9.1c) ==="
cd $SETUP
OUT_DIR=$IDLE_OUT DURATION=3600 INTERVAL=300 NO_RESTART=1 bash ./idle-run.sh
echo "idle завершён в $(date -u +%H:%M:%S) UTC"

echo "=== [5/8] атаки — без разрыва цепочки, сразу за idle, без ssh между ними ==="
# Переменные экспортируются в ЭТОМ процессе, а не в файл для отдельного
# входа (это и было дефектом №43) — run-all-attacks.sh запускается прямо
# следом, в той же detached-цепочке.
export IDLE_METRICS_START=$IDLE_OUT/metrics-start.txt
cd $SETUP/attacks
bash ./run-all-attacks.sh || echo "run-all-attacks.sh вернул $? — гейт всё равно считаем"
echo "атаки завершены в $(date -u +%H:%M:%S) UTC"

echo "=== [6/8] гейт, один вызов, с критерием 16 (слепое окно) и критерием 6 ==="
export IDLE_STATE_END=$IDLE_OUT/state-end.json
export IDLE_METRICS_END=$IDLE_OUT/metrics-end.txt
bash ./run-gate.sh 2>&1 | tee /root/gate-2.9.3.txt
GATE_RC=${PIPESTATUS[0]}
echo "гейт вернул $GATE_RC"

echo "=== [7/8] сводка idle-части (п.3/п.4 глазами самого idle-run) ==="
cat $IDLE_OUT/SUMMARY.txt 2>/dev/null

echo "=== [8/8] отчёт сверх гейта: п.1-п.5 постановки №2.9.3 ==="
# Считает только по файлам на диске, ни одного сетевого запроса — безопасно
# запускать и повторно, уже после прогона.
IDLE_OUT=$IDLE_OUT bash $SETUP/run-2.9.3-report.sh 2>&1 | tee /root/report-2.9.3.txt

echo "=== ПАЙПЛАЙН №2.9.3 ЗАВЕРШЁН $(date -u +%H:%M:%S) UTC, гейт=$GATE_RC ==="
touch /root/PIPELINE-2.9.3-DONE
