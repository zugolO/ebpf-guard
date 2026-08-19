#!/usr/bin/env bash
# Замер №2.9.2: P0-3 -> очистка -> idle-час -> экспорты -> атаки -> гейт.
# Правит 5.9.2f (находка №43): run-2.9.1-pipeline.sh обрывался после
# idle-части и писал /root/idle-2.9.1-exports.sh, который надо было не
# забыть подцепить руками перед отдельным ssh-запуском атак — этот
# отдельный вход и есть sshd-событие оператора, попавшее внутрь измеряемого
# слепого окна (критерий 5.9.2f), а первый вызов run-gate.sh не увидел
# IDLE_METRICS_START и напечатал SKIP по критерию 6; правильный результат
# дал только повторный вызов. Здесь вся цепочка — один detached-процесс:
# между последним срезом idle и baseline-атак нет ни одного ssh-входа, и
# гейт запускается один раз, уже с нужными переменными в своём окружении.
exec > /root/run-2.9.2-pipeline.log 2>&1
set -x
SETUP=/opt/ebpf-guard/deploy/docker-test-setup
IDLE_OUT=$SETUP/idle-results/idle-2.9.2
P0_OUT=$SETUP/idle-results/p0-3-2.9.2

echo "=== [1/6] риск №3: отдельный короткий прогон P0-3 ДО замера ==="
# NO_RESTART=1 в основном окне (5.9.1c) отменяет проверку рестарта/5.6d,
# которая на №2.4 поймала настоящий дефект (находка №20). Гоняем её здесь
# отдельно и коротко; её рестарт остаётся далеко за пределами журнального
# окна idle-часа.
cd $SETUP
OUT_DIR=$P0_OUT DURATION=120 INTERVAL=60 NO_RESTART=0 bash ./idle-run.sh
echo "P0-3 прогон завершён в $(date -u +%H:%M:%S) UTC"
grep -h "before:\|after:\|P0-3" $P0_OUT/idle-run.log

echo "=== [2/6] очистка стора + рестарт агента ==="
systemctl stop ebpf-guard-test.service
rm -f /var/lib/ebpf-guard/test-events.db /var/lib/ebpf-guard/test-events.db-shm /var/lib/ebpf-guard/test-events.db-wal
echo 0 > /var/lib/ebpf-guard/observer-root-pid
systemctl start ebpf-guard-test.service
echo "рестарт в $(date -u +%H:%M:%S) UTC"

echo "=== [3/6] пауза 660с: deploy-рестарт должен выйти за окно журнала idle-run ==="
sleep 660

echo "=== [4/6] idle-час, NO_RESTART=1 (5.9.1c) ==="
cd $SETUP
OUT_DIR=$IDLE_OUT DURATION=3600 INTERVAL=300 NO_RESTART=1 bash ./idle-run.sh
echo "idle завершён в $(date -u +%H:%M:%S) UTC"

echo "=== [5/6] атаки — без разрыва цепочки, сразу за idle, без ssh между ними ==="
# Переменные экспортируются в ЭТОМ процессе, а не в файл для отдельного
# входа (это и было дефектом №43) — run-all-attacks.sh запускается прямо
# следом, в той же detached-цепочке.
export IDLE_METRICS_START=$IDLE_OUT/metrics-start.txt
cd $SETUP/attacks
bash ./run-all-attacks.sh || echo "run-all-attacks.sh вернул $? — гейт всё равно считаем"
echo "атаки завершены в $(date -u +%H:%M:%S) UTC"

echo "=== [6/6] гейт, один вызов, с критерием 16 (слепое окно) и критерием 6 ==="
export IDLE_STATE_END=$IDLE_OUT/state-end.json
export IDLE_METRICS_END=$IDLE_OUT/metrics-end.txt
bash ./run-gate.sh 2>&1 | tee /root/gate-2.9.2.txt
echo "=== ПАЙПЛАЙН №2.9.2 ЗАВЕРШЁН $(date -u +%H:%M:%S) UTC ==="
touch /root/PIPELINE-2.9.2-DONE
