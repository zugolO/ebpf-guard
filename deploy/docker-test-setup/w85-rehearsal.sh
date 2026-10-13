#!/bin/bash
# w85-rehearsal.sh — репетиция ночи закрытия 8.5 на коротких длительностях (запускается НА СТЕНДЕ, отцеплено; скрипт — файлом).
# Те же стадии [1]–[7] пайплайна, что в ночи, но: idle 600 с, пара A/B 2×300 с, под: idle 200 с + удержание 120 с, атаки хоста
# пропущены (SKIP_HOST_ATTACKS=1: они прогонялись отдельно, w85-e1-pack). Профиль ДО F1 сохраняется до репетиции и ВОЗВРАЩАЕТСЯ
# после: репетиция включает F1 переключателем и учится на нём, а ночь обязана стартовать на профиле до F1 (решение 9).
# Хранение: архив репетиции — /root/collect-8.5-rehearsal.tgz (tag 8.5-rehearsal); маркер — /root/PIPELINE-8_5_REHEARSAL-DONE.
set -u
SETUP=${SETUP:-/opt/ebpf-guard/deploy/docker-test-setup}; BASE=${W85_BASE:-/root/w85-base}
STATE=/var/lib/ebpf-guard/profiler-state.json; KEEP=/root/w85-base/profiler-state-before-F1.json
cp -a "$STATE" "$KEEP" && sha256sum "$KEEP" > "$KEEP.sha256" || { echo "die: профиль не сохранён"; exit 1; }
PRIOR=""; for r in $BASE/d1-prior/run-*; do PRIOR="$PRIOR $r/pod-run:$r/pod-attack"; done
cd "$SETUP" && EXPECT_NR=36 NIGHT_TAG=8.5-rehearsal NIGHT_PREV=$BASE/idle-8.2 BASE_IDLE=$BASE/idle-8.2 BASE_ATT=$BASE/pod-attack-8.2 \
    BASE_INC=$BASE/final-incidents-20261012_070020.json D1_PRIOR_RUNS="${PRIOR# }" AB_SECS=300 IDLE_SECS=600 POD_IDLE_SECS=200 POD_HOLD_SECS=120 \
    SKIP_HOST_ATTACKS=1 bash ./run-8.5-night-pipeline.sh
rc=$?
# возврат профиля до F1: агент остановлен на время копирования, затем снова запущен (хост — один, active)
systemctl stop ebpf-guard-test.service; sleep 3
cp -a "$KEEP" "$STATE"; sha256sum "$STATE" | cut -d' ' -f1 > /root/w85-rehearsal-state-after.sha
systemctl start ebpf-guard-test.service; sleep 8
echo "rehearsal rc=$rc; профиль возвращён: $(cut -c1-16 /root/w85-rehearsal-state-after.sha) (копия $(cut -c1-16 "$KEEP.sha256")); агентов $(ps -eo cmd | grep -c '[e]bpf-guard --config'), $(systemctl is-active ebpf-guard-test.service)" > /root/w85-rehearsal-final.txt
