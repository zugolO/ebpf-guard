#!/bin/bash
# w87-rehearsal.sh — РЕПЕТИЦИЯ ночи закрытия 8.7 на коротких длительностях (запускается НА СТЕНДЕ, отцеплено; скрипт — файлом).
# Те же стадии [1]–[7] пайплайна, что в ночи: idle 1500 с (6 срезов, CPU-профиль на каждом → ≥ 6 профилей для 8.6.3а и 8.7.3), окно
# block/mutex 120 с, атаки хоста и гейт ВКЛЮЧЕНЫ (профиль CPU под пакетом, 8.7.4, 8.5.5, контроли правил/цепочки), под: 2 прогона
# (idle 200 с, удержание 120 с). Метки, которым нужны ≥ 5 прогонов или срез 30-й минуты, дают НЕИЗМЕРИМ с названным классом —
# вердиктная строка есть у ВСЕХ меток (сторож полноты). Архив — /root/collect-8.7-rehearsal.tgz; маркер — /root/PIPELINE-8_7_REHEARSAL-DONE.
set -u
SETUP=${SETUP:-/opt/ebpf-guard/deploy/docker-test-setup}; BASE=${W85_BASE:-/root/w85-base}; W86=${W86_BASE:-/root/w86-base}; W87D=${W87_BASE86:-/root/w87-data86}
cd "$SETUP" && EXPECT_NR=36 NIGHT_TAG=8.7-rehearsal NIGHT_PREV=$W86/idle-8.5 BASE_IDLE_82=$BASE/idle-8.2 W86_BASE=$W86 W87_BASE86=$W87D \
    BASE_INC=$BASE/final-incidents-20261012_070020.json IDLE_SECS=${IDLE_SECS:-1500} CPU_PROFILE_EVERY=1 POD_RUNS_N=${POD_RUNS_N:-2} \
    POD_IDLE_SECS=${POD_IDLE_SECS:-200} POD_SHORT_IDLE_SECS=${POD_SHORT_IDLE_SECS:-200} POD_HOLD_SECS=${POD_HOLD_SECS:-120} \
    BLOCK_WINDOW_SECS=${BLOCK_WINDOW_SECS:-120} bash ./run-8.7-night-pipeline.sh
echo "rehearsal rc=$?; агентов $(ps -eo cmd | grep -c '[e]bpf-guard --config'), $(systemctl is-active ebpf-guard-test.service)" > /root/w87-rehearsal-final.txt
