#!/bin/bash
# w9-rehearsal.sh — РЕПЕТИЦИЯ ночи закрытия 9 на коротких длительностях (запускается НА СТЕНДЕ, отцеплено; скрипт — файлом).
# Те же стадии пайплайна, что в ночи: пара 8.8.7 (4 × 60 с), idle 900 с (CPU-профиль на каждом срезе), окно block/mutex 60 с,
# атаки хоста и гейт ВКЛЮЧЕНЫ, лестница В6 со всеми ролями (ступени 30 с), под: 1 прогон (idle 300 с, удержание 60 с). Метки,
# которым нужны ≥ 5 прогонов, срез 30-й минуты или час прогрева, дают НЕИЗМЕРИМ с названным классом — вердиктная строка есть у
# ВСЕХ меток (сторож полноты). Архив — /root/collect-9-rehearsal.tgz; маркер — /root/PIPELINE-9_REHEARSAL-DONE.
set -u
SETUP=${SETUP:-/opt/ebpf-guard/deploy/docker-test-setup}; BASE=${W85_BASE:-/root/w85-base}; W86=${W86_BASE:-/root/w86-base}; W87D=${W87_BASE86:-/root/w87-data86}
cd "$SETUP" && EXPECT_NR=${EXPECT_NR:-36} NIGHT_TAG=9-rehearsal NIGHT_PREV=$W87D/idle BASE_IDLE_82=$BASE/idle-8.2 W86_BASE=$W86 W87_BASE86=$W87D \
    W9_BASE87=${W9_BASE87:-/var/lib/night-8.7-night} AB_BASE_SRC=${AB_BASE_SRC:-/root/w9b-src} AB_IDLE_S=${AB_IDLE_S:-60} \
    BASE_INC=$BASE/final-incidents-20261012_070020.json IDLE_SECS=${IDLE_SECS:-900} CPU_PROFILE_EVERY=1 POD_RUNS_N=${POD_RUNS_N:-1} \
    POD_IDLE_SECS=${POD_IDLE_SECS:-300} POD_SHORT_IDLE_SECS=${POD_SHORT_IDLE_SECS:-300} POD_HOLD_SECS=${POD_HOLD_SECS:-60} \
    BLOCK_WINDOW_SECS=${BLOCK_WINDOW_SECS:-60} STEP_S=${STEP_S:-30} GAP_S=${GAP_S:-10} WARM_S=${WARM_S:-30} \
    LADDER_ROLES=${LADDER_ROLES:-"hostatt0 hostatt host podd"} bash ./run-9-night-pipeline.sh
echo "rehearsal rc=$?; агентов $(ps -eo cmd | grep -c '[e]bpf-guard --config'), $(systemctl is-active ebpf-guard-test.service)" > /root/w9-rehearsal-final.txt
