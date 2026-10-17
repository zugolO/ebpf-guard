#!/bin/bash
# Волна 8.7, заход Е1: смок ВТОРЫМ агентом с метками стадий (server.pprof_stage_labels). Одна роль, один бинарь:
#   idle-окно IDLE_S -> профиль CPU; затем пакет атак с профилями CPU кусками по 30 с (w87-profiles.sh pack-cpu).
#   Рабочий ebpf-guard-test НЕ трогается. Разрез по стадиям печатает w87-e1-table.sh (мак или стенд).
#   w87-e1-stages.sh <SRC> <OUT> [IDLE_S=120]
set -u
SRC=${1:?SRC}; OUT=${2:?OUT}; IDLE=${3:-120}
HERE=$(cd "$(dirname "$0")" && pwd)
source "$HERE/w85-second-agent-lib.sh"
export PATH=$PATH:/usr/local/go/bin
rm -rf "$OUT"; mkdir -p "$OUT"; exec > "$OUT/driver.log" 2>&1
trap 'sa_stop 2> /dev/null; echo "агентов после: $(ps -eo cmd | grep -c "[e]bpf-guard --config")"' EXIT
die() { echo "die: $*" > "$OUT/DONE"; echo "DIE: $*"; exit 1; }
[ "$(ps -eo cmd | grep -c '[e]bpf-guard --config')" -eq 1 ] || die "ожидался ровно один (рабочий) агент до запуска"
echo "[$(date -u +%FT%TZ)] w87-e1-stages head=$(cat $SRC/GIT-HEAD 2> /dev/null) idle=${IDLE}s"
SA_CFG_PATCH="$HERE/w87-e1-patch.py" sa_start "$SRC" /root/w87-e1-run 19261 || die "агент не поднялся"
echo "pid=$SA_PID бинарь $(sha256sum $SRC/build/ebpf-guard | cut -c1-12)"
# входной сторож по РАНТАЙМУ, не по конфигу
flag() { sa_metrics | awk -v f="$1" '$0 ~ "^ebpf_guard_runtime_flag\\{flag=\"" f "\"\\}" { print $NF }'; }
[ "$(flag pprof_stage_labels)" = 1 ] || die "pprof_stage_labels не 1 по рантайму ($(flag pprof_stage_labels))"
[ "$(flag enable_pprof)" = 1 ] || die "enable_pprof не 1 по рантайму"
[ "$(flag pprof_rule_labels)" = 0 ] || die "pprof_rule_labels не 0 по рантайму"
echo "флаги рантайма: stage_labels=1 enable_pprof=1 rule_labels=0"
sleep 60
curl -s --max-time $((IDLE+60)) -H "Authorization: Bearer $SA_TOKEN" "$SA_API/debug/pprof/profile?seconds=$IDLE" > "$OUT/idle.pprof"
echo "idle.pprof $(wc -c < $OUT/idle.pprof) Б"
# --- пакет атак с профилями кусками -------------------------------------------------------------------------
sa_metrics > "$OUT/m0.txt"
mkdir -p "$OUT/pack-cpu"
bash "$HERE/w87-profiles.sh" pack-cpu "127.0.0.1:19261" "$SA_TOKEN" "$OUT/pack-cpu" 30 &
PROF=$!
A="$SRC/deploy/docker-test-setup/attacks"
ls "$A/attack-results" 2> /dev/null | sort > "$OUT/results-before.lst"
( cd "$A" && EBPF_GUARD_API="$SA_API" EBPF_GUARD_TOKEN="$SA_TOKEN" SKIP_INDUCED_DROP=1 bash ./run-all-attacks.sh > "$OUT/attacks.log" 2>&1; echo "rc=$?" > "$OUT/attacks.rc" )
touch "$OUT/pack-cpu/STOP-CPU"; wait $PROF
sleep 20
sa_metrics > "$OUT/m1.txt"
cp "$A/attack-manifest.json" "$OUT/" 2> /dev/null
ls "$A/attack-results" 2> /dev/null | sort | comm -13 "$OUT/results-before.lst" - > "$OUT/results-new.lst"
for f in $(grep -E '^(baseline|final)-alerts-.*\.json$' "$OUT/results-new.lst"); do cp "$A/attack-results/$f" "$OUT/"; done
cp /root/w87-e1-run/agent.log "$OUT/agent.log"
echo "recall по comm: $(ATT=$OUT bash "$HERE/w85-close-report.sh" recall)" | tee "$OUT/recall.txt"
sa_stop
echo "done $(date -u +%FT%TZ)" > "$OUT/DONE"
