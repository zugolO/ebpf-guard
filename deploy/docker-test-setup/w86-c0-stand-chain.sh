#!/bin/bash
# Волна 8.6, заход C, шаг C0: цепочка на стенде вторым агентом, без рабочего ebpf-guard-test.
#   (1) бенч «до» на дампе (конец захода B), (2) тождество и CPU пакета атак: база (B) против нового (C0) — w86-b-pack.sh,
#   (3) пара ABBA idle (окна по IDLE_S с подряд) — w86-b-idle-ab.sh.
#   w86-c0-stand-chain.sh <SRC_BASE> <SRC_NEW> <OUT> [IDLE_S=240]
set -u
BASE=${1:?SRC_BASE}; NEW=${2:?SRC_NEW}; OUT=${3:?OUT}; IDLE=${4:-240}
export PATH=$PATH:/usr/local/go/bin
mkdir -p "$OUT"; rm -f "$OUT/CHAIN-DONE"
D=/root/w86-b-out/events.jsonl
{ echo "BEFORE ($(cat $BASE/GIT-HEAD)) на дампе"
  ( cd $BASE && W86_DUMP=$D go test -run xxx -bench 'BenchmarkG0Dump' -benchtime=300000x -count=3 ./internal/correlator/ 2>&1 | grep -E "Benchmark|FAIL" ) ; } > "$OUT/bench-before.txt" 2>&1
H=$NEW/deploy/docker-test-setup
bash $H/w86-b-pack.sh "$BASE" "$NEW" "$OUT/pack" 300 > "$OUT/pack.launch.log" 2>&1
bash $H/w86-b-idle-ab.sh "$BASE" "$NEW" "$OUT/idle-ab" "$IDLE" "base new new base" > "$OUT/idle-ab.launch.log" 2>&1
echo "done $(date -u +%FT%TZ)" > "$OUT/CHAIN-DONE"
