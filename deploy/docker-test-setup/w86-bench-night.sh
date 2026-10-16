#!/bin/bash
# Волна 8.6, заход C: бенч G0 на дампе w86-b ДО ночи, на коде и бинаре ночи (8.6.3б) + тождество индекса G3 на дампе (8.6.4).
# Считается НА СТЕНДЕ в каталоге выкладки (REPO): sha бинаря REPO/build/ebpf-guard пишется в файл результата; эмиттер
# `w86-close-report.sh bench` сверяет его с sha процесса ночи и печатает НЕИЗМЕРИМ при расхождении.
#   w86-bench-night.sh <REPO> <OUT> [DUMP=/root/w86-b-out/events.jsonl]
# Выход: OUT/bench-result.txt (ключ=значение), OUT/bench-raw.txt, OUT/c0-identity.txt
set -u
REPO=${1:?REPO}; OUT=${2:?OUT}; DUMP=${3:-/root/w86-b-out/events.jsonl}
export PATH=$PATH:/usr/local/go/bin
mkdir -p "$OUT"
[ -s "$DUMP" ] || { echo "die: нет дампа $DUMP" > "$OUT/DONE"; exit 1; }
[ -x "$REPO/build/ebpf-guard" ] || { echo "die: нет $REPO/build/ebpf-guard" > "$OUT/DONE"; exit 1; }
cd "$REPO" || exit 1
W86_DUMP=$DUMP go test -run xxx -bench 'BenchmarkG0Dump/s1\+s2\+G1' -benchtime=300000x -count=3 ./internal/correlator/ > "$OUT/bench-raw.txt" 2>&1
ns=$(grep -a 'BenchmarkG0Dump' "$OUT/bench-raw.txt" | awk '{ print $3 }' | sort -n | awk '{ a[NR] = $1 } END { if (NR) print a[int((NR + 1) / 2)] }')
# IDENT_TESTS (волна 8.7) — список тестов тождества на дампе; по умолчанию один G3. Каждый печатает «событий N, алертов M».
IDENT_TESTS=${IDENT_TESTS:-TestDispatch_ShippedRulesetSameAlerts}
W86_DUMP=$DUMP go test -count=1 -run "^($(echo $IDENT_TESTS | tr ' ' '|'))\$" -v ./internal/correlator/ > "$OUT/c0-identity.txt" 2>&1
ev=$(sed -n 's/.*событий \([0-9]*\), алертов.*/\1/p' "$OUT/c0-identity.txt" | head -1)
{
    echo "binary_sha256=$(sha256sum "$REPO/build/ebpf-guard" | cut -d' ' -f1)"
    echo "src_git=$(cat "$REPO/GIT-HEAD" 2>/dev/null || git -C "$REPO" rev-parse --short=12 HEAD)"
    echo "ns_stand=${ns:-}"
    echo "dump_events=${ev:-0}"
    echo "dump_bytes=$(stat -c %s "$DUMP")"
    echo "taken=$(date -u +%FT%TZ)"
} > "$OUT/bench-result.txt"
echo "done $(date -u +%FT%TZ) ns=${ns:-?}" > "$OUT/DONE"
