#!/bin/bash
# Фикстуры w82-ws-peak.sh: пик working set ≠ пик memory.current; пустой вход — НЕИЗМЕРИМ.
set -u
HERE=$(cd "$(dirname "$0")" && pwd); E="$HERE/w82-ws-peak.sh"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fail=0
need() { grep -qF -- "$3" <<< "$2" && echo "ok   $1" || { echo "FAIL $1: нет «$3» в «$2»"; fail=1; }; }
M=1048576
# t=1: current 150, inactive 90 → ws 60; t=2: current 120, inactive 10 → ws 110 (пик ws при меньшем current)
printf '1.0 %d %d\n2.0 %d %d\n' $((150*M)) $((90*M)) $((120*M)) $((10*M)) > "$T/a.tsv"
need "пик ws и пик current — разные моменты" "$(bash "$E" "$T/a.tsv")" "ws_peak_mib=110.0 ws_peak_s=2.0 current_peak_mib=150.0 current_peak_s=1.0 ws_at_current_peak_mib=60.0"
: > "$T/e.tsv"
need "пустой файл ≠ 0" "$(bash "$E" "$T/e.tsv")" "ws_peak_mib=НЕИЗМЕРИМ"
printf '1.0 %d\n' $((150*M)) > "$T/two.tsv"
need "строки без inactive_file не считаются" "$(bash "$E" "$T/two.tsv")" "ws_peak_mib=НЕИЗМЕРИМ"
need "нет файла ≠ 0" "$(bash "$E" "$T/nope.tsv")" "ws_peak_mib=НЕИЗМЕРИМ"
exit $fail
