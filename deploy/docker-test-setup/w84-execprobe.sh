#!/bin/bash
# w84-execprobe.sh <OUT> — ПЕРВАЯ проверка 8.4.2: что поле filename трейспойнта sched_process_exec (= bprm->filename)
# у шебанг-скрипта — путь САМОГО скрипта, а exec -a его не трогает. bpftrace 0.14, один зонд без предиката.
set -u
OUT=${1:?OUT}; HERE=$(cd "$(dirname "$0")" && pwd); P=/var/tmp/w84p
rm -rf "$OUT" "$P"; mkdir -p "$OUT" "$P"; trap 'rm -rf "$P"' EXIT
printf '#!/bin/sh\nexit 0\n' > "$P/s.sh"; chmod 0755 "$P/s.sh"; ln -s "$P/s.sh" "$P/link.sh"
printf '#!/usr/bin/perl\nexit 0;\n' > "$P/p.pl"; chmod 0755 "$P/p.pl"
bpftrace -e 'tracepoint:sched:sched_process_exec { printf("EXEC comm=%s file=%s\n", comm, str(args->filename)); }' > "$OUT/bt.txt" 2>&1 &
BT=$!; sleep 3
"$P/s.sh"; (cd "$P" && ./s.sh); bash -c "exec -a dpkg $P/s.sh"; "$P/link.sh"; "$P/p.pl"; sh "$P/s.sh"
sleep 2; kill $BT 2>/dev/null; wait $BT 2>/dev/null
bash "$HERE/w84-execprobe-judge.sh" "$OUT/bt.txt" | tee "$OUT/verdicts.txt"
