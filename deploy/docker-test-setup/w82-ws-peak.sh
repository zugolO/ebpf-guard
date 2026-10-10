#!/bin/bash
# w82-ws-peak.sh <samples-ws.tsv> — working set (memory.current − inactive_file) пода: пик.
# Вход: «сек memory.current inactive_file» (10 Гц, строки по 3 поля). kubelet и OOM
# смотрят на working set, а не на memory.current (доводка 8.2, T5); критерий
# 8.2.1 судит memory.current и здесь НЕ меняется. Пустой вход — НЕИЗМЕРИМ, не 0.
set -u
F=${1:?samples-ws.tsv}
awk 'NF == 3 && $3 ~ /^[0-9]+$/ && $2 ~ /^[0-9]+$/ {
        n++; w = $2 - $3; if (w < 0) w = 0
        if (w > m) { m = w; t = $1 }
        if ($2 > c) { c = $2; ct = $1; cw = w } }
    END {
        if (!n) { print "ws_peak_mib=НЕИЗМЕРИМ (нет строк «сек current inactive_file»)"; exit }
        printf "ws_peak_mib=%.1f ws_peak_s=%s current_peak_mib=%.1f current_peak_s=%s ws_at_current_peak_mib=%.1f\n",
            m / 1048576, t, c / 1048576, ct, cw / 1048576 }' "$F" 2>/dev/null || echo "ws_peak_mib=НЕИЗМЕРИМ (нет файла)"
