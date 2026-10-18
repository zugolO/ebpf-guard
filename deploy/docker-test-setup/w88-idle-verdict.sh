#!/bin/bash
# Метка 8.8.7 (часть «CPU с/с»): вердикт по выходу w86-b-idle-ab.sh (ABBA).
#   w88-idle-verdict.sh <OUT> [MAX_RATIO=1.05]
# Вход — строки «wN base|new cpu … = X с/с …» в OUT/w*/idle.txt. Среднее по ролям; PASS, если new ≤ MAX_RATIO × base.
# Нет окна одной из ролей — НЕИЗМЕРИМ, не PASS.
OUT=${1:?OUT}; MAX=${2:-1.05}
awk -v max="$MAX" '
  FNR == 1 { }
  /^w[0-9]+ (base|new) / { role = $2; for (i = 1; i <= NF; i++) if ($i == "=") { v = $(i+1); break }
                           sum[role] += v; n[role]++ }
  END {
    if (n["base"] < 1 || n["new"] < 1) { printf "8.8.7 idle: НЕИЗМЕРИМ — окон base=%d new=%d\n", n["base"], n["new"]; exit }
    b = sum["base"] / n["base"]; w = sum["new"] / n["new"]
    printf "8.8.7 idle: %s — CPU с/с base %.4f (n=%d), new %.4f (n=%d), отношение %.3f (порог ≤ %s)\n", (w <= max * b ? "PASS" : "FAIL"), b, n["base"], w, n["new"], w / b, max
  }' "$OUT"/w*/idle.txt 2> /dev/null || echo "8.8.7 idle: НЕИЗМЕРИМ — нет $OUT/w*/idle.txt"
