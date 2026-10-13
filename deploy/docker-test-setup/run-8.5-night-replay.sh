#!/bin/bash
# run-8.5-night-replay.sh [АРХИВ_НОЧИ] — офлайн-реплей отчётной части run-8.5-night-pipeline.sh (этапы [6]–[6a]) на архиве
# ночи 8.2 (gate-offline-replay-on-mac). Запускается на маке из корня репозитория, bash 4+ (/opt/homebrew/bin/bash).
#   1) копия архива во временный каталог (архив в репозитории не меняется);
#   2) A2/A1 — настоящий go test (a2.txt: вердикты 8.2.3 и 8.5.8), как в префлайте ночи;
#   3) пайплайн в режиме REPLAY_ART: те же команды эмиттеров и тот же сторож; метки без входов в архиве 8.2
#      (ab/, w84/ и т.п.) дают НЕИЗМЕРИМ с названным классом — вердиктная строка есть, сторож зелёный;
#   4) вычёркивание КАЖДОЙ метки REQUIRED_LABELS из объединённого отчёта — сторож обязан назвать её (и только её).
set -u
HERE=$(cd "$(dirname "$0")" && pwd); ROOT=$(cd "$HERE/../.." && pwd)
NIGHT=${1:-$ROOT/server-logs/collect-8.2-night/night-8.2-night}
BASH5=${BASH5:-/opt/homebrew/bin/bash}
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
cp -R "$NIGHT" "$T/art"; rm -f "$T/art"/idle-*.tar.gz
( cd "$ROOT" && go test -count=1 -v -run '^(TestW82_AllocPerEvent|TestW85_A1_AllocPerEventPostF1Mix)' ./internal/correlator/ ) > "$T/art/a2.txt" 2>&1
INC=$(ls "$NIGHT"/attacks-results/final-incidents-20261012_070020.json)
D1=""; for i in 1 2 3; do
    r=$ROOT/server-logs/collect-8.5-d1/w85-podonly/run-$i
    [ -d "$r/pod-run" ] && [ -d "$r/pod-attack" ] && D1="$D1 $r/pod-run:$r/pod-attack"
done
out=$(SETUP="$HERE" REPLAY_ART="$T/art" EXPECT_NR=37 BASE_IDLE="$NIGHT/idle" BASE_ATT="$NIGHT/pod-attack" BASE_INC="$INC" \
      D1_PRIOR_RUNS="${D1# }" AB_SECS=3600 NIGHT_TAG=8.5-replay "$BASH5" "$HERE/run-8.5-night-pipeline.sh" 2>&1); rc=$?
echo "$out" | grep -aE "ДОСТИГНУТО|ПРОВАЛЕН|НЕИЗМЕРИМ|ИЗМЕРЕНО|СТОРОЖ|сторож|РЕПЛЕЙ" | cut -c1-230
echo "-- пайплайн (реплей) rc=$rc"
[ -s "$T/art/all-reports.txt" ] || { echo "FAIL: нет all-reports.txt — отчётная часть не отработала"; echo "$out" | tail -15; exit 1; }
# сторож: вычёркивание каждой метки
awk '/# GUARD-BEGIN/ { p = 1; next } /# GUARD-END/ { exit } p' "$HERE/run-8.5-night-pipeline.sh" > "$T/guard.sh"
source "$T/guard.sh"
bad=0
base_missing=$(label_completeness "$T/art/all-reports.txt" "")
[ -z "$base_missing" ] && echo "OK   на реплее все ${#REQUIRED_LABELS[@]} меток вынесли вердикт" || { echo "FAIL реплей: без вердикта:$base_missing"; bad=$((bad + 1)); }
for lbl in "${REQUIRED_LABELS[@]}"; do
    pat="${lbl//./\\.}"
    grep -avE "(ДОСТИГНУТО|ПРОВАЛЕН|НЕИЗМЕРИМ|ИЗМЕРЕНО): *${pat}( |$)|${pat} (ДОСТИГНУТО|ПРОВАЛЕН|НЕИЗМЕРИМ|ИЗМЕРЕНО)" "$T/art/all-reports.txt" > "$T/cut.txt"
    miss=$(label_completeness "$T/cut.txt" "")
    [ "$miss" = " $lbl" ] && echo "OK   метка $lbl вычеркнута — сторож назвал её одну" || { echo "FAIL метка $lbl вычеркнута — сторож назвал «${miss}»"; bad=$((bad + 1)); }
done
echo "-- расхождений $bad"
[ "$bad" = 0 ] && [ "$rc" = 0 ]
