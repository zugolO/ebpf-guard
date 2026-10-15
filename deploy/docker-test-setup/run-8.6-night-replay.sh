#!/bin/bash
# run-8.6-night-replay.sh [АРХИВ_НОЧИ] — офлайн-реплей отчётной части run-8.6-night-pipeline.sh (этапы [6]–[6a]) на архиве
# ночи 8.5 (gate-offline-replay-on-mac). Запускается на маке из корня репозитория, bash 4+ (/opt/homebrew/bin/bash).
#   1) копия архива во временный каталог (архив в репозитории не меняется);
#   2) A2/A1 — настоящий go test (a2.txt: вердикты 8.2.3 и 8.5.8), как в префлайте ночи;
#   3) пайплайн в режиме REPLAY_ART: те же команды эмиттеров и тот же сторож; метки без входов в архиве 8.5
#      (прогоны пода этой ночи, контроли правил/цепочки, бенч, тождество G3) дают НЕИЗМЕРИМ с названным классом —
#      вердиктная строка есть, сторож зелёный;
#   4) вычёркивание КАЖДОЙ метки REQUIRED_LABELS из объединённого отчёта — сторож обязан назвать её (и только её);
#   5) 8.6.Д на настоящем plan.md: строка отчёта есть.
set -u
HERE=$(cd "$(dirname "$0")" && pwd); ROOT=$(cd "$HERE/../.." && pwd)
NIGHT=${1:-$ROOT/server-logs/collect-8.5-night/night-8.5-night}
BASH5=${BASH5:-/opt/homebrew/bin/bash}
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
cp -R "$NIGHT" "$T/art"; rm -f "$T/art"/idle-*.tar.gz
( cd "$ROOT" && go test -count=1 -v -run '^(TestW82_AllocPerEvent|TestW85_A1_AllocPerEventPostF1Mix)' ./internal/correlator/ ) > "$T/art/a2.txt" 2>&1
# база: архив ночи 8.5 в раскладке /root/w86-base
B=$T/w86-base; mkdir -p "$B"
ln -s "$NIGHT/idle" "$B/idle-8.5"; ln -s "$NIGHT/pod-run" "$B/pod-run-8.5"; ln -s "$NIGHT/pod-attack" "$B/pod-attack-8.5"; ln -s "$NIGHT/pod-inv" "$B/pod-inv-8.5"
ln -s "$NIGHT/attacks-results/final-alerts-20261014_090242.json" "$B/host-final-alerts-8.5.json"
ln -s "$NIGHT/attack-manifest-host.json" "$B/host-manifest-8.5.json"
INC=$(ls "$ROOT"/server-logs/collect-8.2-night/night-8.2-night/attacks-results/final-incidents-20261012_070020.json)
out=$(SETUP="$HERE" REPLAY_ART="$T/art" EXPECT_NR=37 W86_BASE="$B" BASE_IDLE_82="$ROOT/server-logs/collect-8.2-night/night-8.2-night/idle" \
      BASE_INC="$INC" NIGHT_PREV="$ROOT/server-logs/collect-8.2-night/night-8.2-night/idle" NIGHT_TAG=8.6-replay PLAN="$ROOT/plan.md" \
      "$BASH5" "$HERE/run-8.6-night-pipeline.sh" 2>&1); rc=$?
echo "$out" | grep -aE "ДОСТИГНУТО|ПРОВАЛЕН|НЕИЗМЕРИМ|ИЗМЕРЕНО|СТОРОЖ|сторож|РЕПЛЕЙ" | cut -c1-230
echo "-- пайплайн (реплей) rc=$rc"
[ -s "$T/art/all-reports.txt" ] || { echo "FAIL: нет all-reports.txt — отчётная часть не отработала"; echo "$out" | tail -15; exit 1; }
awk '/# GUARD-BEGIN/ { p = 1; next } /# GUARD-END/ { exit } p' "$HERE/run-8.6-night-pipeline.sh" > "$T/guard.sh"
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
# обязательные метки волны 8.6 стоят в таблице сторожа (цикл выше идёт по самой таблице и вычеркнутую из неё не заметит)
for lbl in 8.6.1 8.6.2 8.6.3а 8.6.3б 8.6.4 8.6.5 8.6.6 8.1.1 8.2.2 8.5.5 8.6.Д; do
    case " ${REQUIRED_LABELS[*]} " in *" $lbl "*) ;; *) echo "FAIL метка $lbl не стоит в REQUIRED_LABELS"; bad=$((bad + 1)) ;; esac
done
# убранные метки 8.5 не должны быть в таблице (названы в шапке пайплайна с причинами)
for lbl in 8.5.3 8.5.3a 8.5.4 8.5.6 8.5.7; do
    case " ${REQUIRED_LABELS[*]} " in *" $lbl "*) echo "FAIL метка $lbl должна быть убрана из REQUIRED_LABELS"; bad=$((bad + 1)) ;; esac
done
echo "-- расхождений $bad"
[ "$bad" = 0 ] && [ "$rc" = 0 ]
