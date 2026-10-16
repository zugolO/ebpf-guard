#!/bin/bash
# run-8.7-night-replay.sh [АРХИВ_НОЧИ] — офлайн-реплей отчётной части run-8.7-night-pipeline.sh (этапы [6]–[6a]) на архиве
# ночи 8.6 (gate-offline-replay-on-mac). Запускается на маке из корня репозитория, bash 4+ (/opt/homebrew/bin/bash).
#   1) копия архива во временный каталог (архив в репозитории не меняется);
#   2) A2/A1 — настоящий go test (a2.txt), как в префлайте ночи;
#   3) пайплайн в режиме REPLAY_ART: те же команды эмиттеров и тот же сторож; метки, чьих входов в архиве 8.6 нет
#      (профили под пакетом, block/mutex, срезы 30-й минуты у каждого прогона, тождество новых индексов) дают НЕИЗМЕРИМ
#      или ПРОВАЛЕН с названным классом — вердиктная строка есть, сторож зелёный;
#   4) вычёркивание КАЖДОЙ метки REQUIRED_LABELS из объединённого отчёта — сторож обязан назвать её (и только её);
#   5) 8.7.Д на настоящем plan.md: строка отчёта есть.
set -u
HERE=$(cd "$(dirname "$0")" && pwd); ROOT=$(cd "$HERE/../.." && pwd)
NIGHT=${1:-$ROOT/server-logs/collect-8.6-night/night-8.6-night}
N85=$ROOT/server-logs/collect-8.5-night/night-8.5-night
BASH5=${BASH5:-/opt/homebrew/bin/bash}
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
mkdir -p "$T/art"
# копия без тяжёлого (профили pprof idle нужны 8.6.3а и 8.7.3 — оставляем, остальное архивное — нет)
rsync -a --exclude 'idle-*.tar.gz' --exclude 'attacks-results/final-*-2026[01][0-9]*' --exclude 'pod-image' "$NIGHT/" "$T/art/" 2> /dev/null
# пакет этой ночи в архиве 8.6 — последний final-* по имени; вернуть именно его и его инциденты
for f in $(ls "$NIGHT"/attacks-results/final-alerts-*.json | sort | tail -1) $(ls "$NIGHT"/attacks-results/final-incidents-*.json | sort | tail -1); do
    mkdir -p "$T/art/attacks-results"; cp "$f" "$T/art/attacks-results/"
done
( cd "$ROOT" && go test -count=1 -v -run '^(TestW82_AllocPerEvent|TestW85_A1_AllocPerEventPostF1Mix)' ./internal/correlator/ ) > "$T/art/a2.txt" 2>&1
# база ночи 8.5 (в раскладке /root/w86-base) и ночи 8.6 (в раскладке /root/w87-data86)
B5=$T/w86-base; mkdir -p "$B5"
ln -s "$N85/idle" "$B5/idle-8.5"; ln -s "$N85/pod-run" "$B5/pod-run-8.5"; ln -s "$N85/pod-attack" "$B5/pod-attack-8.5"; ln -s "$N85/pod-inv" "$B5/pod-inv-8.5"
ln -s "$N85/attacks-results/final-alerts-20261014_090242.json" "$B5/host-final-alerts-8.5.json"
ln -s "$N85/attack-manifest-host.json" "$B5/host-manifest-8.5.json"
B6=$T/w87-data86; mkdir -p "$B6/pod-runs"
ln -s "$NIGHT/idle" "$B6/idle"; ln -s "$NIGHT/pod-run" "$B6/pod-run"; ln -s "$NIGHT/pod-attack" "$B6/pod-attack"; ln -s "$NIGHT/pod-inv" "$B6/pod-inv"
for i in 2 3 4 5; do ln -s "$NIGHT/pod-runs/run-$i" "$B6/pod-runs/run-$i"; done
ln -s "$(ls "$NIGHT"/attacks-results/final-alerts-*.json | sort | tail -1)" "$B6/host-final-alerts-8.6.json"
ln -s "$NIGHT/attack-manifest-host.json" "$B6/host-manifest-8.6.json"
INC=$ROOT/server-logs/collect-8.2-night/night-8.2-night/attacks-results/final-incidents-20261012_070020.json
# пайплайн в режиме реплея: START_FILE ночи 8.6 → NIGHT_DATE 20261015, BASE_DATE по умолчанию 20261015 (реплей судит форму, не состав)
out=$(SETUP="$HERE" REPLAY_ART="$T/art" REPLAY_START_FILE=agent-start-8.6-night.txt EXPECT_NR=36 W86_BASE="$B5" W87_BASE86="$B6" \
      BASE_IDLE_82="$ROOT/server-logs/collect-8.2-night/night-8.2-night/idle" BASE_INC="$INC" NIGHT_PREV="$B5/idle-8.5" \
      NIGHT_TAG=8.7-replay PLAN="$ROOT/plan.md" "$BASH5" "$HERE/run-8.7-night-pipeline.sh" 2>&1); rc=$?
echo "$out" | grep -aE "ДОСТИГНУТО|ПРОВАЛЕН|НЕИЗМЕРИМ|ИЗМЕРЕНО|СПРАВОЧНО|СТОРОЖ|сторож|РЕПЛЕЙ" | cut -c1-230
echo "-- пайплайн (реплей) rc=$rc"
[ -s "$T/art/all-reports.txt" ] || { echo "FAIL: нет all-reports.txt — отчётная часть не отработала"; echo "$out" | tail -15; exit 1; }
awk '/# GUARD-BEGIN/ { p = 1; next } /# GUARD-END/ { exit } p' "$HERE/run-8.7-night-pipeline.sh" > "$T/guard.sh"
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
# таблица сторожа содержит все метки волны 8.7 (цикл выше идёт по самой таблице и вычеркнутую из неё не заметит)
n=0; for lbl in 8.7.1 8.7.2 8.7.3 8.7.4 8.7.5 8.7.6 8.7.Д 8.6.1 8.6.3а 8.6.3б 8.6.6 8.1.1 8.2.2 8.5.5 3.P1-19 3.MEM 3.ATTACK 3.STORE 8.1.2 8.1.3 8.1.4 8.2.1 8.2.3 8.2.4 8.2.5 8.4.x 8.5.1 8.5.2 8.5.8 8.1.1r; do
    n=$((n + 1)); case " ${REQUIRED_LABELS[*]} " in *" $lbl "*) ;; *) echo "FAIL метка $lbl не стоит в REQUIRED_LABELS"; bad=$((bad + 1)) ;; esac
done
[ "${#REQUIRED_LABELS[@]}" = 30 ] && [ "$n" = 30 ] || { echo "FAIL в таблице ${#REQUIRED_LABELS[@]} меток, ожидалось 30"; bad=$((bad + 1)); }
# убранные метки не должны быть в таблице
for lbl in 8.6.2 8.6.4 8.6.5 8.6.Д 8.5.3 8.5.3a 8.5.4 8.5.6 8.5.7; do
    case " ${REQUIRED_LABELS[*]} " in *" $lbl "*) echo "FAIL метка $lbl должна быть убрана из REQUIRED_LABELS"; bad=$((bad + 1)) ;; esac
done
echo "-- расхождений $bad"
[ "$bad" = 0 ] && [ "$rc" = 0 ]
