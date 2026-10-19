#!/bin/bash
# Фикстуры эмиттера w87-close-report.sh (ночь 8.7) и мутации. --mutate: каждая мутация ОБЯЗАНА покраснить фикстуры.
# Нужны: bash 4+, jq, go (go tool pprof), python3.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
EMIT=${EMITTER:-$HERE/w87-close-report.sh}
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
source "$HERE/w85-fixture-lib.sh"   # mk (каталог RUN/ATT пода), T
fails=0
ok()  { echo "ok   $1"; }
bad() { echo "FAIL $1"; fails=$((fails + 1)); }
em() { SETUP="$HERE" bash "$EMIT" "$@" 2>&1; }
want() { # <имя> <шаблон> <вывод>
    if echo "$3" | grep -aqE "$2"; then ok "$1"; else bad "$1 — нет «$2»"; echo "$3" | sed 's/^/    | /' | head -16; fi
}

# ── idle с process_cpu_seconds_total ──────────────────────────────────────────
mkcpu() { # <имя> <c0> <c1> [snaps=25] [s1=1000]
    local n=$1 c0=$2 c1=$3 snaps=${4:-25} s1=${5:-1000} i
    local D=$T/$n/idle; mkdir -p "$D/snapshots"
    for i in $(seq 0 $((snaps - 1))); do
        { echo "process_cpu_seconds_total $(awk -v a="$c0" -v b="$c1" -v i="$i" -v n="$snaps" 'BEGIN { printf "%.3f", a + (b - a) * i / (n - 1) }')"
          echo "process_start_time_seconds $([ "$i" -eq $((snaps - 1)) ] && echo "$s1" || echo 1000)"; } > "$D/snapshots/$(printf 'metrics-%04d.txt' "$i")"
    done
    echo "$D"
}
# база ночи 8.6: 0,03058 с/с на 43200 с (145 снимков по 300 с)
BASE=$(mkcpu base 3 1324.26 145)
w() { want "$1" "$2" "$3"; }
# ── 8.7.2 ──────────────────────────────────────────────────────────────────────
G=$(mkcpu g72 3 $((3 + 43200 * 24 / 1000)) 145)           # 0,024 с/с = 78% базы
w 8.7.2-good '^ДОСТИГНУТО: 8\.7\.2 .*78% базы' "$(IDLE=$G BASE_IDLE=$BASE em cpu-idle)"
w 8.7.2-edge-over '^ПРОВАЛЕН: 8\.7\.2 .*idle 0\.0[0-9]+ с/с = 8[1-9]% базы' "$(IDLE=$(mkcpu o72 3 $((3 + 43200 * 26 / 1000)) 145) BASE_IDLE=$BASE em cpu-idle)"   # 0,026 = 85%
w 8.7.2-equal '^ПРОВАЛЕН: 8\.7\.2 ' "$(IDLE=$BASE BASE_IDLE=$BASE em cpu-idle)"
w 8.7.2-restart '^НЕИЗМЕРИМ: 8\.7\.2 .*рестарт агента внутри окна' "$(IDLE=$(mkcpu rs 3 800 145 2000) BASE_IDLE=$BASE em cpu-idle)"
w 8.7.2-no-series '^НЕИЗМЕРИМ: 8\.7\.2 .*снимков 0' "$(IDLE=$T/нет BASE_IDLE=$BASE em cpu-idle)"
w 8.7.2-wrong-base '^НЕИЗМЕРИМ: 8\.7\.2 .*база из архива .* не сходится с объявленной 0\.03058' "$(IDLE=$G BASE_IDLE=$(mkcpu wb 3 1000 145) em cpu-idle)"

# ── 8.6.1 (сторож «не хуже ночи 8.6»): idle ≤ 0,6 × ночь 8.5 (0,0529) ─────────────────────
BASE85=$(mkcpu base85 3 1526.52 97)                          # 0,0529 с/с на 28800 с
w 8.6.1-good '^ДОСТИГНУТО: 8\.6\.1 .*57% базы' "$(IDLE=$(mkcpu g61 3 $((3 + 28800 * 3 / 100)) 97) BASE_IDLE=$BASE85 em cpu-idle86)"
w 8.6.1-over '^ПРОВАЛЕН: 8\.6\.1 .*6[1-9]% базы' "$(IDLE=$(mkcpu o61 3 $((3 + 28800 * 33 / 1000)) 97) BASE_IDLE=$BASE85 em cpu-idle86)"
w 8.6.1-wrong-base '^НЕИЗМЕРИМ: 8\.6\.1 .*не сходится с объявленной 0\.0529 .* — архив не ночь 8\.5' "$(IDLE=$G BASE_IDLE=$BASE em cpu-idle86)"   # база ночи 8.6 вместо 8.5 не принимается

# ── 8.7.1: CPU на событие под пакетом + разложение по типу события ───────────────
mkatt() { # <имя> <cpu_с> <событий> [t=600]
    local n=$1 cpu=$2 ev=$3 t=${4:-600}; local A=$T/$n/att; mkdir -p "$A"
    printf 'process_cpu_seconds_total 100\nprocess_start_time_seconds 5\nebpf_guard_events_total{type="file"} 1000\n' > "$A/m-pre.txt"
    printf 'process_cpu_seconds_total %s\nprocess_start_time_seconds 5\nebpf_guard_events_total{type="file"} %s\n' "$(awk -v c="$cpu" 'BEGIN { print 100 + c }')" "$((1000 + ev))" > "$A/m-att1.txt"
    echo "$t" > "$A/t-att1"; echo "$T/$n/run:$A"
}
BASEATT=$(mkatt batt 150 1093294); BATT=${BASEATT#*:}      # 137,2 мкс на событие (ночь 8.5)
runs() { local r="" i; for i in "$@"; do r="$r $(mkatt "p$RANDOM$i" "$i" 1000000)"; done; echo "${r# }"; }
w 8.7.1-good '^ДОСТИГНУТО: 8\.7\.1 .*медиана 80' "$(POD_RUNS="$(runs 78 79 80 81 82)" BASE_ATT=$BATT em cpu-event)"          # 78..82 мкс ≤ 0,6 × 137,2 = 82,3
w 8.7.1-over '^ПРОВАЛЕН: 8\.7\.1 .*медиана 87' "$(POD_RUNS="$(runs 86 87 87 88 89)" BASE_ATT=$BATT em cpu-event)"             # ночь 8.6 была 87,4 — красная и здесь
w 8.7.1-threshold-not-softened '^ПРОВАЛЕН: 8\.7\.1 .*> 82\.3' "$(POD_RUNS="$(runs 83 83 83 83 83)" BASE_ATT=$BATT em cpu-event)"
w 8.7.1-four-runs '^НЕИЗМЕРИМ: 8\.7\.1 .*прогонов пода с измеренным CPU на событие 4 < 5' "$(POD_RUNS="$(runs 78 79 80 81)" BASE_ATT=$BATT em cpu-event)"
w 8.7.1-median-not-mean '^ДОСТИГНУТО: 8\.7\.1 ' "$(POD_RUNS="$(runs 60 60 60 60 140)" BASE_ATT=$BATT em cpu-event)"                  # выброс не краснит: судит медиана
w 8.7.1-no-events-series '^НЕИЗМЕРИМ: 8\.7\.1 .*нет серии ebpf_guard_events_total' "$(m=$(mkatt ne 80 1000); a=${m#*:}; grep -v events_total "$a/m-att1.txt" > "$a/x"; mv "$a/x" "$a/m-att1.txt"; POD_RUNS="$(runs 78 79 80 81) $m" BASE_ATT=$BATT em cpu-event)"
w 8.7.1-wrong-base '^НЕИЗМЕРИМ: 8\.7\.1 .*база из архива .* мкс не сходится с объявленной 137\.2' "$(POD_RUNS="$(runs 78 79 80 81 82)" BASE_ATT=$(mkatt wbase 150 2000000 | sed 's/.*://') em cpu-event)"
# разложение по event_type: cpu-*.pprof в каталогах атак подов
mkpp() { python3 "$HERE/w87-pprof-fixture.py" "$@"; }
runs_pp() { # профиль на каждый прогон: file 6 с, syscall 2 с, прочее 2 с (без метки)
    local r="" i m a; for i in "$@"; do m=$(mkatt "q$RANDOM$i" "$i" 1000000); a=${m#*:}
        mkpp "$a/cpu-001.pprof" 30 "main>correlator.EvaluateInto:6:event_type=file" "main>correlator.EvaluateInto:2:event_type=syscall" "main>runtime.findRunnable:2"
        r="$r $m"; done; echo "${r# }"; }
o=$(POD_RUNS="$(runs_pp 78 79 80 81 82)" BASE_ATT=$BATT em cpu-event)
w 8.7.1-split-file '      file +[0-9.]+ с +60\.0%' "$o"
w 8.7.1-split-syscall '      syscall +[0-9.]+ с +20\.0%' "$o"
w 8.7.1-split-unlabelled '      без метки +[0-9.]+ с +20\.0%' "$o"
w 8.7.1-split-absent-is-named 'разложение цены по event_type НЕ СНЯТО' "$(POD_RUNS="$(runs 78 79 80 81 82)" BASE_ATT=$BATT em cpu-event)"

# ── 8.7.3: доля планировщика ───────────────────────────────────────────────────
mksched() { # <имя> <число профилей> <findRunnable с> <прочее с>
    local n=$1 k=$2 fr=$3 ot=$4 i; local D=$T/$n/idle; mkdir -p "$D/snapshots"
    for i in $(seq 1 "$k"); do mkpp "$D/snapshots/$(printf 'cpu-%04d.pprof' $((i * 12)))" 30 "runtime.mstart>runtime.schedule>runtime.findRunnable:$fr" "main>correlator.EvaluateInto:$ot"; done
    echo "$D"
}
# Волна 9, В2: 8.7.3 судится секундами findRunnable cum на 270 с ≤ 1,14 (0,8 × 1,43); доля — справка.
# Профили по 30 с: findRunnable fr с на профиль → 9 × fr с на 270 с (порог 1,14 ↔ fr ≈ 0,1267).
BASE143=$(mksched sb 8 0.16 7)                                                                                                         # база ночи 8.6: 1,44 с на 270 с (объявлено 1,43)
w 8.7.3-good '^ДОСТИГНУТО: 8\.7\.3 .*runtime\.findRunnable cum 0\.90 с на 270 с ≤ 1\.14 с = 0\.8 × 1\.43' "$(IDLE=$(mksched s1 8 0.1 7) BASE_IDLE=$BASE143 em sched)"
w 8.7.3-edge-in '^ДОСТИГНУТО: 8\.7\.3 .*cum 1\.08 с на 270 с' "$(IDLE=$(mksched s2 8 0.12 7) BASE_IDLE=$BASE143 em sched)"                 # 1,08 ≤ 1,14
w 8.7.3-edge-out '^ПРОВАЛЕН: 8\.7\.3 .*cum 1\.17 с на 270 с > 1\.14 с' "$(IDLE=$(mksched s3 8 0.13 7) BASE_IDLE=$BASE143 em sched)"       # 1,17 > 1,14
w 8.7.3-night-86 '^ПРОВАЛЕН: 8\.7\.3 .*cum 1\.44 с на 270 с > 1\.14 с' "$(IDLE=$BASE143 BASE_IDLE=$BASE143 em sched)"                     # ночь 8.6 краснеет и здесь
# главное: доля и секунды расходятся — судят секунды
w 8.7.3-low-share-high-seconds '^ПРОВАЛЕН: 8\.7\.3 .*cum 4\.50 с на 270 с > 1\.14 с \(доля 1\.[0-9]+%\)' "$(IDLE=$(mksched s4 8 0.5 30) BASE_IDLE=$BASE143 em sched)"   # доля 1,6% ≤ 15% — прежний критерий пропустил бы
w 8.7.3-high-share-low-seconds '^ДОСТИГНУТО: 8\.7\.3 .*cum 0\.90 с на 270 с .*доля 2[0-9]\.[0-9]+% — справка' "$(IDLE=$(mksched s5 8 0.1 0.3) BASE_IDLE=$BASE143 em sched)" # доля 25% > 15%, секунды 0,90 — форма ночи 8.7
w 8.7.3-share-printed 'профилей 8, runtime\.findRunnable cum [0-9.]+ с за 240 с профилей = 0\.90 с на 270 с \(доля [0-9.]+% — справка\)' "$(IDLE=$(mksched s6 8 0.1 7) BASE_IDLE=$BASE143 em sched)"
w 8.7.3-abs-ratio 'СПРАВОЧНО \(Е3\): runtime\.findRunnable на 270 с: ночь 0\.90 с .*секунды к базе 0\.62' "$(IDLE=$(mksched s7 8 0.1 7) BASE_IDLE=$BASE143 em sched)"
w 8.7.3-no-base 'СПРАВОЧНО: базы того же прибора не задано \(BASE_IDLE\) — судит объявленная константа 1\.14 с' "$(IDLE=$(mksched s8 8 0.1 7) em sched)"
w 8.7.3-wrong-base '^НЕИЗМЕРИМ: 8\.7\.3 .*база из архива 2\.70 с не сходится с объявленной 1\.43 с' "$(IDLE=$(mksched s9 8 0.1 7) BASE_IDLE=$(mksched s10 8 0.3 7) em sched)"
w 8.7.3-thin-base '^НЕИЗМЕРИМ: 8\.7\.3 .*база .* меньше 6 idle-профилей или нет узла' "$(IDLE=$(mksched s11 8 0.1 7) BASE_IDLE=$(mksched s12 3 0.16 7) em sched)"
w 8.7.3-few '^НЕИЗМЕРИМ: 8\.7\.3 .*профилей 3 < 6' "$(IDLE=$(mksched s13 3 0.1 7) em sched)"
w 8.7.3-no-node '^НЕИЗМЕРИМ: 8\.7\.3 .*нет узла runtime\.findRunnable' "$(d=$T/s14/idle; mkdir -p $d/snapshots; for i in 1 2 3 4 5 6 7; do mkpp "$d/snapshots/cpu-000$i.pprof" 30 "main>x:3"; done; IDLE=$d em sched)"

# ── 8.7.6: профили под пакетом ──────────────────────────────────────────────────
mkcpu_dir() { # <каталог> <число файлов> <CPU с в файле>
    mkdir -p "$1"; local i; for i in $(seq 1 "$2"); do mkpp "$1/$(printf 'cpu-%03d.pprof' "$i")" 30 "main>correlator.EvaluateInto:$3:event_type=file"; done
}
mkblock() { mkdir -p "$1"; echo x > "$1/block.pprof"; echo x > "$1/mutex.pprof"; echo "done 2026-10-17T00:00:00Z" > "$1/DONE"; }
pp_runs() { local r="" i m a; for i in $(seq 1 "$1"); do m=$(mkatt "z$RANDOM$i" 80 1000000); a=${m#*:}; mkcpu_dir "$a" 2 "${2:-8}"; r="$r $m"; done; echo "${r# }"; }
HC=$T/hostcpu; mkcpu_dir "$HC" 3 8; BL=$T/blk; mkblock "$BL"
pf() { POD_RUNS="$1" HOST_CPU_DIR=$2 BLOCK_DIR=$3 em prof; }
w 8.7.6-good '^ДОСТИГНУТО: 8\.7\.6 .*хоста и 5 подов' "$(pf "$(pp_runs 5)" "$HC" "$BL")"                                                  # 2×8 с = 1600 сэмплов у пода, 2400 у хоста
w 8.7.6-pod-thin '^ПРОВАЛЕН: 8\.7\.6 .*под 4: сэмплов [0-9]+ < 1000' "$(r="$(pp_runs 2)"; r="$r $(m=$(mkatt thin 80 1000000); mkcpu_dir "${m#*:}" 2 8; echo $m)"; r="$r $(m=$(mkatt thin2 80 1000000); mkcpu_dir "${m#*:}" 1 4; echo $m)"; pf "$r" "$HC" "$BL")"
w 8.7.6-pod-none '^ПРОВАЛЕН: 8\.7\.6 .*под 1: нет cpu-\*\.pprof' "$(pf "$(m=$(mkatt nofile 80 1000000); echo $m)" "$HC" "$BL")"
w 8.7.6-host-none '^ПРОВАЛЕН: 8\.7\.6 .*хост \(окно пакета\): нет cpu-\*\.pprof' "$(pf "$(pp_runs 5)" "$T/нет" "$BL")"
w 8.7.6-no-block '^ПРОВАЛЕН: 8\.7\.6 .*block/mutex-профиль не снят' "$(pf "$(pp_runs 5)" "$HC" "$T/нет")"
w 8.7.6-block-window-not-closed '^ПРОВАЛЕН: 8\.7\.6 .*block/mutex-профиль не снят' "$(b=$T/blk2; mkblock $b; echo 'die: block/mutex не выключены после окна' > $b/DONE; pf "$(pp_runs 5)" "$HC" "$b")"
w 8.7.6-no-pods '^НЕИЗМЕРИМ: 8\.7\.6 .*прогонов пода нет' "$(pf "" "$HC" "$BL")"

# ── 8.6.3а ────────────────────────────────────────────────────────────────────
mkprof() { # <имя> <число профилей> <cum каждого с> — idle/snapshots/cpu-NNNN.pprof по 30 с
    local n=$1 k=$2 cum=$3 i; local D=$T/$n/idle; mkdir -p "$D/snapshots"
    for i in $(seq 1 "$k"); do python3 "$HERE/w86-pprof-fixture.py" "$D/snapshots/$(printf 'cpu-%04d.pprof' $((i * 12)))" 30 "$cum" 1; done
    echo "$D"
}
w 8.6.3а-good '^ДОСТИГНУТО: 8\.6\.3а .*3\.60 с на 270 с' "$(IDLE=$(mkprof p1 9 0.4) em rule-eval)"                 # 9 × 0,4 = 3,6 с на 270 с
w 8.6.3а-normalised '^ДОСТИГНУТО: 8\.6\.3а .*3\.60 с на 270 с' "$(IDLE=$(mkprof p2 12 0.4) em rule-eval)"           # 12 профилей = 360 с: 4,8 с → нормируется на 270 → 3,6
w 8.6.3а-over '^ПРОВАЛЕН: 8\.6\.3а .*4\.50 с на 270 с > 3\.96' "$(IDLE=$(mkprof p3 9 0.5) em rule-eval)"
w 8.6.3а-few '^НЕИЗМЕРИМ: 8\.6\.3а .*профилей 3 < 6' "$(IDLE=$(mkprof p4 3 0.1) em rule-eval)"
w 8.6.3а-no-node '^НЕИЗМЕРИМ: 8\.6\.3а .*нет длительности|нет узла RuleEngine.EvaluateInto' "$(d=$(mkprof p5 6 0); IDLE=$d em rule-eval)"

# ── 8.6.3б ────────────────────────────────────────────────────────────────────
IDT=$T/ident.txt; printf 'sha256=%s\ngit=aabbccddeeff1122\n' "$(printf 'a%.0s' $(seq 64))" > "$IDT"
mkbench() { # <имя> <sha> <ns_stand> [dump=1074590] [ns_mac] [mac_git]
    local f=$T/$1.bench; { echo "binary_sha256=$2"; echo "ns_stand=$3"; echo "dump_events=${4:-1074590}"; [ -n "${5:-}" ] && echo "ns_mac=$5" && echo "mac_git=${6:-aabbccddeeff1122}"; } > "$f"; echo "$f"
}
SHA=$(printf 'a%.0s' $(seq 64))
w 8.6.3б-good '^ДОСТИГНУТО: 8\.6\.3б .*стенд 8800 ns ≤ 19992' "$(BENCH_FILE=$(mkbench b1 "$SHA" 8800) IDENT=$IDT em bench)"
w 8.6.3б-edge-over '^ПРОВАЛЕН: 8\.6\.3б .*стенд 20000 ns > 19992' "$(BENCH_FILE=$(mkbench b2 "$SHA" 20000) IDENT=$IDT em bench)"
w 8.6.3б-sha-mismatch '^НЕИЗМЕРИМ: 8\.6\.3б .*sha бинаря бенча bbbbbbbbbbbb ≠ sha бинаря ночи aaaaaaaaaaaa' "$(BENCH_FILE=$(mkbench b3 "$(printf 'b%.0s' $(seq 64))" 8800) IDENT=$IDT em bench)"
w 8.6.3б-no-file '^НЕИЗМЕРИМ: 8\.6\.3б .*нет файла результата' "$(BENCH_FILE=$T/нет IDENT=$IDT em bench)"
w 8.6.3б-small-dump '^НЕИЗМЕРИМ: 8\.6\.3б .*не дамп w86-b' "$(BENCH_FILE=$(mkbench b4 "$SHA" 8800 20000) IDENT=$IDT em bench)"
w 8.6.3б-mac-same-commit-over '^ПРОВАЛЕН: 8\.6\.3б .*мак 7000 ns > 6145' "$(BENCH_FILE=$(mkbench b5 "$SHA" 8800 1074590 7000) IDENT=$IDT em bench)"
w 8.6.3б-mac-other-commit-info 'НЕ судится' "$(BENCH_FILE=$(mkbench b6 "$SHA" 8800 1074590 7000 ffffffffffff0000) IDENT=$IDT em bench)"

# ── 8.7.4 ─────────────────────────────────────────────────────────────────────
mkal() { # <файл> "rule:comm:n ..."
    local f=$1; shift; local first=1 r
    { echo '['; for r in $1; do IFS=: read -r id comm n <<< "$r"; local i; for i in $(seq 1 "$n"); do [ $first = 1 ] || echo ','; first=0; echo "{\"id\":\"$id-$i\",\"rule_id\":\"$id\",\"comm\":\"$comm\"}"; done; done; echo ']'; } > "$f"
}
MAN=$T/man.json; echo '[{"category":"c","comm":"apache2"},{"category":"d","comm":"nc"}]' > "$MAN"
REG=$T/new-rules.txt; printf 'web_path_traversal_process\t20261015\t8.6-B/1\nold_rule_x\t20261001\t8.2\n' > "$REG"
OLD=$T/old.json; mkal "$OLD" "r_a:nc:3 r_b:apache2:2 bg_x:cron:5"
NEWOK=$T/new-ok.json; mkal "$NEWOK" "r_a:nc:3 r_b:apache2:2 bg_x:cron:6 web_path_traversal_process:apache2:1"
CTL=$T/ctl-ok.txt; printf 'OK   a\nOK   b\nИТОГ: 14 OK, 0 FAIL\n' > "$CTL"
C0=$T/c0.txt; printf '    dispatch_index_test.go:111: событий 1074590, алертов 441630; syscall\n--- PASS: TestDispatch_ShippedRulesetSameAlerts (36.81s)\n' > "$C0"
det() { DET_NEW=$1 DET_OLD=$OLD DET_MAN=$MAN NEW_RULES=${REG_OVERRIDE:-$REG} NIGHT_DATE=${ND-20261016} BASE_DATE=${BD-20261014} RULE_CTL=${RC:-$CTL} C0_IDENT=${C0I:-$C0} em detect; }
w 8.7.4-good-new-rule-by-date '^ДОСТИГНУТО: 8\.7\.4 .*ожидаемым расширением по реестру \(web_path_traversal_process\(атака 1, реестр 20261015\)' "$(det "$NEWOK")"
w 8.7.4-date-after-night '^ПРОВАЛЕН: 8\.7\.4 .*web_path_traversal_process\(атака 1, реестр 20261015 вне окна' "$(ND=20261014 det "$NEWOK")"                  # заведено позже ночи — не могло быть
w 8.7.4-rule-existed-at-base '^ПРОВАЛЕН: 8\.7\.4 .*вне окна' "$(BD=20261015 det "$NEWOK")"                                                              # заведено не позже базы — расширением не объяснить
w 8.7.4-not-in-registry '^ПРОВАЛЕН: 8\.7\.4 .*нет в реестре' "$(printf 'old_rule_x\t20261001\tx\n' > "$T/reg2"; REG_OVERRIDE=$T/reg2 det "$NEWOK")"
NEWBAD=$T/new-bad.json; mkal "$NEWBAD" "r_a:nc:3 bg_x:cron:6 web_path_traversal_process:apache2:1"
w 8.7.4-lost-attack-rule '^ПРОВАЛЕН: 8\.7\.4 .*только в базе: r_b\(атака 2\)' "$(det "$NEWBAD")"
NEWBG=$T/new-bg.json; mkal "$NEWBG" "r_a:nc:3 r_b:apache2:2 bg_x:cron:6 web_path_traversal_process:apache2:1 bg_new:cron:9"
w 8.7.4-background-only-in-new-ok '^ДОСТИГНУТО: 8\.7\.4 ' "$(det "$NEWBG")"
w 8.7.4-ctl-fail '^ПРОВАЛЕН: 8\.7\.4 .*контроли правил: 2 FAIL' "$(printf 'FAIL x\nFAIL y\nИТОГ: 12 OK, 2 FAIL\n' > "$T/ctl-bad"; RC=$T/ctl-bad det "$NEWOK")"
w 8.7.4-ctl-missing '^НЕИЗМЕРИМ: 8\.7\.4 .*нет вывода живых контролей правил' "$(RC=$T/нет det "$NEWOK")"
w 8.7.4-ctl-few '^НЕИЗМЕРИМ: 8\.7\.4 .*контролей OK 5 < 14' "$(printf 'ИТОГ: 5 OK, 0 FAIL\n' > "$T/ctl-few"; RC=$T/ctl-few det "$NEWOK")"
w 8.7.4-g0-identity-fail '^ПРОВАЛЕН: 8\.7\.4 .*тождество на дампе не PASS' "$(printf -- '--- FAIL: TestDispatch_ShippedRulesetSameAlerts\n' > "$T/c0-bad"; C0I=$T/c0-bad det "$NEWOK")"
w 8.7.4-g0-small '^НЕИЗМЕРИМ: 8\.7\.4 .*не на дампе w86-b' "$(printf 'событий 6000, алертов 5\n--- PASS: TestDispatch_ShippedRulesetSameAlerts\n' > "$T/c0-small"; C0I=$T/c0-small det "$NEWOK")"
w 8.7.4-no-snapshot '^НЕИЗМЕРИМ: 8\.7\.4 .*нет или не разобран снимок алертов' "$(det "$T/нет")"
w 8.7.4-two-tests-second-missing '^ПРОВАЛЕН: 8\.7\.4 .*тождество на дампе не PASS: TestP1_Identity' "$(IDENT_TESTS="TestDispatch_ShippedRulesetSameAlerts TestP1_Identity" det "$NEWOK")"
w 8.7.4-no-night-date '^НЕИЗМЕРИМ: 8\.7\.4 .*дата ночи не задана' "$(ND= det "$NEWOK")"

# ── 8.7.5 / 8.6.6: поды ───────────────────────────────────────────────────────
PSHA=abcdef123456
mkpod() { # <имя> [mk-ключи…] [sha=…]
    local n=$1; shift; local sha=$PSHA a=()
    for kv in "$@"; do case "$kv" in sha=*) sha=${kv#sha=} ;; *) a+=("$kv") ;; esac; done
    local ra; ra=$(mk "$n" "${a[@]}"); local R=${ra% *} A=${ra#* }
    echo "$sha" > "$R/pod-sha.txt"; echo "$R:$A"
}
pods() { local r="" i=0 v; for v in "$@"; do i=$((i + 1)); r="$r $(mkpod "pm$RANDOM$i" r2r=$v)"; done; echo "${r# }"; }
pm() { POD_RUNS="$1" POD_SHA=$PSHA em pod-median; }
w 8.7.5-good '^ДОСТИГНУТО: 8\.7\.5 .*медиана 5000 ≤ 7122\.5 по 5 прогонам' "$(pm "$(pods 4000 4500 5000 6000 9000)")"
w 8.7.5-over '^ПРОВАЛЕН: 8\.7\.5 .*медиана ringbuf_to_router 8000 > 7122\.5' "$(pm "$(pods 7500 7600 8000 8100 8200)")"
w 8.7.5-four '^НЕИЗМЕРИМ: 8\.7\.5 .*засчитанных прогонов 4 < 5' "$(pm "$(pods 1 2 3 4)")"
w 8.7.5-foreign-sha '^НЕИЗМЕРИМ: 8\.7\.5 .*sha пода ffffff000000 ≠ ночи abcdef123456' "$(pm "$(pods 100 200 300 400) $(mkpod fx r2r=100 sha=ffffff000000)")"
w 8.7.5-duplicate '^НЕИЗМЕРИМ: 8\.7\.5 .*повторяет уже учтённый каталог' "$(p=$(mkpod dup r2r=100); pm "$(pods 100 200 300 400) $p $p")"
w 8.7.5-no-sha-file '^НЕИЗМЕРИМ: 8\.7\.5 .*нет pod-sha\.txt' "$(p=$(mkpod nos r2r=100); rm -f "${p%%:*}/pod-sha.txt"; pm "$(pods 100 200 300 400) $p")"
w 8.7.5-f1-off '^НЕИЗМЕРИМ: 8\.7\.5 .*F1 не active' "$(pm "$(pods 100 200 300 400) $(mkpod f1off r2r=100 state=off_config)")"
w 8.7.5-no-series '^НЕИЗМЕРИМ: 8\.7\.5 .*ringbuf_to_router не измерен' "$(pm "$(pods 100 200 300 400) $(mkpod nser r2r=none)")"
w 8.7.5-edge-equal '^ДОСТИГНУТО: 8\.7\.5 .*медиана 7122 ≤' "$(pm "$(pods 7122 7122 7122 7122 7122)")"


# ── 8.6.6 (Д6′): база — медиана пиков пяти прогонов ночи 8.6 ─────────────────────
mkinv() { # <имя> <МиБ карт> — maps.json: одна карта + кольцо 4 МиБ
    local D=$T/$1; mkdir -p "$D"
    echo "[{\"name\":\"m1\",\"type\":\"hash\",\"bytes_memlock\":$(($2 * 1048576))},{\"name\":\"r\",\"type\":\"ringbuf\",\"max_entries\":4194304}]" > "$D/maps.json"; echo "$D"
}
bpods() { local r="" i=0 v; for v in "$@"; do i=$((i + 1)); r="$r $(mkpod "bp$RANDOM$i" peak=$v)"; done; echo "${r# }"; }
BASEP=$(bpods 142.8 143.2 143.5 143.7 146.2); BINV=$(mkinv binv 24)      # медиана 143,5 (как ночь 8.6)
pk() { POD_RUNS="$1" BASE_PODS="$BASEP" BASE_INV=$BINV INV=$2 em pod-peak; }
podp() { local r="" i=0 v; for v in "$@"; do i=$((i + 1)); r="$r $(mkpod "pk$RANDOM$i" peak=$v)"; done; echo "${r# }"; }
w 8.6.6-good '^ДОСТИГНУТО: 8\.6\.6 .*≤ 143\.5 МиБ \(медиана пяти прогонов ночи 8\.6\), BPF карты\+кольца 28\.0 ≤ 28\.0' "$(pk "$(podp 130 131 132 133 134)" "$(mkinv ninv 24)")"
w 8.6.6-base-median-printed 'медиана 143\.5 \(разброс 3\.4 МиБ\)' "$(pk "$(podp 130 131 132 133 134)" "$(mkinv ninv1 24)")"
w 8.6.6-peak-over '^ПРОВАЛЕН: 8\.6\.6 .*медиана пиков 144 МиБ > базы 143\.5' "$(pk "$(podp 143 143.5 144 144 145)" "$(mkinv ninv2 24)")"
w 8.6.6-at-base '^ДОСТИГНУТО: 8\.6\.6 ' "$(pk "$(podp 143.5 143.5 143.5 143.5 143.5)" "$(mkinv ninv5 24)")"
w 8.6.6-bpf-over '^ПРОВАЛЕН: 8\.6\.6 .*BPF карты\+кольца 29\.0 МиБ > базы 28\.0' "$(pk "$(podp 130 131 132 133 134)" "$(mkinv ninv3 25)")"
w 8.6.6-bpf-smaller-ok '^ДОСТИГНУТО: 8\.6\.6 .*BPF карты\+кольца 22\.0 ≤ 28\.0' "$(pk "$(podp 130 131 132 133 134)" "$(mkinv ninv6 18)")"   # П6: кольца 4→1 МиБ
w 8.6.6-few-runs '^НЕИЗМЕРИМ: 8\.6\.6 .*прогонов с пиком 3 < 5' "$(pk "$(podp 130 131 132)" "$(mkinv ninv4 24)")"
w 8.6.6-no-maps '^НЕИЗМЕРИМ: 8\.6\.6 .*нет разбираемого maps\.json ночи' "$(pk "$(podp 130 131 132 133 134)" "$T/нет")"
w 8.6.6-wrong-base '^НЕИЗМЕРИМ: 8\.6\.6 .*база из архива .* не сходится с объявленной 143\.5' "$(POD_RUNS="$(podp 130 131 132 133 134)" BASE_PODS="$(bpods 100 101 102 103 104)" BASE_INV=$BINV INV=$(mkinv ninv7 24) em pod-peak)"
w 8.6.6-base-four-runs '^НЕИЗМЕРИМ: 8\.6\.6 .*прогонов базы \(ночь 8\.6\) с пиком 4 < 5' "$(POD_RUNS="$(podp 130 131 132 133 134)" BASE_PODS="$(bpods 143.5 143.5 143.5 143.5)" BASE_INV=$BINV INV=$(mkinv ninv8 24) em pod-peak)"

# ── 8.2.2 (Д3′): срез на 30-й минуте у каждого прогона, медиана ────────────────────
mkinvmem() { # <имя> <memory.current МиБ> <etimes> — инвентарь пода: карты P1 6 МиБ, одна таблица
    local d="$T/$1"; mkdir -p "$d"
    echo "pid=1 etimes= $3 exe_sha=fixture cg=/kubepods/x" > "$d/meta.txt"
    awk -v m="$2" 'BEGIN { printf "%.0f\n", m * 1048576 }' > "$d/memory.current"; awk -v m="$2" 'BEGIN { printf "anon %.0f\nfile 0\n", m * 1048576 / 2 }' > "$d/memory.stat"
    echo '[{"id":1,"type":"hash","name":"live","bytes_memlock":4096},{"id":21,"type":"hash","name":"proc_live","bytes_memlock":3145728},{"id":31,"type":"lru_hash","name":"proc_exited","bytes_memlock":3145728},{"id":41,"type":"percpu_array","name":"proc_table_coun","bytes_memlock":4096}]' > "$d/maps.json"
    echo "$d"
}
invs() { local r="" i=0 v; for v in "$@"; do i=$((i + 1)); r="$r $(mkinvmem "iv$RANDOM$i" "$v" 1900)"; done; echo "${r# }"; }
ms() { POD_INVS="$1" em mem-slice; }
w 8.2.2-median-good '^ДОСТИГНУТО: 8\.2\.2 .*медиана 118\.[0-9]+ МиБ ≤ 120 по 5 срезам' "$(ms "$(invs 124 126 124.1 123 128)")"       # −6 → 118,0 / 120,0 / 118,1 / 117,0 / 122,0 → медиана 118,1
w 8.2.2-median-over '^ПРОВАЛЕН: 8\.2\.2 .*медиана 121\.[0-9]+ МиБ > 120' "$(ms "$(invs 127 127.2 127.5 127 128)")"
w 8.2.2-one-high-run-not-red '^ДОСТИГНУТО: 8\.2\.2 ' "$(ms "$(invs 120 121 122 123 140)")"                                                       # выброс прогона не краснит: судит медиана
w 8.2.2-four '^НЕИЗМЕРИМ: 8\.2\.2 .*срезов на 30-й минуте 4 < 5' "$(ms "$(invs 120 121 122 123)")"
w 8.2.2-young-slice '^НЕИЗМЕРИМ: 8\.2\.2 .*аптайм 300 с < 1800' "$(ms "$(invs 120 121 122 123) $(mkinvmem young 120 300)")"
w 8.2.2-missing-dir '^НЕИЗМЕРИМ: 8\.2\.2 .*прогон 5: нет каталога среза' "$(ms "$(invs 120 121 122 123) $T/нет")"

# ── 8.5.5 (Д12′): без root_pid == 1 ───────────────────────────────────────────
mkinc() { # <файл> <с_цепочкой> <без> [root=nginx] [pid=100]
    local f=$1 w=$2 wo=$3 root=${4:-nginx} pid=${5:-100} i=0 first=1
    { echo '['
      while [ "$i" -lt "$w" ]; do i=$((i + 1)); [ $first = 1 ] || echo ','; first=0; echo "{\"root_pid\":$pid,\"root_comm\":\"$root\",\"process_chain\":[\"$root\",\"bash\",\"curl\"],\"verdict\":\"attack\"}"; done
      i=0
      while [ "$i" -lt "$wo" ]; do i=$((i + 1)); [ $first = 1 ] || echo ','; first=0; echo "{\"root_pid\":$pid,\"root_comm\":\"$root\",\"process_chain\":null,\"verdict\":\"suspicious\"}"; done
      echo ']'; } > "$f"
}
addpid1() { # <файл> — добавляет бесцепочечный инцидент root_pid == 1 (systemd, init.scope)
    jq '. + [{"root_pid":1,"root_comm":"systemd","process_chain":null,"verdict":"suspicious"}]' "$1" > "$1.x" && mv "$1.x" "$1"
}
BI=$T/base-inc.json; mkinc "$BI" 10 0 bash; addpid1 "$BI"             # база: 10 с цепочкой + pid 1 без → 10/11 по старой формуле, 10/10 по новой
HI=$T/host-inc.json; mkinc "$HI" 8 0 bash; addpid1 "$HI"              # ночь 8.6: 8/9 по старой, 8/8 по новой
M0=$T/ch0.txt; M1=$T/ch1.txt
printf 'ebpf_guard_lineage_proc_reads_total 0\nebpf_guard_events_total{type="file"} 1000\nebpf_guard_proc_table_state{state="active"} 1\n' > "$M0"
printf 'ebpf_guard_lineage_proc_reads_total 0\nebpf_guard_events_total{type="file"} 9000\nebpf_guard_proc_table_state{state="active"} 1\n' > "$M1"
ch() { INC=${HOSTINC:-$HI} BASE_INC=$BI CH_M0=$M0 CH_M1=$M1 CTL_INC=$1 em chain; }
mkinc "$T/ctl6" 6 0; mkinc "$T/ctl4" 4 0; mkinc "$T/ctl6x" 5 1; mkinc "$T/ctl10" 10 0
w 8.5.5-good-night-86-shape '^ДОСТИГНУТО: 8\.5\.5 .*без root_pid == 1: ночь 8/8 ≥ база 10/10' "$(ch "$T/ctl6")"                   # ночь 8.6 стала бы зелёной
w 8.5.5-old-share-printed 'СПРАВОЧНО \(прежняя формула.*ночь 8/9, база 10/11' "$(ch "$T/ctl6")"
w 8.5.5-n-too-small '^НЕИЗМЕРИМ: 8\.5\.5 .*инцидентов контроля цепочки 4 < 5' "$(ch "$T/ctl4")"
w 8.5.5-ctl-share-below-base '^ПРОВАЛЕН: 8\.5\.5 .*контроль цепочки: доля 5/6 ниже базы 10/10' "$(ch "$T/ctl6x")"
HX=$T/host-bad.json; mkinc "$HX" 7 1 bash; addpid1 "$HX"
w 8.5.5-host-regress '^ПРОВАЛЕН: 8\.5\.5 .*\(а\) доля с process_chain без pid 1 7/8 ниже базы 10/10' "$(HOSTINC=$HX ch "$T/ctl6")"
HP=$T/host-pid1only.json; echo '[{"root_pid":1,"root_comm":"systemd","process_chain":null}]' > "$HP"
w 8.5.5-only-pid1 '^НЕИЗМЕРИМ: 8\.5\.5 .*нет инцидентов ночи без root_pid == 1' "$(HOSTINC=$HP ch "$T/ctl6")"
w 8.5.5-pid1-with-chain-excluded-both-sides '^ДОСТИГНУТО: 8\.5\.5 ' "$(h=$T/h-x.json; mkinc $h 8 0 bash; jq '. + [{"root_pid":1,"root_comm":"systemd","process_chain":["a"]}]' $h > $h.x; HOSTINC=$h.x ch "$T/ctl6")"
w 8.5.5-ctl-pid1-excluded '^ДОСТИГНУТО: 8\.5\.5 .*контроль цепочки nginx→bash→curl: 6/6' "$(c=$T/ctl6p1.json; mkinc $c 6 0; jq '. + [{"root_pid":1,"root_comm":"nginx","process_chain":null}]' $c > $c.x; ch $c.x)"
w 8.5.5-proc-reads '^ПРОВАЛЕН: 8\.5\.5 .*\(б\) чтений /proc при активной таблице: 5' "$(sed 's/lineage_proc_reads_total 0/lineage_proc_reads_total 5/' "$M1" > "$T/ch1x.txt"; INC=$HI BASE_INC=$BI CH_M0=$M0 CH_M1=$T/ch1x.txt CTL_INC=$T/ctl6 em chain)"
w 8.5.5-table-not-active '^НЕИЗМЕРИМ: 8\.5\.5 .*таблица процессов не active' "$(sed 's/active/degraded/' "$M1" > "$T/ch1d.txt"; INC=$HI BASE_INC=$BI CH_M0=$M0 CH_M1=$T/ch1d.txt CTL_INC=$T/ctl6 em chain)"
w 8.5.5-no-ctl-snapshot '^НЕИЗМЕРИМ: 8\.5\.5 .*нет снимка инцидентов контроля цепочки' "$(ch "$T/нет")"

# ── справочно к 8.1.1: ступеньки next_gc и event_type алертов ───────────────────
mkng() { # <имя> <снимков> "<номер:МиБ> …" — next_gc 40 МиБ, скачки из списка
    local n=$1 k=$2 jumps=$3 i cur=40 j; local D=$T/$n/idle; mkdir -p "$D/snapshots"
    for i in $(seq 0 $((k - 1))); do
        for j in $jumps; do [ "${j%%:*}" = "$i" ] && cur=${j#*:}; done
        printf 'go_memstats_next_gc_bytes %s\n' "$(awk -v c="$cur" 'BEGIN { printf "%.0f", c * 1048576 }')" > "$D/snapshots/$(printf 'metrics-%04d.txt' "$i")"
    done
    echo "$D"
}
EA=$T/edge.json; echo '[{"id":"1","timestamp":"2026-10-16T08:00:00Z","rule_id":"fr_file"},{"id":"2","timestamp":"2026-10-16T08:22:00Z","rule_id":"fr_tls"},{"id":"3","timestamp":"2026-10-16T09:00:00Z","rule_id":"fr_sys"},{"id":"4","timestamp":"2026-10-16T10:00:00Z","rule_id":"fr_dns"}]' > "$EA"
mkdir -p "$T/rules"; printf 'rules:\n  - id: fr_file\n    event_type: file\n  - id: fr_tls\n    event_type: tls\n  - id: fr_sys\n    event_type: syscall\n  - id: fr_dns\n    event_type: dns\n' > "$T/rules/a.yaml"
export RULES_DIR=$T/rules
r=$(IDLE=$(mkng ng1 20 "9:45.8") EDGE_ALERTS=$EA EDGE_N=2 em ref-811)
w 811-ref-jump 'СПРАВОЧНО: 8\.1\.1 прыжков next_gc больше 1 МиБ за срез: 1 — снимок 9: 40\.0→45\.8 МиБ' "$r"
w 811-ref-edge-types 'набор event_type алертов на краях окна .*: dns,file,syscall,tls|набор event_type алертов на краях окна .*: dns,file' "$r"
w 811-ref-no-jump 'прыжков next_gc больше 1 МиБ за срез: 0' "$(IDLE=$(mkng ng2 20 "9:40.5") EDGE_ALERTS=$EA em ref-811)"
w 811-ref-two-jumps 'прыжков next_gc больше 1 МиБ за срез: 2' "$(IDLE=$(mkng ng3 20 "5:46 12:41") EDGE_ALERTS=$EA em ref-811)"
w 811-ref-tls-note 'на краях окна есть tls-алерт' "$(IDLE=$(mkng ng4 20 "") EDGE_ALERTS=$EA EDGE_N=3 em ref-811)"
w 811-ref-no-series 'прыжки next_gc НЕИЗМЕРИМЫ \(в снимках нет go_memstats_next_gc_bytes\)' "$(d=$T/ng5/idle; mkdir -p $d/snapshots; for i in 0 1 2; do echo 'x 1' > $d/snapshots/metrics-000$i.txt; done; IDLE=$d EDGE_ALERTS=$EA em ref-811)"
w 811-ref-no-alerts 'набор event_type алертов на краях окна НЕ СНЯТ' "$(IDLE=$(mkng ng6 20 "") EDGE_ALERTS=$T/нет em ref-811)"
w 811-ref-verdict-free '^СПРАВОЧНО' "$(IDLE=$(mkng ng7 20 "9:45.8") EDGE_ALERTS=$EA em ref-811 | head -1 | sed 's/^== .*/СПРАВОЧНО/'; IDLE=$(mkng ng8 20 "9:45.8") EDGE_ALERTS=$EA em ref-811 | tail -3)"
if em_out=$(IDLE=$(mkng ng9 20 "9:45.8") EDGE_ALERTS=$EA em ref-811) && echo "$em_out" | grep -qE '^(ДОСТИГНУТО|ПРОВАЛЕН|НЕИЗМЕРИМ|ИЗМЕРЕНО):'; then bad "811-ref-prints-no-verdict-line"; else ok "811-ref-prints-no-verdict-line"; fi

# ── 8.1.1r ────────────────────────────────────────────────────────────────────
mkmem() { # <имя> <anon_наклон МиБ/ч> [memstats=yes] — 49 снимков (4 ч)
    local n=$1 sl=$2 ms=${3:-yes} i; local D=$T/$n/idle; mkdir -p "$D/snapshots"
    printf 'timestamp\tn\tcurrent\tanon\tfile\tslab\tpagetables\tkernel_stack\tsock\tmax\n' > "$D/snapshots/cgroup-mem.tsv"
    for i in $(seq 0 48); do
        awk -v i="$i" -v sl="$sl" 'BEGIN { an = (40 + sl * i * 300 / 3600) * 1048576; printf "t\t%d\t%.0f\t%.0f\t%.0f\t0\t0\t0\t0\tmax\n", i, an + 30e6, an, 30e6 }' >> "$D/snapshots/cgroup-mem.tsv"
        { [ "$ms" = yes ] && printf 'go_memstats_heap_inuse_bytes 3e7\ngo_memstats_heap_idle_bytes 1e7\ngo_memstats_heap_released_bytes 4e6\ngo_memstats_stack_inuse_bytes 1.5e6\ngo_memstats_sys_bytes 6e7\n'; echo "process_cpu_seconds_total 1"; } > "$D/snapshots/$(printf 'metrics-%04d.txt' "$i")"
    done
    echo "$D"
}
w 8.1.1r-slope '^ИЗМЕРЕНО: 8\.1\.1r .*anon=\+2\.00 file=\+0\.00 heap_inuse=\+0\.00' "$(IDLE=$(mkmem ms 2) em memsplit)"
w 8.1.1r-flat '^ИЗМЕРЕНО: 8\.1\.1r .*anon=\+0\.00' "$(IDLE=$(mkmem ms0 0) em memsplit)"
w 8.1.1r-no-memstats '^НЕИЗМЕРИМ: 8\.1\.1r .*нет go_memstats' "$(IDLE=$(mkmem msn 1 no) em memsplit)"
mkmem_short() { local D=$T/short/idle; mkdir -p "$D/snapshots"; printf 'timestamp\tn\tcurrent\tanon\tfile\tslab\tpagetables\tkernel_stack\tsock\tmax\n' > "$D/snapshots/cgroup-mem.tsv"
    local i=0; while [ "$i" -lt 6 ]; do printf 't\t%d\t100\t60\t30\t0\t0\t0\t0\tmax\n' "$i" >> "$D/snapshots/cgroup-mem.tsv"; printf 'go_memstats_heap_inuse_bytes 1\ngo_memstats_heap_idle_bytes 1\ngo_memstats_heap_released_bytes 1\ngo_memstats_stack_inuse_bytes 1\ngo_memstats_sys_bytes 1\n' > "$D/snapshots/$(printf 'metrics-%04d.txt' "$i")"; i=$((i + 1)); done; echo "$D"; }
w 8.1.1r-short-idle '^НЕИЗМЕРИМ: 8\.1\.1r .*снимков после часа прогрева меньше трёх' "$(IDLE=$(mkmem_short) em memsplit)"
w 8.1.1r-no-cgroup '^НЕИЗМЕРИМ: 8\.1\.1r .*нет cgroup-mem\.tsv' "$(IDLE=$T/нет em memsplit)"

# ── 8.7.Д ─────────────────────────────────────────────────────────────────────
mkplan() { # <файл> строки «Дn|статус|основание» через \n
    { echo "# plan"; echo "<!-- D-STATUS-BEGIN -->"; echo "| Д | статус | основание |"; echo "|---|---|---|"; printf '%s\n' "$2" | awk -F'|' 'NF == 3 { printf "| %s | %s | %s |\n", $1, $2, $3 }'; echo "<!-- D-STATUS-END -->"; } > "$1"
}
REP=$T/reports.txt; printf 'ДОСТИГНУТО: 8.1.1 ДОСТИГНУТО (x)\nПРОВАЛЕН: 8.2.2 ПРОВАЛЕН (y)\n' > "$REP"
dl() { PLAN=$1 REPORTS=$REP em dlist; }
mkplan "$T/p-ok" $'Д1|закрыт|код\nД15|отложено|решение владельца\nД4b|отложено|решение владельца\nД11|ночь:8.1.1|ночью'
w 8.7.Д-good '^ДОСТИГНУТО: 8\.7\.Д .*строк части Д 4: закрыто 2, отложено решением владельца 2' "$(dl "$T/p-ok")"
mkplan "$T/p-open" $'Д1|закрыт|код\nД2|открыта|—'
w 8.7.Д-open '^ПРОВАЛЕН: 8\.7\.Д .*Д2 открыта' "$(dl "$T/p-open")"
mkplan "$T/p-defer" $'Д1|закрыт|код\nД7|отложено|я так решил'
w 8.7.Д-unlisted-defer '^ПРОВАЛЕН: 8\.7\.Д .*Д7 отложено без решения владельца' "$(dl "$T/p-defer")"
mkplan "$T/p-night-red" $'Д3|ночь:8.2.2|сторож'
w 8.7.Д-night-label-red '^ПРОВАЛЕН: 8\.7\.Д .*Д3 открыта \(метка 8\.2\.2: ПРОВАЛЕН\)' "$(dl "$T/p-night-red")"
mkplan "$T/p-night-missing" $'Д3|ночь:8.9.9|сторож'
w 8.7.Д-night-label-missing '^ПРОВАЛЕН: 8\.7\.Д .*метка 8\.9\.9 без вердикта' "$(dl "$T/p-night-missing")"
mkplan "$T/p-bad" $'Д3|что-то|?'
w 8.7.Д-unknown-status '^НЕИЗМЕРИМ: 8\.7\.Д .*статус «что-то» не из перечня' "$(dl "$T/p-bad")"
w 8.7.Д-no-table '^НЕИЗМЕРИМ: 8\.7\.Д .*нет таблицы статусов' "$(echo "# x" > "$T/p-none"; dl "$T/p-none")"
w 8.7.Д-real-plan-parses '^(ДОСТИГНУТО|ПРОВАЛЕН): 8\.7\.Д ' "$(PLAN=$HERE/../../plan.md REPORTS=$REP em dlist)"


# ── 9.2 (волна 9, В1/Д15): цель 128 МиБ при Rego off ───────────────────────────
rego_pod() { # <имя> <пик МиБ> <rego_active|none>
    local p; p=$(mkpod "$1" peak="$2"); local att=${p#*:}
    [ "$3" != none ] && echo "ebpf_guard_runtime_flag{flag=\"rego_active\"} $3" >> "$att/m-att1.txt"
    echo "$p"
}
rpods() { local r="" i=0 v act=${RA:-0}; for v in "$@"; do i=$((i + 1)); r="$r $(rego_pod "rg$RANDOM$i" "$v" "$act")"; done; echo "${r# }"; }
p128() { POD_RUNS="$1" em pod-peak128; }
w 9.2-good '^ДОСТИГНУТО: 9\.2 .*медиана пиков пода 12[0-9.]* МиБ ≤ 128 МиБ по 5 прогонам core' "$(p128 "$(rpods 120 122 124 126 127)")"
w 9.2-over '^ПРОВАЛЕН: 9\.2 .*медиана пиков 13[0-9.]* МиБ > 128' "$(p128 "$(rpods 130 131 132 133 134)")"
w 9.2-median-not-max '^ДОСТИГНУТО: 9\.2 ' "$(p128 "$(rpods 120 121 122 123 150)")"                        # выброс не краснит: судит медиана
w 9.2-edge-in '^ДОСТИГНУТО: 9\.2 ' "$(p128 "$(rpods 127.5 127.5 127.5 127.5 127.5)")"
w 9.2-edge-out '^ПРОВАЛЕН: 9\.2 ' "$(p128 "$(rpods 128.5 128.5 128.5 128.5 128.5)")"
w 9.2-rego-on-not-counted '^НЕИЗМЕРИМ: 9\.2 .*Rego ВКЛЮЧЁН \(rego_active=1\).*цель 128 судится на core' "$(RA=1 p128 "$(RA=1 rpods 100 100 100 100 100)")"   # 100 МиБ с Rego цель не доказывают
w 9.2-mixed-four-core '^НЕИЗМЕРИМ: 9\.2 .*засчитанных прогонов core 4 < 5' "$(p128 "$(rpods 100 100 100 100) $(RA=1 rpods 100)")"
w 9.2-no-flag-series '^НЕИЗМЕРИМ: 9\.2 .*нет серии runtime_flag.*до волны 9' "$(RA=none p128 "$(RA=none rpods 100 100 100 100 100)")"
w 9.2-four-runs '^НЕИЗМЕРИМ: 9\.2 .*засчитанных прогонов core 4 < 5' "$(p128 "$(rpods 100 100 100 100)")"
w 9.2-over-with-rego-not-fail '^НЕИЗМЕРИМ: 9\.2 ' "$(RA=1 p128 "$(RA=1 rpods 150 150 150 150 150)")"                # 150 с Rego — не провал цели core

# ── мутации ───────────────────────────────────────────────────────────────────
if [ "${1:-}" = --mutate ]; then
    mut() { # <имя> <sed-выражение>
        local f; f=$(mktemp); sed "$2" "$EMIT" > "$f"
        if cmp -s "$f" "$EMIT"; then bad "мутация $1 не применилась"; rm -f "$f"; return; fi
        if EMITTER=$f bash "$0" 2>/dev/null | grep -q '^FAIL'; then ok "мутация $1 покраснила фикстуры"; else bad "мутация $1 НЕ покраснила фикстуры"; fi
        rm -f "$f"
    }
    mut cpu-frac         's/CPU_FRAC=${CPU_FRAC:-0.8}/CPU_FRAC=${CPU_FRAC:-0.99}/'
    mut cpu86-frac       's/CPU_FRAC=0.6 BASE_CPS_EXPECT=0.0529/CPU_FRAC=0.99 BASE_CPS_EXPECT=0.0529/'
    mut cpu86-base       's/BASE_CPS_EXPECT=0.0529 BASE_NAME/BASE_CPS_EXPECT=0 BASE_NAME/'
    mut cpu-base-check   's/BASE_CPS_EXPECT=${BASE_CPS_EXPECT:-0.03058}/BASE_CPS_EXPECT=${BASE_CPS_EXPECT:-0}/'
    mut cpu-restart      's/\[ "\$s0" = "\$s1" \] || { echo "ERR рестарт агента внутри окна \$1/true || { echo "ERR рестарт агента внутри окна $1/'
    mut event-frac       's/EVENT_FRAC=${EVENT_FRAC:-0.6}/EVENT_FRAC=${EVENT_FRAC:-0.7}/'
    mut event-base-check 's/BASE_EVENT_CPS_EXPECT=${BASE_EVENT_CPS_EXPECT:-137.2}/BASE_EVENT_CPS_EXPECT=${BASE_EVENT_CPS_EXPECT:-0}/'
    mut event-median     's/med=\$(printf .%s. "\$vals" | _median); lim=/med=$(printf "%s" "$vals" | sort -n | tail -1); lim=/'
    mut event-min-runs   's/POD_MIN_RUNS=${POD_MIN_RUNS:-5}/POD_MIN_RUNS=${POD_MIN_RUNS:-1}/'
    mut event-split-off  's/^        cpu_split$/        :/'
    mut split-unlabelled 's/tot - l, 100 \* (tot - l) \/ tot/0, 0/'
    mut peak128-limit    's/POD_PEAK_MAX=${POD_PEAK_MAX:-128}/POD_PEAK_MAX=${POD_PEAK_MAX:-999}/'
    mut peak128-rego-on  's/if awk -v v="\$rf" .BEGIN { exit !(v != 0) }.; then cls=/if false; then cls=/'
    mut peak128-no-flag  's/if \[ -z "\$rf" \]; then cls="\$cls; прогон \$k: нет серии/if false; then cls="$cls; прогон $k: нет серии/'
    mut peak128-median   '/^pod_peak128() {/,/^}/ s/med=\$(printf .%s. "\$peaks" | _median)/med=$(printf "%s" "$peaks" | sort -n | tail -1)/'
    mut sched-sec-max    's/SEC_MAX=${SEC_MAX:-1.14}/SEC_MAX=${SEC_MAX:-99}/'
    mut sched-by-share   's/awk -v v="\$cn_s" -v l="\$SEC_MAX" .BEGIN { exit !(v <= l + 1e-9) }. || fail=/awk -v v="$cp" -v l="$SCHED_MAX" "BEGIN { exit !(v <= l) }" || fail=/'
    mut sched-base-check 's/BASE_SEC_EXPECT=${BASE_SEC_EXPECT:-1.43}/BASE_SEC_EXPECT=${BASE_SEC_EXPECT:-0}/'
    mut sched-norm       's/printf "%.2f", c \* n \/ d }.)$/printf "%.2f", c }")/'
    mut sched-fn         's/SCHED_FN=${SCHED_FN:-runtime.findRunnable}/SCHED_FN=${SCHED_FN:-runtime.nothing}/'
    mut sched-abs-ratio  's/cs \/ bs, cp \/ bp/bs \/ cs, bp \/ cp/'
    mut sched-min-profs  's/PROF_MIN=${PROF_MIN:-6}/PROF_MIN=${PROF_MIN:-0}/'
    mut prof-samples     's/PROF_MIN_SAMPLES=${PROF_MIN_SAMPLES:-1000}/PROF_MIN_SAMPLES=${PROF_MIN_SAMPLES:-0}/'
    mut prof-host        's/^    chk "хост (окно пакета)".*$/    :/'
    mut prof-block       's/-s "\$BLOCK_DIR\/block.pprof" \] \&\& \[ -s "\$BLOCK_DIR\/mutex.pprof" \] \&\& grep -aq .\^done. "\$BLOCK_DIR\/DONE" 2> \/dev\/null/true/'
    mut prof-block-done  's/ \&\& grep -aq .\^done. "\$BLOCK_DIR\/DONE" 2> \/dev\/null//'
    mut prof-no-pods     's/\[ "\$k" -gt 0 \] || cls=/true || cls=/'
    mut eval-limit       's/EVAL_LIMIT=${EVAL_LIMIT:-3.96}/EVAL_LIMIT=${EVAL_LIMIT:-99}/'
    mut eval-norm        's/c \* n \/ d/c/'
    mut eval-min-profs   's/PROF_MIN=${PROF_MIN:-6}/PROF_MIN=${PROF_MIN:-0}/'
    mut bench-frac       's/BENCH_FRAC=${BENCH_FRAC:-0.42}/BENCH_FRAC=${BENCH_FRAC:-5}/'
    mut bench-sha        's/elif \[ "\$bsha" != "\$nsha" \]; then/elif false; then/'
    mut bench-dump       's/\[ "\$ev" -ge "\$BENCH_MIN_EVENTS" \] || cls=/true || cls=/'
    mut detect-date-late 's/\[ "\$d" -le "\$NIGHT_DATE" \]/true/'
    mut detect-date-base 's/\[ "\$d" -gt "\$BASE_DATE" \] \&\& //'
    mut detect-only-old  's/\[ -z "\$only_old" \] || fail=/true || fail=/'
    mut detect-registry  's/elif \[ -n "\$d" \]; then only_new=/elif false; then only_new=/'
    mut detect-ctl-fail  's/\[ "\$failn" = 0 \] || fail=/true || fail=/'
    mut detect-ident     's/grep -aq -- "--- PASS: \$t " "\$C0_IDENT" || grep -aq -- "--- PASS: \$t\\$" "\$C0_IDENT" || tnot=/true || tnot=/'
    mut pod-sha          's/if \[ -n "\$POD_SHA" \] \&\& \[ "\$sha" != "\$POD_SHA" \]; then/if false; then/'
    mut pod-dup          's/case " \$seen " in \*" \$key "\*)/case " $seen " in ZZZ)/'
    mut pod-limit        's/BASE_R2R=${BASE_R2R:-7122.5}/BASE_R2R=${BASE_R2R:-99999}/'
    mut pod-min          's/POD_MIN_RUNS:-5/POD_MIN_RUNS:-1/'
    mut peak-cmp         's/awk -v m="\$med" -v b="\$bp" .BEGIN { exit !(m <= b) }. || fail=/true || fail=/'
    mut peak-bpf         's/awk -v n="\$nb" -v b="\$bb" .BEGIN { exit !(n <= b) }. || fail=/true || fail=/'
    mut peak-base-check  's/BASE_PEAK_EXPECT=${BASE_PEAK_EXPECT:-143.5}/BASE_PEAK_EXPECT=${BASE_PEAK_EXPECT:-0}/'
    mut peak-base-runs   's/if \[ "\$bn" -lt "\$POD_MIN_RUNS" \]; then cls=/if false; then cls=/'
    mut slice-median     's/med=\$(printf .%s. "\$vals" | _median)\n        echo "  отсортировано/XX/; s/^        local med; med=\$(printf .%s. "\$vals" | _median)$/        local med; med=$(printf "%s" "$vals" | sort -n | tail -1)/'
    mut slice-limit      's/IDLE_MAX_MIB=${IDLE_MAX_MIB:-120}/IDLE_MAX_MIB=${IDLE_MAX_MIB:-999}/'
    mut slice-n          's/"\$n" -lt "\$POD_MIN_RUNS" \]; then cls="\$cls; срезов/"$n" -lt 1 ]; then cls="$cls; срезов/'
    mut chain-n          's/CTL_MIN=${CTL_MIN:-5}/CTL_MIN=${CTL_MIN:-1}/'
    mut chain-share      's/\[ \$((w \* bt)) -ge \$((bw \* t)) \] || fail=/true || fail=/'
    mut chain-ctl        's/\[ \$((cw \* bt)) -ge \$((bw \* ct)) \] || fail=/true || fail=/'
    mut chain-no-pid1    's/map(select(\$no1 != "no1" or ((.root_pid \/\/ -1) != 1)))/map(select(true))/'
    mut chain-ctl-pid1   's/map(select((.root_pid \/\/ -1) != 1)) | map(select(.root_comm == \$r/map(select(.root_comm == $r/'
    mut chain-proc-reads 's/fail="\$fail; (б) чтений/: "$fail; (б) чтений/'
    mut ref-step         's/STEP_MIB=${STEP_MIB:-1}/STEP_MIB=${STEP_MIB:-100}/'
    mut ref-tls          's/(tls|4)/(nothing)/'
    mut dlist-defer      's/\*" \$id "\*) echo "  \$id: отложено решением/*) echo "  $id: отложено решением/'
    mut dlist-open       's/открыта) echo "  \$id: ОТКРЫТА — \$why"; fail=/открыта) echo "  $id: x"; : /'
    mut dlist-night      's/ДОСТИГНУТО) echo "  \$id: закрыт ночью/*) echo "  $id: закрыт ночью/'
fi
echo "-- fails=$fails"
[ "$fails" = 0 ]
