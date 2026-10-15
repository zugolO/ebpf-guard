#!/bin/bash
# Фикстуры эмиттера w86-close-report.sh и мутации. --mutate: каждая мутация ОБЯЗАНА покраснить фикстуры.
# Нужны: bash 4+, jq, go (go tool pprof), python3.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
EMIT=${EMITTER:-$HERE/w86-close-report.sh}
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
# база ночи 8.5: 0,0529 с/с на 28800 с (97 снимков по 300 с → окно 28800 с)
BASE=$(mkcpu base 3 1526.52 97)
# ── 8.6.1 ──────────────────────────────────────────────────────────────────────
G=$(mkcpu g61 3 $((3 + 28800 * 3 / 100)) 97)           # 0,03 с/с = 57% базы
w() { want "$1" "$2" "$3"; }
w 8.6.1-good '^ДОСТИГНУТО: 8\.6\.1 .*57% базы' "$(IDLE=$G BASE_IDLE=$BASE em cpu-idle)"
w 8.6.1-edge-over '^ПРОВАЛЕН: 8\.6\.1 .*idle 0\.0[0-9]+ с/с = 6[1-9]% базы' "$(IDLE=$(mkcpu o61 3 $((3 + 28800 * 33 / 1000)) 97) BASE_IDLE=$BASE em cpu-idle)"   # 0,033 с/с = 62%
w 8.6.1-equal '^ПРОВАЛЕН: 8\.6\.1 ' "$(IDLE=$BASE BASE_IDLE=$BASE em cpu-idle)"
w 8.6.1-restart '^НЕИЗМЕРИМ: 8\.6\.1 .*рестарт агента внутри окна' "$(IDLE=$(mkcpu rs 3 800 97 2000) BASE_IDLE=$BASE em cpu-idle)"
w 8.6.1-no-series '^НЕИЗМЕРИМ: 8\.6\.1 .*снимков 0' "$(IDLE=$T/нет BASE_IDLE=$BASE em cpu-idle)"
w 8.6.1-wrong-base '^НЕИЗМЕРИМ: 8\.6\.1 .*база из архива .* не сходится с объявленной 0\.0529' "$(IDLE=$G BASE_IDLE=$(mkcpu wb 3 1000 97) em cpu-idle)"

# ── 8.6.2: CPU на событие под пакетом ─────────────────────────────────────────
mkatt() { # <имя> <cpu_с> <событий> [t=600]
    local n=$1 cpu=$2 ev=$3 t=${4:-600}; local A=$T/$n/att; mkdir -p "$A"
    printf 'process_cpu_seconds_total 100\nprocess_start_time_seconds 5\nebpf_guard_events_total{type="file"} 1000\n' > "$A/m-pre.txt"
    printf 'process_cpu_seconds_total %s\nprocess_start_time_seconds 5\nebpf_guard_events_total{type="file"} %s\n' "$(awk -v c="$cpu" 'BEGIN { print 100 + c }')" "$((1000 + ev))" > "$A/m-att1.txt"
    echo "$t" > "$A/t-att1"; echo "$T/$n/run:$A"
}
BASEATT=$(mkatt batt 150 1100000); BATT=${BASEATT#*:}      # 136 мкс на событие
runs() { local r="" i; for i in "$@"; do r="$r $(mkatt "p$RANDOM$i" "$i" 1000000)"; done; echo "${r# }"; }
w 8.6.2-good '^ДОСТИГНУТО: 8\.6\.2 .*медиана 80' "$(POD_RUNS="$(runs 78 79 80 81 82)" BASE_ATT=$BATT em cpu-event)"          # 78..82 мкс ≤ 0,6 × 136
w 8.6.2-over '^ПРОВАЛЕН: 8\.6\.2 .*медиана 100' "$(POD_RUNS="$(runs 98 99 100 101 102)" BASE_ATT=$BATT em cpu-event)"
w 8.6.2-four-runs '^НЕИЗМЕРИМ: 8\.6\.2 .*прогонов пода с измеренным CPU на событие 4 < 5' "$(POD_RUNS="$(runs 78 79 80 81)" BASE_ATT=$BATT em cpu-event)"
w 8.6.2-median-not-mean '^ДОСТИГНУТО: 8\.6\.2 ' "$(POD_RUNS="$(runs 60 60 60 60 140)" BASE_ATT=$BATT em cpu-event)"                  # выброс не краснит: судит медиана
w 8.6.2-no-events-series '^НЕИЗМЕРИМ: 8\.6\.2 .*нет серии ebpf_guard_events_total' "$(m=$(mkatt ne 80 1000); a=${m#*:}; grep -v events_total "$a/m-att1.txt" > "$a/x"; mv "$a/x" "$a/m-att1.txt"; POD_RUNS="$(runs 78 79 80 81) $m" BASE_ATT=$BATT em cpu-event)"

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

# ── 8.6.4 ─────────────────────────────────────────────────────────────────────
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
w 8.6.4-good-new-rule-by-date '^ДОСТИГНУТО: 8\.6\.4 .*ожидаемым расширением по реестру \(web_path_traversal_process\(атака 1, реестр 20261015\)' "$(det "$NEWOK")"
w 8.6.4-date-after-night '^ПРОВАЛЕН: 8\.6\.4 .*web_path_traversal_process\(атака 1, реестр 20261015 вне окна' "$(ND=20261014 det "$NEWOK")"                  # заведено позже ночи — не могло быть
w 8.6.4-rule-existed-at-base '^ПРОВАЛЕН: 8\.6\.4 .*вне окна' "$(BD=20261015 det "$NEWOK")"                                                              # заведено не позже базы — расширением не объяснить
w 8.6.4-not-in-registry '^ПРОВАЛЕН: 8\.6\.4 .*нет в реестре' "$(printf 'old_rule_x\t20261001\tx\n' > "$T/reg2"; REG_OVERRIDE=$T/reg2 det "$NEWOK")"
NEWBAD=$T/new-bad.json; mkal "$NEWBAD" "r_a:nc:3 bg_x:cron:6 web_path_traversal_process:apache2:1"
w 8.6.4-lost-attack-rule '^ПРОВАЛЕН: 8\.6\.4 .*только в базе: r_b\(атака 2\)' "$(det "$NEWBAD")"
NEWBG=$T/new-bg.json; mkal "$NEWBG" "r_a:nc:3 r_b:apache2:2 bg_x:cron:6 web_path_traversal_process:apache2:1 bg_new:cron:9"
w 8.6.4-background-only-in-new-ok '^ДОСТИГНУТО: 8\.6\.4 ' "$(det "$NEWBG")"
w 8.6.4-ctl-fail '^ПРОВАЛЕН: 8\.6\.4 .*контроли правил: 2 FAIL' "$(printf 'FAIL x\nFAIL y\nИТОГ: 12 OK, 2 FAIL\n' > "$T/ctl-bad"; RC=$T/ctl-bad det "$NEWOK")"
w 8.6.4-ctl-missing '^НЕИЗМЕРИМ: 8\.6\.4 .*нет вывода живых контролей правил' "$(RC=$T/нет det "$NEWOK")"
w 8.6.4-ctl-few '^НЕИЗМЕРИМ: 8\.6\.4 .*контролей OK 5 < 14' "$(printf 'ИТОГ: 5 OK, 0 FAIL\n' > "$T/ctl-few"; RC=$T/ctl-few det "$NEWOK")"
w 8.6.4-g0-identity-fail '^ПРОВАЛЕН: 8\.6\.4 .*тождество индекса G3 на дампе не PASS' "$(printf -- '--- FAIL: TestDispatch_ShippedRulesetSameAlerts\n' > "$T/c0-bad"; C0I=$T/c0-bad det "$NEWOK")"
w 8.6.4-g0-small '^НЕИЗМЕРИМ: 8\.6\.4 .*не на дампе w86-b' "$(printf 'событий 6000, алертов 5\n--- PASS: TestDispatch_ShippedRulesetSameAlerts\n' > "$T/c0-small"; C0I=$T/c0-small det "$NEWOK")"
w 8.6.4-no-snapshot '^НЕИЗМЕРИМ: 8\.6\.4 .*нет или не разобран снимок алертов' "$(det "$T/нет")"
w 8.6.4-no-night-date '^НЕИЗМЕРИМ: 8\.6\.4 .*дата ночи не задана' "$(ND= det "$NEWOK")"

# ── 8.6.5 / 8.6.6: поды ───────────────────────────────────────────────────────
PSHA=abcdef123456
mkpod() { # <имя> [mk-ключи…] [sha=…]
    local n=$1; shift; local sha=$PSHA a=()
    for kv in "$@"; do case "$kv" in sha=*) sha=${kv#sha=} ;; *) a+=("$kv") ;; esac; done
    local ra; ra=$(mk "$n" "${a[@]}"); local R=${ra% *} A=${ra#* }
    echo "$sha" > "$R/pod-sha.txt"; echo "$R:$A"
}
pods() { local r="" i=0 v; for v in "$@"; do i=$((i + 1)); r="$r $(mkpod "pm$RANDOM$i" r2r=$v)"; done; echo "${r# }"; }
pm() { POD_RUNS="$1" POD_SHA=$PSHA em pod-median; }
w 8.6.5-good '^ДОСТИГНУТО: 8\.6\.5 .*медиана 5000 ≤ 7122\.5 по 5 прогонам' "$(pm "$(pods 4000 4500 5000 6000 9000)")"
w 8.6.5-over '^ПРОВАЛЕН: 8\.6\.5 .*медиана ringbuf_to_router 8000 > 7122\.5' "$(pm "$(pods 7500 7600 8000 8100 8200)")"
w 8.6.5-four '^НЕИЗМЕРИМ: 8\.6\.5 .*засчитанных прогонов 4 < 5' "$(pm "$(pods 1 2 3 4)")"
w 8.6.5-foreign-sha '^НЕИЗМЕРИМ: 8\.6\.5 .*sha пода ffffff000000 ≠ ночи abcdef123456' "$(pm "$(pods 100 200 300 400) $(mkpod fx r2r=100 sha=ffffff000000)")"
w 8.6.5-duplicate '^НЕИЗМЕРИМ: 8\.6\.5 .*повторяет уже учтённый каталог' "$(p=$(mkpod dup r2r=100); pm "$(pods 100 200 300 400) $p $p")"
w 8.6.5-no-sha-file '^НЕИЗМЕРИМ: 8\.6\.5 .*нет pod-sha\.txt' "$(p=$(mkpod nos r2r=100); rm -f "${p%%:*}/pod-sha.txt"; pm "$(pods 100 200 300 400) $p")"
w 8.6.5-f1-off '^НЕИЗМЕРИМ: 8\.6\.5 .*F1 не active' "$(pm "$(pods 100 200 300 400) $(mkpod f1off r2r=100 state=off_config)")"
w 8.6.5-no-series '^НЕИЗМЕРИМ: 8\.6\.5 .*ringbuf_to_router не измерен' "$(pm "$(pods 100 200 300 400) $(mkpod nser r2r=none)")"
w 8.6.5-edge-equal '^ДОСТИГНУТО: 8\.6\.5 .*медиана 7122 ≤' "$(pm "$(pods 7122 7122 7122 7122 7122)")"

mkinv() { # <имя> <МиБ карт> — maps.json: одна карта + кольцо 4 МиБ
    local D=$T/$1; mkdir -p "$D"
    echo "[{\"name\":\"m1\",\"type\":\"hash\",\"bytes_memlock\":$(($2 * 1048576))},{\"name\":\"r\",\"type\":\"ringbuf\",\"max_entries\":4194304}]" > "$D/maps.json"; echo "$D"
}
BPKRUN=$(mkpod base-peak peak=140); BRUN=${BPKRUN%%:*}; BATTD=${BPKRUN#*:}; BINV=$(mkinv binv 24)       # пик базы 140 МиБ, BPF 28 МиБ
pk() { POD_RUNS="$1" BASE_RUN=$BRUN BASE_ATT=$BATTD BASE_INV=$BINV INV=$2 em pod-peak; }
podp() { local r="" i=0 v; for v in "$@"; do i=$((i + 1)); r="$r $(mkpod "pk$RANDOM$i" peak=$v)"; done; echo "${r# }"; }
w 8.6.6-good '^ДОСТИГНУТО: 8\.6\.6 .*BPF карты\+кольца 28\.0 ≤ 28\.0' "$(pk "$(podp 130 131 132 133 134)" "$(mkinv ninv 24)")"
w 8.6.6-peak-over '^ПРОВАЛЕН: 8\.6\.6 .*медиана пиков 141 МиБ > базы 140' "$(pk "$(podp 140 140 141 142 143)" "$(mkinv ninv2 24)")"
w 8.6.6-bpf-over '^ПРОВАЛЕН: 8\.6\.6 .*BPF карты\+кольца 29\.0 МиБ > базы 28\.0' "$(pk "$(podp 130 131 132 133 134)" "$(mkinv ninv3 25)")"
w 8.6.6-few-runs '^НЕИЗМЕРИМ: 8\.6\.6 .*прогонов с пиком 3 < 5' "$(pk "$(podp 130 131 132)" "$(mkinv ninv4 24)")"
w 8.6.6-no-maps '^НЕИЗМЕРИМ: 8\.6\.6 .*нет разбираемого maps\.json ночи' "$(pk "$(podp 130 131 132 133 134)" "$T/нет")"

# ── 8.5.5 на N ≥ 5 ────────────────────────────────────────────────────────────
mkinc() { # <файл> <с_цепочкой> <без> [root=nginx] — (seq на маке при 0 считает вниз: счёт руками)
    local f=$1 w=$2 wo=$3 root=${4:-nginx} i=0 first=1
    { echo '['
      while [ "$i" -lt "$w" ]; do i=$((i + 1)); [ $first = 1 ] || echo ','; first=0; echo "{\"root_comm\":\"$root\",\"process_chain\":[\"$root\",\"bash\",\"curl\"],\"verdict\":\"attack\"}"; done
      i=0
      while [ "$i" -lt "$wo" ]; do i=$((i + 1)); [ $first = 1 ] || echo ','; first=0; echo "{\"root_comm\":\"$root\",\"process_chain\":null,\"verdict\":\"suspicious\"}"; done
      echo ']'; } > "$f"
}
BI=$T/base-inc.json; mkinc "$BI" 10 1 bash        # база 10/11
HI=$T/host-inc.json; mkinc "$HI" 3 0 bash
M0=$T/ch0.txt; M1=$T/ch1.txt
printf 'ebpf_guard_lineage_proc_reads_total 0\nebpf_guard_events_total{type="file"} 1000\nebpf_guard_proc_table_state{state="active"} 1\n' > "$M0"
printf 'ebpf_guard_lineage_proc_reads_total 0\nebpf_guard_events_total{type="file"} 9000\nebpf_guard_proc_table_state{state="active"} 1\n' > "$M1"
ch() { INC=$HI BASE_INC=$BI CH_M0=$M0 CH_M1=$M1 CTL_INC=$1 em chain; }
mkinc "$T/ctl6" 6 0; mkinc "$T/ctl4" 4 0; mkinc "$T/ctl6x" 5 1; mkinc "$T/ctl10" 10 0
w 8.5.5-good '^ДОСТИГНУТО: 8\.5\.5 .*контроль цепочки nginx→bash→curl: 6/6' "$(ch "$T/ctl6")"
w 8.5.5-n-too-small '^НЕИЗМЕРИМ: 8\.5\.5 .*инцидентов контроля цепочки 4 < 5' "$(ch "$T/ctl4")"
w 8.5.5-share-below-base '^ПРОВАЛЕН: 8\.5\.5 .*доля 5/6 ниже базы 10/11' "$(ch "$T/ctl6x")"
w 8.5.5-share-at-base '^ДОСТИГНУТО: 8\.5\.5 ' "$(ch "$T/ctl10")"
w 8.5.5-host-regress '^ПРОВАЛЕН: 8\.5\.5 .*хост' "$(HI=$T/host-bad.json; mkinc "$HI" 1 2 bash; INC=$HI BASE_INC=$BI CH_M0=$M0 CH_M1=$M1 CTL_INC=$T/ctl6 em chain)"
w 8.5.5-no-ctl-snapshot '^НЕИЗМЕРИМ: 8\.5\.5 .*нет снимка инцидентов контроля цепочки' "$(ch "$T/нет")"

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
w 8.1.1r-no-cgroup '^НЕИЗМЕРИМ: 8\.1\.1r .*нет cgroup-mem\.tsv' "$(IDLE=$T/нет em memsplit)"

# ── 8.6.Д ─────────────────────────────────────────────────────────────────────
mkplan() { # <файл> строки «Дn|статус|основание» через \n
    { echo "# plan"; echo "<!-- D-STATUS-BEGIN -->"; echo "| Д | статус | основание |"; echo "|---|---|---|"; printf '%s\n' "$2" | awk -F'|' 'NF == 3 { printf "| %s | %s | %s |\n", $1, $2, $3 }'; echo "<!-- D-STATUS-END -->"; } > "$1"
}
REP=$T/reports.txt; printf 'ДОСТИГНУТО: 8.1.1 ДОСТИГНУТО (x)\nПРОВАЛЕН: 8.2.2 ПРОВАЛЕН (y)\n' > "$REP"
dl() { PLAN=$1 REPORTS=$REP em dlist; }
mkplan "$T/p-ok" $'Д1|закрыт|код\nД15|отложено|решение владельца\nД4b|отложено|решение владельца\nД11|ночь:8.1.1|ночью'
w 8.6.Д-good '^ДОСТИГНУТО: 8\.6\.Д .*строк части Д 4: закрыто 2, отложено решением владельца 2' "$(dl "$T/p-ok")"
mkplan "$T/p-open" $'Д1|закрыт|код\nД2|открыта|—'
w 8.6.Д-open '^ПРОВАЛЕН: 8\.6\.Д .*Д2 открыта' "$(dl "$T/p-open")"
mkplan "$T/p-defer" $'Д1|закрыт|код\nД7|отложено|я так решил'
w 8.6.Д-unlisted-defer '^ПРОВАЛЕН: 8\.6\.Д .*Д7 отложено без решения владельца' "$(dl "$T/p-defer")"
mkplan "$T/p-night-red" $'Д3|ночь:8.2.2|сторож'
w 8.6.Д-night-label-red '^ПРОВАЛЕН: 8\.6\.Д .*Д3 открыта \(метка 8\.2\.2: ПРОВАЛЕН\)' "$(dl "$T/p-night-red")"
mkplan "$T/p-night-missing" $'Д3|ночь:8.9.9|сторож'
w 8.6.Д-night-label-missing '^ПРОВАЛЕН: 8\.6\.Д .*метка 8\.9\.9 без вердикта' "$(dl "$T/p-night-missing")"
mkplan "$T/p-bad" $'Д3|что-то|?'
w 8.6.Д-unknown-status '^НЕИЗМЕРИМ: 8\.6\.Д .*статус «что-то» не из перечня' "$(dl "$T/p-bad")"
w 8.6.Д-no-table '^НЕИЗМЕРИМ: 8\.6\.Д .*нет таблицы статусов' "$(echo "# x" > "$T/p-none"; dl "$T/p-none")"
w 8.6.Д-real-plan-parses '^(ДОСТИГНУТО|ПРОВАЛЕН): 8\.6\.Д ' "$(PLAN=$HERE/../../plan.md REPORTS=$REP em dlist)"

# ── мутации ───────────────────────────────────────────────────────────────────
if [ "${1:-}" = --mutate ]; then
    mut() { # <имя> <sed-выражение>
        local f; f=$(mktemp); sed "$2" "$EMIT" > "$f"
        if cmp -s "$f" "$EMIT"; then bad "мутация $1 не применилась"; rm -f "$f"; return; fi
        if EMITTER=$f bash "$0" 2>/dev/null | grep -q '^FAIL'; then ok "мутация $1 покраснила фикстуры"; else bad "мутация $1 НЕ покраснила фикстуры"; fi
        rm -f "$f"
    }
    mut cpu-frac         's/CPU_FRAC=${CPU_FRAC:-0.6}/CPU_FRAC=${CPU_FRAC:-0.99}/'
    mut cpu-base-check   's/BASE_CPS_EXPECT=${BASE_CPS_EXPECT:-0.0529}/BASE_CPS_EXPECT=${BASE_CPS_EXPECT:-0}/'
    mut cpu-restart      's/\[ "\$s0" = "\$s1" \] || { echo "ERR рестарт агента внутри окна \$1/true || { echo "ERR рестарт агента внутри окна $1/'
    mut event-median     's/med=\$(printf .%s. "\$vals" | _median); lim=/med=$(printf "%s" "$vals" | sort -n | tail -1); lim=/'
    mut event-min-runs   's/POD_MIN_RUNS=${POD_MIN_RUNS:-5}/POD_MIN_RUNS=${POD_MIN_RUNS:-1}/'
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
    mut detect-g0        's/grep -aq -- .--- PASS: TestDispatch_ShippedRulesetSameAlerts. "\$C0_IDENT"/true/'
    mut pod-sha          's/if \[ -n "\$POD_SHA" \] \&\& \[ "\$sha" != "\$POD_SHA" \]; then/if false; then/'
    mut pod-dup          's/case " \$seen " in \*" \$key "\*)/case " $seen " in ZZZ)/'
    mut pod-limit        's/BASE_R2R=${BASE_R2R:-7122.5}/BASE_R2R=${BASE_R2R:-99999}/'
    mut pod-min          's/POD_MIN_RUNS:-5/POD_MIN_RUNS:-1/'
    mut peak-cmp         's/awk -v m="\$med" -v b="\$bp" .BEGIN { exit !(m <= b) }. || fail=/true || fail=/'
    mut peak-bpf         's/awk -v n="\$nb" -v b="\$bb" .BEGIN { exit !(n <= b) }. || fail=/true || fail=/'
    mut chain-n          's/CTL_MIN=${CTL_MIN:-5}/CTL_MIN=${CTL_MIN:-1}/'
    mut chain-share      's/\[ \$((cw \* bt)) -ge \$((bw \* ct)) \] || fail=/true || fail=/'
    mut dlist-defer      's/\*" \$id "\*) echo "  \$id: отложено решением/*) echo "  $id: отложено решением/'
    mut dlist-open       's/открыта) echo "  \$id: ОТКРЫТА — \$why"; fail=/открыта) echo "  $id: x"; : /'
    mut dlist-night      's/ДОСТИГНУТО) echo "  \$id: закрыт ночью/*) echo "  $id: закрыт ночью/'
fi
echo "-- fails=$fails"
[ "$fails" = 0 ]
