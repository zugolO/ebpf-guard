#!/bin/bash
# Построители синтетических входов эмиттера w85-close-report.sh (используются фикстурами эмиттера и
# фикстурами сторожа полноты ночи 8.5). Читают переменную T (каталог).

# mk <имя> [ключ=значение…] — каталог RUN/ATT; ключи: state=active|off_no_rules|none r2r=<дельта>|none
#                              cats=<число категорий> missed=<число непойманных> peak=<МиБ старта/атак> kf=yes|no
mk() {
    local n=$1; shift
    local state=active r2r=1200 cats=16 missed=0 peak=140 kf=yes
    for kv in "$@"; do eval "${kv%%=*}='${kv#*=}'"; done
    local R=$T/$n/run A=$T/$n/att; mkdir -p "$R" "$A"
    # memory.current: байты, 2 колонки
    awk -v p="$peak" 'BEGIN { for (i = 0; i < 700; i++) printf "%.1f %.0f\n", i / 10, p * 1048576 * (0.8 + 0.2 * (i % 7) / 6) }' > "$R/samples.tsv"
    cp "$R/samples.tsv" "$A/samples.tsv"
    for s in pre att1; do : > "$A/m-$s.txt"; done
    if [ "$r2r" != none ]; then
        echo 'ebpf_guard_events_dropped_total{collector="fileaccess",reason="ringbuf_to_router"} 100' >> "$A/m-pre.txt"
        echo "ebpf_guard_events_dropped_total{collector=\"fileaccess\",reason=\"ringbuf_to_router\"} $((100 + r2r))" >> "$A/m-att1.txt"
    fi
    if [ "$kf" = yes ]; then
        echo 'ebpf_guard_syscall_events_kernel_filtered_total{nr="9"} 1000' >> "$A/m-pre.txt"
        echo 'ebpf_guard_syscall_events_kernel_filtered_total{nr="9"} 90000' >> "$A/m-att1.txt"
    fi
    : > "$A/f1.txt"
    if [ "$state" != none ]; then
        for s in pre post; do echo "$s ebpf_guard_kernel_predicate_state{state=\"$state\"} 1" >> "$A/f1.txt"; done
    fi
    # манифест: cats категорий, у каждой своя comm; baseline пуст, final содержит всех кроме missed
    local i first=1
    {
        echo '['
        for i in $(seq 1 "$cats"); do [ $first = 1 ] || echo ','; first=0; echo "{\"category\":\"cat$i\",\"comm\":\"c$i\"}"; done
        echo ']'
    } > "$A/attack-manifest.json"
    echo '[]' > "$A/baseline-alerts-1.json"
    {
        echo '['
        first=1
        for i in $(seq 1 "$cats"); do
            [ "$i" -le $((cats - missed)) ] || continue
            [ $first = 1 ] || echo ','; first=0; echo "{\"id\":\"a$i\",\"comm\":\"c$i\"}"
        done
        echo ']'
    } > "$A/final-alerts-1.json"
    echo "$R $A"
}

# ── flow (8.5.1), anomaly-hour (8.5.3a), ab (8.5.3) ────────────────────────────
# mkidle <имя> [ключ=значение…] — каталог idle со snapshots/metrics-NNNN.txt, шаг 300 с
#   snaps=<число снимков> by=<by_nr за час> kf=<kernel_filtered за час | none> state=active|off_config|none
#   anom0=<anomaly в снимке 0> anomhr=<прирост за час | none> reset=<номер снимка, где счётчик падает | 0>
mkidle() {
    local n=$1; shift
    local snaps=25 by=1000 kf=9000 state=active anom0=100 anomhr=20 reset=0
    for kv in "$@"; do eval "${kv%%=*}='${kv#*=}'"; done
    local D=$T/$n/idle; mkdir -p "$D/snapshots"
    local i b k an
    for i in $(seq 0 $((snaps - 1))); do
        b=$(awk -v i="$i" -v by="$by" 'BEGIN { printf "%.0f", 5000 + by * i / 12 }')
        k=$(awk -v i="$i" -v kf="$kf" 'BEGIN { printf "%.0f", 1000 + kf * i / 12 }')
        an=$(awk -v i="$i" -v a0="$anom0" -v h="$anomhr" 'BEGIN { printf "%.0f", a0 + h * i / 12 }')
        [ "$reset" != 0 ] && [ "$i" -ge "$reset" ] && b=$((b / 100))
        f=$D/snapshots/$(printf 'metrics-%04d.txt' "$i")
        {
            echo "ebpf_guard_syscall_events_by_nr_total{nr=\"9\"} $((b * 7 / 10))"
            echo "ebpf_guard_syscall_events_by_nr_total{nr=\"321\"} $((b - b * 7 / 10))"
            [ "$kf" != none ] && echo "ebpf_guard_syscall_events_kernel_filtered_total{nr=\"9\"} $k"
            [ "$state" != none ] && echo "ebpf_guard_kernel_predicate_state{state=\"$state\"} 1"
            [ "$anomhr" != none ] && echo "ebpf_guard_alert_volume_by_event_type_total{event_type=\"syscall\",rule_id=\"anomaly_detection\"} $an"
        } > "$f"
    done
    echo "$D"
}

# mkidlew <имя> <окно1> <окно2> … — idle только с anomaly_detection: приращения за окна (12 снимков на окно, линейно);
#   окно «r» после числа — сброс счётчика (рестарт): «20 16r 4»
mkidlew() {
    local n=$1; shift
    local D=$T/$n/idle; mkdir -p "$D/snapshots"
    local cur=100 idx=0 w reset i base
    echo "ebpf_guard_alert_volume_by_event_type_total{event_type=\"syscall\",rule_id=\"anomaly_detection\"} $cur" > "$D/snapshots/metrics-0000.txt"
    for w in "$@"; do
        reset=0; case "$w" in *r) reset=1; w=${w%r} ;; esac
        base=$cur
        for i in $(seq 1 12); do
            idx=$((idx + 1))
            cur=$(awk -v b="$base" -v w="$w" -v i="$i" 'BEGIN { printf "%.0f", b + w * i / 12 }')
            [ "$reset" = 1 ] && [ "$i" -ge 6 ] && cur=3
            echo "ebpf_guard_alert_volume_by_event_type_total{event_type=\"syscall\",rule_id=\"anomaly_detection\"} $cur" > "$D/snapshots/$(printf 'metrics-%04d.txt' "$idx")"
        done
    done
    echo "$D"
}

# mkab <имя> [ключ=значение…]: A (a0→ab), B (ab→b1); stA/stB — состояния F1; drop=<файл> — не создавать
mkab() {
    local n=$1; shift
    local a0=100 ab=130 b1=150 sta0=off_config sta=off_config stb=active drop=""
    for kv in "$@"; do eval "${kv%%=*}='${kv#*=}'"; done
    local D=$T/$n/ab; mkdir -p "$D"
    w() { { echo "ebpf_guard_kernel_predicate_state{state=\"$2\"} 1"; [ "$3" != none ] && echo "ebpf_guard_alert_volume_by_event_type_total{event_type=\"syscall\",rule_id=\"anomaly_detection\"} $3"; } > "$D/$1"; }
    w m-a0.txt "$sta0" "$a0"; w m-ab.txt "$sta" "$ab"; w m-b1.txt "$stb" "$b1"
    printf 'window_s=60\nswitch_at=%s\n' x > "$D/ab-meta.txt"
    [ -n "$drop" ] && rm -f "$D/$drop"
    echo "$D"
}

# ── controls (8.5.2) ──────────────────────────────────────────────────────────
mkctl() { # mkctl <имя> [miss=<rule_id>] [state=active|...] [gate=PASS|FAIL|none] [alerts=none]
    local n=$1; shift
    local miss="" state=active gate=PASS alerts=yes
    for kv in "$@"; do eval "${kv%%=*}='${kv#*=}'"; done
    local D=$T/$n; mkdir -p "$D"
    echo "ebpf_guard_kernel_predicate_state{state=\"$state\"} 1" > "$D/state.txt"
    if [ "$alerts" = yes ]; then
        {
            echo '{"alerts":['
            local first=1 r
            for r in rootkit_anonymous_exec_memory sigma_mprotect_exec_heap mitre_sandbox_detect_cpuid; do
                [ "$r" = "$miss" ] && continue
                [ $first = 1 ] || echo ','; first=0; echo "{\"rule_id\":\"$r\",\"comm\":\"python3\"}"
            done
            echo ',{"rule_id":"cryptominer_binary_name","comm":"xmrig"}'
            echo ']}'
        } > "$D/alerts.json"
    fi
    case "$gate" in
        PASS) echo "[PASS] recall по манифесту: 16/16" > "$D/gate.txt" ;;
        FAIL) echo "[FAIL] recall по манифесту: 14/16" > "$D/gate.txt" ;;
    esac
    echo "$D"
}

# ── cpu (8.5.4) и mem (8.5.6) ─────────────────────────────────────────────────
# mkcpuidle <имя> [c0=3 c1=100 s0=1000 s1=1000 snaps=25 series=yes|no] — idle с process_cpu_seconds_total в крайних снимках
mkcpuidle() {
    local n=$1; shift
    local c0=3 c1=100 s0=1000 s1=1000 snaps=25 series=yes
    for kv in "$@"; do eval "${kv%%=*}='${kv#*=}'"; done
    local D=$T/$n/idle; mkdir -p "$D/snapshots"
    local i last=$((snaps - 1)) f
    for i in $(seq 0 "$last"); do
        f=$D/snapshots/$(printf 'metrics-%04d.txt' "$i")
        : > "$f"
        [ "$series" = yes ] || continue
        if [ "$i" = 0 ]; then printf 'process_cpu_seconds_total %s\nprocess_start_time_seconds %s\n' "$c0" "$s0" > "$f"
        elif [ "$i" = "$last" ]; then printf 'process_cpu_seconds_total %s\nprocess_start_time_seconds %s\n' "$c1" "$s1" > "$f"
        else printf 'process_cpu_seconds_total %s\nprocess_start_time_seconds %s\n' "$(awk -v a="$c0" -v b="$c1" -v i="$i" -v l="$last" 'BEGIN { print a + (b - a) * i / l }')" "$s0" > "$f"
        fi
    done
    echo "$D"
}
# mkcpuatt <имя> [c0=100 c1=300 t=600 s0=1000 s1=1000 series=yes|no] — окно атак пода: m-pre, m-att1, t-att1
mkcpuatt() {
    local n=$1; shift
    local c0=100 c1=300 t=600 s0=1000 s1=1000 series=yes
    for kv in "$@"; do eval "${kv%%=*}='${kv#*=}'"; done
    local D=$T/$n/att; mkdir -p "$D"
    : > "$D/m-pre.txt"; : > "$D/m-att1.txt"
    if [ "$series" = yes ]; then
        printf 'process_cpu_seconds_total %s\nprocess_start_time_seconds %s\n' "$c0" "$s0" > "$D/m-pre.txt"
        printf 'process_cpu_seconds_total %s\nprocess_start_time_seconds %s\n' "$c1" "$s1" > "$D/m-att1.txt"
    fi
    [ "$t" = none ] || echo "$t" > "$D/t-att1"
    echo "$D"
}
# mkinv <имя> [ml=<МиБ карт> ring=<МиБ колец> counts=yes|no raw=<файл содержимого вместо maps.json>] — инвентарь пода (bpftool -j map show)
mkinv() {
    local n=$1; shift
    local ml=9 ring=13 counts=yes
    for kv in "$@"; do eval "${kv%%=*}='${kv#*=}'"; done
    local D=$T/$n/inv; mkdir -p "$D"
    awk -v ml="$ml" -v ring="$ring" -v counts="$counts" 'BEGIN {
        printf "["
        printf "{\"id\":1,\"type\":\"hash\",\"name\":\"fd_path_map\",\"bytes_memlock\":%d},", (ml - 1) * 1048576
        if (counts == "yes") printf "{\"id\":2,\"type\":\"hash\",\"name\":\"syscall_counts\",\"bytes_memlock\":%d},", 1048576
        else printf "{\"id\":2,\"type\":\"hash\",\"name\":\"other_map\",\"bytes_memlock\":%d},", 1048576
        printf "{\"id\":3,\"type\":\"ringbuf\",\"name\":\"events\",\"max_entries\":%d,\"bytes_memlock\":0},", ring * 1048576 / 2
        printf "{\"id\":4,\"type\":\"ringbuf\",\"name\":\"events2\",\"max_entries\":%d,\"bytes_memlock\":0}", ring * 1048576 / 2
        printf "]\n" }' > "$D/maps.json"
    echo "$D"
}

# ── chain (8.5.5) ─────────────────────────────────────────────────────────────
# mkinc <имя> <с_цепочкой> <всего> — снимок инцидентов
mkinc() {
    local n=$1 w=$2 t=$3 i
    local f=$T/$n.json
    { echo '['; for ((i = 1; i <= t; i++)); do
        [ "$i" -gt 1 ] && echo ','
        if [ "$i" -le "$w" ]; then echo "{\"id\":\"i$i\",\"process_chain\":[\"nginx\",\"bash\"]}"; else echo "{\"id\":\"i$i\",\"process_chain\":[]}"; fi
      done; echo ']'; } > "$f"
    echo "$f"
}
# mkchm <имя> [reads0=10 reads1=10 ev0=1000 ev1=900000 state=active series=yes] — снимки метрик окна; печатает «M0 M1»
mkchm() {
    local n=$1; shift
    local reads0=10 reads1=10 ev0=1000 ev1=900000 state=active series=yes
    for kv in "$@"; do eval "${kv%%=*}='${kv#*=}'"; done
    local a=$T/$n-m0.txt b=$T/$n-m1.txt
    : > "$a"; : > "$b"
    if [ "$series" = yes ]; then
        echo "ebpf_guard_lineage_proc_reads_total $reads0" >> "$a"; echo "ebpf_guard_lineage_proc_reads_total $reads1" >> "$b"
        echo "ebpf_guard_events_total{type=\"syscall\"} $ev0" >> "$a"; echo "ebpf_guard_events_total{type=\"syscall\"} $ev1" >> "$b"
    fi
    [ "$state" != none ] && echo "ebpf_guard_proc_table_state{state=\"$state\"} 1" >> "$b"
    echo "$a $b"
}
