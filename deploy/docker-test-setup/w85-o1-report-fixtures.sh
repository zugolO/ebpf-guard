#!/bin/bash
# Фикстуры эмиттера w85-o1-report.sh и мутации. --mutate: каждая мутация ОБЯЗАНА покраснить фикстуры.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
EMIT=${EMITTER:-$HERE/w85-o1-report.sh}
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fails=0
ok()  { echo "ok   $1"; }
bad() { echo "FAIL $1"; fails=$((fails + 1)); }

# mk <имя> [a41=… b41=… a56=0 b56=… anA=… anB=… drA=… drB=… cpuA=… cpuB=… alA=… alB=… ctl=… done=yes win=600 drop=<файл> bt=<вариант>]
#   ctl — «ПРАВИЛО=A:B» через пробел, по умолчанию все socket-правила 3:3, fork_bomb 0:4
mk() {
    local n=$1; shift
    local a41=5000 b41=5010 a56=0 b56=900 anA=20 anB=22 drA=695 drB=695 cpuA=40 cpuB=41 alA=7000000000 alB=7100000000 done=yes win=600 dropf="" btv=ok ctlA="" ctlB="" nodrops=0
    for kv in "$@"; do eval "${kv%%=*}='${kv#*=}'"; done
    local d=$T/$n; mkdir -p "$d/A" "$d/B"
    [ "$done" = yes ] && echo "done 2026-10-13T00:00:00Z" > "$d/DONE" || echo "die: x" > "$d/DONE"
    echo "$win" > "$d/window_s.txt"
    local r
    for r in A B; do
        local e41 e56 an dr cpu al
        if [ $r = A ]; then e41=$a41; e56=$a56; an=$anA; dr=$drA; cpu=$cpuA; al=$alA; else e41=$b41; e56=$b56; an=$anB; dr=$drB; cpu=$cpuB; al=$alB; fi
        {
            echo "ebpf_guard_syscall_events_by_nr_total{nr=\"41\"} 100"
            echo "ebpf_guard_syscall_events_by_nr_total{nr=\"56\"} 0"
            echo "ebpf_guard_syscall_events_by_nr_total{nr=\"59\"} 10"
            echo "ebpf_guard_alert_volume_by_event_type_total{event_type=\"syscall\",rule_id=\"anomaly_detection\"} 100"
            [ $nodrops = 1 ] || echo "ebpf_guard_events_dropped_total{collector=\"fileaccess\",reason=\"path_denylist\"} 1000"
            echo "process_cpu_seconds_total 500"
            echo "go_memstats_alloc_bytes_total 1000000000"
        } > "$d/$r/m0.txt"
        {
            echo "ebpf_guard_syscall_events_by_nr_total{nr=\"41\"} $((100 + e41))"
            echo "ebpf_guard_syscall_events_by_nr_total{nr=\"56\"} $e56"
            echo "ebpf_guard_syscall_events_by_nr_total{nr=\"59\"} 60"
            echo "ebpf_guard_alert_volume_by_event_type_total{event_type=\"syscall\",rule_id=\"anomaly_detection\"} $((100 + an))"
            [ $nodrops = 1 ] || echo "ebpf_guard_events_dropped_total{collector=\"fileaccess\",reason=\"path_denylist\"} $((1000 + dr))"
            echo "process_cpu_seconds_total $((500 + cpu))"
            echo "go_memstats_alloc_bytes_total $((1000000000 + al))"
        } > "$d/$r/m1.txt"
        local c2=1 ex=1 arp=1 fb=0; [ $r = B ] && fb=4
        local o; o=$([ $r = A ] && echo "$ctlA" || echo "$ctlB")
        for kv in $o; do eval "${kv%%=*}='${kv#*=}'"; done
        printf 'c2_raw_socket_shell %s\nexfil_raw_socket_by_non_root %s\nmitre_arp_spoof_raw_socket %s\nimpact_fork_bomb_pattern %s\n' "$c2" "$ex" "$arp" "$fb" > "$d/$r/ctl.txt"
    done
    case "$btv" in
        ok)      printf '@s[2, 1]: 9000\n@s[2, 3]: 20\n@s[17, 2]: 5\n@s[1, 1]: 975\n@cl[0]: 500\n@cl[65534]: 12\n' > "$d/bt.txt" ;;
        nosock)  printf '@cl[0]: 500\n' > "$d/bt.txt" ;;
    esac
    [ -z "$dropf" ] || rm -f "$d/$dropf"
    echo "$d"
}
want() { # <имя> <каталог> <шаблон> [ENV=… …]
    local name=$1 dir=$2 pat=$3; shift 3
    local out; out=$(env OUT="$dir" "$@" bash "$EMIT" 2>&1)
    if echo "$out" | grep -aqE "$pat"; then ok "$name"; else bad "$name — нет «${pat}»"; echo "$out" | sed 's/^/    | /' | head -16; fi
}
want good           "$(mk good)"                                       '^ДОСТИГНУТО: 8\.5\.O1p .*\+900 событий'
want good-ctl       "$(mk good-c)"                                     '^ДОСТИГНУТО: 8\.5\.O1c '
want share          "$(mk share)"                                      '^ИЗМЕРЕНО: 8\.5\.O1s .*вызовов 10000, из них SOCK_RAW или AF_PACKET .* 25 = 0\.25%; clone вызовов 512'
want anom-edge      "$(mk edge anA=100 anB=120)"                       '^ДОСТИГНУТО: 8\.5\.O1p '
want anom-over      "$(mk over anA=100 anB=121)"                       '^ПРОВАЛЕН: 8\.5\.O1p .*anomaly_detection B 121 > A 100 \+ полоса 20'
want floor19        "$(mk floor anA=64 anB=82)"                        '^  anomaly_detection: A 64, B 82, полоса max\(2·√A, 19\) = 19'
want floor19-ok     "$(mk floor2 anA=64 anB=82)"                       '^ДОСТИГНУТО: 8\.5\.O1p '
want floor-off      "$(mk flooroff anA=64 anB=82)"                     '^ПРОВАЛЕН: 8\.5\.O1p .*B 82 > A 64 \+ полоса 16' AB_NULL_GAP=0
want drops          "$(mk drops drB=696)"                              '^ПРОВАЛЕН: 8\.5\.O1p .*дропы B 696 > A 695'
want alloc-edge     "$(mk alle alA=1000000000 alB=1040000000)"         '^ДОСТИГНУТО: 8\.5\.O1p '
want alloc-over     "$(mk allo alA=1000000000 alB=1040000001)"         '^ПРОВАЛЕН: 8\.5\.O1p .*аллокации'
want no-drop-series "$(mk nodrop nodrops=1)"                           '^НЕИЗМЕРИМ: 8\.5\.O1p .*da'
want ctl-socket-dead "$(mk cdead ctlB='ex=0')"                         '^ПРОВАЛЕН: 8\.5\.O1c .*exfil_raw_socket_by_non_root у B не сработало'
want ctl-fork-B-mute "$(mk cfb ctlB='fb=0')"                           '^ПРОВАЛЕН: 8\.5\.O1c .*impact_fork_bomb_pattern у B'
want ctl-fork-A-loud "$(mk cfa ctlA='fb=2')"                           '^ПРОВАЛЕН: 8\.5\.O1c .*у A \(clone закрыт\) = 2'
want ctl-none       "$(mk cnone ctlA='arp=none')"                      '^НЕИЗМЕРИМ: 8\.5\.O1c .*A/mitre_arp_spoof_raw_socket: счёт не получен'
want no-socket-bt   "$(mk nosock btv=nosock)"                          '^НЕИЗМЕРИМ: 8\.5\.O1s '
want not-done       "$(mk nd done=no)"                                 '^НЕИЗМЕРИМ: 8\.5\.O1 .*прогон не завершён'
want no-metrics     "$(mk nomet dropf=B/m1.txt)"                       '^НЕИЗМЕРИМ: 8\.5\.O1 .*B: нет m1\.txt'
want no-bt          "$(mk nobt dropf=bt.txt)"                          '^НЕИЗМЕРИМ: 8\.5\.O1 .*нет bt\.txt'
out=$(OUT="$T/нет" bash "$EMIT" 2>&1); echo "$out" | grep -aq '^НЕИЗМЕРИМ: 8\.5\.O1 .*нет каталога' && ok no-dir || bad no-dir

if [ "${1:-}" = --mutate ]; then
    mut() { # <имя> <sed-выражение>
        local f; f=$(mktemp); sed "$2" "$EMIT" > "$f"
        if cmp -s "$f" "$EMIT"; then bad "мутация $1 не применилась"; rm -f "$f"; return; fi
        if EMITTER=$f bash "$0" 2>/dev/null | grep -q '^FAIL'; then ok "мутация $1 покраснила фикстуры"; else bad "мутация $1 НЕ покраснила фикстуры"; fi
        rm -f "$f"
    }
    mut band-gate      's/\[ "\$B" -le \$((A + band)) \] || fail=/true || fail=/'
    mut floor-default  's/AB_NULL_GAP=\${AB_NULL_GAP:-19}/AB_NULL_GAP=${AB_NULL_GAP:-0}/'
    mut floor-apply    's/\[ "\$AB_NULL_GAP" -gt "\$band" \] \&\& band=\$AB_NULL_GAP/true/'
    mut drops-gate     's/\[ "\$db" -le "\$da" \] || fail=/true || fail=/'
    mut alloc-gate     's/awk -v a="\$la" -v b="\$lb" -v p="\$ALLOC_NOISE_PCT" .BEGIN { exit !(b <= a \* (1 + p \/ 100)) }. || fail=/true || fail=/'
    mut alloc-noise    's/ALLOC_NOISE_PCT=\${ALLOC_NOISE_PCT:-4}/ALLOC_NOISE_PCT=${ALLOC_NOISE_PCT:-40}/'
    mut ctl-socket     's/\[ "\$v" -ge 1 \] || fail="\$fail; \$rule у \$r не сработало"/true/'
    mut ctl-fork-B     's/\[ "\$vb" -ge 1 \] || fail=/true || fail=/'
    mut ctl-fork-A     's/\[ "\$va" -eq 0 \] || fail=/true || fail=/'
    mut done-guard     's/if ! grep -q .\^done. "\$OUT\/DONE" 2>\/dev\/null; then/if false; then/'
    mut absent-zero    's/case "\$x" in ..|.?.) miss="\$miss \$v" ;; esac/true/'
    mut pass-share     's/if (kv\[2\] == 3 || kv\[1\] == 17)/if (kv[2] == 3)/'
fi
echo "-- fails=$fails"
[ "$fails" = 0 ]
