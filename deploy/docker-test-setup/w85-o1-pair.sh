#!/bin/bash
# w85-o1-pair.sh <SRC> <OUT> [WIN=600] — волна 8.5, O1 (замер цены, включение решает владелец): два ВТОРЫХ агента одного
# бинаря РАБОТАЮТ ОДНОВРЕМЕННО на одном узле (одно окно, одна нагрузка), рабочий агент не трогается.
#   A — ядерный allowlist по умолчанию (socket(41) в нём уже открыт порцией 4 волны 7, clone(56) нет), F1 включён;
#   B — то же + clone(56), кандидаты F1 [9,10,158,41,56] (F1 для 41 и 56 предиката не выведет — блокеры в тесте
#       TestW85_O1_DeriveForRejectedNrs).
# В окне WIN — bpftrace 0.14 одним скриптом (второй свидетель): socket по (family, type&15), clone по uid.
# После окна — положительные контроли СЫРЫМ syscall (w85-o1-ctl.py) на оба агента, алерты по правилам.
# Выход: $OUT/{A,B}/{m0,m1,ctl.txt}, $OUT/bt.txt, $OUT/DONE; затем эмиттер w85-o1-report.sh.
set -u
SRC=${1:?SRC}; OUT=${2:?OUT}; WIN=${3:-600}; HERE=$(cd "$(dirname "$0")" && pwd)
source "$HERE/w85-second-agent-lib.sh"
rm -rf "$OUT"; mkdir -p "$OUT/A" "$OUT/B"; exec > "$OUT/driver.log" 2>&1
PIDA=""; PIDB=""
stop_all() { for p in $PIDA $PIDB; do kill "$p" 2> /dev/null; done; sleep 2; for p in $PIDA $PIDB; do kill -9 "$p" 2> /dev/null; done; echo "агентов после: $(ps -eo cmd | grep -c '[e]bpf-guard --config')"; }
trap stop_all EXIT
die() { echo "die: $*" > "$OUT/DONE"; echo "DIE: $*"; exit 1; }
echo "[$(date -u +%FT%TZ)] w85-o1-pair git $(cat "$SRC/GIT-HEAD" 2>/dev/null) WIN=$WIN"
[ "$(ps -eo cmd | grep -c '[e]bpf-guard --config')" -eq 1 ] || die "ожидался ровно один (рабочий) агент до запуска"
export SA_CFG_PATCH="$HERE/w85-o1-cfg.py"
W85_O1_ROLE=A sa_start "$SRC" /root/w85-run-o1A 19221 || die "агент A не поднялся"; PIDA=$SA_PID; APIA=$SA_API
W85_O1_ROLE=B sa_start "$SRC" /root/w85-run-o1B 19222 || die "агент B не поднялся"; PIDB=$SA_PID; APIB=$SA_API
echo "A pid $PIDA $APIA; B pid $PIDB $APIB"
mf() { curl -s --max-time 20 -H "Authorization: Bearer $SA_TOKEN" "$1/metrics"; }
for r in A B; do api=$APIA; [ $r = B ] && api=$APIB
    mf "$api" | grep -a '^ebpf_guard_kernel_predicate_state' | grep -a ' 1$' | sed "s/^/$r /"
    mf "$api" | grep -aE '^ebpf_guard_kernel_predicate_nr' | grep -av ' 0$' | sed "s/^/$r /"
done | tee "$OUT/f1-state.txt"
sleep 20
mf "$APIA" > "$OUT/A/m0.txt"; mf "$APIB" > "$OUT/B/m0.txt"; T0=$(date +%s); echo "$T0" > "$OUT/t0.txt"
bpftrace -e "tracepoint:syscalls:sys_enter_socket { @s[args->family, args->type & 15] = count(); }
tracepoint:syscalls:sys_enter_clone { @cl[uid] = count(); }
interval:s:$WIN { exit(); }" > "$OUT/bt.txt" 2>&1
mf "$APIA" > "$OUT/A/m1.txt"; mf "$APIB" > "$OUT/B/m1.txt"; T1=$(date +%s); echo "$((T1 - T0))" > "$OUT/window_s.txt"
echo "окно $((T1 - T0)) с"
# контроли сырым syscall; обе стороны получают ОДНИ И ТЕ ЖЕ вызовы
TC=$(date +%s); echo "$TC" > "$OUT/tc.txt"
for m in sock-c2 sock-exfil sock-arp; do python3 "$HERE/w85-o1-ctl.py" $m 5; done > "$OUT/ctl-run.txt" 2>&1
python3 "$HERE/w85-o1-ctl.py" clone 12 >> "$OUT/ctl-run.txt" 2>&1
sleep 10
cnt() { # <api> <rule> — алертов правила с comm=python3 и timestamp ≥ TC
    curl -s --max-time 30 -H "Authorization: Bearer $SA_TOKEN" "$1/api/v1/alerts?limit=5000" | jq -r --argjson t0 "$TC" --arg r "$2" \
      '[(if type == "array" then . else .alerts // [] end)[] | select((.rule_id // .RuleID) == $r)
        | select(((.timestamp // .Timestamp // "1970-01-01T00:00:00Z") | sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601) >= $t0)
        | select((.comm // "") == "python3")] | length' 2> /dev/null || echo none
}
for r in A B; do api=$APIA; [ $r = B ] && api=$APIB; : > "$OUT/$r/ctl.txt"
    for rule in c2_raw_socket_shell exfil_raw_socket_by_non_root mitre_arp_spoof_raw_socket impact_fork_bomb_pattern; do
        echo "$rule $(cnt "$api" $rule)" >> "$OUT/$r/ctl.txt"
    done
done
cat "$OUT/ctl-run.txt"; echo "A:"; cat "$OUT/A/ctl.txt"; echo "B:"; cat "$OUT/B/ctl.txt"
mf "$APIA" > "$OUT/A/m2.txt"; mf "$APIB" > "$OUT/B/m2.txt"
echo "== O1"
OUT=$OUT bash "$HERE/w85-o1-report.sh" | tee "$OUT/report.txt"
echo "done $(date -u +%FT%TZ)" > "$OUT/DONE"
