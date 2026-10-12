#!/bin/bash
# w85-f3-smoke.sh <SRC> — волна 8.5, F3: самоисключение служебных bpf() на ЖИВОМ ядре.
# Второй агент из SRC (свой порт 19194, стор, правила; рабочий агент не трогается) и ДВА процесса-
# контроля одного кода: P — «агент» (его tgid программируется в agent_pid_map syscall-объекта
# через bpftool: настоящий агент так же программируется из Go), Q — чужой процесс.
#   каждый: N служебных bpf() (cmd 1,2,4,24 по N/4) сырым syscall (libc-обёртка подменила бы номер),
#   затем PROG_LOAD (cmd 5, правило rootkit_bpf_prog_load_suspicious, comm python3).
# Свидетельство — счётчик ядра syscall_counts (tgid, nr=321): у P ровно 2N (enter и exit), у Q нет
# записи; алерт на cmd 5 есть у ОБОИХ (разрушительное от «агента» идёт как раньше; чужой не затронут).
# Режимы: run <SRC> (на стенде) и verdict <DIR> (чистая функция над снимками; фикстуры).
set -u
MODE=${1:-}
verdict() {
    local D=$1 N cls="" fail="" pn qn pa qa
    N=$(cat "$D/n.txt" 2>/dev/null)
    [ -n "$N" ] || { echo "НЕИЗМЕРИМ: F3 НЕИЗМЕРИМ (класс НАЗВАН: нет n.txt)"; return; }
    for f in counts.json alerts.json pids.txt; do [ -s "$D/$f" ] || cls="$cls; нет $f"; done
    [ -n "$cls" ] && { echo "НЕИЗМЕРИМ: F3 НЕИЗМЕРИМ (класс НАЗВАН:${cls#;})"; return; }
    read -r P Q < "$D/pids.txt"
    # syscall_counts: ключ {tgid, nr}, значение {n, ...}
    pn=$(jq -r --argjson p "$P" '[.[] | select((.formatted // .).key.tgid == $p and (.formatted // .).key.nr == 321) | (.formatted // .).value.n] | add // 0' "$D/counts.json" 2>/dev/null)
    qn=$(jq -r --argjson q "$Q" '[.[] | select((.formatted // .).key.tgid == $q and (.formatted // .).key.nr == 321) | (.formatted // .).value.n] | add // 0' "$D/counts.json" 2>/dev/null)
    case "$pn$qn" in *[!0-9]*|'') echo "НЕИЗМЕРИМ: F3 НЕИЗМЕРИМ (класс НАЗВАН: syscall_counts не разобран jq)"; return ;; esac
    pa=$(jq -r --argjson p "$P" '[(.alerts // .)[] | select((.rule_id // .RuleID) == "rootkit_bpf_prog_load_suspicious" and ((.pid // .PID) == $p))] | length' "$D/alerts.json" 2>/dev/null)
    qa=$(jq -r --argjson q "$Q" '[(.alerts // .)[] | select((.rule_id // .RuleID) == "rootkit_bpf_prog_load_suspicious" and ((.pid // .PID) == $q))] | length' "$D/alerts.json" 2>/dev/null)
    echo "  N служебных вызовов на процесс: $N (событий enter+exit: $((2 * N)))"
    echo "  P («агент», pid $P): счётчик ядра syscall_counts(tgid,321) = $pn (ожидается $((2 * N))), алертов PROG_LOAD: ${pa:-?}"
    echo "  Q (чужой, pid $Q): счётчик ядра syscall_counts(tgid,321) = $qn (ожидается 0), алертов PROG_LOAD: ${qa:-?}"
    [ "$pn" = $((2 * N)) ] || fail="$fail; у «агента» служебные не исключены точно (счёт $pn ≠ $((2 * N)))"
    [ "$qn" = 0 ] || fail="$fail; у чужого процесса служебные исключены ($qn) — самоисключение не по tgid"
    [ "${pa:-0}" -ge 1 ] || fail="$fail; разрушительный cmd 5 от «агента» не дал алерта (исключён зря)"
    [ "${qa:-0}" -ge 1 ] || fail="$fail; cmd 5 от чужого процесса не дал алерта"
    if [ -n "$fail" ]; then echo "ПРОВАЛЕН: F3 ПРОВАЛЕН (${fail#; })"
    else echo "ДОСТИГНУТО: F3 ДОСТИГНУТО (служебные bpf() от tgid «агента» исключены ровно ($pn = 2×$N), чужого — нет; PROG_LOAD от обоих даёт алерт)"; fi
}
if [ "$MODE" = verdict ]; then verdict "${2:?DIR}"; exit 0; fi
[ "$MODE" = run ] || { echo "usage: w85-f3-smoke.sh run <SRC> | verdict <DIR>" >&2; exit 2; }

SRC=${2:?SRC}; N=${N:-200}
RUN=${RUN:-/root/w85-run-f3}; BIN=$SRC/build/ebpf-guard; PORT=19194; TOKEN=w85f3smoketoken0123456789abcdef012
CTL=$(cd "$(dirname "$0")" && pwd)/w85-f3-ctl.py
BASECFG=$SRC/deploy/docker-test-setup/config-test.yaml
rm -rf "$RUN"; mkdir -p "$RUN"
python3 - "$RUN" "$SRC" "$BASECFG" "$PORT" <<'PY'
import sys
run, src, base, port = sys.argv[1:5]
s = open(base).read()
def sub(old, new):
    global s
    assert old in s, old
    s = s.replace(old, new, 1)
sub('bind_address: "0.0.0.0:19090"', 'bind_address: "127.0.0.1:%s"' % port)
sub('path: /var/lib/ebpf-guard/profiler-state.json', 'path: %s/profiler-state.json' % run)
sub('path: "/var/lib/ebpf-guard/test-events.db"', 'path: "%s/events.db"' % run)
sub('audit_log: "/var/log/ebpf-guard/audit.jsonl"', 'audit_log: "%s/audit.jsonl"' % run)
sub('path: "/opt/ebpf-guard/rules/"', 'path: "%s/rules/"' % src)
sub('hot_reload: true', 'hot_reload: false')
sub('admin_token: ""', 'admin_token: "w85f3smoketoken0123456789abcdef012"')
sub('viewer_token: ""', 'viewer_token: "w85f3viewertoken0123456789abcdef01"')
sub('unix_socket:\n    enabled: true', 'unix_socket:\n    enabled: false')
sub('observer_exclude:\n    enabled: true', 'observer_exclude:\n    enabled: false')
open(run + '/config.yaml', 'w').write(s)
PY
[ $? -eq 0 ] || { echo "CONFIG FAIL"; exit 2; }
cd "$RUN"
setsid nohup "$BIN" --config "$RUN/config.yaml" --log-level=info > "$RUN/agent.log" 2>&1 &
APID=$!
for i in $(seq 1 60); do grep -q "kernel_filter: agent self-exclusion enabled" "$RUN/agent.log" 2>/dev/null && break
    kill -0 $APID 2>/dev/null || { echo "AGENT DIED"; tail -20 "$RUN/agent.log"; exit 3; }; sleep 1; done
sleep 4
# Карты именно ЭТОГО агента: на стенде работает и хостовый агент со своей программой trace_sys_enter
# (объект без F3), поэтому программа выбирается по картам — той, у кого есть и agent_pid_map, и
# syscall_counts, и она единственна (после старта второго агента таких программ — одна).
read -r PROG MAPID CNT < <(python3 - <<'PY'
import json, subprocess
progs = json.loads(subprocess.check_output(["bpftool", "-j", "prog", "show"]))
maps = {m["id"]: m.get("name", "") for m in json.loads(subprocess.check_output(["bpftool", "-j", "map", "show"]))}
found = []
for p in progs:
    if p.get("name") != "trace_sys_enter":
        continue
    names = {maps.get(i, ""): i for i in p.get("map_ids", [])}
    if "agent_pid_map" in names and "syscall_counts" in names:
        found.append((p["id"], names["agent_pid_map"], names["syscall_counts"]))
print(*found[-1]) if found else print("- - -")
PY
)
[ "$PROG" != "-" ] || { echo "НЕИЗМЕРИМ: F3 НЕИЗМЕРИМ (класс НАЗВАН: ни у одной программы trace_sys_enter нет agent_pid_map вместе с syscall_counts — объект без F3)"; kill $APID; exit 0; }
echo "agent pid $APID prog $PROG agent_pid_map id $MAPID syscall_counts id $CNT"
# P: процесс-«агент». Стартует, ждёт файл-сигнал, делает N служебных + PROG_LOAD; его pid пишется в карту ДО сигнала.
python3 "$CTL" "$RUN/go-p" "$N" > "$RUN/p.out" 2>&1 & P=$!
python3 "$CTL" "$RUN/go-q" "$N" > "$RUN/q.out" 2>&1 & Q=$!
sleep 1
bpftool map update id "$MAPID" key 0 0 0 0 value $(python3 -c "import struct,sys;print(' '.join(str(b) for b in struct.pack('<I',$P)))") any \
    || { echo "НЕИЗМЕРИМ: F3 НЕИЗМЕРИМ (класс НАЗВАН: bpftool не записал agent_pid_map)"; kill $APID $P $Q; exit 0; }
touch "$RUN/go-p"; wait $P; sleep 2; touch "$RUN/go-q"; wait $Q; sleep 8
bpftool map dump id "$CNT" -j > "$RUN/counts.json" 2>"$RUN/counts.err"
curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$PORT/api/v1/alerts?limit=2000" > "$RUN/alerts.json"
echo "$P $Q" > "$RUN/pids.txt"; echo "$N" > "$RUN/n.txt"
kill $APID; sleep 2; kill -9 $APID 2>/dev/null
verdict "$RUN"
