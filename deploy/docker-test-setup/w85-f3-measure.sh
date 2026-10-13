#!/bin/bash
# w85-u1-host-smoke.sh <SRC> — замер F3 (кто делает bpf() у агента): второй агент из SRC (порт 19196, свой стор и правила
# из SRC; рабочий агент не трогается) и bpftrace по (comm, pid, cmd) 30 с; сравнение с by_nr{321}.
set -u
SRC=${1:?SRC}; RUN=${RUN:-/root/w85-run-bt}; BIN=$SRC/build/ebpf-guard; PORT=19196; TOKEN=w85u1smoketoken0123456789abcdef012
rm -rf "$RUN"; mkdir -p "$RUN"
python3 - "$RUN" "$SRC" "$SRC/deploy/docker-test-setup/config-test.yaml" "$PORT" <<'PY'
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
sub('admin_token: ""', 'admin_token: "w85u1smoketoken0123456789abcdef012"')
sub('viewer_token: ""', 'viewer_token: "w85u1viewertoken0123456789abcdef01"')
sub('unix_socket:\n    enabled: true', 'unix_socket:\n    enabled: false')
sub('observer_exclude:\n    enabled: true', 'observer_exclude:\n    enabled: false')
open(run + '/config.yaml', 'w').write(s)
PY
cd "$RUN"
setsid nohup "$BIN" --config "$RUN/config.yaml" --log-level=info > "$RUN/agent.log" 2>&1 &
APID=$!
for i in $(seq 1 60); do grep -q "syscall: collector enabled" "$RUN/agent.log" 2>/dev/null && break; kill -0 $APID 2>/dev/null || { echo "AGENT DIED"; tail -20 "$RUN/agent.log"; exit 3; }; sleep 1; done
sleep 8
M() { curl -s --max-time 10 -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:19196/metrics" | awk '$1=="ebpf_guard_syscall_events_by_nr_total{nr=\"321\"}"{print $2}'; }
a=$(M)
bpftrace -e 'tracepoint:syscalls:sys_enter_bpf { @c[comm, pid, args->cmd] = count(); @t = count(); } interval:s:30 { exit(); }' > "$RUN/bt.txt" 2>&1
b=$(M)
echo "agent_pid=$APID by_nr321 delta=$((b - a)) за 30 с" >> "$RUN/bt.txt"
curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:19196/metrics" | grep -aE '^ebpf_guard_syscall_(self_excluded_total|events_kernel_filtered_total\{nr="321"\})' >> "$RUN/bt.txt"
cat "$RUN/bt.txt"
kill $APID; sleep 2; kill -9 $APID 2>/dev/null
