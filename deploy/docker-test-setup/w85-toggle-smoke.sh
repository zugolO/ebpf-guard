#!/bin/bash
# Волна 8.5, этап 1: переключатель предикатов на ходу (инструмент пары A/B 8.5.3).
set -u
SRC=${W85_SRC:-/root/w85-src}; CTL="$(cd "$(dirname "$0")" && pwd)/w85-ctl.py"; BASECFG="${W85_BASECFG:-$SRC/deploy/docker-test-setup/config-test.yaml}"; RUN=/root/w85-run-toggle; BIN=$SRC/build/ebpf-guard
TOKEN=w85smoketoken0123456789abcdef01234
rm -rf "$RUN"; mkdir -p "$RUN"
python3 - "$RUN" "$SRC" "$BASECFG" <<'PY'
import sys
run, src = sys.argv[1:3]
s = open(sys.argv[-1]).read()
def sub(old, new):
    global s
    assert old in s, old
    s = s.replace(old, new, 1)
sub('bind_address: "0.0.0.0:19090"', 'bind_address: "127.0.0.1:19193"')
sub('path: /var/lib/ebpf-guard/profiler-state.json', 'path: %s/profiler-state.json' % run)
sub('path: "/var/lib/ebpf-guard/test-events.db"', 'path: "%s/events.db"' % run)
sub('audit_log: "/var/log/ebpf-guard/audit.jsonl"', 'audit_log: "%s/audit.jsonl"' % run)
sub('path: "/opt/ebpf-guard/rules/"', 'path: "%s/rules/"' % src)
sub('hot_reload: true', 'hot_reload: false')
sub('admin_token: ""', 'admin_token: "w85smoketoken0123456789abcdef01234"')
sub('viewer_token: ""', 'viewer_token: "w85viewertoken0123456789abcdef0123"')
sub('unix_socket:\n    enabled: true', 'unix_socket:\n    enabled: false')
sub('observer_exclude:\n    enabled: true', 'observer_exclude:\n    enabled: false')
sub('kernel_filter:\n    enabled: true\n', 'kernel_filter:\n    enabled: true\n    arg_predicates:\n      enabled: false\n      counters_interval: 2s\n')
open(run + '/config.yaml', 'w').write(s)
PY
cd "$RUN"
setsid nohup "$BIN" --config "$RUN/config.yaml" --log-level=info > "$RUN/agent.log" 2>&1 &
APID=$!
for i in $(seq 1 60); do grep -q "kernel_pred: state changed\|syscall: collector enabled" "$RUN/agent.log" 2>/dev/null && break; sleep 1; done; sleep 6
M() { curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:19193/metrics; }
nr9() { M | awk '$1=="ebpf_guard_syscall_events_by_nr_total{nr=\"9\"}"{print $2}'; }
state() { M | grep '^ebpf_guard_kernel_predicate_state' | grep ' 1$' | sed 's/.*state="\([^"]*\)".*/\1/'; }
sw() { curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d "{\"enabled\":$1}" http://127.0.0.1:19193/api/v1/tuning/kernel-predicates; echo; }
benign() { python3 "$CTL" 0 1500 > /dev/null; }
echo "GET: $(curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:19193/api/v1/tuning/kernel-predicates)  state=$(state)"
a=$(nr9); benign; sleep 3; b=$(nr9); echo "A (off):  mmap events from the payload: $((b-a))"
echo "POST true:  $(sw true)  state=$(state)"
a=$(nr9); benign; sleep 3; b=$(nr9); echo "B (on):   mmap events from the payload: $((b-a))"
echo "POST true again: $(sw true)"
echo "POST false: $(sw false) state=$(state)"
a=$(nr9); benign; sleep 3; b=$(nr9); echo "A2 (off): mmap events from the payload: $((b-a))"
kill $APID; sleep 2; kill -9 $APID 2>/dev/null
