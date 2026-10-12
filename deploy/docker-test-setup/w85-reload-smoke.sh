#!/bin/bash
# Волна 8.5, этап 1: перезагрузка правил перепрограммирует карту ядра БЕЗ правки C.
# Второй агент из /root/w85-src на порту 19192 с копией каталога правил.
set -u
SRC=${W85_SRC:-/root/w85-src}; CTL="$(cd "$(dirname "$0")" && pwd)/w85-ctl.py"; BASECFG="${W85_BASECFG:-$SRC/deploy/docker-test-setup/config-test.yaml}"; RUN=/root/w85-run-reload; BIN=$SRC/build/ebpf-guard
TOKEN=w85smoketoken0123456789abcdef01234
rm -rf "$RUN"; mkdir -p "$RUN"; cp -r $SRC/rules "$RUN/rules"; find "$RUN/rules" -name '._*' -delete
python3 - "$RUN" "$BASECFG" <<'PY'
import sys
run = sys.argv[1]
s = open(sys.argv[-1]).read()
def sub(old, new):
    global s
    assert old in s, old
    s = s.replace(old, new, 1)
sub('bind_address: "0.0.0.0:19090"', 'bind_address: "127.0.0.1:19192"')
sub('path: /var/lib/ebpf-guard/profiler-state.json', 'path: %s/profiler-state.json' % run)
sub('path: "/var/lib/ebpf-guard/test-events.db"', 'path: "%s/events.db"' % run)
sub('audit_log: "/var/log/ebpf-guard/audit.jsonl"', 'audit_log: "%s/audit.jsonl"' % run)
sub('path: "/opt/ebpf-guard/rules/"', 'path: "%s/rules/"' % run)
sub('admin_token: ""', 'admin_token: "w85smoketoken0123456789abcdef01234"')
sub('viewer_token: ""', 'viewer_token: "w85viewertoken0123456789abcdef0123"')
sub('unix_socket:\n    enabled: true', 'unix_socket:\n    enabled: false')
sub('observer_exclude:\n    enabled: true', 'observer_exclude:\n    enabled: false')
sub('kernel_filter:\n    enabled: true\n', 'kernel_filter:\n    enabled: true\n    arg_predicates:\n      enabled: true\n      counters_interval: 2s\n')
open(run + '/config.yaml', 'w').write(s)
PY
cd "$RUN"
setsid nohup "$BIN" --config "$RUN/config.yaml" --log-level=info > "$RUN/agent.log" 2>&1 &
APID=$!
for i in $(seq 1 60); do grep -q "kernel_pred: state changed" "$RUN/agent.log" 2>/dev/null && break; kill -0 $APID 2>/dev/null || { echo DIED; tail "$RUN/agent.log"; exit 3; }; sleep 1; done
sleep 4
M() { curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:19192/metrics; }
nr9() { M | awk '$1=="ebpf_guard_syscall_events_by_nr_total{nr=\"9\"}"{print $2}'; }
state() { M | grep '^ebpf_guard_kernel_predicate_state' | grep ' 1$' | sed 's/.*state="\([^"]*\)".*/\1/'; }
benign() { python3 "$CTL" 0 1500 > /dev/null; }
reload() { sed -i "s/anomaly_threshold: 0\.[0-9]*/anomaly_threshold: $1/" "$RUN/config.yaml"; sleep 4; }

echo "T0 state=$(state)"
a=$(nr9); benign; sleep 3; b=$(nr9); echo "T1 predicate active: mmap events from 1500 benign loops (3000 enter+exit): $((b-a))"

cat > "$RUN/rules/zz-w85-mut.yaml" <<'YAML'
rules:
  - id: w85_mut_comm_any_nr
    name: "w85 mutation: comm rule without nr"
    description: "Smoke mutation: a comm rule that can match ANY syscall number removes the kernel predicate."
    event_type: syscall
    condition:
      field: comm
      op: eq
      values: ["w85-never-runs"]
    severity: warning
    action: alert
YAML
reload 0.71
echo "T2 after adding comm-any-nr rule + reload: state=$(state)"
grep -E "kernel_pred: (state changed|syscall number forwarded)" "$RUN/agent.log" | tail -4 | cut -c1-260
a=$(nr9); benign; sleep 3; b=$(nr9); echo "T3 predicate removed: mmap events from the same payload: $((b-a))"

rm -f "$RUN/rules/zz-w85-mut.yaml"
reload 0.72
echo "T4 after removing the rule + reload: state=$(state)"
a=$(nr9); benign; sleep 3; b=$(nr9); echo "T5 predicate back: mmap events from the same payload: $((b-a))"
kill $APID; sleep 2; kill -9 $APID 2>/dev/null
