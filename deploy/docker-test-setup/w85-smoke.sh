#!/bin/bash
# Волна 8.5, этап 1: смок F1/F2 на стенде — верификатор, предикаты, счётчики,
# положительные контроли. Второй агент ИЗ ОТДЕЛЬНОГО КАТАЛОГА на другом порту,
# рабочий ebpf-guard-test не трогается. W85_SRC — каталог сборки (по умолчанию /root/w85-src). Использование: w85-smoke.sh <on|off> <сек>
set -u
MODE=${1:-on}; WIN=${2:-70}
SRC=${W85_SRC:-/root/w85-src}; CTL="$(cd "$(dirname "$0")" && pwd)/w85-ctl.py"; BASECFG="${W85_BASECFG:-$SRC/deploy/docker-test-setup/config-test.yaml}"; RUN=/root/w85-run-$MODE
BIN=$SRC/build/ebpf-guard
TOKEN=w85smoketoken0123456789abcdef01234
rm -rf "$RUN"; mkdir -p "$RUN"
python3 - "$MODE" "$RUN" "$SRC" "$BASECFG" <<'PY'
import re, sys
mode, run, src = sys.argv[1:4]
s = open(sys.argv[-1]).read()
def sub(old, new, count=1):
    global s
    assert old in s, old
    s = s.replace(old, new, count)
sub('bind_address: "0.0.0.0:19090"', 'bind_address: "127.0.0.1:19191"')
sub('path: /var/lib/ebpf-guard/profiler-state.json', 'path: %s/profiler-state.json' % run)
sub('path: "/var/lib/ebpf-guard/test-events.db"', 'path: "%s/events.db"' % run)
sub('audit_log: "/var/log/ebpf-guard/audit.jsonl"', 'audit_log: "%s/audit.jsonl"' % run)
sub('path: "/opt/ebpf-guard/rules/"', 'path: "%s/rules/"' % src)
sub('hot_reload: true', 'hot_reload: false')
sub('admin_token: ""', 'admin_token: "w85smoketoken0123456789abcdef01234"')
sub('viewer_token: ""', 'viewer_token: "w85viewertoken0123456789abcdef0123"')
sub('unix_socket:\n    enabled: true', 'unix_socket:\n    enabled: false')
sub('observer_exclude:\n    enabled: true', 'observer_exclude:\n    enabled: false')
sub('kernel_filter:\n    enabled: true\n', 'kernel_filter:\n    enabled: true\n    arg_predicates:\n      enabled: %s\n      counters_interval: 2s\n' % ('true' if mode == 'on' else 'false'))
open(run + '/config.yaml', 'w').write(s)
PY
[ $? -eq 0 ] || { echo "CONFIG FAIL"; exit 2; }
cd "$RUN"
setsid nohup "$BIN" --config "$RUN/config.yaml" --log-level=info > "$RUN/agent.log" 2>&1 &
APID=$!
echo "agent pid $APID mode=$MODE"
# ждём подъёма (до 60 с): строка про предикаты или сбой загрузки
for i in $(seq 1 60); do
  if grep -q "kernel_pred: state changed\|syscall: collector creation failed\|failed to load" "$RUN/agent.log" 2>/dev/null; then break; fi
  kill -0 $APID 2>/dev/null || { echo "AGENT DIED"; tail -20 "$RUN/agent.log"; exit 3; }
  sleep 1
done
sleep 5
echo "--- kernel_pred / syscall collector lines"
grep -E "kernel_pred|kernel_filter: enabled|syscall: collector|verifier|load.*fail|failed to (load|attach)|collector.*(fail|error)" "$RUN/agent.log" | head -20

M() { curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:19191/metrics; }
snap() { M | grep -E '^ebpf_guard_(syscall_events_by_nr_total|syscall_events_kernel_filtered_total|syscall_counts_folded_total|kernel_predicate_state|kernel_predicate_nr)' | grep -vE ' 0$' ; }
M > "$RUN/m0.txt"
T0=$(date +%s)
mkdir -p /tmp/w85 && cp /usr/bin/python3 /tmp/w85/xmrig
# контроли: атака ×5 и обычные ×3000, дважды (в начале и в середине окна)
python3 "$CTL" 5 3000 > "$RUN/ctl1.out" 2>&1
/tmp/w85/xmrig -c 'pass' > "$RUN/xmrig.out" 2>&1
sleep $((WIN/2))
python3 "$CTL" 5 3000 > "$RUN/ctl2.out" 2>&1
sleep $((WIN/2))
M > "$RUN/m1.txt"
curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:19191/api/v1/alerts?limit=1000" > "$RUN/alerts.json"
echo "--- series (nonzero) at end"
grep -E '^ebpf_guard_(syscall_events_by_nr_total|syscall_events_kernel_filtered_total|syscall_counts_folded_total|kernel_predicate_state|kernel_predicate_nr)' "$RUN/m1.txt" | grep -vE ' 0$'
echo "--- alerts of the controls"
python3 - "$RUN/alerts.json" <<'PY'
import json, sys, collections
d = json.load(open(sys.argv[1]))
al = d.get('alerts', d) if isinstance(d, dict) else d
c = collections.Counter()
for a in al:
    rid = a.get('rule_id') or a.get('RuleID')
    if rid in ('rootkit_anonymous_exec_memory','sigma_mprotect_exec_heap','mitre_sandbox_detect_cpuid','cryptominer_binary_name'):
        c[(rid, a.get('comm') or a.get('Comm'))] += 1
for k, v in sorted(c.items()): print(k, v)
print("alerts total", len(al))
PY
# Сверка F2: слитое в профиль = отброшенное ядром (до единицы); слив идёт раз в
# counters_interval, поэтому до трёх повторов снимка, а не один.
if [ "$MODE" = on ]; then
  ok=0
  for try in 1 2 3; do
    sleep 3; M > "$RUN/m2.txt"
    kf=$(awk '/^ebpf_guard_syscall_events_kernel_filtered_total\{/{s+=$2} END{printf "%d", s}' "$RUN/m2.txt")
    cf=$(awk '/^ebpf_guard_syscall_counts_folded_total\{/{s+=$2} END{printf "%d", s}' "$RUN/m2.txt")
    [ "$kf" = "$cf" ] && [ "$kf" != 0 ] && { ok=1; break; }
  done
  [ $ok = 1 ] && echo "CHECK counts_folded = kernel_filtered: PASS ($cf = $kf)" || echo "CHECK counts_folded = kernel_filtered: FAIL (folded=$cf kernel_filtered=$kf)"
  grep -E '^ebpf_guard_syscall_counts_map_(fill_ratio|live_entries)' "$RUN/m2.txt"
fi
cat "$RUN/ctl1.out" "$RUN/ctl2.out" "$RUN/xmrig.out" | head -5
kill $APID; sleep 2; kill -9 $APID 2>/dev/null
echo "--- errors in agent log"
grep -iE "error|panic|verifier" "$RUN/agent.log" | grep -viE "k3s|kubernetes|k8s|docker|runtime enricher|dns|tls|uprobe|lsm|http_plaintext|gpu|cloud|iouring" | head -10
