#!/bin/bash
# w85-u1-host-smoke.sh <SRC> — U1 на хосте: второй агент из SRC (порт 19195, свой стор и правила
# из SRC; рабочий агент не трогается) и проба w85-u1-smoke.sh против его API.
set -u
SRC=${1:?SRC}; RUN=${RUN:-/root/w85-run-u1}; BIN=$SRC/build/ebpf-guard; PORT=19195; TOKEN=w85u1smoketoken0123456789abcdef012
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
bash "$(dirname "$0")/w85-u1-smoke.sh" "127.0.0.1:$PORT" "$TOKEN" host
kill $APID; sleep 2; kill -9 $APID 2>/dev/null
