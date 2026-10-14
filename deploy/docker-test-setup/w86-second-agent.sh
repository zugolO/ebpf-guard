#!/bin/bash
# Волна 8.6, заход A: второй агент на стенде для смоков (Д16, Д14) — рабочий
# ebpf-guard-test не трогается. Рецепт: память stand-second-agent-smoke.
#
#   w86-second-agent.sh pack                 (мак) пакет дерева -> ssh -> /root/w86-src, make generate && build
#   w86-second-agent.sh config NAME PORT [k=v ...]   (стенд) свой конфиг /root/w86/NAME/config.yaml
#       k=v — точечная правка конфига по пути через точку (значение — YAML): enforcement.dry_run=false
#   w86-second-agent.sh start NAME           (стенд) detached; pid -> /root/w86/NAME/agent.pid
#   w86-second-agent.sh stop NAME            (стенд) SIGTERM, ждёт выхода
set -u
KEY=${STAND_KEY:-$HOME/.ssh/id_ed25519_ebaka2}
HOST=${STAND_HOST:-root@89.125.2.154}
ROOT=/root/w86

case "${1:-}" in
pack)
	repo=$(cd "$(dirname "$0")/../.." && pwd)
	cd "$repo" || exit 1
	git ls-files -co --exclude-standard | grep -vE '^(server-logs|build|plan)' > /tmp/w86-files.txt
	COPYFILE_DISABLE=1 tar czf /tmp/w86-src.tgz -T /tmp/w86-files.txt
	ssh -i "$KEY" "$HOST" 'cat > /root/w86-src.tgz' < /tmp/w86-src.tgz
	ssh -i "$KEY" "$HOST" '
set -e
export PATH=$PATH:/usr/local/go/bin
rm -rf /root/w86-src && mkdir -p /root/w86-src /root/w86 && tar xzf /root/w86-src.tgz -C /root/w86-src
cd /root/w86-src && make generate > /root/w86/generate.log 2>&1 && make build > /root/w86/build.log 2>&1
tail -2 /root/w86/build.log; ls -l build/ebpf-guard; sha256sum build/ebpf-guard | cut -c1-12'
	;;
config)
	name=$2; port=$3; shift 3
	d=$ROOT/$name; mkdir -p "$d/state" "$d/rules"
	rm -rf "$d/rules"; cp -r /root/w86-src/rules "$d/rules"
	python3 - "$d" "$port" "$@" <<'PY'
import sys, yaml
d, port, overrides = sys.argv[1], sys.argv[2], sys.argv[3:]
c = yaml.safe_load(open('/root/w86-src/deploy/docker-test-setup/config-test.yaml'))
c['server']['bind_address'] = '127.0.0.1:' + port
c['rules']['path'] = d + '/rules/'
c['rules']['hot_reload'] = False
c['correlator']['observer_exclude']['enabled'] = False
c['profiler']['state_persistence']['path'] = d + '/state/profiler-state.json'
c['enforcement']['audit_log'] = d + '/state/audit.jsonl'
c['auth']['viewer_token'] = 'w86viewer' + port
c['auth']['admin_token'] = 'w86admin' + port
c['store']['sqlite']['path'] = d + '/state/events.db'
c['notifications']['unix_socket']['enabled'] = False
for o in overrides:
    k, v = o.split('=', 1)
    node = c
    parts = k.split('.')
    for p in parts[:-1]:
        node = node.setdefault(p, {})
    node[parts[-1]] = yaml.safe_load(v)
yaml.safe_dump(c, open(d + '/config.yaml', 'w'), allow_unicode=True, sort_keys=False)
print('config', d + '/config.yaml')
PY
	;;
start)
	d=$ROOT/$2
	cd /root/w86-src || exit 1
	(setsid nohup sh -c "echo \$\$ > $d/agent.pid; exec /root/w86-src/build/ebpf-guard --config=$d/config.yaml --log-level=info" < /dev/null > "$d/agent.log" 2>&1 &)
	sleep 3; echo "pid $(cat "$d/agent.pid")"
	;;
stop)
	d=$ROOT/$2
	pid=$(cat "$d/agent.pid") || exit 1
	kill "$pid"; for _ in $(seq 1 40); do kill -0 "$pid" 2>/dev/null || { echo stopped; exit 0; }; sleep 0.5; done
	echo "still alive $pid"; exit 1
	;;
*) sed -n 2,12p "$0"; exit 2 ;;
esac
