#!/bin/bash
# Волна 8.6 B: пакет дерева (git ls-files -co без server-logs/build/plan*) -> стенд -> make generate && build в REMOTE_DIR.
#   w86-src-to-stand.sh <LOCAL_DIR> <REMOTE_DIR>
# Нужен второй каталог сборки (база и новый бинарь рядом): w86-second-agent.sh pack пишет только в /root/w86-src.
set -eu
KEY=${STAND_KEY:-$HOME/.ssh/id_ed25519_ebaka2}; HOST=${STAND_HOST:-root@89.125.2.154}
L=${1:?LOCAL_DIR}; R=${2:?REMOTE_DIR}
cd "$L"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
git ls-files -co --exclude-standard | grep -vE '^(server-logs|build|plan)' > "$T/files.txt"
COPYFILE_DISABLE=1 tar czf "$T/src.tgz" -T "$T/files.txt" 2> /dev/null
git rev-parse --short=12 HEAD > "$T/GIT-HEAD"
ssh -i "$KEY" "$HOST" "cat > $R.tgz" < "$T/src.tgz"
ssh -i "$KEY" "$HOST" "
set -e
export PATH=\$PATH:/usr/local/go/bin
rm -rf $R && mkdir -p $R && tar xzf $R.tgz -C $R 2> /dev/null
cd $R && make generate > $R.generate.log 2>&1 && make build > $R.build.log 2>&1
echo $(cat "$T/GIT-HEAD") > $R/GIT-HEAD
tail -1 $R.build.log; sha256sum build/ebpf-guard | cut -c1-12" < /dev/null
