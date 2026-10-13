#!/bin/bash
# w85-deploy.sh [rev] — выкладка HEAD на стенд для ночи закрытия 8.5 (шаг 5, часть 2). Запускается на маке из корня репозитория.
# push не нужен: коммиты едут git bundle в /opt/ebpf-guard (ветка testing стенда сбрасывается на rev), бинарь собирается НА СТЕНДЕ из этого
# коммита (make generate → make build), рабочий агент перезапускается на нём. Профиль до F1 (profiler-state.json) копируется в бэкап и
# НЕ удаляется/не обнуляется; конфиг агента не меняется этим скриптом (F1 по умолчанию выключен — включает пайплайн ночи).
# Сторожа: агент после — один, active, sha процесса = sha файла, правила загружены, состояние таблицы процессов active, состояние F1 off_config.
set -eu
REV=${1:-HEAD}
HOST=${W85_HOST:-root@89.125.2.154}; KEY=${W85_KEY:-$HOME/.ssh/id_ed25519_ebaka2}
SSH="ssh -i $KEY -o BatchMode=yes -o ConnectTimeout=15 $HOST"
cd "$(git rev-parse --show-toplevel)"
[ -z "$(git status --porcelain --untracked-files=no)" ] || { echo "die: незакоммиченные правки — выкладка только из коммита" >&2; exit 1; }
SHA=$(git rev-parse "$REV"); SHORT=$(git rev-parse --short=12 "$REV")
BASE=$($SSH 'git -C /opt/ebpf-guard rev-parse HEAD' </dev/null)
git cat-file -e "$BASE^{commit}" 2> /dev/null || { echo "die: коммит стенда $BASE неизвестен локально" >&2; exit 1; }
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
git bundle create "$TMP/w85.bundle" "$BASE..$SHA" > /dev/null 2>&1 || { echo "die: bundle $BASE..$SHA" >&2; exit 1; }
scp -q -i "$KEY" "$TMP/w85.bundle" "$HOST:/root/w85-deploy.bundle"
$SSH "set -eu; export PATH=\$PATH:/usr/local/go/bin
TS=\$(date -u +%Y%m%dT%H%M%SZ); BK=/root/ebpf-guard-backups/pre-8.5-night-\$TS; mkdir -p \$BK
cd /opt/ebpf-guard
used=\$(df -P / | awk 'NR == 2 { sub(/%/, \"\", \$5); print \$5 }'); [ \"\$used\" -le 80 ] || { echo \"die: диск \$used%\"; exit 2; }
[ \"\$(ps -eo cmd | grep -c '[e]bpf-guard --config')\" -eq 1 ] || { echo 'die: агентов не 1'; exit 2; }
cp -a build/ebpf-guard \$BK/ebpf-guard.bin; cp -a deploy/docker-test-setup/config-test.yaml \$BK/
cp -a /var/lib/ebpf-guard/profiler-state.json \$BK/profiler-state-before-F1.json; sha256sum \$BK/profiler-state-before-F1.json | tee \$BK/profiler-state.sha256
cp -a /var/lib/ebpf-guard/token \$BK/ 2>/dev/null || true
ls -la /var/lib/ebpf-guard/ > \$BK/var-lib-before.txt
echo \"бэкап: \$BK\"
git fetch -q /root/w85-deploy.bundle $SHA
git checkout -q -- bpf/vmlinux.h internal/bpf/xdp_bpf_gen.go deploy/docker-test-setup/attacks/run-gate.sh 2>/dev/null || true
git reset -q --hard $SHA
rm -f /root/w85-deploy.bundle
echo $SHORT > GIT-HEAD
make generate > /root/w85-deploy-generate.log 2>&1 || { tail -20 /root/w85-deploy-generate.log; exit 3; }
make build > /root/w85-deploy-build.log 2>&1 || { tail -20 /root/w85-deploy-build.log; exit 4; }
sha256sum build/ebpf-guard | tee BINARY-SHA256
build/ebpf-guard version 2>&1 | head -3
go clean -cache
df -h / | tail -1
git log --oneline -1
echo \"\$BK\" > /root/w85-last-backup.txt"
echo "ok: /opt/ebpf-guard на $SHORT собран, агент ещё НЕ перезапущен (перезапуск — отдельным шагом)"
