#!/bin/bash
# Волна 8.5: отправка на стенд и сборка бинаря ИЗ КОММИТА (архив обязан нести
# тождество бинаря). Запускается на маке из корня репозитория:
#   deploy/docker-test-setup/w85-ship.sh [rev]       (по умолчанию HEAD)
# Рабочее дерево репозитория на стенде (/opt/ebpf-guard) и рабочий агент не
# трогаются: исходники — в /root/w85-src-<sha>, туда же сборка. Дерево с
# незакоммиченными tracked-правками — отказ.
set -eu
REV=${1:-HEAD}
HOST=${W85_HOST:-root@89.125.2.154}
KEY=${W85_KEY:-$HOME/.ssh/id_ed25519_ebaka2}
SSH="ssh -i $KEY -o BatchMode=yes -o ConnectTimeout=15 $HOST"
cd "$(git rev-parse --show-toplevel)"
if [ "$REV" = HEAD ] && [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  echo "die: незакоммиченные правки — бинарь для стенда собирается только из коммита" >&2; exit 1
fi
SHA=$(git rev-parse --short=12 "$REV")
DST=/root/w85-src-$SHA
TMP=$(mktemp -d)
export COPYFILE_DISABLE=1
git archive --format=tar.gz -o "$TMP/src.tgz" "$REV"
# AppleDouble в архиве обнуляет набор правил (память macos-tar-appledouble…): проверка, не надежда.
if tar tzf "$TMP/src.tgz" | grep -q '/\._\|^\._'; then echo "die: в архиве файлы ._*" >&2; exit 1; fi
scp -q -i "$KEY" "$TMP/src.tgz" "$HOST:/root/w85-src-$SHA.tgz"
$SSH "set -eu; export PATH=\$PATH:/usr/local/go/bin; rm -rf $DST; mkdir -p $DST; tar xzf /root/w85-src-$SHA.tgz -C $DST; rm -f /root/w85-src-$SHA.tgz
cd $DST; echo $SHA > GIT-HEAD
make generate > build-generate.log 2>&1 || { tail -20 build-generate.log; exit 3; }
make build > build.log 2>&1 || { tail -20 build.log; exit 4; }
sha256sum build/ebpf-guard | tee BINARY-SHA256
go clean -cache
df -h / | tail -1"
rm -rf "$TMP"
echo "ok: $DST (git $SHA)"
