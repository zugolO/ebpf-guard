#!/bin/bash
# w86-night-after.sh [CLEAN=1] — разбор ночи закрытия 8.6 с мака: проверка маркера, архив → server-logs/collect-8.6-night/,
# вердикты ТОЛЬКО эмиттерами (строки из отчётов архива, не пересчёт), состояние стенда после ночи. CLEAN=1 — после проверки
# архива удалить ночные каталоги на стенде (диск ≤ 80%), ВКЛЮЧАЯ go-build .cache в артефактах контролей.
set -u
HOST=${W85_HOST:-root@89.125.2.154}; KEY=${W85_KEY:-$HOME/.ssh/id_ed25519_ebaka2}
SSH="ssh -i $KEY -o BatchMode=yes -o ConnectTimeout=20 $HOST"
ROOT=$(cd "$(dirname "$0")/../.." && pwd); DST=$ROOT/server-logs/collect-8.6-night
MARK=/root/PIPELINE-8_6_NIGHT-DONE
echo "== маркер: $($SSH "cat $MARK 2>/dev/null || echo ОТСУТСТВУЕТ" </dev/null)"
$SSH "test -s /root/collect-8.6-night.tgz" </dev/null || { echo "нет архива /root/collect-8.6-night.tgz — ночь не закончилась или упала: $($SSH 'tail -5 /root/run-8.6-night-pipeline.log' </dev/null)"; exit 2; }
mkdir -p "$DST"; $SSH "cat /root/collect-8.6-night.tgz" </dev/null > "$DST/collect-8.6-night.tgz"
tar xzf "$DST/collect-8.6-night.tgz" -C "$DST" 2> /dev/null; A=$(ls -d "$DST"/night-8.6-night 2> /dev/null | head -1)
[ -d "$A" ] || { echo "архив не распакован"; exit 3; }
echo "== тождество: $(cat "$A/binary-identity.txt" 2>/dev/null | tr '\n' ' ')"
echo "== вердикты по меткам (из отчётов архива)"
grep -aE '^(ДОСТИГНУТО|ПРОВАЛЕН|НЕИЗМЕРИМ|ИЗМЕРЕНО): ' "$A/all-reports.txt" | cut -c1-400
echo "== сторож полноты"; $SSH "grep -a 'сторож полноты' /root/run-8.6-night-pipeline.log | tail -1" </dev/null
echo "== ВНИМАНИЕ-строки пайплайна"; $SSH "grep -a 'ВНИМАНИЕ' /root/run-8.6-night-pipeline.log | cut -c1-260" </dev/null
echo "== стенд после ночи"
$SSH 'ps -eo pid,etimes,cmd | grep "[e]bpf-guard --config"; systemctl is-active ebpf-guard-test; dpkg -s irqbalance | sed -n 2p; systemctl is-active irqbalance; dpkg -s w84svc 2>&1 | head -1; df -h / | tail -1; helm list -A 2>/dev/null | tail -2' </dev/null
if [ "${CLEAN:-0}" = 1 ]; then
    echo "== CLEAN: удаляю ночные каталоги на стенде (архив скопирован: $(ls -la "$DST/collect-8.6-night.tgz" | awk '{print $5}') Б)"
    # артефакты контролей несут go-build .cache (память helm-on-stand-is-root-bin: диск 54% с 14.10) — чистятся вместе с ночными каталогами
    $SSH 'rm -rf /var/lib/night-8.6-night /root/collect-8.6-night.tgz /var/lib/w86nightctl /var/lib/w86chainctl; find /root -maxdepth 3 -type d -name .cache -path "*control*" -exec rm -rf {} + 2>/dev/null; /usr/local/go/bin/go clean -cache 2>/dev/null; df -h / | tail -1' </dev/null
fi
