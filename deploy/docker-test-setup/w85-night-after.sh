#!/bin/bash
# w85-night-after.sh [CLEAN=1] — разбор ночи закрытия 8.5 с мака (шаг 6): проверка маркера, архив → server-logs/collect-8.5-night/,
# вердикты ТОЛЬКО эмиттерами (строки из отчётов архива, не пересчёт), состояние стенда после ночи. CLEAN=1 — после проверки
# архива удалить ночные каталоги на стенде (диск ≤ 80%). Вердикты по меткам печатаются из all-reports.txt; 8.5.7 — отдельно
# информационно по всем прогонам пода, добранным вне ночи (определение метки — медиана шести — не меняется).
set -u
HOST=${W85_HOST:-root@89.125.2.154}; KEY=${W85_KEY:-$HOME/.ssh/id_ed25519_ebaka2}
SSH="ssh -i $KEY -o BatchMode=yes -o ConnectTimeout=20 $HOST"
ROOT=$(cd "$(dirname "$0")/../.." && pwd); DST=$ROOT/server-logs/collect-8.5-night
MARK=/root/PIPELINE-8_5_NIGHT-DONE
echo "== маркер: $($SSH "cat $MARK 2>/dev/null || echo ОТСУТСТВУЕТ" </dev/null)"
$SSH "test -s /root/collect-8.5-night.tgz" </dev/null || { echo "нет архива /root/collect-8.5-night.tgz — ночь не закончилась или упала: $($SSH 'tail -5 /root/run-8.5-night-pipeline.log' </dev/null)"; exit 2; }
mkdir -p "$DST"; $SSH "cat /root/collect-8.5-night.tgz" </dev/null > "$DST/collect-8.5-night.tgz"
tar xzf "$DST/collect-8.5-night.tgz" -C "$DST" 2> /dev/null; A=$(ls -d "$DST"/night-8.5-night 2> /dev/null | head -1)
[ -d "$A" ] || { echo "архив не распакован"; exit 3; }
echo "== тождество: $(cat "$A/binary-identity.txt" 2>/dev/null | tr '\n' ' ')"
echo "== вердикты по меткам (из отчётов архива)"
grep -aE '^(ДОСТИГНУТО|ПРОВАЛЕН|НЕИЗМЕРИМ|ИЗМЕРЕНО): ' "$A/all-reports.txt" | cut -c1-400
echo "== сторож полноты"; $SSH "grep -a 'сторож полноты' /root/run-8.5-night-pipeline.log | tail -1" </dev/null
echo "== стенд после ночи"
$SSH 'ps -eo pid,etimes,cmd | grep "[e]bpf-guard --config"; systemctl is-active ebpf-guard-test; dpkg -s irqbalance | sed -n 2p; systemctl is-active irqbalance; dpkg -s w84svc 2>&1 | head -1; df -h / | tail -1; helm list -A 2>/dev/null | tail -2' </dev/null
if [ "${CLEAN:-0}" = 1 ]; then
    echo "== CLEAN: удаляю ночные каталоги на стенде (архив скопирован: $(ls -la "$DST/collect-8.5-night.tgz" | awk '{print $5}') Б)"
    $SSH 'rm -rf /var/lib/night-8.5-night /root/collect-8.5-night.tgz; go_bin=/usr/local/go/bin/go; $go_bin clean -cache 2>/dev/null; df -h / | tail -1' </dev/null
fi
