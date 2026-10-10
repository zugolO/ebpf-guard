#!/bin/bash
# w82-dns-smoke.sh — волна 8.2 B3: кольцо dns_events 4 МиБ (BIN_A) против 512 КиБ
# (BIN_B), плечи A B B A. Потери в ядре у DNS не считаются (в dns.bpf.c нет
# счётчика отказа резерва), поэтому судит доля: ebpf_guard_dns_queries_total
# (дельта) против отправленного флудером. Идентичность: один sha на плечо.
set -u
SEQ=${SEQ:-"A B B A"}
BIN_A=${BIN_A:-/root/ebpf-guard-w82-B1}
BIN_B=${BIN_B:-/root/ebpf-guard-w82-B2B3}
WARM=${WARM:-60}
OUT=${OUT:-/root/w82-dns-out}
UNIT=ebpf-guard-test.service
TOKEN=$(grep '^admin=' /var/lib/ebpf-guard/token | cut -d= -f2)
M() { curl -s --max-time 30 -H "Authorization: Bearer $TOKEN" localhost:19090/metrics; }
rm -rf "$OUT"; mkdir -p "$OUT"
i=0
for arm in $SEQ; do
  i=$((i+1)); D=$OUT/$i-$arm; mkdir -p "$D"
  eval BIN=\$BIN_$arm
  sha256sum "$BIN" | cut -c1-12 > "$D/bin.sha"
  systemctl stop $UNIT; sleep 3
  cp "$BIN" /opt/ebpf-guard/build/ebpf-guard
  systemctl start $UNIT; sleep "$WARM"
  [ "$(ps -eo cmd | grep -c '[e]bpf-guard --config')" -eq 1 ] || { echo "DIE agents" > "$OUT/DIE"; exit 1; }
  bpftool -j map show > "$D/maps.json" 2>&1
  M > "$D/m-pre.txt"
  python3 /root/w82-dns-flood.py > "$D/flood.txt" 2>&1
  sleep 30
  M > "$D/m-post.txt"
  echo "arm $arm done" >> "$OUT/progress.txt"
done
echo done > "$OUT/DONE"
