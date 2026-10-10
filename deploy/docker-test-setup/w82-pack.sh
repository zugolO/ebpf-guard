#!/bin/bash
# w82-pack.sh — волна 8.2, этап 2 (B2/B3): один бинарь на пакете атак с замером
# заполнения карт и потерь по коллекторам.
#
#   ARMS="A B" BIN_A=/root/ebpf-guard-w82-B1 BIN_B=/root/ebpf-guard-w82-B2B3
#
# Плечо = стоп юнита → чистка стора → бинарь → старт → прогрев → снимок метрик →
# сэмплер заполнения карт (раз в SAMPLE_S с) → run-all-attacks.sh (без наведённого
# дропа, как в w81-pair-run item11) → снимок метрик → алерты окна. Бинарь A —
# база (B1: мёртвые карты убраны, размеры прежние), B — B2+B3 (размеры карт,
# кольца). Отчёт — w82-pack-report.py: заполнение (макс.) против размера,
# потери по коллекторам, промахи fd_path (ebpf_guard_file_unresolved_rw_filtered_total),
# тождество алертов по правилам.
#
# Запускать отсоединённо, забирать $OUT отдельным коротким ssh:
#   setsid nohup /root/w82-pack.sh >/root/w82-pack.log 2>&1 </dev/null &
set -u
ARMS=${ARMS:-"A B"}
BIN_A=${BIN_A:-/root/ebpf-guard-w82-B1}
BIN_B=${BIN_B:-/root/ebpf-guard-w82-B2B3}
WARM=${WARM:-120}
SAMPLE_S=${SAMPLE_S:-10}
OUT=${OUT:-/root/w82-pack-out}
SETUP=/opt/ebpf-guard/deploy/docker-test-setup
UNIT=ebpf-guard-test.service
TOKEN=$(grep '^admin=' /var/lib/ebpf-guard/token | cut -d= -f2)
M() { curl -s --max-time 30 -H "Authorization: Bearer $TOKEN" localhost:19090/metrics; }
die() { echo "DIE: $*" | tee "$OUT/DIE"; exit 1; }

rm -rf "$OUT"; mkdir -p "$OUT"
for a in $ARMS; do
  eval b=\$BIN_$a
  [ -x "$b" ] || die "нет бинаря плеча $a: $b"
done

# Сэмплер: число живых записей в картах агента. Идентификаторы карт берутся
# один раз до цикла (карты живут весь прогон плеча), в цикле — по одному
# bpftool dump на карту: лишних exec в окне атак как можно меньше.
sampler() {
  local D=$1 names="fd_path_map syscall_args conn_meta_map conn_start_map proc_args_map" n id c t line
  declare -A ID
  for n in $names; do
    ID[$n]=$(python3 -c "
import json
m=[x for x in json.load(open('$D/maps-pre.json')) if x.get('name')=='$n']
print(m[0]['id'] if m else '')")
  done
  while :; do
    t=$(date +%s); line="$t"
    for n in $names; do
      if [ -n "${ID[$n]}" ]; then
        c=$(bpftool map dump id "${ID[$n]}" 2>/dev/null | grep -c '^        "key":')
        line="$line $n=$c"
      else
        line="$line $n=NA"
      fi
    done
    echo "$line" >> "$D/fill.txt"
    sleep "$SAMPLE_S"
  done
}

i=0
for arm in $ARMS; do
  i=$((i+1)); D=$OUT/$i-$arm; mkdir -p "$D"
  eval BIN=\$BIN_$arm
  sha256sum "$BIN" | cut -c1-12 > "$D/bin.sha"
  systemctl stop $UNIT; sleep 3
  rm -f /var/lib/ebpf-guard/test-events.db* 2>/dev/null
  cp "$BIN" /opt/ebpf-guard/build/ebpf-guard
  systemctl start $UNIT
  [ "$(ps -eo cmd | grep -c '[e]bpf-guard --config')" -eq 1 ] || die "агентов не 1"
  date +%s > "$D/t-start"
  sleep "$WARM"
  M > "$D/m-pre.txt"; date +%s > "$D/t-att0"
  bpftool -j map show > "$D/maps-pre.json" 2>&1
  sampler "$D" & SP=$!
  ( cd $SETUP/attacks && SKIP_INDUCED_DROP=1 bash ./run-all-attacks.sh > "$D/attacks.log" 2>&1; echo "rc=$?" > "$D/attacks.rc" )
  sleep 30
  kill "$SP" 2>/dev/null; wait "$SP" 2>/dev/null
  M > "$D/m-post.txt"; date +%s > "$D/t-att1"
  curl -s --max-time 60 -H "Authorization: Bearer $TOKEN" \
    "localhost:19090/api/v1/alerts?since=$(( $(date +%s) - $(cat "$D/t-att0") + 5 ))s&limit=20000" > "$D/alerts.json"
  journalctl -u $UNIT --since "@$(cat "$D/t-start")" --no-pager > "$D/journal.log" 2>&1
  echo "arm $arm done $(date -u +%FT%TZ)" >> "$OUT/progress.txt"
done
echo done > "$OUT/DONE"
