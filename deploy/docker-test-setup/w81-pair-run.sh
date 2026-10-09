#!/bin/bash
# Wave 8.1 items 7 and 11 — A/B pair on ONE binary, arms switched without
# changing the image:
#   MODE=item7  СНЯТ 07.10.2026: тумблер EBPF_GUARD_FILE_MUTATION_HOOKS удалён
#               вместе с вердиктом пары (plan.md, «7 — ВЕРДИКТ пары»), плечо A
#               на нынешнем бинаре не выключает хуки и мерило бы B против B.
#               Исход на dpkg и контролях — w81-dpkg-smoke.sh (№543).
#   MODE=item11 A: collectors.file_ops.drop_unresolved_rw=false
#               B: collectors.file_ops.drop_unresolved_rw=true
# Every arm: stop, clean store, start, warm-up, idle window (metrics at both
# ends), then the arm's tail: item7 — positive control on /var/log and /etc
# (result sentinel per step), item11 — attack pack without the induced drop.
# Run detached; fetch $OUT with a separate short ssh afterwards.
set -u
MODE=${MODE:?item11}
[ "$MODE" = item7 ] && { echo "MODE=item7 снят: тумблера хуков больше нет, см. w81-dpkg-smoke.sh"; exit 2; }
BIN=${BIN:-/root/ebpf-guard-W81}
SEQ=${SEQ:-"A B B A"}
WARM=${WARM:-300}
WIN=${WIN:-1500}
OUT=${OUT:-/root/w81-$MODE-out}
SETUP=/opt/ebpf-guard/deploy/docker-test-setup
UNIT=ebpf-guard-test.service
DROPIN_DIR=/etc/systemd/system/$UNIT.d
DROPIN=$DROPIN_DIR/w81-arm.conf
ORIG=/root/ebpf-guard-A.prebuild
TOKEN=$(grep '^admin=' /var/lib/ebpf-guard/token | cut -d= -f2)
M() { curl -s --max-time 30 -H "Authorization: Bearer $TOKEN" localhost:19090/metrics; }
die() { echo "DIE: $*" | tee "$OUT/DIE"; restore; exit 1; }
restore() {
  rm -f "$DROPIN"; systemctl daemon-reload
  systemctl stop $UNIT
  cp "$ORIG" /opt/ebpf-guard/build/ebpf-guard
  systemctl start $UNIT
}
rm -rf "$OUT"; mkdir -p "$OUT" "$DROPIN_DIR"
[ -x "$BIN" ] || { echo "no binary $BIN"; exit 1; }
sha256sum "$BIN" | cut -c1-12 > "$OUT/bin.sha"

systemctl stop $UNIT
cp "$BIN" /opt/ebpf-guard/build/ebpf-guard

control_item7() {
  local D=$1 r=/var/log/w81ctl e=/etc/w81ctl.d
  date +%s > "$D/t-ctl"
  {
    mkdir -p $r && echo "mkdir ok"
    echo payload > $r/a.log && echo "write ok"
    truncate -s0 $r/a.log && echo "truncate rc=$? size=$(stat -c %s $r/a.log)"
    mv $r/a.log $r/b.log && echo "rename ok exists_b=$(test -f $r/b.log && echo 1)"
    rm $r/b.log && echo "unlink ok gone=$(test ! -e $r/b.log && echo 1)"
    rmdir $r && echo "rmdir-varlog ok gone=$(test ! -e $r && echo 1)"
    mkdir -p $e && rmdir $e && echo "rmdir-etc ok gone=$(test ! -e $e && echo 1)"
  } > "$D/control.txt" 2>&1
  sleep 20
  M > "$D/m-ctl.txt"
  curl -s --max-time 30 -H "Authorization: Bearer $TOKEN" \
    "localhost:19090/api/v1/alerts?since=$(( $(date +%s) - $(cat "$D/t-ctl") + 5 ))s&limit=500" > "$D/alerts-ctl.json"
}

tail_item11() {
  local D=$1
  M > "$D/m-att0.txt"; date +%s > "$D/t-att0"
  ( cd $SETUP/attacks && SKIP_INDUCED_DROP=1 bash ./run-all-attacks.sh > "$D/attacks.log" 2>&1; echo "rc=$?" > "$D/attacks.rc" )
  sleep 30
  M > "$D/m-att1.txt"; date +%s > "$D/t-att1"
}

i=0
for arm in $SEQ; do
  i=$((i+1)); D=$OUT/$i-$arm; mkdir -p "$D"
  CFG=$SETUP/config-test.yaml
  ENVLINE=""
  case "$MODE:$arm" in
    item7:A)  ENVLINE='Environment=EBPF_GUARD_FILE_MUTATION_HOOKS=0' ;;
    item7:B)  ;;
    item11:A) ;;
    item11:B)
      CFG=$SETUP/config-test-w81dur.yaml
      sed 's/^  file_ops:$/  file_ops:\n    drop_unresolved_rw: true/' $SETUP/config-test.yaml > "$CFG"
      grep -q 'drop_unresolved_rw: true' "$CFG" || die "config edit failed" ;;
  esac
  printf '[Service]\n%s\nExecStart=\nExecStart=/opt/ebpf-guard/build/ebpf-guard --config=%s --log-level=info\n' "$ENVLINE" "$CFG" > "$DROPIN"
  systemctl daemon-reload
  systemctl stop $UNIT
  rm -f /var/lib/ebpf-guard/test-events.db*
  date +%s > "$D/t-start"
  systemctl start $UNIT
  sleep 60
  PID=$(systemctl show -p MainPID --value $UNIT)
  sha256sum /proc/$PID/exe | cut -c1-12 > "$D/sha"
  tr '\0' '\n' < /proc/$PID/environ | grep -E 'EBPF_GUARD_|GOMEMLIMIT' | sort > "$D/env"
  tr '\0' ' ' < /proc/$PID/cmdline > "$D/cmdline"
  ps -C ebpf-guard -o pid= | wc -l > "$D/ncopies"
  journalctl -u $UNIT --since "@$(cat "$D/t-start")" -o cat --no-pager -a > "$D/journal-start.txt"
  M > "$D/m-start.txt"
  # smoke: verifier + attach, before any window is spent
  if [ "$MODE" = item7 ] && [ "$arm" = B ]; then
    grep -a '"mutation_hooks":8' "$D/journal-start.txt" > /dev/null || die "arm $i B: mutation_hooks != 8 (verifier/attach), see journal-start.txt"
  fi
  if [ "$MODE" = item7 ] && [ "$arm" = A ]; then
    grep -a '"mutation_hooks":0' "$D/journal-start.txt" > /dev/null || die "arm $i A: toggle did not disable hooks"
  fi
  if [ "$MODE" = item11 ] && [ "$arm" = B ]; then
    grep -a 'dropping read/write events with unresolved path' "$D/journal-start.txt" > /dev/null || die "arm $i B: drop not enabled"
  fi
  sleep $((WARM-60))
  M > "$D/m0.txt"; date +%s > "$D/t0"
  sleep "$WIN"
  M > "$D/m1.txt"; date +%s > "$D/t1"
  cat /sys/fs/cgroup/system.slice/$UNIT/memory.current > "$D/memcur" 2>/dev/null
  case "$MODE" in
    item7) control_item7 "$D" ;;
    item11) tail_item11 "$D" ;;
  esac
  journalctl -u $UNIT --since "@$(cat "$D/t-start")" -o cat --no-pager -a > "$D/journal.txt"
  rm -f $SETUP/config-test-w81dur.yaml
done
restore
echo done > "$OUT/DONE"
