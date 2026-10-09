#!/bin/bash
# w81-h4-attacks.sh — №552 (Р2) волны 8.1: пакет атак + гейт после правки критерия 6
# (зачёт по renamed_total) и новых входов пакета (chmod под /etc/ssh и
# /usr/local/bin, чтение /var/lib/containerd/ процессом контейнера). Вердикт —
# сколько из прежних 12 «потерь» осталось и почему, по содержимому.
#
# Один бинарь, чистый стор, прогрев, пакет без наведённого дропа (как
# w81-pair-run.sh item11), снимки /metrics до и после, стор окна, хвост
# attack-results этого прогона, журнал. Запуск отцепленным процессом;
# результаты забирать коротким ssh после $OUT/DONE
# ([[waiting-loop-must-not-ssh-into-window]]).
set -u
OUT=${OUT:-/var/lib/w81-h4-attacks}
WARM=${WARM:-300}
SETUP=/opt/ebpf-guard/deploy/docker-test-setup
REPO=/opt/ebpf-guard
UNIT=ebpf-guard-test.service
BIN=$REPO/build/ebpf-guard
CFG=$SETUP/config-test.yaml
API=http://localhost:19090
TOKEN=$(grep '^admin=' /var/lib/ebpf-guard/token | cut -d= -f2)
M() { curl -s --max-time 30 -H "Authorization: Bearer $TOKEN" "$API/metrics"; }
die() { echo "DIE: $*" | tee "$OUT/DIE"; echo "die: $*" > "$OUT/DONE"; exit 1; }

rm -rf "$OUT"; mkdir -p "$OUT"
exec > "$OUT/driver.log" 2>&1
echo "[$(date -u +%FT%TZ)] w81-h4-attacks"

# ── преflight ────────────────────────────────────────────────────────────────
[ "$(ps -eo cmd | grep -c '[e]bpf-guard --config')" -eq 1 ] || die "агентов не 1"
"$BIN" version > "$OUT/binary-version.txt" 2>&1
grep -q 'rego=true' "$OUT/binary-version.txt" || die "бинарь без тега rego"
"$BIN" rules --config "$CFG" > "$OUT/rules.txt" 2>&1
grep -qE '^loaded [1-9][0-9]* rules' "$OUT/rules.txt" || die "бинарь не загружает правила"
grep -q 'run_chmod_sensitive_paths_positive_control$' $SETUP/attacks/run-all-attacks.sh || die "в пакете нет шага chmod-входов №552"
grep -q 'run_host_mount_positive_control$' $SETUP/attacks/run-all-attacks.sh || die "в пакете нет шага host_mount №552"
grep -q 'metric_renamed_grown' $SETUP/attacks/run-gate.sh || die "гейт без зачёта по renamed_total"
docker image inspect busybox >/dev/null 2>&1 || die "нет локального busybox для host_mount"
echo "fs /var/tmp=$(stat -c %d /var/tmp) /lib/modules=$(stat -c %d /lib/modules/$(uname -r))" > "$OUT/fs.txt"
sha256sum $REPO/rules/container-escape.yaml $REPO/rules/sigma-linux.yaml $REPO/rules/defense-evasion.yaml $SETUP/attacks/run-all-attacks.sh $SETUP/attacks/run-gate.sh \
    $SETUP/attacks/new-rules.txt $SETUP/attacks/background-rules.txt > "$OUT/inputs.sha"

# ── рестарт с чистым стором ──────────────────────────────────────────────────
systemctl stop $UNIT
rm -f /var/lib/ebpf-guard/test-events.db*
date +%s > "$OUT/t-start"
systemctl start $UNIT
for i in $(seq 1 60); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 $API/health)" = 200 ] && break; sleep 2
done
PID=$(systemctl show -p MainPID --value $UNIT)
sf=$(sha256sum "$BIN" | cut -d' ' -f1); sp=$(sha256sum /proc/$PID/exe | cut -d' ' -f1)
{ echo "path=$BIN"; echo "sha256=$sf"; echo "sha256_proc=$sp"; echo "pid=$PID"
  echo "cmdline=$(tr '\0' ' ' < /proc/$PID/cmdline)"; cat "$OUT/binary-version.txt"; } > "$OUT/binary-identity.txt"
[ "$sf" = "$sp" ] || die "sha процесса ≠ sha файла"
echo "[$(date -u +%FT%TZ)] агент pid $PID sha ${sf:0:12}, прогрев $WARM с"
sleep "$WARM"

# ── пакет атак (гейт — внутри full_run) ──────────────────────────────────────
touch "$OUT/t-att0.ref"
M > "$OUT/m0.txt"; date +%s > "$OUT/t0"
( cd $SETUP/attacks && SKIP_INDUCED_DROP=1 bash ./run-all-attacks.sh > "$OUT/attacks.log" 2>&1; echo "rc=$?" > "$OUT/attacks.rc" )
sleep 30
M > "$OUT/m1.txt"; date +%s > "$OUT/t1"
curl -s --max-time 60 -H "Authorization: Bearer $TOKEN" \
    "$API/api/v1/alerts?since=$(( $(cat "$OUT/t1") - $(cat "$OUT/t0") + 5 ))s&limit=20000" > "$OUT/alerts-att.json"

mkdir -p "$OUT/attack-results"
find $SETUP/attacks/attack-results -maxdepth 1 -type f -newer "$OUT/t-att0.ref" -exec cp {} "$OUT/attack-results/" \;
cp $SETUP/attacks/attack-manifest.json "$OUT/" 2>/dev/null
journalctl -u $UNIT --since "@$(cat "$OUT/t-start")" -o cat --no-pager -a > "$OUT/journal.txt"
echo "[$(date -u +%FT%TZ)] done"
echo "done $(date -u +%FT%TZ)" > "$OUT/DONE"
