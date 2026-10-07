#!/bin/bash
# Wave 8.2 item A1 — memory inventory of the running agent (read-only).
#
# Snapshots every row of the memory budget that the pod limit actually sees:
# cgroup memory.current/memory.stat, smaps by mapping, BPF maps (bpftool,
# memlock + program references), physical BPF vmalloc pages by caller
# (maps / ring buffers / JIT — memory.stat on 5.15 does not name them),
# Go memstats and heap/allocs profiles, and a 60 s alloc-rate delta.
#
# Nothing is restarted or changed. Two curl calls hit the API (they produce a
# few alerts — do not run inside a measured window).
#
# Usage (on the stand, detached, then fetch OUT with a separate short ssh):
#   setsid nohup /root/w82-mem-inventory.sh [OUT_DIR] >/root/w82-inv.log 2>&1 </dev/null &
# Upload with a separate `ssh 'cat > file' < file` call: a trailing `&` in the
# same command detaches stdin and the script arrives empty (0 bytes).
set -u
OUT=${1:-/var/tmp/w82-inv}
API=${API:-localhost:19090}
mkdir -p "$OUT"
P=$(pgrep -f "^/opt/ebpf-guard/build/ebpf-guard --config" | head -1)
[ -n "$P" ] || { echo "agent not running" >&2; exit 1; }
echo "pid=$P etimes=$(ps -o etimes= -p "$P") exe_sha=$(sha256sum /proc/"$P"/exe | cut -c1-12) kernel=$(uname -r) nproc=$(nproc)" > "$OUT/meta.txt"
CG=$(awk -F: '$1=="0"{print $3}' /proc/"$P"/cgroup); echo "cg=$CG" >> "$OUT/meta.txt"
cat /sys/fs/cgroup"$CG"/memory.current > "$OUT/memory.current"
cat /sys/fs/cgroup"$CG"/memory.stat > "$OUT/memory.stat"
cat /proc/"$P"/smaps_rollup > "$OUT/smaps_rollup"
cat /proc/"$P"/status > "$OUT/status"
awk '/^[0-9a-f]+-[0-9a-f]+ /{name=$6; if(name=="")name="[anon]"} /^Rss:/{r[name]+=$2} END{for(n in r) printf "%10d KiB %s\n", r[n], n}' /proc/"$P"/smaps | sort -rn | head -25 > "$OUT/smaps_by_map.txt"
bpftool -j map show > "$OUT/maps.json" 2>&1
bpftool -j prog show > "$OUT/progs.json" 2>&1
grep bpf /proc/vmallocinfo | awk '{c=$3; p=0; for(i=4;i<=NF;i++) if($i ~ /^pages=/){split($i,a,"="); p=a[2]} pages[c]+=p; n[c]++} END{for(k in pages) printf "%8.1f MiB phys %4d %s\n", pages[k]*4/1024, n[k], k}' | sort -rn > "$OUT/bpf_vmalloc.txt"
TOK=$(grep '^admin=' /var/lib/ebpf-guard/token | cut -d= -f2)
curl -s -H "Authorization: Bearer $TOK" "$API/metrics" > "$OUT/metrics.txt"
curl -s -H "Authorization: Bearer $TOK" "$API/debug/pprof/heap" > "$OUT/heap.pprof"
curl -s -H "Authorization: Bearer $TOK" "$API/debug/pprof/allocs" > "$OUT/allocs.pprof"
sleep 60
curl -s -H "Authorization: Bearer $TOK" "$API/metrics" > "$OUT/metrics60.txt"
cat /sys/fs/cgroup"$CG"/memory.current > "$OUT/memory.current60"
ls -l /proc/"$P"/exe > "$OUT/exe"
echo done > "$OUT/DONE"
