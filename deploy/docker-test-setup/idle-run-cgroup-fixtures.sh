#!/bin/bash
# Фикстуры прибора cgroup-памяти из idle-run.sh (волна 8.1, этап D).
#
# Функции НЕ переписываются здесь, а ВЫРЕЗАЮТСЯ из idle-run.sh по имени и
# исполняются как есть: фикстура, повторяющая логику своими словами, зеленеет на
# своей копии и ничего не говорит о том тексте, который поедет на стенд
# ([[self-test-fixtures-miss-live-log-shape]]). Запуск с mac, стенд не нужен.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
SRC="$HERE/idle-run.sh"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
FAIL=0
ok()  { echo "  OK    $*"; }
bad() { echo "  FAIL  $*"; FAIL=$((FAIL + 1)); }

# Вырезаем две функции по их именам и проверяем, что вырезалось не пусто: если
# функцию переименуют, фикстура обязана покраснеть, а не тихо проверить пустоту
# ([[helper-called-before-definition-is-silent-pass]]).
extract() { awk -v f="$1" 'index($0, f "() {") == 1 { p = 1 } p { print } p && $0 == "}" { exit }' "$SRC"; }
{
    echo 'log() { :; }'
    extract cgroup_resolve
    extract cgroup_snapshot
} > "$T/lib.sh"
for f in cgroup_resolve cgroup_snapshot; do
    grep -q "^$f() {" "$T/lib.sh" || { bad "функция $f не вырезана из idle-run.sh (переименована?)"; FAIL=1; }
done
[ "$FAIL" -eq 0 ] || { echo "idle-run-cgroup-fixtures: ЕСТЬ РАСХОЖДЕНИЯ ($FAIL)"; exit 1; }

# подставное дерево: /proc/4242/cgroup → 0::/system.slice/ebpf-guard-test.service
mk_tree() {
    local cur="$1" anon="$2" file="$3" path="${4:-/system.slice/ebpf-guard-test.service}"
    rm -rf "$T/proc" "$T/cg"; mkdir -p "$T/proc/4242" "$T/cg$path"
    printf '0::%s\n' "$path" > "$T/proc/4242/cgroup"
    printf '%s\n' "$cur" > "$T/cg$path/memory.current"
    printf 'max\n' > "$T/cg$path/memory.max"
    { echo "anon $anon"; echo "file $file"; echo "kernel_stack 1114112"; echo "pagetables 1437696";
      echo "slab 1234567"; echo "sock 0"; echo "shmem 0"; } > "$T/cg$path/memory.stat"
}

run_snap() {
    OUT="$T/out" CG_ROOT="$T/cg" PROC_ROOT="$T/proc" CGROUP_MEM=1 bash -c '
        set -u
        OUT="'"$T/out"'"; CG_ROOT="'"$T/cg"'"; PROC_ROOT="'"$T/proc"'"
        source "'"$T/lib.sh"'"
        cgroup_resolve 4242
        echo "CG_DIR=$CG_DIR"
        cgroup_snapshot 7 2026-10-04T00:00:00Z
    '
}

mkdir -p "$T/out/snapshots"
echo "[живой cgroup: резолв и строка tsv]"
mk_tree 242221056 123456789 32505856
o=$(run_snap)
printf '%s' "$o" | grep -qF "CG_DIR=$T/cg/system.slice/ebpf-guard-test.service" \
    && ok "резолв берёт путь из /proc/<pid>/cgroup, а не из имени юнита" \
    || bad "резолв: $o"
line=$(tail -1 "$T/out/snapshots/cgroup-mem.tsv" 2>/dev/null)
nf=$(printf '%s' "$line" | awk -F'\t' '{print NF}')
[ "$nf" = 10 ] && ok "строка среза — 10 полей" || bad "полей $nf, ожидалось 10: $line"
printf '%s' "$line" | awk -F'\t' '$3 == 242221056 && $4 == 123456789 && $5 == 32505856 && $8 == 1114112 && $10 == "max" { exit 0 } { exit 1 }' \
    && ok "current/anon/file/kernel_stack/max на своих местах" || bad "величины разъехались: $line"

echo "[cgroup не найден: прибор молчит, а не пишет нули]"
rm -rf "$T/out"; mkdir -p "$T/out/snapshots"
rm -rf "$T/cg"; mkdir -p "$T/cg"   # /proc есть, cgroupfs пустой
o=$(run_snap)
printf '%s' "$o" | grep -qF 'CG_DIR=' && printf '%s' "$o" | grep -q 'CG_DIR=$' \
    && ok "резолв вернул пусто (нет memory.current)" || bad "резолв не распознал отсутствие cgroup: $o"
[ ! -e "$T/out/snapshots/cgroup-mem.tsv" ] \
    && ok "файла нет вовсе — ноль не печатается" \
    || bad "прибор написал строку без cgroup: $(cat "$T/out/snapshots/cgroup-mem.tsv")"

echo "[делегированная раскладка: путь другой, резолв обязан его взять]"
rm -rf "$T/out"; mkdir -p "$T/out/snapshots"
mk_tree 100000000 50000000 1000000 /kubepods.slice/kubepods-burstable.slice/pod123/agent
o=$(run_snap)
printf '%s' "$o" | grep -qF "CG_DIR=$T/cg/kubepods.slice/kubepods-burstable.slice/pod123/agent" \
    && ok "путь пода взят как есть" || bad "делегированная раскладка потеряна: $o"

echo
[ "$FAIL" -eq 0 ] && { echo "idle-run-cgroup-fixtures: расхождений 0"; exit 0; }
echo "idle-run-cgroup-fixtures: ЕСТЬ РАСХОЖДЕНИЯ ($FAIL)"; exit 1
