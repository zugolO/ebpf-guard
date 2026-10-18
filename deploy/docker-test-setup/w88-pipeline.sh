#!/bin/bash
# Волна 8.8: цепочка прогонов лестницы w88-load.sh одним отсоединённым запуском.
#   w88-pipeline.sh <TAG> <SRC> <ROLES...>      роли: host pod host8 pod8 pod1c pod2c podd diag hostatt0 podatt0 hostatt podatt podatt1c podattd podatt2c
#   (podd/podattd — под с limits.cpu из ЧАРТА, без --set: проверка умолчания; pod1c/podatt1c — то же значение, но ручным override)
#   (att0 — эталон без нагрузки: ставить ДО att той же пары, тогда att печатает 8.8.6 с составом)
# Артефакты — /root/w88-<TAG>-<роль>/, отчёты — /root/w88-<TAG>.report, маркер конца — /root/w88-<TAG>.DONE.
TAG=${1:?TAG}; SRC=${2:?SRC}; shift 2
HERE=$(cd "$(dirname "$0")" && pwd)
HOST_STEPS=${HOST_STEPS:-0 500 1500 5000 15000 30000 45000 60000 max}
POD_STEPS=${POD_STEPS:-0 500 1500 3000 5000 8000 12000 20000 40000}
# Р8: лестницы пода с лимитом 1 и 2 ядра (ёмкость ∝ CPU: ступени сдвинуты)
POD1_STEPS=${POD1_STEPS:-0 1500 5000 7500 10000 12500 15000 20000 30000 45000}
POD2_STEPS=${POD2_STEPS:-0 5000 10000 15000 20000 25000 30000 37500 45000 60000 max}
rm -f "/root/w88-$TAG.DONE" "/root/w88-$TAG.report"
for r in "$@"; do
    OUT=/root/w88-$TAG-$r
    qcores=0.5
    case $r in
        host)   STEPS=$HOST_STEPS PROBE=1 CONTROLS=8 bash "$HERE/w88-load.sh" host steps "$SRC" "$OUT"; role=host ;;
        host8)  STEPS=$HOST_STEPS GEN_PROCS=8 PROBE=1 bash "$HERE/w88-load.sh" host steps "$SRC" "$OUT"; role=host ;;
        pod)    STEPS=$POD_STEPS PROBE=1 CONTROLS=8 bash "$HERE/w88-load.sh" pod steps "$SRC" "$OUT"; role=pod ;;
        pod8)   STEPS=$POD_STEPS GEN_PROCS=8 PROBE=1 bash "$HERE/w88-load.sh" pod steps "$SRC" "$OUT"; role=pod ;;
        # п.3 владельца: под 500m без зонда/контролей на ступени 0, зонд 100 оп/с, ступени как у pod1c
        pod05)  STEPS=${POD05_STEPS:-0 1500 5000 7500 10000 12500 15000 20000 30000 45000} AUX_SKIP_STEP0=1 PROBE_RATE=100 PROBE=1 CONTROLS=8 bash "$HERE/w88-load.sh" pod steps "$SRC" "$OUT"; role=pod ;;
        pod1c)  qcores=1; CPU_LIMIT=1 STEPS=$POD1_STEPS AUX_SKIP_STEP0=1 PROBE_RATE=100 PROBE=1 CONTROLS=8 bash "$HERE/w88-load.sh" pod steps "$SRC" "$OUT"; role=pod ;;
        pod2c)  qcores=2; CPU_LIMIT=2 STEPS=$POD2_STEPS AUX_SKIP_STEP0=1 PROBE_RATE=100 PROBE=1 CONTROLS=8 bash "$HERE/w88-load.sh" pod steps "$SRC" "$OUT"; role=pod ;;
        # решение владельца 18.10: умолчание чарта = 1 ядро; --set не передаётся, 8.8.5 сверяет базу сторожа с квотой из cgroup
        podd)   qcores=1; STEPS=${PODD_STEPS:-0 1500 5000 10000 20000 30000 45000 60000 max} AUX_SKIP_STEP0=1 PROBE_RATE=100 PROBE=1 CONTROLS=8 bash "$HERE/w88-load.sh" pod steps "$SRC" "$OUT"; role=pod ;;
        diag)   STEPS=${DIAG_STEPS:-30000 45000 60000} GEN_PROCS=8 DIAG=1 bash "$HERE/w88-load.sh" host steps "$SRC" "$OUT"; role=diag ;;
        hostatt)  ATTACK_RATE=${ATTACK_RATE:-20000} bash "$HERE/w88-load.sh" host attack "$SRC" "$OUT"; role=host ;;
        podatt)   ATTACK_RATE=${ATTACK_RATE:-20000} bash "$HERE/w88-load.sh" pod attack "$SRC" "$OUT"; role=pod ;;
        podattd)  ATTACK_RATE=${ATTACK_RATE:-20000} bash "$HERE/w88-load.sh" pod attack "$SRC" "$OUT"; role=pod ;;
        podatt2c) CPU_LIMIT=2 ATTACK_RATE=${ATTACK_RATE:-20000} bash "$HERE/w88-load.sh" pod attack "$SRC" "$OUT"; role=pod ;;
        podatt1c) CPU_LIMIT=1 ATTACK_RATE=${ATTACK_RATE:-20000} bash "$HERE/w88-load.sh" pod attack "$SRC" "$OUT"; role=pod ;;
        # без нагрузки (1 оп/с): эталон состава детекта для 8.8.6
        hostatt0) ATTACK_RATE=1 bash "$HERE/w88-load.sh" host attack "$SRC" "$OUT"; role=host ;;
        podatt0)  ATTACK_RATE=1 bash "$HERE/w88-load.sh" pod attack "$SRC" "$OUT"; role=pod ;;
    esac
    {
        echo "### $r $(cat "$OUT/DONE" 2> /dev/null)"
        case $r in
            hostatt|podatt) bash "$HERE/w88-hot-verdict.sh" "${r%att}" "$OUT/attack"; bash "$HERE/w88-att-verdict.sh" "${r%att}" "$OUT/attack" "$( [ -d "/root/w88-$TAG-${r}0/attack" ] && echo "/root/w88-$TAG-${r}0/attack")" ;;
            podattd) bash "$HERE/w88-hot-verdict.sh" podd "$OUT/attack"; bash "$HERE/w88-att-verdict.sh" podd "$OUT/attack" "$( [ -d "/root/w88-$TAG-podatt0/attack" ] && echo "/root/w88-$TAG-podatt0/attack")" ;;
            podatt2c) bash "$HERE/w88-hot-verdict.sh" pod2c "$OUT/attack"; bash "$HERE/w88-att-verdict.sh" pod2c "$OUT/attack" "$( [ -d "/root/w88-$TAG-podatt0/attack" ] && echo "/root/w88-$TAG-podatt0/attack")" ;;
            podatt1c) bash "$HERE/w88-hot-verdict.sh" pod1c "$OUT/attack"; bash "$HERE/w88-att-verdict.sh" pod1c "$OUT/attack" "$( [ -d "/root/w88-$TAG-podatt0/attack" ] && echo "/root/w88-$TAG-podatt0/attack")" ;;
            *att0) cat "$OUT/attack/recall.txt" 2> /dev/null ;;
            diag) for d in "$OUT"/step-*; do echo "== $(basename "$d"): off-CPU (bpftrace), топ стеков по сумме ожидания"; grep -a -E "^@off_total_ns|^@off_ns|^\s+[a-z_]+\+|^\]: " "$d/offcpu.txt" 2> /dev/null | head -40; done ;;
            *) python3 "$HERE/w88-load-report.py" "$OUT" role=$role cpu_limit=$qcores ;;
        esac
    } >> "/root/w88-$TAG.report"
    sleep 20
done
echo "done $(date -u +%FT%TZ)" > "/root/w88-$TAG.DONE"
