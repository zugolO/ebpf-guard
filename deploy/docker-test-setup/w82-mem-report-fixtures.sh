#!/bin/bash
# Фикстуры эмиттера w82-mem-report.sh: каждая ветка вердиктов 8.2.2/8.2.4
# предъявлена своим синтетическим инвентарём (архивы стенда в git не лежат).
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
E="$HERE/w82-mem-report.sh"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fail=0
mk() { # <каталог> <memory.current МиБ> <etimes> <dead 0|1> <vmalloc 0|1> <maps МиБ> <rings МиБ>
    local d="$T/$1"; mkdir -p "$d"
    echo "pid=1 etimes= $3 exe_sha=fixture" > "$d/meta.txt"
    echo $(( $2 * 1048576 )) > "$d/memory.current"
    printf 'anon %d\nfile 0\n' $(( $2 * 1048576 / 2 )) > "$d/memory.stat"
    if [ "$4" = 1 ]; then
        echo '[{"id":1,"type":"hash","name":"live","bytes_memlock":4096},{"id":2,"type":"ringbuf","name":"events","max_entries":4194304,"bytes_memlock":0},{"id":3,"type":"lru_hash","name":"proc_args_map","bytes_memlock":4194304}]' > "$d/maps.json"
    else
        echo '[{"id":1,"type":"hash","name":"live","bytes_memlock":4096},{"id":2,"type":"ringbuf","name":"events","max_entries":4194304,"bytes_memlock":0}]' > "$d/maps.json"
    fi
    echo '[{"id":10,"map_ids":[1,2]},{"id":11,"map_ids":null}]' > "$d/progs.json"
    [ "$5" = 1 ] && printf '%8.1f MiB phys %4d %s\n%8.1f MiB phys %4d %s\n' "$6" 10 bpf_map_area_alloc+0x0/0x0 "$7" 2 __bpf_ringbuf_alloc+0x0/0x0 > "$d/bpf_vmalloc.txt"
    printf 'go_memstats_alloc_bytes_total 1000000\nebpf_guard_events_total{type="file"} 1000\n' > "$d/metrics.txt"
    printf 'go_memstats_alloc_bytes_total 7000000\nebpf_guard_events_total{type="file"} 7000\n' > "$d/metrics60.txt"
}
need() { # <имя> <вывод> <строка...>
    local n="$1" o="$2"; shift 2
    for s in "$@"; do grep -qF -- "$s" <<< "$o" || { echo "FAIL $n: нет «${s}»"; fail=1; return; }; done
    echo "ok   $n"
}
mk pass 100 1900 0 1 20 10
o=$(bash "$E" "$T/pass"); need "всё в бюджете" "$o" "ДОСТИГНУТО: 8.2.2 ДОСТИГНУТО" "ДОСТИГНУТО: 8.2.4 ДОСТИГНУТО (карт без программ 0, карты+кольца 30.0" "1000  Б/событие" "поток на стенде, Б/событие"
mk ws 100 1900 0 1 20 10; printf 'anon 1\nfile 0\ninactive_file %d\n' $((36*1048576)) > "$T/ws/memory.stat"
o=$(bash "$E" "$T/ws"); need "working set = current − inactive_file" "$o" "64.0  то, что видит kubelet"
o=$(bash "$E" "$T/pass"); need "нет inactive_file — НЕИЗМЕРИМ, не current" "$o" "НЕИЗМЕРИМ  нет inactive_file"
mk dead 100 1900 1 1 20 10
o=$(bash "$E" "$T/dead"); need "мёртвая карта" "$o" "ПРОВАЛЕН: 8.2.4 ПРОВАЛЕН (карт без программ 1" "proc_args_map ×1"
mk big 130 1900 0 1 30 15
o=$(bash "$E" "$T/big"); need "сверх бюджета" "$o" "ПРОВАЛЕН: 8.2.2 ПРОВАЛЕН (memory.current idle 130.0" "ПРОВАЛЕН: 8.2.4 ПРОВАЛЕН (карт без программ 0, карты+кольца 45.0"
mk young 100 1000 0 0 0 0
o=$(bash "$E" "$T/young"); need "аптайм и нет vmalloc" "$o" "НЕИЗМЕРИМ: 8.2.2 НЕИЗМЕРИМ (класс НАЗВАН: аптайм 1000" "НЕИЗМЕРИМ: 8.2.4 НЕИЗМЕРИМ (класс НАЗВАН: нет bpf_vmalloc.txt"
mk flow_young 100 1900 0 1 20 10; sed -i.bak 's/etimes= 1900/etimes= 30/' "$T/flow_young/meta.txt"
o=$(bash "$E" "$T/flow_young"); need "поток: окно захватывает старт — НЕИЗМЕРИМ" "$o" "НЕИЗМЕРИМ  первый снимок на аптайме 30 с < 60"
mk flow_empty 100 1900 0 1 20 10; : > "$T/flow_empty/metrics60.txt"
o=$(bash "$E" "$T/flow_empty"); need "поток: пустой снимок — НЕИЗМЕРИМ, не 0" "$o" "НЕИЗМЕРИМ  нет пары metrics/metrics60"
mk vmap 100 1900 0 1 20 0
o=$(bash "$E" "$T/vmap"); need "кольца через vmap" "$o" "= размер колец (vmap без pages=" "ДОСТИГНУТО: 8.2.4 ДОСТИГНУТО (карт без программ 0, карты+кольца 24.0"
mk empty 100 1900 0 1 20 10; : > "$T/empty/memory.current"; rm -f "$T/empty/maps.json"
o=$(bash "$E" "$T/empty"); need "пустой снимок ≠ ноль" "$o" "НЕИЗМЕРИМ: 8.2.2 НЕИЗМЕРИМ (класс НАЗВАН: нет memory.current)" "НЕИЗМЕРИМ: 8.2.4 НЕИЗМЕРИМ (класс НАЗВАН: нет maps.json"
# 8.2.2 (№560): карты P1 вычитаются из memory.current; две таблицы на ноде — НЕИЗМЕРИМ.
p1maps() { # <каталог> <число таблиц>
    local d="$T/$1" j='{"id":1,"type":"hash","name":"live","bytes_memlock":4096},{"id":2,"type":"ringbuf","name":"events","max_entries":4194304,"bytes_memlock":0}' i
    for i in $(seq 1 "$2"); do j="$j,{\"id\":$((20+i)),\"type\":\"hash\",\"name\":\"proc_live\",\"bytes_memlock\":3145728},{\"id\":$((30+i)),\"type\":\"lru_hash\",\"name\":\"proc_exited\",\"bytes_memlock\":3145728},{\"id\":$((40+i)),\"type\":\"percpu_array\",\"name\":\"proc_table_coun\",\"bytes_memlock\":4096}"; done
    echo "[$j]" > "$d/maps.json"
}
mk p1 124 1900 0 1 20 10; p1maps p1 1
o=$(bash "$E" "$T/p1"); need "8.2.2 минус карты P1" "$o" "ДОСТИГНУТО: 8.2.2 ДОСТИГНУТО (memory.current idle 124.0 − карты P1 6.0 = 118.0 МиБ ≤ 120, запас 2.0"
mk p1big 127 1900 0 1 20 10; p1maps p1big 1
o=$(bash "$E" "$T/p1big"); need "8.2.2 сверх порога и после вычета" "$o" "ПРОВАЛЕН: 8.2.2 ПРОВАЛЕН (memory.current idle 127.0 − карты P1 6.0 = 121.0 МиБ > 120"
mk p1two 110 1900 0 1 20 10; p1maps p1two 2
o=$(bash "$E" "$T/p1two"); need "8.2.2 две таблицы — НЕИЗМЕРИМ, не вычет обеих" "$o" "НЕИЗМЕРИМ: 8.2.2 НЕИЗМЕРИМ (класс НАЗВАН: таблиц процессов на ноде 2"
mk p1nomaps 110 1900 0 1 20 10; rm -f "$T/p1nomaps/maps.json"
o=$(bash "$E" "$T/p1nomaps"); need "8.2.2 без maps.json — НЕИЗМЕРИМ, не сырой current" "$o" "НЕИЗМЕРИМ: 8.2.2 НЕИЗМЕРИМ (класс НАЗВАН: нет maps.json — цену карт P1 вычесть нечем"
# C5: sys 100 − released 40 = 60 Go; current 100 → не-Go 40; текст 30 → резерв 70.
mkgo() { # <каталог> <inuse МиБ> [текст КиБ]
    mk "$1" 100 1900 0 1 20 10
    printf 'go_memstats_sys_bytes %d\ngo_memstats_heap_released_bytes %d\ngo_memstats_heap_inuse_bytes %d\n' $((100*1048576)) $((40*1048576)) $(($2*1048576)) >> "$T/$1/metrics.txt"
    [ -n "${3:-}" ] && printf '%10d KiB /opt/ebpf-guard/build/ebpf-guard\n     5 KiB /lib/libc.so\n' "$3" > "$T/$1/smaps_by_map.txt"
}
mkgo c5ok 40 30720
o=$(bash "$E" "$T/c5ok"); need "C5 резерв из не-Go и текста" "$o" "40.0  memory.current − Go" "30.0  RSS файла бинаря" "70  не-Go + текст" "122.0  лимит пода 192" "ИНФО: C5 GOMEMLIMIT по лимиту пода 122 МиБ ≥ пол 50.0 — годится (резерв 70)"
# Под (A4): cg=/kubepods… — текст уже внутри memory.current, резерв = не-Go (40), не 70.
mkgo c5pod 40 30720; echo "cg=/kubepods.slice/kubepods-burstable.slice/x.scope" >> "$T/c5pod/meta.txt"
o=$(bash "$E" "$T/c5pod"); need "C5 под: текст не считается дважды" "$o" "учёт: cgroup контейнера пода" "40  не-Go (текст внутри)" "152.0  лимит пода 192"
mkgo c5spiral 70 30720
o=$(bash "$E" "$T/c5spiral"); need "C5 бюджет пика ниже пола" "$o" "ИНФО: C5 GOMEMLIMIT по бюджету пика 80 МиБ < пол 87.5 — держать пик 150 одним GC нельзя"
mkgo c5notext 40
o=$(bash "$E" "$T/c5notext"); need "C5 без текста — НЕИЗМЕРИМ, не ноль" "$o" "НЕИЗМЕРИМ  нет строки бинаря в smaps_by_map.txt — считается 0"
mk c5nogo 100 1900 0 1 20 10
o=$(bash "$E" "$T/c5nogo"); need "C5 без метрик Go" "$o" "ИНФО: C5 НЕИЗМЕРИМ (класс НАЗВАН"
exit $fail
