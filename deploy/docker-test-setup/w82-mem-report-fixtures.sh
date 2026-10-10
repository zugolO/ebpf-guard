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
o=$(bash "$E" "$T/pass"); need "всё в бюджете" "$o" "ДОСТИГНУТО: 8.2.2 ДОСТИГНУТО" "ДОСТИГНУТО: 8.2.4 ДОСТИГНУТО (карт без программ 0, карты+кольца 30.0" "1000  Б/событие"
mk dead 100 1900 1 1 20 10
o=$(bash "$E" "$T/dead"); need "мёртвая карта" "$o" "ПРОВАЛЕН: 8.2.4 ПРОВАЛЕН (карт без программ 1" "proc_args_map ×1"
mk big 130 1900 0 1 30 15
o=$(bash "$E" "$T/big"); need "сверх бюджета" "$o" "ПРОВАЛЕН: 8.2.2 ПРОВАЛЕН (memory.current idle 130.0" "ПРОВАЛЕН: 8.2.4 ПРОВАЛЕН (карт без программ 0, карты+кольца 45.0"
mk young 100 1000 0 0 0 0
o=$(bash "$E" "$T/young"); need "аптайм и нет vmalloc" "$o" "НЕИЗМЕРИМ: 8.2.2 НЕИЗМЕРИМ (класс НАЗВАН: аптайм 1000" "НЕИЗМЕРИМ: 8.2.4 НЕИЗМЕРИМ (класс НАЗВАН: нет bpf_vmalloc.txt"
mk vmap 100 1900 0 1 20 0
o=$(bash "$E" "$T/vmap"); need "кольца через vmap" "$o" "= размер колец (vmap без pages=" "ДОСТИГНУТО: 8.2.4 ДОСТИГНУТО (карт без программ 0, карты+кольца 24.0"
mk empty 100 1900 0 1 20 10; : > "$T/empty/memory.current"; rm -f "$T/empty/maps.json"
o=$(bash "$E" "$T/empty"); need "пустой снимок ≠ ноль" "$o" "НЕИЗМЕРИМ: 8.2.2 НЕИЗМЕРИМ (класс НАЗВАН: нет memory.current)" "НЕИЗМЕРИМ: 8.2.4 НЕИЗМЕРИМ (класс НАЗВАН: нет maps.json"
exit $fail
