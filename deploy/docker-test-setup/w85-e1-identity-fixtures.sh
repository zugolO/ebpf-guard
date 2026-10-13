#!/bin/bash
# Фикстуры w85-e1-identity.sh и мутации.
set -u
HERE=$(cd "$(dirname "$0")" && pwd); EMIT=${EMITTER:-$HERE/w85-e1-identity.sh}
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fails=0; ok() { echo "ok   $1"; }; bad() { echo "FAIL $1"; fails=$((fails + 1)); }
# al <файл> <правило:comm:n>… — массив алертов
al() { local f=$1; shift; local first=1 x r c n i; printf '[' > "$f"
    for x in "$@"; do r=${x%%:*}; c=${x#*:}; c=${c%%:*}; n=${x##*:}
        for i in $(seq 1 "$n"); do [ $first = 1 ] || printf ',' >> "$f"; first=0; printf '{"rule_id":"%s","comm":"%s"}' "$r" "$c" >> "$f"; done
    done; printf ']' >> "$f"; }
echo '[{"category":"c1","comm":"sqlmap"},{"category":"c2","comm":"xmrig"}]' > "$T/man.json"
want() { local out; out=$(bash "$EMIT" "$2" "$3" "$4" ${5:-} 2>&1); if echo "$out" | grep -aqE "$6"; then ok "$1"; else bad "$1 — нет «${6}»"; echo "$out" | sed 's/^/    | /' | head -8; fi; }
al "$T/a.json" r1:sqlmap:3 r2:xmrig:1 bg1:systemd:2
al "$T/b.json" r1:sqlmap:4 r2:xmrig:2 bg1:systemd:1
want same          "$T/a.json" "$T/b.json" "$T/man.json" "" '^ДОСТИГНУТО: 8\.5\.E1i .*расхождений детекта нет'
al "$T/c.json" r1:sqlmap:3 r2:xmrig:1 bg1:systemd:2 bgonly:systemd-logind:1
want bg-only-new   "$T/c.json" "$T/b.json" "$T/man.json" "" '^ДОСТИГНУТО: 8\.5\.E1i .*различия только в фоне узла: bgonly\(фон, только в новом\)'
al "$T/d.json" r1:sqlmap:3 bg1:systemd:2
want lost-attack   "$T/d.json" "$T/b.json" "$T/man.json" "" '^ПРОВАЛЕН: 8\.5\.E1i .*только в старом r2\(атака 2\)'
al "$T/e.json" r1:sqlmap:3 r2:xmrig:1 r3:sqlmap:1
want gained-attack "$T/e.json" "$T/b.json" "$T/man.json" "" '^ПРОВАЛЕН: 8\.5\.E1i .*только в новом r3\(атака 1\)'
al "$T/f.json" r1:sqlmap:30 r2:xmrig:1
want volume-bg     "$T/f.json" "$T/b.json" "$T/man.json" "" 'объём разошёлся > 3× \(фон окон\): r1 4→30'
echo '[]' > "$T/empty.json"
want empty         "$T/empty.json" "$T/b.json" "$T/man.json" "" '^НЕИЗМЕРИМ: 8\.5\.E1i .*ноль правил'
want no-file       "$T/нет.json" "$T/b.json" "$T/man.json" "" '^НЕИЗМЕРИМ: 8\.5\.E1i .*нет или не разобран'
want no-manifest   "$T/a.json" "$T/b.json" "$T/нет.json" "" '^НЕИЗМЕРИМ: 8\.5\.E1i .*нет манифеста'
if [ "${1:-}" = --mutate ]; then
    mut() { local f; f=$(mktemp); sed "$2" "$EMIT" > "$f"; if cmp -s "$f" "$EMIT"; then bad "мутация $1 не применилась"; rm -f "$f"; return; fi
        if EMITTER=$f bash "$0" 2>/dev/null | grep -q '^FAIL'; then ok "мутация $1 покраснила фикстуры"; else bad "мутация $1 НЕ покраснила фикстуры"; fi; rm -f "$f"; }
    mut manifest-blind 's/if \[ "\$a" -gt 0 \]; then only_new=/if true; then only_new=/'
    mut old-side       's/a=\$(atk "\$O" "\$r"); if \[ "\$a" -gt 0 \]; then only_old=/a=0; if [ "$a" -gt 0 ]; then only_old=/'
    mut verdict-new    's/if \[ -z "\$only_new" \] \&\& \[ -z "\$only_old" \]; then/if [ -z "$only_new" ]; then/'
    mut empty-guard    's/if \[ "\$tn" -eq 0 \] || \[ "\$to" -eq 0 \]; then/if false; then/'
fi
echo "-- fails=$fails"; [ "$fails" = 0 ]
