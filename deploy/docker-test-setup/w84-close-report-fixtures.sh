#!/bin/bash
# Фикстуры эмиттера w84-close-report.sh и мутации. --mutate: каждая мутация эмиттера ОБЯЗАНА покраснить фикстуры.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
EMIT=${EMITTER:-$HERE/w84-close-report.sh}
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fails=0
ok()  { echo "ok   $1"; }
bad() { echo "FAIL $1"; fails=$((fails + 1)); }
R=impact_systemd_service_disabled; X=dpkg-maintainer-script-stop

# sc <OUT> <NN-имя> <expect> [wit=1 alerts=0 exc=0 total=0 dedup=0 rl=0 noparse=0 cmdlog=<текст>]
sc() {
    local out=$1 name=$2 expect=$3; shift 3
    local wit=1 alerts=0 exc=0 total=0 dedup=0 rl=0 noparse=0 cmdlog=""
    for kv in "$@"; do eval "${kv%%=*}='${kv#*=}'"; done
    local d=$out/$name; mkdir -p "$d"
    echo "$expect" > "$d/expect"; echo "заметка" > "$d/note"
    : > "$d/witness.txt"; local i; for ((i = 1; i <= wit; i++)); do echo "SYSTEMCTL pid=$i file=/usr/bin/systemctl p1=1:sh:dash" >> "$d/witness.txt"; done
    if [ "$noparse" = 1 ]; then echo 'не json' > "$d/alerts.json"; else
        { echo '['; for ((i = 1; i <= alerts; i++)); do [ "$i" -gt 1 ] && echo ','; echo "{\"rule_id\":\"$R\",\"comm\":\"systemctl\"}"; done; echo ']'; } > "$d/alerts.json"
    fi
    { echo "ebpf_guard_rule_exceptions_total{exception_name=\"$X\",rule_id=\"$R\"} 5"
      echo "ebpf_guard_alerts_total{rule_id=\"$R\"} 10"
      echo "ebpf_guard_alerts_dedup_dropped_by_rule_total{rule_id=\"$R\"} 1"
      echo "ebpf_guard_alerts_ratelimited_by_rule_total{rule_id=\"$R\"} 2"; } > "$d/m0.txt"
    { echo "ebpf_guard_rule_exceptions_total{exception_name=\"$X\",rule_id=\"$R\"} $((5 + exc))"
      echo "ebpf_guard_alerts_total{rule_id=\"$R\"} $((10 + total))"
      echo "ebpf_guard_alerts_dedup_dropped_by_rule_total{rule_id=\"$R\"} $((1 + dedup))"
      echo "ebpf_guard_alerts_ratelimited_by_rule_total{rule_id=\"$R\"} $((2 + rl))"; } > "$d/m1.txt"
    [ -n "$cmdlog" ] && echo "$cmdlog" > "$d/cmd.log"
}
good() { # good <OUT> — все сценарии «как надо»
    local o=$1; mkdir -p "$o"; echo "done 2026-10-13T00:00:00Z" > "$o/DONE"
    sc "$o" 01-L1-dpkg-remove silent exc=1
    sc "$o" 02-L2-apt-reinstall silent exc=2
    for n in 03-X1-pre-invoke 04-X2-copy-perl-script 05-X3-prerm-outside-info 06-X4-name-spoof; do sc "$o" "$n" alert alerts=1 total=1; done
    sc "$o" 07-X5-pid-reuse alert alerts=1 total=1 cmdlog="REUSED pid=4242"
}
want() { # want <имя> <OUT> <шаблон>
    local out; out=$(bash "$EMIT" "$2" 2>&1)
    if echo "$out" | grep -aqE "$3"; then ok "$1"; else bad "$1 — нет «${3}»"; echo "$out" | sed 's/^/    | /' | head -14; fi
}

good "$T/good"; want good "$T/good" '^ДОСТИГНУТО: 8\.4\.x .*без алерта 2.*спуфов с алертом 5'
good "$T/fp"; sc "$T/fp" 01-L1-dpkg-remove silent alerts=1 exc=1; want false-positive "$T/fp" '^ПРОВАЛЕН: 8\.4\.x .*01-L1-dpkg-remove: ЛОЖНЫЙ алерт'
good "$T/spoofquiet"; sc "$T/spoofquiet" 05-X3-prerm-outside-info alert; want spoof-silent "$T/spoofquiet" '^ПРОВАЛЕН: 8\.4\.x .*05-X3-prerm-outside-info: СПУФ ушёл в тишину'
good "$T/spoofdedup"; sc "$T/spoofdedup" 05-X3-prerm-outside-info alert dedup=1; want spoof-dedup "$T/spoofdedup" '^НЕИЗМЕРИМ: 8\.4\.x .*дедуп \+1'
good "$T/spoofrl"; sc "$T/spoofrl" 05-X3-prerm-outside-info alert rl=3; want spoof-ratelimited "$T/spoofrl" '^НЕИЗМЕРИМ: 8\.4\.x .*лимитер \+3'
good "$T/spoofapi"; sc "$T/spoofapi" 05-X3-prerm-outside-info alert alerts=0 total=1; want spoof-by-counter "$T/spoofapi" '^ДОСТИГНУТО: 8\.4\.x '
good "$T/noexc"; sc "$T/noexc" 02-L2-apt-reinstall silent exc=0; want no-exception-use "$T/noexc" '^НЕИЗМЕРИМ: 8\.4\.x .*исключение НЕ применялось'
good "$T/nowit"; sc "$T/nowit" 01-L1-dpkg-remove silent wit=0 exc=1; want no-witness-legit "$T/nowit" '^НЕИЗМЕРИМ: 8\.4\.x .*свидетель не видел systemctl'
good "$T/nowit2"; sc "$T/nowit2" 06-X4-name-spoof alert wit=0 alerts=0; want no-witness-spoof "$T/nowit2" '^НЕИЗМЕРИМ: 8\.4\.x .*06-X4-name-spoof: свидетель не видел'
good "$T/skip"; sc "$T/skip" 02-L2-apt-reinstall skip; want skipped "$T/skip" '^НЕИЗМЕРИМ: 8\.4\.x .*02-L2-apt-reinstall не исполнен'
good "$T/noreuse"; sc "$T/noreuse" 07-X5-pid-reuse alert alerts=1 total=1 cmdlog="NO-REUSE: новый pid 5 != 4"; want x5-no-reuse "$T/noreuse" '^НЕИЗМЕРИМ: 8\.4\.x .*X5: реюз pid НЕ воспроизведён'
good "$T/noparse"; sc "$T/noparse" 01-L1-dpkg-remove silent noparse=1 exc=1; want unparsable "$T/noparse" '^НЕИЗМЕРИМ: 8\.4\.x .*без разбираемого снимка'
good "$T/both"; sc "$T/both" 01-L1-dpkg-remove silent alerts=1 exc=1; sc "$T/both" 02-L2-apt-reinstall skip; want fail-and-unmeasurable "$T/both" '^ПРОВАЛЕН: 8\.4\.x .*неизмеримо также'
good "$T/nodone"; rm "$T/nodone/DONE"; want no-done "$T/nodone" '^НЕИЗМЕРИМ: 8\.4\.x .*нет DONE'
good "$T/die"; echo "die: нет bpftrace" > "$T/die/DONE"; want died "$T/die" '^НЕИЗМЕРИМ: 8\.4\.x .*die: нет bpftrace'
mkdir -p "$T/empty"; echo "done x" > "$T/empty/DONE"; want empty "$T/empty" '^НЕИЗМЕРИМ: 8\.4\.x .*нет ни одного сценария'
want no-dir "$T/нет-такого" '^НЕИЗМЕРИМ: 8\.4\.x .*нет каталога'

if [ "${1:-}" = "--mutate" ]; then
    echo "== мутации: каждая обязана покраснить фикстуры"
    mut() { # mut <имя> <sed-выражение>
        local n=$1 expr=$2 m=$T/mut-$1.sh
        sed -e "$expr" "$EMIT" > "$m"
        if cmp -s "$m" "$EMIT"; then bad "мутация $n не изменила эмиттер (выражение устарело)"; return; fi
        if ! EMITTER=$m bash "$0" > /dev/null 2>&1; then ok "мутация $n покраснила фикстуры"; else bad "мутация $n ПРОШЛА фикстуры — прибор не ловит"; fi
    }
    mut no-witness-guard  's/if \[ "\$wit" -eq 0 \]; then/if false; then/'
    mut fp-not-failed     's/if \[ "\$na" -gt 0 \]; then$/if false; then/'
    mut exc-use-not-needed 's/elif \[ "\$de" -lt 1 \]; then/elif false; then/'
    mut spoof-silent-ok   's/fail="\$fail; \$name: СПУФ ушёл в тишину (алертов 0, systemctl был)"/ok=$((ok + 1))/'
    mut dedup-not-class   's/elif { \[ "\$dd" != "?" \] \&\& \[ "\$dd" -gt 0 \]; } || { \[ "\$dr" != "?" \] \&\& \[ "\$dr" -gt 0 \]; }; then/elif false; then/'
    mut x5-reuse-not-needed 's/if grep -aq .\^REUSED pid=. "\$x5\/cmd.log" 2>\/dev\/null; then/if true; then/'
    mut done-guard        's/if \[ ! -s "\$OUT\/DONE" \] || ! grep -q .\^done. "\$OUT\/DONE" 2>\/dev\/null; then/if false; then/'
    mut skip-as-ok        's/echo "  \$name: НЕ ИСПОЛНЕН (\$(cat "\$d\/note" 2>\/dev\/null))"; cls="\$cls; \$name не исполнен"; continue/ok=$((ok + 1)); continue/'
    mut counter-alt-off   's/if \[ "\$na" -gt 0 \] || { \[ "\$dt" != "?" \] \&\& \[ "\$dt" -gt 0 \]; }; then/if [ "$na" -gt 0 ]; then/'
fi
echo "-- fails=$fails"
[ "$fails" = 0 ]
