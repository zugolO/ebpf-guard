#!/bin/bash
# Фикстуры w9-ladder-verdict.sh (метки 8.8.1–8.8.7 и 9.6 ночи 9).
#   w9-ladder-verdict-fixtures.sh            — фикстуры
#   w9-ladder-verdict-fixtures.sh --mutate   — мутации переходника обязаны покраснить фикстуры
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
MODE=${1:-}
EM=${EM:-$HERE/w9-ladder-verdict.sh}
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fails=0; ok() { echo "ok   $1"; }; bad() { echo "FAIL $1"; fails=$((fails + 1)); }
w() { # w <имя> <регэксп> <вывод>
    grep -aqE "$2" <<< "$3" && ok "$1" || { bad "$1"; printf '%s\n' "$3" | sed 's/^/     /' | head -14; }
}
full() { # полный отчёт лестницы + пара; $1 — sed-правка строк
    cat > "$T/rep" <<'EOF'
### host done
8.8.1 host: PASS — ступеней судимо 6
8.8.2 host: PASS — минимум 1.00
8.8.3 host: PASS — худшая потеря 0.00%
8.8.4 host: PASS — худшая потеря 0.00% (0.0 соб.), порог 0.1%
8.8.5 host: НЕИЗМЕРИМ — метка только для роли pod
### podd done
8.8.1 pod: PASS — ступеней судимо 7
8.8.2 pod: PASS — минимум 1.00
8.8.3 pod: PASS — худшая потеря 0.00%
8.8.4 pod: PASS — худшая потеря 0.00%
8.8.5 pod: PASS — база сторожа 1.0 (квота 1.0)
### hostatt
8.8.6h host: PASS — чтений 327
8.8.6 host: PASS — recall 16/16; выпало 0
EOF
    echo "8.8.7 idle: PASS — отношение 1.003 (порог ≤ 1.05)" > "$T/ab"
    [ -n "${1:-}" ] && sed -i.bak -E "$1" "$T/rep" "$T/ab"
    bash "$EM" "$T/rep" "$T/ab"
}
o=$(full); w all-pass '^ДОСТИГНУТО: 9\.6 ' "$o"
w all-pass-884 '^ДОСТИГНУТО: 8\.8\.4 \(не хуже 8\.8; host PASS; pod PASS\)' "$o"
w all-pass-885-pod-only '^ДОСТИГНУТО: 8\.8\.5 \(не хуже 8\.8; pod PASS\)' "$o"
o=$(full 's/^8\.8\.4 pod: PASS/8.8.4 pod: FAIL/'); w pod-884-fail '^ПРОВАЛЕН: 8\.8\.4 \(хуже 8\.8 \(эталон PASS\); pod: ' "$o"
w pod-884-fail-96 '^ПРОВАЛЕН: 9\.6 \(метки хуже 8\.8: 8\.8\.4' "$o"
o=$(full '/^8\.8\.[0-9]+(\(0\))? pod: /d'); w pod-missing '^НЕИЗМЕРИМ: 8\.8\.1 \(класс НАЗВАН; pod: нет строки эмиттера' "$o"
w pod-missing-96 '^НЕИЗМЕРИМ: 9\.6 \(класс НАЗВАН: неизмеримы: 8\.8\.1 8\.8\.2 8\.8\.3 8\.8\.4 8\.8\.5' "$o"
o=$(full 's/^8\.8\.3 host: PASS/8.8.3 host: НЕИЗМЕРИМ/'); w host-883-unm '^НЕИЗМЕРИМ: 8\.8\.3 \(класс НАЗВАН; host: ' "$o"
o=$(full 's/^8\.8\.7 idle: PASS/8.8.7 idle: НЕИЗМЕРИМ/'); w ab-off '^НЕИЗМЕРИМ: 8\.8\.7 ' "$o"
w ab-off-96-unaffected '^ДОСТИГНУТО: 9\.6 ' "$o"
o=$(full 's/^8\.8\.6h host: PASS/8.8.6h host: FAIL/'); w hot-fail-96 '^ПРОВАЛЕН: 9\.6 .*8\.8\.6h' "$o"
o=$(bash "$EM" "$T/нет" 2>&1); w no-input '^НЕИЗМЕРИМ: 9\.6 ' "$o"

if [ "$MODE" = "--mutate" ]; then
    echo "── мутации переходника ──"
    mutate() { # mutate <имя> <sed> <мин. красных>
        cp "$EM" "$T/mut.sh"; sed -i.bak "$2" "$T/mut.sh"; cmp -s "$T/mut.sh" "$EM" && { bad "мутация '$1' не изменила файл"; return; }
        n=$(EM="$T/mut.sh" bash "$0" 2>&1 | grep -c '^FAIL')
        [ "$n" -ge "$3" ] && ok "мутация '$1' краснит $n фикстур" || bad "мутация '$1' краснит только $n (< $3)"
    }
    mutate "FAIL прощается" 's/FAIL) fail="\$fail; \$r: \$(role_detail "\$lbl" "\$r")" ;;/FAIL) ;;/' 2
    mutate "нет строки = PASS" 's/НЕТ) unm="\$unm; \$r: нет строки эмиттера" ;;/НЕТ) ;;/' 2
    mutate "под не обязателен" 's/"8.8.4:host pod"/"8.8.4:host"/' 1
    mutate "9.6 не судит 8.8.6h" 's/8.8.5 8.8.6 8.8.6h; do/8.8.5 8.8.6; do/' 1
fi
echo "итого: $fails красных"; [ "$fails" -eq 0 ]
