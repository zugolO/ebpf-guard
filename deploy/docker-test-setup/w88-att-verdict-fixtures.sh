#!/bin/bash
# Фикстуры w88-att-verdict.sh (метка 8.8.6, состав детекта): синтетический пакет из 16 категорий и реестр фонового таймера.
#   w88-att-verdict-fixtures.sh            — фикстуры
#   w88-att-verdict-fixtures.sh --mutate   — мутации эмиттера обязаны покраснить фикстуры
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPT=${VERDICT:-$HERE/w88-att-verdict.sh}
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fails=0; ok() { echo "ok   $1"; }; bad() { echo "FAIL $1"; fails=$((fails + 1)); }
cp "$HERE/w85-close-report.sh" "$T/" 2> /dev/null; mkdir -p "$T/attacks"

mk() { # mk <каталог> <rule_id через пробел для НОВЫХ алертов> — 16 категорий, у каждой новый алерт с её comm; baseline пуст
    mkdir -p "$1"
    jq -n '[range(1;17) | {category: "cat\(.)", comm: "c\(.)", timestamp: "2026-10-18T10:00:00Z"}]' > "$1/attack-manifest.json"
    echo '[]' > "$1/baseline-alerts-20261018_100000.json"
    python3 - "$1" "$2" <<'PY'
import json, sys
d, ids = sys.argv[1], sys.argv[2].split()
al = [{"id": f"a{i}", "rule_id": r, "comm": f"c{i % 16 + 1}"} for i, r in enumerate(ids)]
json.dump(al, open(f"{d}/final-alerts-20261018_100000.json", "w"))
PY
}
BASE_IDS="r_a r_b r_c r_d r_e r_f r_g r_h r_i r_j r_k r_l r_m r_n r_o r_p k8s_token_access"
mk "$T/base" "$BASE_IDS"
echo "k8s_token_access" > "$T/reg.txt"
v() { ATT_TIMER_REG="$T/reg.txt" bash "$SCRIPT" pod1c "$1" "$T/base" 2>&1; }
has() { grep -aqE "$2" <<< "$1"; }

mk "$T/same" "$BASE_IDS"; o=$(v "$T/same"); has "$o" '8\.8\.6 pod1c: PASS' && ok "тот же состав: PASS" || { bad "тот же состав"; echo "$o"; }
mk "$T/timer" "r_a r_b r_c r_d r_e r_f r_g r_h r_i r_j r_k r_l r_m r_n r_o r_p"; o=$(v "$T/timer")
has "$o" '8\.8\.6 pod1c: PASS' && has "$o" 'не судится.*k8s_token_access' && ok "выпал только тип реестра: PASS, тип напечатан" || { bad "тип реестра"; echo "$o"; }
mk "$T/real" "r_a r_b r_c r_d r_e r_f r_g r_h r_i r_j r_k r_l r_m r_n r_o k8s_token_access"; o=$(v "$T/real")
has "$o" '8\.8\.6 pod1c: FAIL.*выпало 1: r_p' && ok "выпал настоящий тип: FAIL" || { bad "настоящий тип"; echo "$o"; }
mk "$T/both" "r_a r_b r_c r_d r_e r_f r_g r_h r_i r_j r_k r_l r_m r_n r_o"; o=$(v "$T/both")
has "$o" '8\.8\.6 pod1c: FAIL.*выпало 1: r_p.*k8s_token_access' && ok "выпал и настоящий, и реестровый: FAIL, оба напечатаны" || { bad "оба"; echo "$o"; }
: > "$T/reg.txt"; o=$(v "$T/timer"); has "$o" '8\.8\.6 pod1c: FAIL.*выпало 1: k8s_token_access' && ok "пустой реестр: тип судится" || { bad "пустой реестр"; echo "$o"; }
printf '# k8s_token_access\n\n' > "$T/reg.txt"; o=$(v "$T/timer"); has "$o" '8\.8\.6 pod1c: FAIL' && ok "закомментированная строка реестра не действует" || { bad "комментарий"; echo "$o"; }
echo "k8s_token_access" > "$T/reg.txt"
mk "$T/norec" "r_a r_b r_c r_d r_e r_f r_g r_h r_i r_j r_k r_l r_m r_n r_o"; python3 - "$T/norec" <<'PY'
import json, sys
f = sys.argv[1] + "/final-alerts-20261018_100000.json"; a = json.load(open(f))
json.dump([x for x in a if x["comm"] != "c3"], open(f, "w"))
PY
o=$(v "$T/norec"); has "$o" '8\.8\.6 pod1c: FAIL.*recall 14/16' && ok "recall 14/16: FAIL при любом составе" || { bad "recall"; echo "$o"; }

if [ "${1:-}" = "--mutate" ]; then
    echo "── мутации эмиттера ──"
    mutate() { # mutate <имя> <sed> <минимум красных>
        cp "$HERE/w88-att-verdict.sh" "$T/mut.sh"; cp "$HERE/w85-close-report.sh" "$T/"
        sed -i.bak "$2" "$T/mut.sh"; cmp -s "$T/mut.sh" "$HERE/w88-att-verdict.sh" && { bad "мутация '$1' не изменила файл"; return; }
        n=$(VERDICT="$T/mut.sh" bash "$0" 2>&1 | grep -c '^FAIL')
        [ "$n" -ge "$3" ] && ok "мутация '$1' краснит $n фикстур" || bad "мутация '$1' краснит только $n (< $3)"
    }
    mutate "реестр не читается" 's|^reg=\$(grep -vE.*|reg=""|' 2
    mutate "реестр не печатается" 's|\${skipped:+; не судится|${skippedX:+; не судится|' 1
    mutate "выпавшие не считаются" 's|\[ "\$nm" -eq 0 \] \|\| verdict=FAIL|true \|\| verdict=FAIL|' 2
    mutate "комментарии реестра действуют" "s/grep -vE '^\\[\\[:space:\\]\\]\\*(#|\\$)'/sed 's\\/^# *\\/\\/'/" 1
fi
echo "итого: $fails красных"; [ "$fails" -eq 0 ]
