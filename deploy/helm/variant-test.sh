#!/bin/bash
# 9.1 / Д15 (волна 9): чарт выбирает один из двух артефактов — core (умолчание, образ без
# тега -full, policy.rego выключен) и full (образ <tag>-full, Rego включается ключом).
# Рендер core + policy.rego.enabled=true обязан упасть. Запуск: variant-test.sh [путь к чарту]
set -u
CHART=${1:-$(dirname "$0")/ebpf-guard}
HELM=${HELM:-helm}
fail=0
ok()  { echo "OK   $*"; }
bad() { echo "FAIL $*"; fail=1; }

r() { "$HELM" template t "$CHART" "$@" 2>&1; }

out=$(r)
img=$(echo "$out" | grep -m1 -E 'image: "?zugolO/ebpf-guard:')
{ [ -n "$img" ] && ! echo "$img" | grep -q -- '-full'; } && ok "умолчание — образ core (без -full)" || bad "умолчание: образ не core: $(echo "$out" | grep -m1 'image: .*ebpf-guard')"
echo "$out" | grep -A2 '^ *policy:' | grep -q 'enabled: false' && ok "умолчание — policy.rego.enabled: false" || bad "умолчание: policy.rego не выключен"
echo "$out" | grep -A2 '^ *sequence:' | grep -q 'enabled: false' && ok "умолчание — profiler.sequence.enabled: false" || bad "умолчание: sequence не выключен"

out=$(r --set image.variant=full --set config.policy.rego.enabled=true)
echo "$out" | grep -qE 'image: "?zugolO/ebpf-guard:[^"[:space:]]+-full' && ok "full — образ с суффиксом -full" || bad "full: образ без -full"
echo "$out" | grep -A2 '^ *policy:' | grep -q 'enabled: true' && ok "full + ключ — policy.rego.enabled: true" || bad "full: ключ не дошёл до конфига"

out=$(r --set config.policy.rego.enabled=true)
echo "$out" | grep -q 'requires image.variant=full' && ok "core + rego.enabled=true — рендер падает с причиной" || bad "core + rego.enabled=true отрисовался: $(echo "$out" | head -3)"

out=$(r --set config.profiler.sequence.enabled=true)
echo "$out" | grep -A2 '^ *sequence:' | grep -q 'enabled: true' && ok "sequence — опция включается" || bad "sequence: ключ не дошёл"
exit $fail
