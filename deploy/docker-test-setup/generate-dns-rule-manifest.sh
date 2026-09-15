#!/usr/bin/env bash
# generate-dns-rule-manifest.sh — item 1 постановки волны 6.3 (находка №327,
# пункт 4 «Что из этого следует для постановки 6.3», plan.md, §6.3).
#
# ЗАЧЕМ. `Alert.Event` помечен `json:"-"` (pkg/types), стор и метрики не несут
# оси event_type — разрез по источнику события возможен ТОЛЬКО манифестом
# rule_id в слое правил. attacks/dns-rule-ids.txt — этот манифест, снятый
# 15.09.2026 (30 id). Правило с event_type: dns, добавленное ПОСЛЕ снятия
# манифеста, молча упадёт в корзину «старого шума» — тот же механизм, что
# [[new-rule-breaks-replays]]. Этот скрипт — сторож дрейфа манифеста, а не
# просто генератор: манифест обязан сверяться на КАЖДОМ прогоне волны 6.3,
# сверка должна быть первым пунктом волны, потому что от неё зависят все
# величины объёма (6.3.3/6.3.4).
#
# ИЗВЛЕЧЕНИЕ. Простой построчный автомат по rules/*.yaml (rules/rego/ и
# rules/custom/ не содержат правил с event_type: dns на 15.09.2026 — сверено
# руками, не гарантия конструкции): строка "- id: <rule_id>" открывает
# текущее правило, строка "event_type: dns" внутри него добавляет id в
# список. Без внешних зависимостей (yq/python-yaml на mac нет) — это
# оправдано простотой формы rules/*.yaml (плоский список правил, id всегда
# первым полем), не переносится на вложенные структуры без проверки.
#
# ИСПОЛЬЗОВАНИЕ.
#   ./generate-dns-rule-manifest.sh          — печатает текущий манифест в stdout
#   ./generate-dns-rule-manifest.sh --check  — сверяет со снятым attacks/dns-rule-ids.txt,
#                                               код возврата 1 и diff при расхождении
#   ./generate-dns-rule-manifest.sh --write  — перезаписывает attacks/dns-rule-ids.txt
#                                               (только вместе с записью в plan.md, см. шапку файла)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RULES_DIR="$REPO_ROOT/rules"
MANIFEST="$SCRIPT_DIR/attacks/dns-rule-ids.txt"

extract_dns_rule_ids() {
    awk '
        /^[[:space:]]*-[[:space:]]*id:/ {
            line=$0
            sub(/^[[:space:]]*-[[:space:]]*id:[[:space:]]*/, "", line)
            gsub(/"/, "", line)
            cur=line
            next
        }
        /^[[:space:]]*event_type:[[:space:]]*dns[[:space:]]*$/ {
            if (cur != "") print cur
        }
    ' "$RULES_DIR"/*.yaml | sort -u
}

current_ids="$(extract_dns_rule_ids)"
current_count="$(echo "$current_ids" | grep -c . || true)"

mode="${1:-}"

case "$mode" in
    --check)
        checked_in_ids="$(grep -v '^#' "$MANIFEST" | grep -v '^[[:space:]]*$' | sort -u)"
        if [[ "$current_ids" == "$checked_in_ids" ]]; then
            echo "OK: манифест dns-rule-ids.txt дрейфа не показал — $current_count id, сверка с rules/*.yaml совпала"
            exit 0
        fi
        added="$(comm -23 <(echo "$current_ids") <(echo "$checked_in_ids"))"
        removed="$(comm -13 <(echo "$current_ids") <(echo "$checked_in_ids"))"
        echo "=== МАНИФЕСТ DNS-ПРАВИЛ УСТАРЕЛ: dns-rule-ids.txt разошёлся с rules/*.yaml"
        [[ -n "$added" ]] && printf 'добавлено (есть в rules/, нет в манифесте):\n%s\n' "$added"
        [[ -n "$removed" ]] && printf 'пропало (есть в манифесте, нет в rules/):\n%s\n' "$removed"
        echo "Обновить: ./generate-dns-rule-manifest.sh --write, и записать в plan.md, какая волна и почему изменила состав (не тихо — см. шапку dns-rule-ids.txt)."
        exit 1
        ;;
    --write)
        tmp="$(mktemp)"
        # Заголовок манифеста сохраняется руками (описывает происхождение и
        # порядок обновления) — перезаписывается только список id ниже него.
        awk '/^[^#]/{exit} {print}' "$MANIFEST" > "$tmp"
        echo "$current_ids" >> "$tmp"
        mv "$tmp" "$MANIFEST"
        echo "OK: dns-rule-ids.txt перезаписан, $current_count id. Не забыть запись в plan.md."
        ;;
    "")
        echo "$current_ids"
        ;;
    *)
        echo "usage: $0 [--check|--write]" >&2
        exit 2
        ;;
esac
