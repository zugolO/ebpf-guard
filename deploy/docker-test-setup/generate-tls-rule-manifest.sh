#!/usr/bin/env bash
# generate-tls-rule-manifest.sh — item 1 постановки волны 6.4 (plan.md, §6.4).
#
# ЗАЧЕМ. Ровно тот же довод, что у generate-dns-rule-manifest.sh (№327): без оси
# event_type в сторе/метриках разрез по источнику события возможен только манифестом
# rule_id в слое правил. attacks/tls-rule-ids.txt — этот манифест для 23 TLS-правил,
# снятый 23.09.2026.
#
# ДВА СЕМЕЙСТВА, НЕ ОДНО. 23 правила `event_type: tls` кормятся ДВУМЯ разными
# коллекторами: 13 «plaintext» (uprobe SSL_write/SSL_read, `collectors.tls`) и
# 10 «ja3» (kprobe sendto, `collectors.tls_fingerprint`) — см. постановку 6.4,
# «Состав предмета». Общий ноль по 23 скрыл бы, что одно семейство живо, а другое
# нет (развилка item 4 закрыта исходом (б), №433: JA3-семейство вне предмета
# измерения прогонов A/B волны 6.4, но остаётся в манифесте — манифест описывает
# состав правил, а не то, что волна меряет). Манифест поэтому пишет ДВЕ секции.
#
# ИЗВЛЕЧЕНИЕ. Тот же построчный автомат по rules/*.yaml, что у DNS-манифеста:
# "- id: <rule_id>" открывает правило, "event_type: tls" внутри него — TLS-правило,
# "field: ja3" (с необязательным "- " перед ним, условие бывает внутри
# condition_group) — правило семейства ja3, иначе — plaintext. rules/rego/ и
# rules/custom/ не содержат event_type: tls на 23.09.2026 — сверено руками, не
# гарантия конструкции (тот же оговор, что у DNS-манифеста).
#
# ИСПОЛЬЗОВАНИЕ.
#   ./generate-tls-rule-manifest.sh          — печатает текущий манифест в stdout
#   ./generate-tls-rule-manifest.sh --check  — сверяет со снятым attacks/tls-rule-ids.txt,
#                                               код возврата 1 и diff при расхождении
#   ./generate-tls-rule-manifest.sh --write  — перезаписывает attacks/tls-rule-ids.txt
#                                               (только вместе с записью в plan.md)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RULES_DIR="$REPO_ROOT/rules"
MANIFEST="$SCRIPT_DIR/attacks/tls-rule-ids.txt"

extract_tls_rule_ids() {
    awk '
        /^[[:space:]]*-[[:space:]]*id:/ {
            if (cur != "" && is_tls) {
                print (has_ja3 ? "ja3" : "plaintext") "\t" cur
            }
            line=$0
            sub(/^[[:space:]]*-[[:space:]]*id:[[:space:]]*/, "", line)
            gsub(/"/, "", line)
            cur=line
            is_tls=0
            has_ja3=0
            next
        }
        /^[[:space:]]*event_type:[[:space:]]*tls[[:space:]]*$/ { is_tls=1 }
        /^[[:space:]]*-?[[:space:]]*field:[[:space:]]*ja3[[:space:]]*$/ { has_ja3=1 }
        END {
            if (cur != "" && is_tls) print (has_ja3 ? "ja3" : "plaintext") "\t" cur
        }
    ' "$RULES_DIR"/*.yaml | sort -k1,1 -k2,2
}

# Печатает манифест в формате секций: "# plaintext (N)" / id-список / "# ja3 (N)" / id-список.
format_manifest() {
    local raw="$1"
    local plaintext_ids ja3_ids
    plaintext_ids="$(echo "$raw" | awk -F'\t' '$1=="plaintext"{print $2}')"
    ja3_ids="$(echo "$raw" | awk -F'\t' '$1=="ja3"{print $2}')"
    local plaintext_count ja3_count
    plaintext_count="$(echo "$plaintext_ids" | grep -c . || true)"
    ja3_count="$(echo "$ja3_ids" | grep -c . || true)"
    printf '# plaintext (%s)\n%s\n# ja3 (%s)\n%s\n' \
        "$plaintext_count" "$plaintext_ids" "$ja3_count" "$ja3_ids"
}

parse_section() {
    # $1 = имя секции (plaintext|ja3), читает stdin манифеста, печатает id этой секции.
    awk -v want="# $1" '
        /^# (plaintext|ja3)/ { insection = ($0 == want || $0 ~ ("^" want "( |\\()")); next }
        /^[[:space:]]*$/ { next }
        insection { print }
    '
}

current_raw="$(extract_tls_rule_ids)"
current_count="$(echo "$current_raw" | grep -c . || true)"

mode="${1:-}"

case "$mode" in
    --check)
        checked_body="$(grep -v '^#[^ ]* SEE-HEADER' "$MANIFEST" | awk '/^[^#]|^# (plaintext|ja3)/')"
        checked_plaintext="$(echo "$checked_body" | parse_section plaintext | sort -u)"
        checked_ja3="$(echo "$checked_body" | parse_section ja3 | sort -u)"
        current_plaintext="$(echo "$current_raw" | awk -F'\t' '$1=="plaintext"{print $2}' | sort -u)"
        current_ja3="$(echo "$current_raw" | awk -F'\t' '$1=="ja3"{print $2}' | sort -u)"

        if [[ "$current_plaintext" == "$checked_plaintext" && "$current_ja3" == "$checked_ja3" ]]; then
            echo "OK: манифест tls-rule-ids.txt дрейфа не показал — $current_count id (plaintext + ja3), сверка с rules/*.yaml совпала"
            exit 0
        fi
        echo "=== МАНИФЕСТ TLS-ПРАВИЛ УСТАРЕЛ: tls-rule-ids.txt разошёлся с rules/*.yaml"
        added_p="$(comm -23 <(echo "$current_plaintext") <(echo "$checked_plaintext"))"
        removed_p="$(comm -13 <(echo "$current_plaintext") <(echo "$checked_plaintext"))"
        added_j="$(comm -23 <(echo "$current_ja3") <(echo "$checked_ja3"))"
        removed_j="$(comm -13 <(echo "$current_ja3") <(echo "$checked_ja3"))"
        [[ -n "$added_p" ]] && printf 'plaintext добавлено:\n%s\n' "$added_p"
        [[ -n "$removed_p" ]] && printf 'plaintext пропало:\n%s\n' "$removed_p"
        [[ -n "$added_j" ]] && printf 'ja3 добавлено:\n%s\n' "$added_j"
        [[ -n "$removed_j" ]] && printf 'ja3 пропало:\n%s\n' "$removed_j"
        echo "Обновить: ./generate-tls-rule-manifest.sh --write, и записать в plan.md, какая волна и почему изменила состав."
        exit 1
        ;;
    --write)
        tmp="$(mktemp)"
        awk '/^[^#]/{exit} /^# (plaintext|ja3) \([0-9]+\)$/{exit} {print}' "$MANIFEST" > "$tmp"
        format_manifest "$current_raw" >> "$tmp"
        mv "$tmp" "$MANIFEST"
        echo "OK: tls-rule-ids.txt перезаписан, $current_count id. Не забыть запись в plan.md."
        ;;
    "")
        format_manifest "$current_raw"
        ;;
    *)
        echo "usage: $0 [--check|--write]" >&2
        exit 2
        ;;
esac
