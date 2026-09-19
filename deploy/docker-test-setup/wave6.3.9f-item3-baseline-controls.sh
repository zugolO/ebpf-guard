#!/bin/bash
# wave6.3.9f-item3-baseline-controls.sh — опорный набор положительных
# контролей детекта (item 3 волны 6.3.9.F, находка №370/item 5 постановки
# волны 6.3.9).
#
# ЗАЧЕМ. `6.3.9.5` («ни один положительный контроль детекта не потерян»)
# сравнивает прогон B с чем-то — а на прогоне A (`collect-6.3-run6`) опорный
# снимок не был снят вовсе (находка №370: единственный контроль в архиве —
# `6.2.6.4`). Без него `6.3.9.5` на прогоне B выносит НЕИЗМЕРИМ, а
# неизмеримость этой метки отменяет снижение шума при ЛЮБОЙ величине.
# Постановка требует снять набор ВХОДОМ волны, ДО правки досева item 4 —
# этот скрипт и есть тот вход; он запускается ещё раз, без изменений, ПОСЛЕ
# правки (прогон B) для сравнения.
#
# СОСТАВ (постановка волны 6.3.9, item 5): 6.0.13…6.0.18, DNS-манифест
# (6.3.1), спуф argv[0], container_escape_proc_write, длинная метка 5.9.5c.
# 6.0.13…6.0.18 УЖЕ несут внутри себя container_escape_proc_write (=6.0.15)
# и спуф argv[0] (=6.0.16/6.0.17) — готовый `wave7-controls.sh` (волна 6.0m)
# исполняет все шесть, и здесь он переиспользуется как есть, а не
# переписывается: другой контроль на ту же находку был бы вторым источником
# дефектов вместо одного. Своих тел этот файл заводит два — 5.9.5c и 6.3.1,
# ни один из которых wave7-controls.sh не несёт.
#
# ГИГИЕНА КОНТРОЛЕЙ (см. память):
#   - каждый контроль несёт СВОЙ сторож результата, не код возврата
#     ([[positive-control-needs-result-sentinel]]);
#   - провал одного контроля не валит набор — die() здесь пишет строку и
#     продолжает, как в wave7-controls.sh ([[die-only-for-unmeasurable-run]]);
#   - артефакты — вне /root/ ([[control-artifacts-must-live-outside-root]]:
#     /root/ живёт под drift-правилом, и собственные файлы набора создавали
#     бы алерты в чужом окне, если бы прогон B делил с ним измерение);
#   - `set -u`, без `set -e` — ЭТОТ файл сам исполняется (`bash …`), не
#     source'ится, так что даже `set -e` не утёк бы наружу
#     ([[sourcing-lib-leaks-set-e]]), но и внутри он не нужен: die()
#     обязана позволить соседним контролям исполниться.
set -u
export PATH="$PATH:/usr/local/bin:/usr/local/go/bin"

if [ "${1:-}" = "--self-test" ]; then
    # ФИКСТУРНЫЙ РЕЖИМ (item 5 волны 6.3-up, Д5). Проверяет ВЕТКИ вердиктов
    # (pass/die), реестр ролей (baseline|check, отказ невалидной роли) и отказ
    # перезаписи (реестра меток и файла вердиктов по тегу) — то есть ровно то,
    # что до сих пор проверялось только руками на живом заходе (находка №376
    # была поймана боевым снятием набора, не тестом). ЕДИНСТВЕННАЯ сеть здесь
    # — локальный HTTP-стаб на 127.0.0.1, поднятый этим же прогоном; живого
    # агента, kubectl и реального DNS-резолва самотест не требует
    # (память gate-offline-replay-on-mac: 6.3.1 указывается на заведомо
    # нечитаемый манифест — та же ветка НЕИЗМЕРИМ, что на стенде без манифеста
    # — полный k8s-поход по-прежнему проверяется только на стенде метками
    # 6.3u.1/6.3u.2, не этим самотестом).
    SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
    ST_WORK="$(mktemp -d "${TMPDIR:-/tmp}/w639i3-self.XXXXXX")"
    ST_STUB_PID=""
    ST_FAILS=0
    _st_cleanup() {
        [ -n "$ST_STUB_PID" ] && kill "$ST_STUB_PID" >/dev/null 2>&1
        rm -rf "$ST_WORK"
    }
    trap _st_cleanup EXIT
    _st_fail() { echo "    ПРОВАЛ: $*"; ST_FAILS=$((ST_FAILS + 1)); }

    # ── Локальный HTTP-стаб /api/v1/alerts. Число алертов под STUB_RULE
    # читается из файла STUB_STATE ПРИ КАЖДОМ запросе — фикстуры меняют
    # содержимое файла между двумя вызовами _rule_count(), и это даёт
    # PASS/FAIL веткам 5.9.5c без реального детекта.
    cat > "$ST_WORK/stub.py" <<'PYEOF'
import http.server, json, os
STATE = os.environ["STUB_STATE"]
RULE = os.environ.get("STUB_RULE", "dns_tunneling_long_domain")
def count():
    try:
        with open(STATE) as f:
            return int((f.read() or "0").strip())
    except Exception:
        return 0
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        if not self.path.startswith("/api/v1/alerts"):
            self.send_response(404); self.end_headers(); return
        n = count()
        body = json.dumps([{"rule_id": RULE, "timestamp": "2026-09-19T00:00:00Z"} for _ in range(n)]).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
srv = http.server.HTTPServer(("127.0.0.1", 0), H)
print(srv.server_port, flush=True)
srv.serve_forever()
PYEOF
    export STUB_STATE="$ST_WORK/stub-state"
    echo 0 > "$STUB_STATE"
    python3 "$ST_WORK/stub.py" > "$ST_WORK/stub-port.txt" 2>"$ST_WORK/stub-err.txt" &
    ST_STUB_PID=$!
    ST_PORT=""
    for _st_i in $(seq 1 50); do
        ST_PORT="$(cat "$ST_WORK/stub-port.txt" 2>/dev/null)"
        [ -n "$ST_PORT" ] && break
        sleep 0.1
    done
    if [ -z "$ST_PORT" ]; then
        echo "СТОРОЖ САМОТЕСТА НЕИЗМЕРИМ: HTTP-стаб не поднялся ($(cat "$ST_WORK/stub-err.txt" 2>/dev/null))"
        exit 2
    fi
    ST_API="http://127.0.0.1:$ST_PORT"
    ST_NOMANIFEST="$ST_WORK/no-such-manifest.txt"
    echo "=== ФИКСТУРНЫЙ ПРОГОН wave6.3.9f-item3-baseline-controls.sh (стаб на $ST_API) ==="

    # ── F1: невалидная роль отклоняется (rc=2), реестр не создаётся.
    F1="$ST_WORK/f1"; mkdir -p "$F1"
    OUT=$(W3_ROLE=bogus W3_ART="$F1" W3_TAG=t1 W3_TOKEN=x W3_API="$ST_API" \
          SETUP="$ST_WORK/nosetup" W3_MANIFEST="$ST_NOMANIFEST" bash "$SELF" 2>&1)
    RC=$?
    echo "--- F1: невалидная роль отклоняется"
    if [ "$RC" -eq 2 ] && printf '%s' "$OUT" | grep -q "допустимы baseline"; then
        echo "    OK  rc=2, роль отклонена с объяснением"
    else
        _st_fail "F1: rc=$RC, вывод: $(printf '%s' "$OUT" | head -3)"
    fi

    # ── F2: первый заход создаёт реестр роли; без сети/kubectl всё уходит в FAIL.
    echo 0 > "$STUB_STATE"
    F2="$ST_WORK/f2"; mkdir -p "$F2"
    OUT=$(W3_ROLE=baseline W3_ART="$F2" W3_TAG=t1 W3_TOKEN=x W3_API="$ST_API" \
          SETUP="$ST_WORK/nosetup" W3_MANIFEST="$ST_NOMANIFEST" W3_593C_SLEEP=1 bash "$SELF" 2>&1)
    RC=$?
    echo "--- F2: первый заход роли baseline создаёт реестр"
    if [ "$RC" -eq 0 ] && [ -r "$F2/baseline-labels-baseline.txt" ] \
        && grep -q '^6\.0\.13 FAIL$' "$F2/baseline-labels-baseline.txt" \
        && grep -q '^5\.9\.5c FAIL$' "$F2/baseline-labels-baseline.txt" \
        && grep -q '^6\.3\.1 FAIL$' "$F2/baseline-labels-baseline.txt"; then
        echo "    OK  реестр создан, wave7-отсутствие/dig-неудача/manifest-отсутствие классифицированы FAIL"
    else
        _st_fail "F2: rc=$RC, реестр: $(cat "$F2/baseline-labels-baseline.txt" 2>/dev/null | tr '\n' ';')"
    fi

    # ── F3: повторный заход той же роли БЕЗ W3_FORCE отказывает, реестр не тронут.
    SUM_BEFORE=$(md5sum "$F2/baseline-labels-baseline.txt" 2>/dev/null || md5 -q "$F2/baseline-labels-baseline.txt" 2>/dev/null)
    OUT=$(W3_ROLE=baseline W3_ART="$F2" W3_TAG=t2 W3_TOKEN=x W3_API="$ST_API" \
          SETUP="$ST_WORK/nosetup" W3_MANIFEST="$ST_NOMANIFEST" bash "$SELF" 2>&1)
    RC=$?
    SUM_AFTER=$(md5sum "$F2/baseline-labels-baseline.txt" 2>/dev/null || md5 -q "$F2/baseline-labels-baseline.txt" 2>/dev/null)
    echo "--- F3: повторный заход без W3_FORCE отказывает, реестр не тронут"
    if [ "$RC" -eq 2 ] && printf '%s' "$OUT" | grep -q "уже существует" && [ "$SUM_BEFORE" = "$SUM_AFTER" ]; then
        echo "    OK  rc=2, реестр байт-в-байт тот же"
    else
        _st_fail "F3: rc=$RC, реестр изменился: $([ "$SUM_BEFORE" = "$SUM_AFTER" ] && echo нет || echo ДА)"
    fi

    # ── F4: W3_FORCE=1 позволяет перезаписать реестр той же роли (PASS-ветка тоже жива).
    echo 0 > "$STUB_STATE"
    ( sleep 0.3; echo 1 > "$STUB_STATE" ) & disown
    OUT=$(W3_ROLE=baseline W3_ART="$F2" W3_TAG=t3 W3_FORCE=1 W3_TOKEN=x W3_API="$ST_API" \
          SETUP="$ST_WORK/nosetup" W3_MANIFEST="$ST_NOMANIFEST" W3_593C_SLEEP=1 bash "$SELF" 2>&1)
    RC=$?
    echo "--- F4: W3_FORCE=1 перезаписывает реестр; 5.9.5c способна дойти до ДОСТИГНУТО"
    if [ "$RC" -eq 0 ] && printf '%s' "$OUT" | grep -q '5\.9\.5c ДОСТИГНУТО' \
        && grep -q '^5\.9\.5c OK$' "$F2/baseline-labels-baseline.txt"; then
        echo "    OK  реестр перезаписан, PASS-ветка 5.9.5c реально исполнима"
    else
        _st_fail "F4: rc=$RC, вывод: $(printf '%s' "$OUT" | grep '5\.9\.5c')"
    fi

    # ── F5: коллизия W3_TAG (файл вердиктов) отказывает независимо от роли/реестра.
    echo 0 > "$STUB_STATE"
    F5="$ST_WORK/f5"; mkdir -p "$F5"
    W3_ROLE=baseline W3_ART="$F5" W3_TAG=fixedtag W3_TOKEN=x W3_API="$ST_API" \
        SETUP="$ST_WORK/nosetup" W3_MANIFEST="$ST_NOMANIFEST" bash "$SELF" >/dev/null 2>&1
    OUT=$(W3_ROLE=check W3_ART="$F5" W3_TAG=fixedtag W3_TOKEN=x W3_API="$ST_API" \
          SETUP="$ST_WORK/nosetup" W3_MANIFEST="$ST_NOMANIFEST" bash "$SELF" 2>&1)
    RC=$?
    echo "--- F5: одинаковый W3_TAG на втором заходе (другая роль) отказывает по файлу вердиктов"
    if [ "$RC" -eq 2 ] && printf '%s' "$OUT" | grep -q "W3_TAG"; then
        echo "    OK  rc=2, отказ называет W3_TAG"
    else
        _st_fail "F5: rc=$RC, вывод: $(printf '%s' "$OUT" | head -3)"
    fi

    # ── F6/F7: явные PASS/FAIL ветки 5.9.5c по отдельности (не только внутри F2/F4).
    echo 0 > "$STUB_STATE"
    ( sleep 0.3; echo 1 > "$STUB_STATE" ) & disown
    F6="$ST_WORK/f6"; mkdir -p "$F6"
    OUT=$(W3_ROLE=baseline W3_ART="$F6" W3_TAG=passtag W3_TOKEN=x W3_API="$ST_API" \
          SETUP="$ST_WORK/nosetup" W3_MANIFEST="$ST_NOMANIFEST" W3_593C_SLEEP=1 bash "$SELF" 2>&1)
    echo "--- F6: 5.9.5c PASS-ветка (рост числа алертов между до/после)"
    if printf '%s' "$OUT" | grep -q '5\.9\.5c ДОСТИГНУТО'; then
        echo "    OK"
    else
        _st_fail "F6: ветка ДОСТИГНУТО не напечатана: $(printf '%s' "$OUT" | grep '5\.9\.5c')"
    fi

    echo 0 > "$STUB_STATE"
    F7="$ST_WORK/f7"; mkdir -p "$F7"
    OUT=$(W3_ROLE=baseline W3_ART="$F7" W3_TAG=failtag W3_TOKEN=x W3_API="$ST_API" \
          SETUP="$ST_WORK/nosetup" W3_MANIFEST="$ST_NOMANIFEST" W3_593C_SLEEP=1 bash "$SELF" 2>&1)
    echo "--- F7: 5.9.5c FAIL-ветка (число алертов не растёт)"
    if printf '%s' "$OUT" | grep -q '5\.9\.5c ПРОВАЛЕН'; then
        echo "    OK"
    else
        _st_fail "F7: ветка ПРОВАЛЕН не напечатана: $(printf '%s' "$OUT" | grep '5\.9\.5c')"
    fi

    # ── F9: классификация группы 6.0.13...6.0.18 по ДВУМ источникам (die-запись
    # приоритетнее сторожа результата; отсутствие обоих — FAIL с названным
    # классом «не исполнился»), фейковый wave7-controls.sh под контролем.
    F9SETUP="$ST_WORK/f9setup"; mkdir -p "$F9SETUP"
    cat > "$F9SETUP/wave7-controls.sh" <<'W7EOF'
#!/bin/bash
set -u
: > "${WAVE7_VERDICTS:?}"
{
    echo "критерий=6.0.13"
    echo "причина: fixture forced failure"
} >> "$WAVE7_VERDICTS"
echo "6.0.14 доказан живьём"
# 6.0.15..6.0.18: ни записи о провале, ни сторожа результата — «не исполнился».
W7EOF
    chmod +x "$F9SETUP/wave7-controls.sh"
    echo 0 > "$STUB_STATE"
    F9="$ST_WORK/f9"; mkdir -p "$F9"
    OUT=$(W3_ROLE=baseline W3_ART="$F9" W3_TAG=w7tag W3_TOKEN=x W3_API="$ST_API" \
          SETUP="$F9SETUP" W3_MANIFEST="$ST_NOMANIFEST" bash "$SELF" 2>&1)
    echo "--- F9: группа 6.0.13...6.0.18 — die-запись, сторож результата, неисполнение"
    if [ -r "$F9/baseline-labels-baseline.txt" ] \
        && grep -q '^6\.0\.13 FAIL$' "$F9/baseline-labels-baseline.txt" \
        && grep -q '^6\.0\.14 OK$' "$F9/baseline-labels-baseline.txt" \
        && grep -q '^6\.0\.15 FAIL$' "$F9/baseline-labels-baseline.txt" \
        && grep -q '^6\.0\.18 FAIL$' "$F9/baseline-labels-baseline.txt"; then
        echo "    OK  6.0.13=FAIL(die), 6.0.14=OK(сторож), 6.0.15/18=FAIL(не исполнился)"
    else
        _st_fail "F9: реестр: $(cat "$F9/baseline-labels-baseline.txt" 2>/dev/null | tr '\n' ';')"
    fi

    # ── F10: отсутствующий токен — die() записывает набор_целиком, а не молчит.
    F10="$ST_WORK/f10"; mkdir -p "$F10"
    OUT=$(W3_ROLE=baseline W3_ART="$F10" W3_TAG=notoken W3_TOKEN="" W3_API="$ST_API" \
          SETUP="$ST_WORK/nosetup" W3_MANIFEST="$ST_NOMANIFEST" bash "$SELF" 2>&1)
    echo "--- F10: отсутствующий bearer-токен фиксируется как набор_целиком FAIL"
    if [ -r "$F10/baseline-labels-baseline.txt" ] && grep -q '^набор_целиком FAIL$' "$F10/baseline-labels-baseline.txt"; then
        echo "    OK"
    else
        _st_fail "F10: реестр: $(cat "$F10/baseline-labels-baseline.txt" 2>/dev/null | tr '\n' ';')"
    fi

    # ── F11: 6.3u.1/6.3u.2 без запроса печатают НЕИЗМЕРИМ с названным классом
    # (не молчат, не притворяются ДОСТИГНУТО) — item 6 волны 6.3-up.
    echo 0 > "$STUB_STATE"
    F11="$ST_WORK/f11"; mkdir -p "$F11"
    OUT=$(W3_ROLE=baseline W3_ART="$F11" W3_TAG=t1 W3_TOKEN=x W3_API="$ST_API" \
          SETUP="$ST_WORK/nosetup" W3_MANIFEST="$ST_NOMANIFEST" bash "$SELF" 2>&1)
    echo "--- F11: 6.3u.1/6.3u.2 без запроса — НЕИЗМЕРИМ с названным классом, не молчание"
    if printf '%s' "$OUT" | grep -q '6\.3u\.1 НЕИЗМЕРИМ: класс=не запрошен' \
        && printf '%s' "$OUT" | grep -q '6\.3u\.2 НЕИЗМЕРИМ: класс=второй запуск ещё не снят'; then
        echo "    OK"
    else
        _st_fail "F11: вывод: $(printf '%s' "$OUT" | grep '6\.3u')"
    fi

    # ── F12: 6.3u.2 достигает ДОСТИГНУТО на второй роли той же базы, когда
    # 6.0.15 = OK на обеих (сторож №373: метка обязана уметь сказать не-FAIL).
    F12="$ST_WORK/f12"; mkdir -p "$F12"
    printf '6.0.15 OK\n' > "$F12/baseline-labels-baseline.txt"
    F12SETUP="$ST_WORK/f12setup"; mkdir -p "$F12SETUP"
    printf '#!/bin/bash\nset -u\necho "6.0.15 доказан живьём"\n' > "$F12SETUP/wave7-controls.sh"
    chmod +x "$F12SETUP/wave7-controls.sh"
    OUT=$(W3_ROLE=check W3_ART="$F12" W3_TAG=t2 W3_TOKEN=x W3_API="$ST_API" \
          SETUP="$F12SETUP" W3_MANIFEST="$ST_NOMANIFEST" bash "$SELF" 2>&1)
    echo "--- F12: 6.3u.2 достигает ДОСТИГНУТО, когда 6.0.15=OK на обеих ролях"
    if printf '%s' "$OUT" | grep -q '6\.3u\.2 ДОСТИГНУТО'; then
        echo "    OK"
    else
        _st_fail "F12: вывод: $(printf '%s' "$OUT" | grep '6\.3u\.2')"
    fi

    echo
    if [ "$ST_FAILS" -gt 0 ]; then
        echo "САМОТЕСТ ПРОВАЛЕН: расхождений $ST_FAILS"
        exit 1
    fi
    echo "САМОТЕСТ ПРОЙДЕН: 11 фикстур, расхождений 0"
    exit 0
fi

SETUP="${SETUP:-/opt/ebpf-guard/deploy/docker-test-setup}"
VPS_IP="${VPS_IP:-localhost}"
W3_API="${W3_API:-http://${VPS_IP}:19090}"
W3_TOKEN="${W3_TOKEN:-${EBPF_GUARD_TOKEN:-$(grep '^admin=' /var/lib/ebpf-guard/token 2>/dev/null | cut -d= -f2)}}"
W3_KUBECTL="${W3_KUBECTL:-/usr/local/bin/kubectl}"
W3_NS="${W3_NS:-w639f3}"
W3_POD="${W3_POD:-w639f3-dns-probe}"
W3_MANIFEST="${W3_MANIFEST:-$SETUP/attacks/dns-rule-ids.txt}"

# Артефакты вне /root/ (память control-artifacts-must-live-outside-root).
W3_ART="${W3_ART:-/var/lib/w639f3-item3-artifacts}"
mkdir -p "$W3_ART" 2>/dev/null || true
# ФАЙЛ ВЕРДИКТОВ — СВОЙ НА КАЖДЫЙ ЗАПУСК, И СТАРЫЙ НЕ ЗАТИРАЕТСЯ.
#
# Набор исполняется ДВАЖДЫ по построению: опорный снимок (прогон A2, бинарь БЕЗ
# досева) и проверочный (прогон B, бинарь С досевом) — а `6.3.9.5` сравнивает
# один с другим. Фиксированное имя файла + `: >` означало бы, что второй запуск
# СТИРАЕТ то единственное, с чем обязан сравниваться, и метка вынесла бы
# НЕИЗМЕРИМ по вине самого прибора — ровно цена, которую находка №370 уже
# однажды предъявила волне. Поэтому имя несёт метку запуска, а `-latest`
# (копия, не симлинк: архив собирается `cp`) указывает на последний.
W3_TAG="${W3_TAG:-$(date -u +%Y%m%dT%H%M%SZ)}"
# РОЛЬ ЗАПУСКА — ВХОД КРИТЕРИЯ 6.3.9.5, А НЕ ПОДПИСЬ ДЛЯ ЧИТАТЕЛЯ.
#   baseline — снят на бинаре БЕЗ досева (прогон A2, вход волны);
#   check    — снят на бинаре С досевом (прогон B), сравнивается с baseline.
# Каждая роль пишет НОРМАЛИЗОВАННЫЙ реестр «<критерий> OK|FAIL» — по образцу
# emitted-labels.txt рантайма контролей: класс берётся из реестра, а не
# восстанавливается регэкспом по словам вердиктного текста (item 9 стража
# полноты — эвристика по словам верна ровно до первого объяснения, упомянувшего
# чужое вердиктное слово). Реестр роли baseline НЕ перезаписывается молча:
# затереть опорный снимок значит сделать 6.3.9.5 неизмеримой прибором.
W3_ROLE="${W3_ROLE:-baseline}"
case "$W3_ROLE" in
    baseline|check) ;;
    *) echo "=== ОТКАЗ: W3_ROLE=$W3_ROLE — допустимы baseline (прогон A2, БЕЗ досева) и check (прогон B, С досевом) ==="; exit 2 ;;
esac
W3_LABELS="${W3_LABELS:-$W3_ART/baseline-labels-$W3_ROLE.txt}"
if [ -e "$W3_LABELS" ] && [ "${W3_FORCE:-0}" != "1" ]; then
    echo "=== ОТКАЗ: реестр роли $W3_ROLE уже существует ($W3_LABELS). Перезапись стёрла бы снимок, с которым сравнивается 6.3.9.5; W3_FORCE=1 — только осознанно ==="
    exit 2
fi
: > "$W3_LABELS" 2>/dev/null || true
_w3_label() { # $1 = критерий (может не вычлениться из текста), $2 = класс
    # Пустой ключ записался бы строкой « FAIL» и при сверке прогона B прочитался
    # бы как «критерий без имени потерян» — безымянная запись обязана иметь имя.
    printf '%s %s\n' "${1:-набор_целиком}" "$2" >> "$W3_LABELS" 2>/dev/null || true
}
W3_VERDICTS="${W3_VERDICTS:-$W3_ART/baseline-controls-verdicts-$W3_TAG.txt}"
if [ -e "$W3_VERDICTS" ]; then
    echo "=== ОТКАЗ: $W3_VERDICTS уже существует — запуск с тем же W3_TAG затёр бы опорный снимок, с которым сравнивается 6.3.9.5. Задайте другой W3_TAG ==="
    exit 2
fi
: > "$W3_VERDICTS" 2>/dev/null || true
W3_DONE="${W3_DONE:-$W3_ART/DONE-$W3_TAG}"
rm -f "$W3_DONE" 2>/dev/null || true

W3_FAILS=0
# Регэксп несёт необязательное «u» (порядок: 6.0.15, но 6.3u.1/6.3u.2 — метки
# долга куста, item 6 волны 6.3-up) — без него «6.3u.1» вычленялся бы как
# «6.3», и обе метки волны 6.3-up схлопывались бы в один ключ реестра.
_w3_extract_id() { printf '%s' "$*" | grep -oE '[0-9]+\.[0-9]+u?(\.[0-9]+)*[a-z]?' | head -1; }
die() {
    echo "=== ОПОРНЫЙ КОНТРОЛЬ ПРОВАЛЕН/НЕИЗМЕРИМ (набор продолжается): $* ==="
    W3_FAILS=$((W3_FAILS + 1))
    _w3_label "$(_w3_extract_id "$*")" FAIL
    {
        echo "критерий=$(_w3_extract_id "$*")"
        echo "время_UTC=$(date -u +%FT%TZ)"
        echo "причина: $*"
        echo "---"
    } >> "$W3_VERDICTS" 2>/dev/null || true
}
pass() {
    echo "=== $* ==="
    _w3_label "$(_w3_extract_id "$*")" OK
    { echo "$*"; echo "время_UTC=$(date -u +%FT%TZ)"; echo "---"; } >> "$W3_VERDICTS" 2>/dev/null || true
}

echo "# wave6.3.9f-item3-baseline-controls.sh, прогон от $(date -u +%FT%TZ)" >> "$W3_VERDICTS"
echo "=== ОПОРНЫЙ НАБОР ПОЛОЖИТЕЛЬНЫХ КОНТРОЛЕЙ (item 3 волны 6.3.9.F, находка №370) ==="
echo "HEAD: $(cd "$SETUP/../.." 2>/dev/null && git rev-parse --short HEAD 2>/dev/null || echo '?')"

if [ -z "${W3_TOKEN:-}" ]; then
    die "ОПОРНЫЙ НАБОР НЕИЗМЕРИМ ЦЕЛИКОМ: bearer-токен агента не найден (/var/lib/ebpf-guard/token) — ни один HTTP-контроль не исполним"
fi

_alerts() { curl -s --max-time 20 -H "Authorization: Bearer $W3_TOKEN" "$W3_API/api/v1/alerts?limit=200000" 2>/dev/null; }
_rule_count() { # $1=rule_id
    _alerts | jq --arg r "$1" '[.[]|select(.rule_id==$r)]|length' 2>/dev/null || echo 0
}

echo
echo "--- 6.0.13…6.0.18 (container_escape_proc_write=6.0.15, argv[0]-спуф=6.0.16/6.0.17): переиспользуем wave7-controls.sh как есть ---"
# ГРУППА ПИШЕТСЯ ПОКРИТЕРИЙНО, А НЕ ОДНОЙ ЗАПИСЬЮ (правка 18.09.2026, найдена
# первым же боевым снятием опорного набора — находка №376). Раньше все шесть
# контролей сворачивались в ОДИН класс под ключом «6.0.13»: один провалившийся
# контроль уводил в FAIL всю шестёрку, и в сравнении прогона B не участвовал
# НИ ОДИН из пяти взятых — то есть цена одного самоизрасходованного контроля
# была слепота критерия 6.3.9.5 по всей группе. Класс каждого берётся из ДВУХ
# источников: запись «критерий=<id>» в вердиктах wave7 (провал — приоритетнее)
# и сторож результата «<id> доказан живьём» в его же логе
# ([[positive-control-needs-result-sentinel]]); отсутствие обоих — тоже FAIL,
# но с НАЗВАННЫМ классом «не исполнился», а не молчанием.
_w3_w7_group="6.0.13 6.0.14 6.0.15 6.0.16 6.0.17 6.0.18"
if [ -r "$SETUP/wave7-controls.sh" ]; then
    W3_W7_VERDICTS="$W3_ART/wave7-verdicts-$W3_TAG.txt"
    W3_W7_LOG="$W3_ART/wave7-log-$W3_TAG.txt"
    DRIFT_PC_API="$W3_API" DRIFT_PC_TOKEN="$W3_TOKEN" WAVE7_VERDICTS="$W3_W7_VERDICTS" \
        bash "$SETUP/wave7-controls.sh" > "$W3_W7_LOG" 2>&1
    sed 's/^/  [6.0h\/k\/l] /' "$W3_W7_LOG"
    for _w7c in $_w3_w7_group; do
        if grep -q "^критерий=${_w7c}$" "$W3_W7_VERDICTS" 2>/dev/null; then
            # ПРОВАЛ ПЕРЕВЕШИВАЕТ СТОРОЖА. Починено в источнике волной 6.3-up
            # (item 3, Д3): wave7-controls.sh больше не печатает «доказан
            # живьём» после собственного die() — каждый критерий 6.0.13…6.0.18
            # теперь ветвится if/else, и обе строки на одном критерии
            # одновременно не появляются. Приоритет записи о провале остаётся
            # здесь как защита от повторного возврата бага, а не потому что он
            # всё ещё нужен для корректности.
            _w3_label "$_w7c" FAIL
            W3_FAILS=$((W3_FAILS + 1))
            echo "  $_w7c FAIL (запись о провале в $W3_W7_VERDICTS)"
        elif grep -q "${_w7c} доказан живьём" "$W3_W7_LOG" 2>/dev/null; then
            _w3_label "$_w7c" OK
            echo "  $_w7c OK (сторож результата: «доказан живьём»)"
        else
            _w3_label "$_w7c" FAIL
            W3_FAILS=$((W3_FAILS + 1))
            echo "  $_w7c FAIL (класс НАЗВАН: контроль не исполнился — ни записи о провале, ни сторожа результата в логе)"
        fi
    done
    {
        echo "6.0.13…6.0.18: классы записаны покритерийно, см. $W3_LABELS"
        echo "время_UTC=$(date -u +%FT%TZ)"
        echo "---"
    } >> "$W3_VERDICTS" 2>/dev/null || true
else
    for _w7c in $_w3_w7_group; do
        _w3_label "$_w7c" FAIL
        W3_FAILS=$((W3_FAILS + 1))
    done
    echo "=== ОПОРНЫЙ КОНТРОЛЬ НЕИЗМЕРИМ: $SETUP/wave7-controls.sh не найден на стенде — все шесть критериев группы без класса ==="
fi

echo
echo "--- 5.9.5c: длинная/высокоэнтропийная DNS-метка с ноды ---"
if ! command -v dig >/dev/null 2>&1; then
    die "5.9.5c НЕИЗМЕРИМ: dig недоступен на стенде"
else
    _593c_rules="dns_tunneling_long_domain exfil_dns_txt_long_label netintr_dns_long_label webshell_dns_exfil_long_subdomain"
    for r in $_593c_rules; do
        v=$(_rule_count "$r")
        eval "_593c_before_${r}=\${v:-0}"
    done
    _593c_filler_a=$(printf 'x%.0s' $(seq 1 60))
    _593c_filler_b=$(printf 'y%.0s' $(seq 1 60))
    _593c_qname="${_593c_filler_a}.${_593c_filler_b}.ebpfguard-5951c-w639f3.dns-tunnel-canary.invalid"
    dig +short +time=2 +tries=1 "$_593c_qname" >/dev/null 2>&1
    _593c_rc=$?
    echo "  dig на $_593c_qname выполнен (rc=$_593c_rc, длина qname: ${#_593c_qname})"
    sleep "${W3_593C_SLEEP:-15}"
    _593c_hit=0
    _593c_named=""
    for r in $_593c_rules; do
        after=$(_rule_count "$r")
        eval "before=\${_593c_before_${r}:-0}"
        d=$(( ${after:-0} - ${before:-0} ))
        echo "  $r: ${before:-0} -> ${after:-0} (Δ$d)"
        if [ "$d" -gt 0 ]; then _593c_hit=$((_593c_hit + 1)); _593c_named="$_593c_named $r"; fi
    done
    if [ "$_593c_hit" -lt 1 ]; then
        die "5.9.5c ПРОВАЛЕН: длинная метка подана (dig rc=$_593c_rc), ни одно из четырёх правил манифеста не поднялось"
    else
        pass "5.9.5c ДОСТИГНУТО: сработали $_593c_hit/4 правил ($_593c_named)"
    fi
fi

echo
echo "--- 6.3.1: DNS-манифест — длинный/DGA-подобный qname из пода busybox ---"
if [ ! -r "$W3_MANIFEST" ]; then
    die "6.3.1 НЕИЗМЕРИМ: манифест $W3_MANIFEST не читается"
else
    _631_ids=$(grep -v '^#' "$W3_MANIFEST" | grep -v '^[[:space:]]*$')
    _631_ids_sp=$(printf '%s' "$_631_ids" | tr '\n' ' ')
    "$W3_KUBECTL" create namespace "$W3_NS" --dry-run=client -o yaml 2>/dev/null | "$W3_KUBECTL" apply -f - >/dev/null 2>&1
    "$W3_KUBECTL" -n "$W3_NS" delete pod "$W3_POD" --ignore-not-found --wait=true >/dev/null 2>&1
    "$W3_KUBECTL" -n "$W3_NS" run "$W3_POD" --image=busybox:1.36 --restart=Never --command -- sleep 600 >/dev/null 2>&1
    _631_ready=0
    "$W3_KUBECTL" -n "$W3_NS" wait --for=condition=Ready "pod/$W3_POD" --timeout=90s >/dev/null 2>&1 && _631_ready=1
    if [ "$_631_ready" -ne 1 ]; then
        die "6.3.1 НЕИЗМЕРИМ: $W3_POD не поднялся за 90с — подать нагрузку неоткуда"
    else
        _631_label=$(head -c 64 /dev/urandom 2>/dev/null | base64 2>/dev/null | tr -dc 'a-z0-9' | head -c 55)
        [ -z "${_631_label:-}" ] && _631_label="x7k2qv9zwmrl4bnt8pd3jf6hs1ce5ay0gu3kv8wz2mqr7nxb"
        _631_domain="${_631_label}.w639f3-dga-probe.invalid"
        _631_t0=$(date -u +%s)
        _631_out=$("$W3_KUBECTL" -n "$W3_NS" exec "$W3_POD" -- nslookup "$_631_domain" 2>&1)
        echo "  запрошено: $_631_domain (${#_631_domain} симв.)"
        echo "  вывод nslookup (обрезан): $(printf '%s' "${_631_out:-}" | tr '\n' ' ' | cut -c1-200)"
        sleep 15
        _631_hit=$(_alerts | jq --arg ids "$_631_ids_sp" --arg pod "$W3_POD" --argjson t "$_631_t0" \
            '[.[]|select((.rule_id as $r|($ids|split(" "))|index($r)) and ((.enrichment.pod_name // "")==$pod) and ((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t))]' 2>/dev/null)
        _631_n=$(printf '%s' "${_631_hit:-[]}" | jq 'length' 2>/dev/null)
        _631_rules=$(printf '%s' "${_631_hit:-[]}" | jq -r '.[].rule_id' 2>/dev/null | sort -u | tr '\n' ' ')
        echo "  алертов из манифеста от $W3_POD: ${_631_n:-0} (правила: ${_631_rules:-нет})"
        if [ -z "${_631_out:-}" ]; then
            die "6.3.1 НЕИЗМЕРИМ: exec в под не дал вывода — подача не подтверждена"
        elif [ "${_631_n:-0}" -lt 1 ]; then
            die "6.3.1 ПРОВАЛЕН: qname подан ($_631_domain), ни одно правило манифеста не поднялось"
        else
            pass "6.3.1 ДОСТИГНУТО: ${_631_n} алертов из манифеста подняты ($_631_rules)"
        fi
    fi
    "$W3_KUBECTL" -n "$W3_NS" delete pod "$W3_POD" --ignore-not-found --wait=false >/dev/null 2>&1
fi

echo
echo "--- 6.3u.1: IPv6-DNS положительный контроль (item 6 волны 6.3-up) ---"
# Опт-ин, НЕ по умолчанию: контроль поднимает свой UDP-слушатель на ::1:53,
# и на каждом заходе, где его никто не просил, метка обязана честно назвать
# класс «не запрошен», а не молчать (память wave-criteria-need-an-emitter) и
# не притворяться, что снят реальный замер (память verdict-line-that-can-
# only-say-unmeasurable — метка обязана уметь дойти и до ДОСТИГНУТО).
W3_IPV6_DNS="${W3_IPV6_DNS:-0}"
if [ "$W3_IPV6_DNS" != "1" ]; then
    die "6.3u.1 НЕИЗМЕРИМ: класс=не запрошен (W3_IPV6_DNS=0 по умолчанию — контроль поднимает слушателя на ::1:53 и не должен исполняться на каждом заходе молча)"
elif ! command -v dig >/dev/null 2>&1; then
    die "6.3u.1 НЕИЗМЕРИМ: класс=dig недоступен на стенде"
elif ! command -v python3 >/dev/null 2>&1; then
    die "6.3u.1 НЕИЗМЕРИМ: класс=python3 недоступен — нечем поднять слушателя на ::1:53"
elif [ ! -r "$W3_MANIFEST" ]; then
    die "6.3u.1 НЕИЗМЕРИМ: класс=манифест $W3_MANIFEST не читается — правил для сверки нет"
else
    _631u1_ids=$(grep -v '^#' "$W3_MANIFEST" | grep -v '^[[:space:]]*$' | tr '\n' ' ')
    _631u1_stub_dir=$(mktemp -d "${TMPDIR:-/tmp}/w63u1.XXXXXX" 2>/dev/null)
    if [ -z "${_631u1_stub_dir:-}" ] || [ -z "${_631u1_ids// /}" ]; then
        die "6.3u.1 НЕИЗМЕРИМ: класс=не удалось подготовить контроль (пустой manifest или mktemp)"
    else
        # Слушатель отвечает на ЛЮБОЙ UDP-пакет на ::1:53 минимальным
        # DNS-ответом (QR=1) — цель контроля в том, что запрос ДОШЁЛ до
        # коллектора, а не в честном резолве (память coredns-holds-no-
        # persistent-dns-socket: положительный контроль надо СОЗДАВАТЬ).
        python3 - >"$_631u1_stub_dir/listener.log" 2>&1 <<'PYEOF' &
import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
s.bind(("::1", 53))
s.settimeout(30)
try:
    while True:
        data, addr = s.recvfrom(512)
        resp = bytearray(data)
        if len(resp) >= 3:
            resp[2] |= 0x80
        s.sendto(bytes(resp), addr)
except socket.timeout:
    pass
PYEOF
        _631u1_listener_pid=$!
        sleep 1
        if ! kill -0 "$_631u1_listener_pid" 2>/dev/null; then
            die "6.3u.1 НЕИЗМЕРИМ: класс=слушатель ::1:53 не поднялся ($(cat "$_631u1_stub_dir/listener.log" 2>/dev/null | tr '\n' ' ' | cut -c1-200))"
        else
            _631u1_metrics_total() {
                curl -s --max-time 10 -H "Authorization: Bearer $W3_TOKEN" "$W3_API/metrics" 2>/dev/null \
                    | awk -F'[{} ]' '/^events_total\{/ && /type="dns"/{s+=$NF} END{print s+0}'
            }
            _631u1_before=$(_631u1_metrics_total)
            # Опорный счёт алертов манифеста берётся ДО зонда: ревизия
            # 19.09.2026 нашла, что метка считала алерты манифеста
            # АБСОЛЮТНЫМ числом по всему стору. На непустом сторе (а к этому
            # шагу он непустой всегда) любое прошлое DNS-правило давало
            # hits>0, и метка вынесла бы ДОСТИГНУТО, даже если IPv6-запрос не
            # дошёл вовсе — ложный PASS ровно того класса, что
            # [[control-after-attacks-hits-filled-limiter]]. Величина —
            # дельта, как и у events_total рядом.
            _631u1_hits_before=$(_alerts | jq --arg ids "$_631u1_ids" \
                '[.[]|select(.rule_id as $r|($ids|split(" "))|index($r))]|length' 2>/dev/null)
            _631u1_domain="w63u1-ipv6-probe-$(head -c 32 /dev/urandom 2>/dev/null | base64 2>/dev/null | tr -dc 'a-z0-9' | head -c 20).invalid"
            dig +short +time=2 +tries=1 -6 @::1 -p 53 "$_631u1_domain" >/dev/null 2>&1
            _631u1_rc=$?
            sleep "${W3_593C_SLEEP:-15}"
            kill "$_631u1_listener_pid" >/dev/null 2>&1
            wait "$_631u1_listener_pid" 2>/dev/null
            _631u1_after=$(_631u1_metrics_total)
            _631u1_delta=$(( ${_631u1_after:-0} - ${_631u1_before:-0} ))
            _631u1_hits_after=$(_alerts | jq --arg ids "$_631u1_ids" \
                '[.[]|select(.rule_id as $r|($ids|split(" "))|index($r))]|length' 2>/dev/null)
            _631u1_hits=$(( ${_631u1_hits_after:-0} - ${_631u1_hits_before:-0} ))
            echo "  ::1:53 слушатель pid=$_631u1_listener_pid, dig -6 rc=$_631u1_rc, events_total{type=dns} ${_631u1_before:-0}->${_631u1_after:-0} (Δ$_631u1_delta), алертов манифеста ${_631u1_hits_before:-0}->${_631u1_hits_after:-0} (Δ$_631u1_hits)"
            if [ "$_631u1_rc" -ne 0 ]; then
                # СТОРОЖ РЕЗУЛЬТАТА ВПЕРЕДИ ВЕРДИКТА. Слушатель отвечает на
                # любой пакет, поэтому rc!=0 означает, что запрос НЕ ушёл
                # (нет ::1 на lo, IPv6 выключен в ядре, dig без поддержки -6).
                # Нули ниже тогда приборные, и класс метки — НЕИЗМЕРИМ, а не
                # ПРОВАЛЕН: детект об этом не спрашивали
                # ([[positive-control-needs-result-sentinel]]).
                die "6.3u.1 НЕИЗМЕРИМ: класс=IPv6-запрос не ушёл (dig -6 @::1 rc=$_631u1_rc) — величины ниже приборные, а не вердикт о детекте"
            elif [ "${_631u1_delta:-0}" -gt 0 ] && [ "${_631u1_hits:-0}" -gt 0 ]; then
                pass "6.3u.1 ДОСТИГНУТО: events_total{type=dns} вырос на $_631u1_delta И алертов манифеста стало на $_631u1_hits больше — IPv6-запрос дошёл до коллектора и до правил (правка №388: is_dns_packet больше не AF_INET-only)"
            else
                die "6.3u.1 ПРОВАЛЕН: запрос ушёл (rc=0), но events_total{type=dns} Δ=$_631u1_delta, алертов манифеста Δ=$_631u1_hits — обе величины обязаны быть >0. Читать так: ноль по обеим = trace_connect не принял AF_INET6 (на ноде бинарь без правки №388, либо make generate собрал старый bpf/dns.bpf.c); events>0 при Δалертов=0 = событие видно, а правила по нему молчат"
            fi
        fi
    fi
    rm -rf "$_631u1_stub_dir" 2>/dev/null || true
fi

echo
echo "--- 6.3u.2: 6.0.15 (container_escape_proc_write, переармирован item 4 волны 6.3-up) берётся ДВА запуска подряд ---"
# Предмет метки — сравнение ДВУХ ролей одной базы дрейфа, а не один прогон:
# первый заход этого файла (какой бы ролью он ни был) не может доказать
# «взято два раза», только НАЗВАТЬ, что второй запуск ещё не снят — та же
# форма НЕИЗМЕРИМ-с-классом, что у 6.3.9.4/6.3.9.5 на прогоне A.
_w3u2_this=$(grep -E '^6\.0\.15 ' "$W3_LABELS" 2>/dev/null | tail -1 | awk '{print $2}')
case "$W3_ROLE" in
    baseline) _w3u2_sibling_role=check ;;
    check)    _w3u2_sibling_role=baseline ;;
esac
_w3u2_sibling_file="$W3_ART/baseline-labels-${_w3u2_sibling_role}.txt"
if [ -z "${_w3u2_this:-}" ]; then
    die "6.3u.2 НЕИЗМЕРИМ: класс=6.0.15 не вынес класса на роли $W3_ROLE в этом запуске (см. $W3_LABELS)"
elif [ ! -r "$_w3u2_sibling_file" ]; then
    die "6.3u.2 НЕИЗМЕРИМ: класс=второй запуск ещё не снят (роль $W3_ROLE есть в $W3_ART, роли $_w3u2_sibling_role — нет); метка достижима только после исполнения ОБЕИХ ролей на одной базе дрейфа"
else
    _w3u2_sibling=$(grep -E '^6\.0\.15 ' "$_w3u2_sibling_file" 2>/dev/null | tail -1 | awk '{print $2}')
    if [ "${_w3u2_this:-}" = "OK" ] && [ "${_w3u2_sibling:-}" = "OK" ]; then
        pass "6.3u.2 ДОСТИГНУТО: 6.0.15 = OK на обеих ролях (роль $W3_ROLE и роль $_w3u2_sibling_role, $W3_ART)"
    else
        die "6.3u.2 ПРОВАЛЕН: 6.0.15 = ${_w3u2_this:-?} (роль $W3_ROLE), ${_w3u2_sibling:-?} (роль $_w3u2_sibling_role) — обе роли обязаны дать OK"
    fi
fi

echo
# ═════════════════════════════════════════════════════════════════════════════
# 6.3u.3 / 6.3u.4 — КОНТРОЛИ НАХОДОК №384 и №385 (ревизия 19.09.2026).
#
# ЧТО ИМЕННО МЕРИТСЯ. `DNSPrefilter.ShouldEvaluate` решает, дойдёт ли DNS-
# событие до Rego. Обе находки — о событиях, которые он выбрасывал молча,
# хотя правило партиции `dns` на них матчит. Прибор обязан различать ТРИ
# исхода, а не два ([[invariants-find-what-fixtures-cannot]]):
#   • базовый алерт не поднялся вовсе      -> НЕИЗМЕРИМ (класс назван)
#   • базовый алерт есть, обогащения нет   -> ПРОВАЛЕН (префильтр глушит)
#   • обогащённый алерт есть               -> ДОСТИГНУТО
#
# ПОЧЕМУ ЗОНД ИМЕННО ТАКОЙ. Rego в этом движке НЕ создаёт алертов, а
# обогащает уже поднятый ([engine.go, evaluateRegoPolicies] — вызывается
# ПОСЛЕ фильтра YAML-правил). Значит зонду нужны ДВА свойства сразу:
#   (1) поднять YAML-алерт — берётся `dns_any_query` (qtype=255, правило
#       включено и стоит в манифесте dns-rule-ids.txt);
#   (2) быть НЕВИДИМЫМ для всех прочих проверок префильтра, иначе форвард
#       случится по чужой причине и контроль зачтёт себе чужой механизм.
# Оба имени зонда подобраны ИЗМЕРЕНИЕМ на самом префильтре 19.09.2026, а не
# на глаз (см. таблицу в plan.md): у 6.3u.3 форвард даёт ровно зеркало
# is_dga_domain, у 6.3u.4 — ровно ось parent_comm.
#
# АТРИБУЦИЯ. YAML-алерт несёт `message = rule.Description`, то есть
# СТАТИЧЕСКУЮ строку: по ней конкретный запрос не опознать. Обогащённый
# несёт message ИЗ Rego, и там есть и qname, и pid — поэтому положительная
# половина обоих контролей ищет свой зонд по содержимому message, а не по
# количеству алертов ([[control-after-attacks-hits-filled-limiter]]: счёт
# «всего в сторе» на заполненном сторе даёт ложный PASS).
W3_REGO_PROBE="${W3_REGO_PROBE:-1}"

# Зонд: один UDP-запрос qtype=ANY (255) на резолвер ноды. Нужен собственный
# сокет, а не `dig`: (а) comm вызывающего — вход обоих правил, и он обязан
# быть управляемым; (б) свежий connect() гарантирует проход через
# trace_connect, а не надежду на чужой долгоживущий сокет
# ([[coredns-holds-no-persistent-dns-socket]]). Ответ не нужен и не ждётся:
# событием является сам запрос.
#
# Тело зонда лежит ФАЙЛОМ, а не heredoc'ом внутри строки: 6.3u.4 обязан
# запустить его ИЗ ПРОЦЕССА-РОДИТЕЛЯ с нужным comm, а вложенный heredoc в
# аргументе -c разбирается двумя шеллами подряд и ломается молча.
W3_PROBE_PY="${W3_PROBE_PY:-$(mktemp "${TMPDIR:-/tmp}/w63u-probe.XXXXXX.py" 2>/dev/null)}"
if [ -n "${W3_PROBE_PY:-}" ]; then
    cat > "$W3_PROBE_PY" <<'PYEOF'
import os, random, socket, struct, sys

qname = sys.argv[1]
q = b"".join(bytes([len(p)]) + p.encode() for p in qname.split(".")) + b"\x00"
pkt = struct.pack("!HHHHHH", random.randint(0, 65535), 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", 255, 1)

ns = "127.0.0.53"
try:
    with open("/etc/resolv.conf") as f:
        for line in f:
            if line.startswith("nameserver"):
                ns = line.split()[1]
                break
except OSError:
    pass

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    s.connect((ns, 53))
    s.send(pkt)
    print(os.getpid())
except OSError as e:
    print("ERR %s" % e, file=sys.stderr)
    sys.exit(1)
finally:
    s.close()
PYEOF
fi

# Счёт алертов правила по ТЕКУЩЕМУ состоянию стора — для дельты базового
# YAML-правила (имя которого обогащение ПЕРЕЗАПИСЫВАЕТ, см. ниже).
_w3_rego_hits() { # $1 = rule_id, $2 = подстрока message
    _alerts | jq -r --arg r "$1" --arg m "$2" \
        '[.[]|select(.rule_id==$r)|select((.message//"")|contains($m))]|length' 2>/dev/null || echo 0
}

echo "--- 6.3u.3: №384 — dns.rego is_dga_domain достижим (зеркало предиката в префильтре) ---"
if [ "$W3_REGO_PROBE" != "1" ]; then
    die "6.3u.3 НЕИЗМЕРИМ: класс=не запрошен (W3_REGO_PROBE=0)"
elif ! command -v python3 >/dev/null 2>&1; then
    die "6.3u.3 НЕИЗМЕРИМ: класс=python3 недоступен — нечем послать зонд с управляемым comm"
elif ! command -v jq >/dev/null 2>&1; then
    die "6.3u.3 НЕИЗМЕРИМ: класс=jq недоступен — разбор /api/v1/alerts невозможен"
elif [ -z "${W3_PROBE_PY:-}" ] || [ ! -s "$W3_PROBE_PY" ]; then
    die "6.3u.3 НЕИЗМЕРИМ: класс=тело зонда не собрано (mktemp в ${TMPDIR:-/tmp})"
else
    # Имя зонда: первая метка 16 символов, с цифрами, без словарного куска —
    # is_dga_domain(dns.rego) ИСТИНА. Измерено 19.09.2026: n-gram 0.430,
    # IsDGA=false, длина 30 (<50), TLD не подозрительный — то есть НИ ОДНА
    # другая проверка префильтра его не форвардит. Суффикс случайный: он и
    # есть ключ атрибуции в message обогащённого алерта.
    # РОВНО 4 шестнадцатеричных знака, и это не косметика. Модель n-gram
    # берёт МАКСИМУМ по меткам имени, а метки короче ngramMinLabelLen (10)
    # не судит вовсе. С 8 знаками вторая метка «w63u3<tag>» становится
    # 13-символьной случайной строкой и сама набирает 0.55…0.64 — измерено
    # 19.09.2026, — то есть событие форвардилось бы по ОБЩЕЙ ветке n-gram, а
    # не по зеркалу is_dga_domain, и метка 6.3u.3 зачла бы себе чужой
    # механизм. С 4 знаками метка девятисимвольная, модель её пропускает, и
    # оценка всего имени остаётся 0.430 — ниже порога, единственный путь
    # форварда — предикат №384.
    _w3u3_tag=$(head -c 8 /dev/urandom 2>/dev/null | od -An -tx1 | tr -d ' \n' | head -c 4)
    _w3u3_qname="server1234567890.w63u3${_w3u3_tag}.invalid"
    _w3u3_base_before=$(_rule_count dns_any_query)
    _w3u3_pid=$(python3 "$W3_PROBE_PY" "$_w3u3_qname" 2>/dev/null)
    _w3u3_rc=$?
    sleep "${W3_593C_SLEEP:-15}"
    _w3u3_base_after=$(_rule_count dns_any_query)
    _w3u3_enriched=$(_w3_rego_hits dga_domain "$_w3u3_qname")
    echo "  зонд qname=$_w3u3_qname (pid=${_w3u3_pid:-?}, rc=$_w3u3_rc), dns_any_query ${_w3u3_base_before:-0}->${_w3u3_base_after:-0}, алертов dga_domain с этим qname: ${_w3u3_enriched:-0}"
    if [ "$_w3u3_rc" -ne 0 ] || [ -z "${_w3u3_pid:-}" ]; then
        # Сторож результата ВПЕРЕДИ вердикта: не состоявшийся send(2) даёт
        # приборный ноль, а не ответ о детекте ([[positive-control-needs-result-sentinel]]).
        die "6.3u.3 НЕИЗМЕРИМ: класс=зонд не отправлен (rc=$_w3u3_rc) — ноль ниже был бы приборным"
    elif [ "${_w3u3_enriched:-0}" -gt 0 ]; then
        pass "6.3u.3 ДОСТИГНУТО: алерт по зонду $_w3u3_qname несёт rule_id=dga_domain из Rego — префильтр больше не глушит собственный предикат dns.rego (№384 закрыта живьём)"
    elif [ "$(( ${_w3u3_base_after:-0} - ${_w3u3_base_before:-0} ))" -gt 0 ]; then
        die "6.3u.3 ПРОВАЛЕН: базовый алерт поднят (dns_any_query +$(( ${_w3u3_base_after:-0} - ${_w3u3_base_before:-0} ))), но обогащения dga_domain по этому qname НЕТ — зеркало is_dga_domain в префильтре не работает на этом бинаре (проверить, что на ноде бинарь с правкой №384, и что policy.rego.enabled не выключен конфигом)"
    else
        die "6.3u.3 НЕИЗМЕРИМ: класс=базовый YAML-алерт не поднялся вовсе (dns_any_query не вырос) — вопрос о префильтре не задан: коллектор не увидел запрос ЛИБО правило dns_any_query сужено/молчит. Читать вместе с 6.3.0/6.3.1 этого же прогона"
    fi
fi

echo
echo "--- 6.3u.4: №385 — правила lineage.rego достижимы на DNS-событии (ось parent_comm) ---"
# Родитель с нужным comm СОЗДАЁТСЯ копией реального бинаря под именем nginx —
# тот же приём, что у 6.0.15/6.0.16 (системный бинарь дал бы постоянный comm
# и чужие совпадения). Ребёнок — python3: он входит в is_shell обоих
# определений (dns.rego и lineage.rego), поэтому правило
# reverse_shell_webserver требует ровно пары (python3, nginx).
if [ "$W3_REGO_PROBE" != "1" ]; then
    die "6.3u.4 НЕИЗМЕРИМ: класс=не запрошен (W3_REGO_PROBE=0)"
elif ! command -v python3 >/dev/null 2>&1; then
    die "6.3u.4 НЕИЗМЕРИМ: класс=python3 недоступен — нечем послать зонд из процесса с comm из is_shell"
elif ! command -v jq >/dev/null 2>&1; then
    die "6.3u.4 НЕИЗМЕРИМ: класс=jq недоступен — разбор /api/v1/alerts невозможен"
elif [ -z "${W3_PROBE_PY:-}" ] || [ ! -s "$W3_PROBE_PY" ]; then
    die "6.3u.4 НЕИЗМЕРИМ: класс=тело зонда не собрано (mktemp в ${TMPDIR:-/tmp})"
else
    _w3u4_src=""
    for _w3u4_cand in /bin/bash /usr/bin/bash /bin/sh; do
        [ -x "$_w3u4_cand" ] && { _w3u4_src="$_w3u4_cand"; break; }
    done
    _w3u4_dir=$(mktemp -d "${TMPDIR:-/tmp}/w63u4.XXXXXX" 2>/dev/null)
    if [ -z "$_w3u4_src" ] || [ -z "${_w3u4_dir:-}" ]; then
        die "6.3u.4 НЕИЗМЕРИМ: класс=нечем собрать родителя (нет исполняемого шелла или mktemp)"
    elif ! cp "$_w3u4_src" "$_w3u4_dir/nginx" 2>/dev/null || ! chmod +x "$_w3u4_dir/nginx" 2>/dev/null || [ ! -x "$_w3u4_dir/nginx" ]; then
        die "6.3u.4 НЕИЗМЕРИМ: класс=копия $_w3u4_src под именем nginx не исполнима (noexec на ${TMPDIR:-/tmp}?) — execve упал бы до запроса, и ноль был бы приборным (класс находки №176)"
    else
        # Имя зонда ДОБРОКАЧЕСТВЕННОЕ намеренно: первая метка 13 символов без
        # цифр (is_dga_domain ложь), n-gram 0.319, TLD не подозрительный,
        # длина 27. Если алерт обогатится — это может быть ТОЛЬКО ось
        # parent_comm, никакая другая проверка префильтра его не пропускает.
        _w3u4_qname="control-probe.w63u4.invalid"
        _w3u4_base_before=$(_rule_count dns_any_query)
        # Родитель исполняет ребёнка, ребёнок печатает свой pid — он и есть
        # ключ атрибуции: message правила reverse_shell_webserver несёт pid,
        # но не qname.
        #
        # `; :` в конце — НЕ украшение. bash применяет exec-оптимизацию к
        # ОДИНОЧНОЙ простой команде в -c: процесс-родитель заменился бы
        # образом python3, сохранив свой pid и СВОЕГО родителя, и
        # parent_comm в событии оказался бы comm этого скрипта, а не nginx.
        # Контроль тогда мерил бы не ту ось и давал ложный ПРОВАЛ. Список из
        # двух команд заставляет bash форкнуть ребёнка по-настоящему.
        _w3u4_pid=$("$_w3u4_dir/nginx" -c "$(command -v python3) '$W3_PROBE_PY' '$_w3u4_qname'; :" 2>/dev/null)
        _w3u4_rc=$?
        sleep "${W3_593C_SLEEP:-15}"
        _w3u4_base_after=$(_rule_count dns_any_query)
        _w3u4_enriched=0
        [ -n "${_w3u4_pid:-}" ] && _w3u4_enriched=$(_w3_rego_hits reverse_shell_webserver "pid=${_w3u4_pid}")
        echo "  зонд qname=$_w3u4_qname из python3 (pid=${_w3u4_pid:-?}, rc=$_w3u4_rc) под родителем comm=nginx ($_w3u4_dir/nginx), dns_any_query ${_w3u4_base_before:-0}->${_w3u4_base_after:-0}, алертов reverse_shell_webserver с этим pid: ${_w3u4_enriched:-0}"
        rm -rf "$_w3u4_dir" 2>/dev/null || true
        if [ "$_w3u4_rc" -ne 0 ] || [ -z "${_w3u4_pid:-}" ]; then
            die "6.3u.4 НЕИЗМЕРИМ: класс=зонд не отправлен (rc=$_w3u4_rc) — ноль ниже был бы приборным"
        elif [ "${_w3u4_enriched:-0}" -gt 0 ]; then
            pass "6.3u.4 ДОСТИГНУТО: алерт DNS-события от python3 под родителем nginx несёт rule_id=reverse_shell_webserver (pid=$_w3u4_pid) — партиция dns компилирует lineage.rego, и префильтр больше не выбрасывает такие события по доброкачественности имени (№385 закрыта живьём)"
        elif [ "$(( ${_w3u4_base_after:-0} - ${_w3u4_base_before:-0} ))" -gt 0 ]; then
            die "6.3u.4 ПРОВАЛЕН: базовый алерт поднят (dns_any_query +$(( ${_w3u4_base_after:-0} - ${_w3u4_base_before:-0} ))), но обогащения reverse_shell_webserver по pid=$_w3u4_pid НЕТ. Читать в порядке: parent_comm в событии пуст (тогда ось не доехала из ядра — проверить bpf/common.h и поле parent_comm) ЛИБО передача parentComm в ShouldEvaluate отсутствует в этом бинаре (правка №385 не в сборке)"
        else
            die "6.3u.4 НЕИЗМЕРИМ: класс=базовый YAML-алерт не поднялся вовсе (dns_any_query не вырос) — вопрос о префильтре не задан"
        fi
    fi
fi

echo
echo "--- 6.3u.5: №386 — вход бэкфилла по udp6 существует и имеет ожидаемую форму ---"
# ЧТО ЭТОТ КОНТРОЛЬ МОЖЕТ И ЧЕГО НЕ МОЖЕТ. Бэкфилл — СТАРТОВЫЙ скан: его
# нельзя переисполнить на живом агенте, а обе половины №386 (ретрай
# неймспейса после невезучего pid и независимое чтение udp6) сняты
# офлайн-тестами. Живьём проверяемо другое и не менее важное: что ВХОД, на
# который правка опирается, на ЭТОЙ ноде существует и выглядит так, как
# предполагает парсер. Ноль здесь означал бы, что правка №383/№386
# структурно бесполезна на этом ядре, и это надо знать ДО того, как
# величины волны будут приписаны ей.
#
# Зонд: собственный IPv6-сокет, подключённый к ::1:53, живущий достаточно
# долго, чтобы его увидели в /proc ([[control-payload-must-outlive-its-readlink]]).
if ! command -v python3 >/dev/null 2>&1; then
    die "6.3u.5 НЕИЗМЕРИМ: класс=python3 недоступен — нечем создать connected UDP6-сокет"
else
    python3 -c "
import socket, time
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.connect(('::1', 53))
time.sleep(40)
" >/dev/null 2>&1 &
    _w3u5_pid=$!
    sleep 2
    if ! kill -0 "$_w3u5_pid" 2>/dev/null; then
        die "6.3u.5 НЕИЗМЕРИМ: класс=IPv6-сокет не создан (IPv6 выключен в ядре этой ноды) — вход бэкфилла по udp6 на ней отсутствует структурно, и это ОТВЕТ, а не сбой прибора"
    else
        # Ровно тот разбор, что делает connectedPort53Inodes: колонка 3 —
        # rem_address вида <hex>:<порт>, порт 0035, адрес не весь нулевой;
        # колонка 10 — inode. Считаем ОТДЕЛЬНО udp и udp6 по всем netns.
        _w3u5_count() { # $1 = имя таблицы (udp|udp6)
            for _p in /proc/[0-9]*; do
                [ -r "$_p/net/$1" ] || continue
                awk 'NR>1 && $10 != "" && $10 != "0" {
                        split($3, a, ":");
                        if (toupper(a[2]) == "0035") { z=a[1]; gsub(/0/, "", z); if (z != "") print $10 }
                     }' "$_p/net/$1" 2>/dev/null
            done | sort -u | wc -l | tr -d ' '
        }
        _w3u5_udp=$(_w3u5_count udp)
        _w3u5_udp6=$(_w3u5_count udp6)
        kill "$_w3u5_pid" >/dev/null 2>&1
        wait "$_w3u5_pid" 2>/dev/null
        echo "  connected-to-:53 inode'ов по всем netns: udp=$_w3u5_udp, udp6=$_w3u5_udp6 (в окне жив собственный сокет на ::1:53, pid=$_w3u5_pid)"
        if [ "${_w3u5_udp6:-0}" -ge 1 ]; then
            pass "6.3u.5 ДОСТИГНУТО: таблица /proc/<pid>/net/udp6 на этой ноде существует, несёт колонки в том же формате, что udp, и отдала $_w3u5_udp6 inode(ов) на порт 53 — вход правки №383/№386 реален, а не предполагаем (остаток №386 — ретрай неймспейса — снят офлайн-тестами, живьём гонка не воспроизводима по построению)"
        else
            die "6.3u.5 ПРОВАЛЕН: собственный сокет на ::1:53 жив, а разбор udp6 по всем netns дал 0 inode'ов — либо формат таблицы на этом ядре иной, чем предполагает connectedPort53Inodes, либо сокет не попал ни в одну прочитанную таблицу. Пока так, бэкфилл по udp6 на этой ноде не добавляет НИЧЕГО, и величины IPv6 нельзя приписывать №383"
        fi
    fi
fi

echo
echo "=== ИТОГ ОПОРНОГО НАБОРА: провалов/неизмеримых = $W3_FAILS ==="
echo "  артефакт: $W3_VERDICTS"
if [ "$W3_FAILS" -gt 0 ]; then
    echo "  ⚠ опорный набор НЕПОЛОН — 6.3.9.5 на прогоне B, сравниваясь с этим снимком, обязана назвать неполные метки НЕИЗМЕРИМЫМИ, а не молчать о них"
fi
echo "$W3_FAILS" > "$W3_DONE"
# Копия под стабильным именем — её и читает прогон B как «последний снятый
# набор»; сам тегированный файл при этом остаётся на месте навсегда.
cp "$W3_VERDICTS" "$W3_ART/baseline-controls-verdicts-latest.txt" 2>/dev/null || true
echo "  последний снимок: $W3_ART/baseline-controls-verdicts-latest.txt (копия $W3_VERDICTS)"
echo "  реестр классов роли $W3_ROLE: $W3_LABELS"
sed 's/^/    /' "$W3_LABELS" 2>/dev/null
