#!/usr/bin/env bash
# wave6.1-realistic-attack.sh — реалистичная проверка контейнерной оси волны 6.1
# ЧЕРЕЗ НАСТОЯЩУЮ HTTP-АТАКУ на контейнеризованное веб-приложение.
#
# Зачем отдельно от wave6.1-controls.sh. Тот контроль подаёт вход `docker exec`
# внутрь контейнера (busybox читает /etc/passwd) — это доказывает МЕХАНИКУ оси,
# но не является «атакой через веб-приложение»: снаружи HTTP-запроса нет. Буква
# критерия 6.1 («на прогоне атак через веб») требует, чтобы файл открыл сам
# рабочий тред приложения по HTTP-запросу.
#
# Почему не сам OWASP Juice Shop (проверено на ebaka2 03.09.2026). Штатный
# Juice Shop НЕ уязвим к LFI на уровне ФС: его роутер нормализует/блокирует
# `../` до вызова open() (`/ftp/..%2f..%2fetc%2fpasswd` -> 403; `/ftp/../../etc/
# passwd` -> express-нормализация до open, ядро не видит `../`; poison-null-byte
# читает только внутри /ftp). До Q9-правил такой запрос не доходит в принципе.
#
# Почему не node вообще. node 20 называет ВСЕ треды "node" (проверено
# /proc/<tid>/comm), включая тред-пул libuv, делающий файловый ввод-вывод. То
# есть контейнерный node-LFI ловится comm-списком и БЕЗ оси — комментарии
# правил, ссылавшиеся на "libuv-worker", исправлены (находка №219). Ось реально
# нужна рантаймам, чей рабочий тред ВНЕ comm-списка: Go (comm=имя бинаря),
# Tomcat (http-nio-*), tokio. Поэтому целью здесь служит vulnweb — умышленно
# уязвимый Go-веб (fixtures/vulnweb/vulnweb.go), у которого comm="vulnweb".
#
# Три контроля, все три обязаны пройти:
#   1) ПОЗИТИВНЫЙ  — HTTP-LFI на контейнеризованный vulnweb поднимает Q9-правило,
#                    и алерт несёт container_id (сработала именно ось).
#   2) НЕГАТИВНЫЙ  — тот же бинарь на ХОСТЕ по тому же HTTP молчит (ось не вернула
#                    хостовой FP — тот самый FP, ради устранения которого Q9
#                    сужалось в волне 3).
#   3) FP-СТОРОЖ   — старт свежих контейнеров НЕ поднимает Q9 от runc:[N:INIT]/
#                    containerd-shim (исключение волны 6.1: runtime-init читает
#                    /etc/passwd нового контейнера, будучи временно тегнут его
#                    cgroup — без исключения это FP на КАЖДЫЙ старт пода).
#
# Требует на хосте: docker, go, curl, jq, busybox-образ. API агента и токен —
# как в wave6.1-controls.sh.
set -u

W61_API="${W61_API:-http://127.0.0.1:19090}"
W61_TOKEN_FILE="${W61_TOKEN_FILE:-/var/lib/ebpf-guard/token}"
W61_PORT_CTR="${W61_PORT_CTR:-8091}"
W61_PORT_HOST="${W61_PORT_HOST:-8092}"
W61_BASE_IMAGE="${W61_BASE_IMAGE:-busybox:latest}"
W61_RULES="owasp_path_traversal owasp_web_sensitive_file_read appexploit_lfi_passwd_access appexploit_xxe_file_read webshell_sensitive_file_read"
VERDICTS="${W61_REAL_VERDICTS:-/root/wave6.1-realistic-verdicts.txt}"

_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VULN_SRC="${W61_VULN_SRC:-$_here/attacks/fixtures/vulnweb/vulnweb.go}"
VULN_BIN="${W61_VULN_BIN:-/root/vulnweb}"

TOK="$(grep '^admin=' "$W61_TOKEN_FILE" 2>/dev/null | cut -d= -f2)"
[ -z "$TOK" ] && TOK="$(head -c 200 "$W61_TOKEN_FILE" 2>/dev/null)"

_fail=0
die() { echo "!!! $*" >&2; _fail=$((_fail+1)); }

_alerts() { curl -s -H "Authorization: Bearer $TOK" "$W61_API/api/v1/alerts"; }

# _q9_count <T0> <ctr|host> — число Q9-алертов с непустым (ctr) / пустым (host)
# container_id, появившихся не раньше T0.
_q9_count() {
    _alerts | jq -r --arg ids "$W61_RULES" --arg t0 "$1" --arg mode "$2" '
      [ .[]
        | select(.timestamp >= $t0)
        | select(.rule_id as $r | ($ids|split(" "))|index($r))
        | select(if $mode=="ctr" then (.enrichment.container_id//"")!=""
                 else (.enrichment.container_id//"")=="" end)
      ] | length' 2>/dev/null || echo 0
}

cleanup() {
    docker rm -f w61ra_vuln >/dev/null 2>&1
    pkill -f "$VULN_BIN" >/dev/null 2>&1
    rm -f "$VULN_BIN"
}
trap cleanup EXIT

# --- сборка цели --------------------------------------------------------------
[ -f "$VULN_SRC" ] || { echo "нет исходника цели: $VULN_SRC"; exit 2; }
command -v go >/dev/null 2>&1 || { echo "нет go на хосте — цель не собрать"; exit 2; }
CGO_ENABLED=0 go build -o "$VULN_BIN" "$VULN_SRC" 2>&1 | head
[ -x "$VULN_BIN" ] || { echo "сборка vulnweb не удалась ($VULN_SRC)"; exit 2; }
echo "цель собрана: $VULN_BIN ($(basename "$VULN_SRC")), comm цели = vulnweb (вне comm-списка Q9)"
echo "# wave6.1-realistic-attack.sh, прогон от $(date -u +%FT%TZ)" > "$VERDICTS"

# === 1) ПОЗИТИВНЫЙ ============================================================
docker rm -f w61ra_vuln >/dev/null 2>&1
docker run -d --name w61ra_vuln -p 127.0.0.1:"$W61_PORT_CTR":8091 \
    -v "$VULN_BIN":/vulnweb:ro --entrypoint /vulnweb "$W61_BASE_IMAGE" >/dev/null 2>&1
sleep 3
CID="$(docker inspect -f '{{.Id}}' w61ra_vuln 2>/dev/null)"
HEALTH="$(curl -s "http://127.0.0.1:$W61_PORT_CTR/healthz" 2>/dev/null)"
if [ "$HEALTH" != "ok" ]; then
    die "6.1-real/1 НЕ ИСПОЛНЕН: контейнеризованный vulnweb не поднялся (health='$HEALTH', cid=${CID:0:12}). Механика контроля отказала — позитива не существует, критерий НЕ ИЗМЕРЕН этим прогоном"
else
    T1="$(date -u +%Y-%m-%dT%H:%M:%SZ)"; sleep 1
    for _i in $(seq 1 15); do curl -s -o /dev/null "http://127.0.0.1:$W61_PORT_CTR/read?path=/etc/passwd"; done
    sleep 4
    POS="$(_q9_count "$T1" ctr)"
    echo "  1) ПОЗИТИВНЫЙ: HTTP-LFI на контейнер ${CID:0:12} -> Q9-алертов с container_id = $POS"
    _alerts | jq -r --arg ids "$W61_RULES" --arg t0 "$T1" '
      [.[]|select(.timestamp>=$t0)|select(.rule_id as $r|($ids|split(" "))|index($r))
        |select((.enrichment.container_id//"")!="")]|.[]
      |"     \(.rule_id) comm=\(.comm) cid=\((.enrichment.container_id)[0:12])"' 2>/dev/null | sort -u
    if [ "${POS:-0}" -ge 1 ]; then
        echo "6.1-real/1 PASS $(date -u +%FT%TZ)" >> "$VERDICTS"
    else
        die "6.1-real/1 ПРОВАЛЕН: настоящая HTTP-LFI на контейнеризованный веб (comm=vulnweb ВНЕ comm-списка) НЕ подняла ни одного Q9-правила с container_id. Ось до правил не доходит. Читать: (1) поднят ли runtime-энричер (лог агента 'runtime enricher active'); (2) ставится ли обогащение ДО correlate (cmd/ebpf-guard/main.go); (3) видит ли агент /proc контейнера"
    fi
fi

# === 2) НЕГАТИВНЫЙ ============================================================
ADDR="127.0.0.1:$W61_PORT_HOST" setsid nohup "$VULN_BIN" >/dev/null 2>&1 &
sleep 2
HEALTH_H="$(curl -s "http://127.0.0.1:$W61_PORT_HOST/healthz" 2>/dev/null)"
if [ "$HEALTH_H" != "ok" ]; then
    die "6.1-real/2 НЕ ИСПОЛНЕН: хостовый vulnweb не поднялся (health='$HEALTH_H'). Негатив не подан — ноль ниже не читается"
else
    T2="$(date -u +%Y-%m-%dT%H:%M:%SZ)"; sleep 1
    for _i in $(seq 1 15); do curl -s -o /dev/null "http://127.0.0.1:$W61_PORT_HOST/read?path=/etc/passwd"; done
    sleep 4
    NEG="$(_q9_count "$T2" host)"
    echo "  2) НЕГАТИВНЫЙ: тот же бинарь на ХОСТЕ, тот же HTTP -> ХОСТОВЫХ Q9-алертов (container_id пуст) = $NEG"
    if [ "${NEG:-0}" -eq 0 ]; then
        echo "6.1-real/2 PASS $(date -u +%FT%TZ)" >> "$VERDICTS"
    else
        die "6.1-real/2 ПРОВАЛЕН: тот же LFI С ХОСТА поднял +$NEG ХОСТОВЫХ Q9-алертов — ось матчит там, где контейнера нет (возврат FP, ради устранения которого Q9 сужалось). Читать: не тегает ли агент непустым container_id хостовые процессы (общий cgroup-неймспейс)"
    fi
fi

# === 3) FP-СТОРОЖ (исключение runc-init) =====================================
T3="$(date -u +%Y-%m-%dT%H:%M:%SZ)"; sleep 1
docker run --rm busybox:latest true >/dev/null 2>&1
docker run --rm busybox:latest sh -c 'echo hi' >/dev/null 2>&1
sleep 4
LEAK="$(_alerts | jq -r --arg ids "$W61_RULES" --arg t0 "$T3" '
  [.[]|select(.timestamp>=$t0)|select(.rule_id as $r|($ids|split(" "))|index($r))
    |select(.comm|test("runc|containerd-shim"))]|length' 2>/dev/null || echo 0)"
echo "  3) FP-СТОРОЖ: старт 2 свежих контейнеров -> Q9-алертов от runc/containerd-shim = $LEAK (ожидается 0)"
if [ "${LEAK:-0}" -eq 0 ]; then
    echo "6.1-real/3 PASS $(date -u +%FT%TZ)" >> "$VERDICTS"
else
    _alerts | jq -r --arg ids "$W61_RULES" --arg t0 "$T3" '
      [.[]|select(.timestamp>=$t0)|select(.rule_id as $r|($ids|split(" "))|index($r))
        |select(.comm|test("runc|containerd-shim"))]|.[]|"     УТЕЧКА: \(.rule_id) comm=\(.comm)"' 2>/dev/null | sort -u
    die "6.1-real/3 ПРОВАЛЕН: старт контейнера поднял $LEAK Q9-алертов от runtime-init (runc/containerd-shim) — исключение волны 6.1 не применилось. На узле с оборотом подов это критический FP на каждый старт. Читать: применились ли новые правила (рестарт агента после правки rules/), покрывает ли not_in-список comm рантайма на этом узле"
fi

echo "=== wave6.1-realistic-attack.sh завершён: проваленных контролей $_fail, вердикты в $VERDICTS ==="
[ "$_fail" -eq 0 ] || exit 1
