#!/bin/bash
# run-6.2.1-pipeline.sh — прогон волны 6.2.1 (долг базового прогона 6.2).
#
# ЧТО ЭТОТ ПРОГОН МЕРЯЕТ. Базовый прогон 6.2 (04.09.2026, архив
# server-logs/collect-6.2) провалил гейт волны 6 на два порядка и дал девять
# находок №220…№228. Три из них — дефекты самого измерителя, и они починены в
# wave6.2.1-controls.sh ДО этого прогона: без них прогон повторил бы приборные
# нули, а не измерил починку.
#
# ЧЕМ ОТЛИЧАЕТСЯ ОТ run-6.2-baseline.sh:
#   * прогон НЕ базовый. Ключ дрейфа {Comm,Namespace,AppLabel} нода уже
#     сдвинула на прошлом прогоне; величины дрейфа здесь засчитываются, если
#     6.2.1.A взят;
#   * реестры пополняются ДО прогона (пункт Д) — сужение 6.2.1.1 меняет состав
#     сработавших правил, и без записи КАЖДЫЙ архив старше сужения напечатает
#     их потерей: жёсткий стоп без единого регресса продукта;
#   * тихое окно объёма закрывается сторожем потерь событий (находка №222):
#     ненулевая дельта дропов делает окно НЕИЗМЕРИМЫМ, а не «взятым с
#     оговоркой»;
#   * артефакты пишутся в каталог этого прогона, и он чистится на старте
#     (находка №228: в сборке 6.2 лежал снимок суточной давности от репетиции).
#
# Гигиена (память ebpf-guard-measurement-hygiene): чистый стор, рестарт больше
# чем за 1200 с до окна, никаких заходов на сервер внутри окна, никаких
# фоновых циклов на стенде.
set -u
export PATH=$PATH:/usr/local/bin
SETUP="${SETUP:-/opt/ebpf-guard/deploy/docker-test-setup}"
SVC="${SVC:-ebpf-guard-test.service}"
PROLOGUE="${PROLOGUE:-1800}"
WINDOW="${WINDOW:-600}"
NS="${NS:-w621}"
ART="${ART:-/root/wave6.2.1-artifacts}"
OUT="${OUT:-/root/run-6.2.1.log}"

echo "=== ПРОГОН 6.2.1, старт $(date -u +%FT%TZ) ==="

# ── Шаг 0. Реестры ДО прогона (пункт Д «Переноса в 6.1…6.4»). ──────────────
# Сужение шума ноды (находка №220) МЕНЯЕТ состав сработавших правил. Правило,
# переставшее срабатывать после сужения, реплей на архивах старше сужения
# прочитает потерей. Механика renamed-rules.txt/new-rules.txt рассчитана
# ровно на это (память rule-rename-breaks-replays, new-rule-breaks-replays);
# silent-rules.txt здесь НЕ годится — та строка бессрочна и утверждала бы,
# что стенд не воспроизводит сценарий, а он его воспроизводит.
echo "--- реестры до прогона ---"
for f in idle-actors.txt new-rules.txt renamed-rules.txt silent-rules.txt; do
    _r621_found=0
    for d in "$SETUP/attacks" "$SETUP/scripts" "$SETUP" /opt/ebpf-guard/scripts; do
        if [ -f "$d/$f" ]; then
            echo "  $d/$f: $(wc -l < "$d/$f") строк"
            _r621_found=1
            break
        fi
    done
    [ "$_r621_found" -eq 1 ] || echo "  СТОП-КАНДИДАТ: $f не найден ни в одном из проверенных каталогов ($SETUP/attacks, $SETUP/scripts, $SETUP, /opt/ebpf-guard/scripts)"
done
# Сверка автоматическая, а не «проверь глазами» (урок находки №225: реестр,
# который никто не сверяет, отстаёт молча). Две поправки к первой редакции
# этого шага, обе — цена, снятая до прогона:
#   1) она предписывала писать сужённые правила в renamed-rules.txt. Это дало
#      бы ПРЕФЛАЙТ FAIL гейта (run-gate.sh:423, сторож №170): запись там
#      обязана быть переименованием — старого id в rules/ нет, новый есть, а у
#      сужения id не меняется. Правильный реестр — new-rules.txt: его вычитание
#      действует только на архивах СТАРШЕ даты записи;
#   2) сужения ПО COMM (k3s-server/coredns/containerd) в реестр не вносятся
#      вовсе: на старых архивах этих comm нет, правило сработает как раньше, и
#      запись маскировала бы настоящий регресс. Ниже — только те пять, у
#      которых изменено само условие.
#   3) слой 3 перевёл три правила о смене прав с syscall-оси на файловую и
#      добавил им предикат пути. На архивах старше этой волны файловых
#      chmod-событий нет физически, значит на реплее правила немы по
#      построению — им запись обязательна, наравне с сужениями по условию.
#   4) дата записи обязана быть СТРОГО БОЛЬШЕ даты архива, который она
#      покрывает (run-gate.sh:1459, сравнение d < $2). Записи, датированные
#      днём самого архива, его не покрывают; проверка ниже это ловит.
W621_NARROWED_COND="container_escape_host_mount container_escape_host_network cryptominer_xmrig_signature evasion_iptables_flush sigma_iptables_flush container_escape_host_mount_from_host evasion_chmod_sensitive sigma_chmod_executable_tmp sigma_sensitive_file_chmod sigma_sensitive_file_chmod_daemon"
# Дата архива, который записи обязаны покрывать: окно замера 6.2 снято
# 04.09.2026. Запись с датой <= этой архив НЕ покрывает.
W621_ARCHIVE_DATE=20260904
W621_NODE_ACTORS_REQ="k3s-server coredns containerd containerd-shim iptables local-path-prov runc"
_r621_reg="$SETUP/attacks/new-rules.txt"
_r621_idle="$SETUP/attacks/idle-actors.txt"
_r621_gap=""
for _r in $W621_NARROWED_COND; do
    awk -v r="$_r" -v a="$W621_ARCHIVE_DATE" \
        '!/^[[:space:]]*(#|$)/ && $1 == r && $2 ~ /^[0-9]{8}$/ && $2+0 > a+0 {found=1} END{exit !found}' \
        "$_r621_reg" 2>/dev/null || _r621_gap="$_r621_gap new-rules.txt:$_r"
done
for _a in $W621_NODE_ACTORS_REQ; do
    grep -qE "^${_a}[[:space:]]" "$_r621_idle" 2>/dev/null || _r621_gap="$_r621_gap idle-actors.txt:$_a"
done
if [ -n "$_r621_gap" ]; then
    echo "СТОП ДО ПРОГОНА: реестры не заполнены:$_r621_gap"
    echo "  Реплей архива этой волны встанет ЖЁСТКИМ СТОПОМ №1 без единого регресса продукта"
    echo "  (пункт Д «Переноса в 6.1…6.4»). Прогон не начат — агент не тронут, стор не очищен."
    exit 1
fi
echo "  реестры сверены: сужений по условию $(echo $W621_NARROWED_COND | wc -w) в new-rules.txt, акторов ноды $(echo $W621_NODE_ACTORS_REQ | wc -w) в idle-actors.txt"

# ── Шаг 1. Чистый стор и рестарт. ─────────────────────────────────────────
echo "--- стор ---"
kubectl -n "$NS" delete pod --all --ignore-not-found --wait=true >/dev/null 2>&1
rm -rf "$ART" 2>/dev/null
systemctl stop "$SVC"
rm -f /var/lib/ebpf-guard/test-events.db /var/lib/ebpf-guard/test-events.db-wal /var/lib/ebpf-guard/test-events.db-shm
systemctl start "$SVC"
date -u +%FT%TZ > /root/agent-start-6.2.1.txt
echo "агент поднят $(cat /root/agent-start-6.2.1.txt), стор пуст"

# ── Шаг 2. Приборность до пролога: ждать 1800 с ради неизмеримого прогона
#    незачем (память die-only-for-unmeasurable-run — die только за неизмеримость).
sleep 30
if ! journalctl -u "$SVC" --since "-2 min" --no-pager | grep -q 'k8s enricher active'; then
    echo "СТОП: k8s-энричер не поднялся после рестарта — прогон неизмерим"
    date -u +%FT%TZ > /root/PIPELINE-6.2.1-DONE
    exit 1
fi
echo "k8s-энричер поднят"

# Немота по среде фиксируется здесь же, пока журнал стартовых строк свеж
# (находка №225): 11 недостижимых syscall-правил и kmod-коллектор.
journalctl -u "$SVC" --since "-3 min" --no-pager \
    | grep -E 'no reachable nr in the kernel allowlist|cgroup escape collector unavailable' \
    > /root/env-muteness-6.2.1.txt 2>/dev/null
echo "немота по среде записана: /root/env-muteness-6.2.1.txt ($(wc -l < /root/env-muteness-6.2.1.txt) строк)"

# ── Шаг 3. Пролог. Ключ дрейфа обязан закрыть обучение ДО окна (пункт А). ──
echo "--- пролог ${PROLOGUE}s (обучение дрейфа закрывается: 600 × 2 = 1200 с) ---"
sleep "$PROLOGUE"

# ── Шаг 4. Контроли. Порядок внутри скрипта: реестр → приборность → пролог →
#    ТИХОЕ ОКНО (вход не подаётся) → вход (6.2.1.2/6.2.1.2b/6.2.1.3) →
#    оборот подов. Вход после окна, а не до — иначе лимитер, выбранный
#    контролем, показывает себя вместо фона ноды.
echo "--- контроли волны 6.2.1 ---"
W621_WINDOW="$WINDOW" W621_NS="$NS" W621_ART="$ART" W621_SVC="$SVC" \
W621_CHURN=3 W621_GATE=100 W621_VERDICTS=/root/wave6.2.1-controls-verdicts.txt \
    bash "$SETUP/wave6.2.1-controls.sh"

# ── Шаг 5. Сборка архива. Кладётся ТОЛЬКО то, что написал этот прогон
#    (находка №228). Ничего не копируется из каталогов прошлых волн.
echo "--- сборка архива ---"
COLLECT=/root/collect-6.2.1
rm -rf "$COLLECT"; mkdir -p "$COLLECT/controls" "$COLLECT/node"
cp -r "$ART" "$COLLECT/controls/artifacts" 2>/dev/null
cp /root/wave6.2.1-controls-verdicts.txt "$COLLECT/controls/" 2>/dev/null
cp /root/agent-start-6.2.1.txt /root/env-muteness-6.2.1.txt "$COLLECT/" 2>/dev/null
cp "$SETUP/config-test.yaml" "$SETUP/wave6.2.1-controls.sh" "$SETUP/run-6.2.1-pipeline.sh" "$COLLECT/" 2>/dev/null
journalctl -u "$SVC" --since "$(cat /root/agent-start-6.2.1.txt)" --no-pager > "$COLLECT/journal-agent-6.2.1.log" 2>/dev/null
kubectl get nodes -o wide > "$COLLECT/node/nodes.txt" 2>/dev/null
kubectl get pods -A -o wide > "$COLLECT/node/pods.txt" 2>/dev/null
kubectl version -o json > "$COLLECT/node/version.json" 2>/dev/null
git -C /opt/ebpf-guard log --oneline -6 > "$COLLECT/git-head.txt" 2>/dev/null
[ -f "$OUT" ] && cp "$OUT" "$COLLECT/run-6.2.1.log"
echo "архив: $COLLECT ($(du -sh "$COLLECT" 2>/dev/null | cut -f1))"
echo "  забрать: rsync -az root@<стенд>:$COLLECT/ server-logs/collect-6.2.1/"

echo "=== ПРОГОН 6.2.1 ЗАВЕРШЁН $(date -u +%FT%TZ) ==="
date -u +%FT%TZ > /root/PIPELINE-6.2.1-DONE
