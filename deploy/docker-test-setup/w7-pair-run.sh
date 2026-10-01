#!/bin/bash
# Запуск пары A/B порции `nr` С MAC одним вызовом и двухфазное ожидание.
#   фаза 0 — ОДИН заход по ssh: стартует отцепленный драйвер и печатает ПЛАН окон;
#   фаза 1 — ЛОКАЛЬНЫЙ sleep до SAFE_AFTER из плана (на стенд не заходим вовсе);
#   фаза 2 — опрос маркера, только после расчётного финиша.
# Ожидатель «на глаз» дал №317/№318: два опроса легли внутрь окна роли B.
#
# Ничего не доставляет на стенд: бандл с явным рефом — отдельный шаг (CLAUDE.md
# памяти стенда). Переопределения W7_SSH / W7_SLEEP_CMD / W7_NOW_CMD — для фикстуры.
set -u
POR="${1:?порция не названа}"
SSH="${W7_SSH:-ssh -i $HOME/.ssh/id_ed25519_ebaka2 root@89.125.2.154}"
SLEEP="${W7_SLEEP_CMD:-sleep}"
NOW="${W7_NOW_CMD:-date +%s}"
POLL="${W7_POLL_SECS:-60}"
MAXPOLL="${W7_MAX_POLLS:-120}"
REMOTE_SETUP="${W7_REMOTE_SETUP:-/opt/ebpf-guard/deploy/docker-test-setup}"

plan=$($SSH "setsid nohup bash $REMOTE_SETUP/w7-pair-driver.sh $POR >/dev/null 2>&1 < /dev/null & sleep 3; cat /root/w7-pair-P${POR}.plan") \
    || { echo "ЗАПУСК НЕ УДАЛСЯ: ssh вернул ошибку"; exit 1; }
echo "$plan"
safe=$(printf '%s\n' "$plan" | sed -n 's/^SAFE_AFTER=//p')
marker=$(printf '%s\n' "$plan" | sed -n 's/^MARKER=//p')
case "$safe" in ''|*[!0-9]*) echo "ЗАПУСК НЕ УДАЛСЯ: плана окон нет — ожидатель вслепую не ставится"; exit 1;; esac
[ -n "$marker" ] || { echo "ЗАПУСК НЕ УДАЛСЯ: в плане нет маркера"; exit 1; }

now=$($NOW)
wait_s=$(( safe - now ))
[ "$wait_s" -gt 0 ] && { echo "фаза 1: локальное ожидание ${wait_s}s до SAFE_AFTER=$safe, на стенд не заходим"; $SLEEP "$wait_s"; }
n=0
while [ "$n" -lt "$MAXPOLL" ]; do
    n=$(( n + 1 ))
    if $SSH "test -s $marker"; then
        echo "фаза 2: маркер $marker есть (опрос $n)"; exit 0
    fi
    $SLEEP "$POLL"
done
echo "ОЖИДАНИЕ ИСТЕКЛО: маркера нет после $n опросов ПОСЛЕ расчётного финиша — это сбой драйвера, а не нетерпение"
exit 2
