#!/bin/bash
# wave6.2.3-controls.sh — контроли волны 6.2.3 (долг прогона 6.2.2, находки
# №246…№252). Форк wave6.2.2-controls.sh, не переписывание: механика прогона
# №1 6.2.2 доказана живьём (архив реплеится, сторожи результата работают,
# провал контроля не убивает прогон) — здесь меняются только вердикты и
# подачи пунктов item 1/2 постановки волны (plan.md, §6.2.3 «Что делает
# волна 6.2.3»).
#
# ЭТОТ ФОРК РЕШАЕТ ЧЕТЫРЕ ПУНКТА ИЗ ШЕСТИ (item 1, 2, 3, 4). Пункты 5…6
# (исключение c2_periodic_beacon_pattern №247/решение 2, ложь инцидентного
# слоя в правилах №250/решение 5) НЕ реализованы этим форком и остаются
# долгом. 6.2.2.6/6.2.2.8/6.2.2.7/6.2.2.10/6.2.2.11 перенесены как регрессия
# под своими новыми метками (6.2.3.10/6.2.3.11/6.2.3.8/6.2.3.9) БЕЗ изменения
# подачи. См. plan.md, открытые вопросы волны 6.2.3, item 5…6.
#
# ITEM 3 (№249 + решение 4 — механизм немоты op=write установлен подачей,
# 06.09.2026): критерии 6.2.3.5/6.2.3.6 подают `echo … >> path` и
# `dd of=path` на один и тот же путь под /var/log/ и читают исход
# sigma_log_deletion по КАЖДОЙ подаче отдельно. Живой прогон на ebaka2 назвал
# механизм — FD→PATH (dup2 не хукнут): в NOFIX-сборке (dup-хуки отключены)
# ОБЕ подачи молчали (strace дал незапланированный факт — GNU dd с `of=`
# тоже идёт через open→dup2(fd,1)→write(1,…), а не пишет в свой собственный
# fd, как предполагала постановка), в WITHFIX — обе поднимают с верным
# путём. Хуки sys_enter_dup/dup2/dup3 (bpf/fileaccess.bpf.c, dup_commit)
# переносят fd_path_map на новый fd при возврате из dup-вызова; привязка не
# тихая — тот же счётчик ebpf_guard_file_hook_attach_total, что у chmod.
#
# ITEM 4 (№248, сужение верхушки шума, 06.09.2026): sigma_failed_login_syscall_daemon
# и rootkit_pam_module_added_daemon (rules/sigma-linux.yaml,
# rules/rootkit-detection.yaml) сужены осью op=write — были: любой read/open
# от sshd|cron, 3090/2400 и 2970/2280 алертов/окно на двух архивах 6.2.2,
# первые два источника разбивки (в) (6.2.3.2). Критерий 6.2.3.13 берёт обе
# половины живьём: фон (26 sshd-подключений за 90 с реального
# ssh-брутфорса на ebaka2) молчит; подделка identity (comm=sshd/cron через
# копию бинаря, а не `exec -a` — argv[0] не задаёт comm, задаёт basename
# пути execve), ДЕЙСТВИТЕЛЬНО пишущая в PAM, по-прежнему поднимает оба
# правила (severity=info, считаются в alerts_filtered_total, входят в
# формулу (а) — решение 1). Записи new-rules.txt датой 20260906.
#
# ITEM 1 (чинится измеритель — до всего остального):
#   №251  Инцидентный слой (6.2.2.9 → 6.2.3.7): вердикт строится на
#         ПОЛНОМ W623_NODE_ACTORS (список уже был в файле, цикл его не
#         использовал — критерий 6.2.2.9 проверял только
#         runc:[...]/flannel/comm измерителя и промахивался мимо
#         containerd-shim/k3s-server/kubelet/coredns/etc). Добавлено
#         разделение по фазам: инцидент с корнем из
#         W623_NODE_ACTORS∪W623_INSTR_COMMS_FLAT, чьё время попадает в окно
#         позитивных контролей [attack_phase_start, attack_phase_end], есть
#         ОЖИДАЕМЫЙ true positive и в ложь не засчитывается; вне окна —
#         засчитывается. Границы фазы пишутся эпохами в тот же
#         window-epoch.txt, что и границы тихого окна.
#   №252  HOME контроля — $W623_ART, а не /root (иначе .curlrc, .kube/cache,
#         .jq, .cache/go-build сами становятся источником алертов
#         drift_new_file_dir_sensitive, находка №252). Критерий доли
#         измерителя (6.2.2.5 → 6.2.3.3) проверяет ОБА пути — $W623_ART и
#         /root — и остаётся ВЕРДИКТОМ, а не поправкой к чтению. Список comm
#         измерителя (W623_INSTR_COMMS_FLAT) строится САМОСКАНИРОВАНИЕМ
#         текста этого файла (какие внешние команды он реально вызывает), а
#         не задаётся руками; sleep/setsid/sh/dd/printf обязаны быть
#         найдены — иначе преflight ПРОВАЛЕН.
#
# ITEM 2 (№248 + решение 1 — формула гейта закрывается):
#   Критерий 6.2.3.1 (было 6.2.2.1) печатает все ЧЕТЫРЕ слоя раздельно:
#   alerts_total, alerts_filtered_total, alerts_ratelimited_by_rule_total,
#   alerts_dedup_dropped_by_rule_total. Вердикт по-прежнему выносится
#   формулой (а) = alerts_total + alerts_filtered_total (info включительно,
#   решение 1: (б) без info отвергнута — переименование объёма, №232). Рядом
#   ОБЯЗАТЕЛЬНА величина (в) = сумма всех четырёх слоёв, БЕЗ порога (правило
#   5.9.6 — порог впервые измеренной величине не назначается). Страж ложного
#   PASS сохранён и уточнён: PASS по (а) при непустом списке правил с
#   ненулевым срезом лимитера ЗА ОКНО есть НЕИЗМЕРИМОСТЬ, а не взятый
#   критерий (FAIL при тех же условиях действителен). Новый критерий 6.2.3.2
#   ранжирует поимённую разбивку по (в) — через w623_value_v_by_rule
#   (wave6.2.3-metrics-lib.sh) — а не по остатку после лимитера, как делала
#   6.2.2.3; офлайн-сторож на ОБОИХ архивах 6.2.2 проверяет, что первыми
#   встают sigma_failed_login_syscall_daemon и rootkit_pam_module_added_daemon
#   (3090/2970 на collect-6.2.2-run1, 2400/2280 на collect-6.2.2), а не
#   c2_periodic_beacon_pattern (985/985) — см. --self-test в
#   wave6.2.3-metrics-lib.sh.
#
# ЧТО НАСЛЕДОВАНО БЕЗ ИЗМЕНЕНИЙ ИЗ 6.2.2 (перенумеровано механически, подача
# та же): №238 (список срезанных правил по метрике, w623_ratelimited_by_rule),
# №239 (разбивка величины по метрике, 6.2.2.3 остаётся под старым номером —
# критерий 6.2.3.12), №240 (эпоха вместо ISO-8601 для journalctl), №241
# (копия лога — последним действием, в пайплайне), №237 (заморозка базы
# дрейфа приращением счётчика), №236 (цена старта пода, порог 45/под), №244
# (профиль и потолок ресурсов пайплайном, 6.2.3.8/6.2.3.9), №243 (живой
# сторож monitored_syscalls).
#
# ЧТО ПЕРЕНЕСЕНО РЕГРЕССИЕЙ И ПОЧЕМУ СОХРАНИЛО СТАРЫЕ НОМЕРА. Контроли
# 6.2.1.2, 6.2.1.2b, 6.2.1.3, 6.2.1.6, 6.2.1.8, 6.2.1.9, 6.2.2.2, 6.2.2.3 —
# восемь штук, критерий 6.2.3.12 — стоят под СВОИМИ старыми метками
# (перечень явно зафиксирован постановкой волны 6.2.3, plan.md). Их метки НЕ
# перенумерованы намеренно (память criteria-index-pins-replay-labels):
# перенумерация меток — ровно то, что роняет преflight на прошлых архивах.
# Новые/изменённые критерии этой волны несут номера 6.2.3.*, и вердикт-файл
# читается однозначно.
#
# ЗАПУСК. Скрипт не самостоятелен: нужен живой агент с kubernetes.enabled:true
# и готовая нода. Провал контроля НЕ убивает чужой прогон (волна 6.0m,
# память die-only-for-unmeasurable-run); die() здесь только считает и пишет
# вердикт.
#   W623_API           — база HTTP API агента (http://<host>:19090)
#   W623_TOKEN         — bearer-токен (формат файла токена — admin=<...>)
#   W623_KUBECTL       — путь к kubectl
#   W623_NS            — namespace контролей (по умолчанию w623)
#   W623_WINDOW        — длина тихого окна объёма, с (по умолчанию 600)
#   W623_GATE          — гейт волны 6, алертов/ч (по умолчанию 100)
#   W623_GATE_FORMULA  — all | noinfo (решение по №232; по умолчанию all)
#   W623_CHURN_BUDGET  — порог цены старта пода (по умолчанию 45, №236)
#   W623_PROFILE_SECS  — длина окна pprof (по умолчанию 30, №244)
#   W623_SMOKE         — 1: смок-режим, все ветки исполняются на коротких
#                        временах; длинные ожидания укорочены, НИ ОДИН блок
#                        не пропускается (память smoke-only-does-not-cover-attack-window)
set -u
export TZ=UTC   # см. _w623_epoch/_w623_utc: встроенный printf вместо внешнего `date`

VPS_IP="${VPS_IP:-localhost}"
W623_API="${W623_API:-http://${VPS_IP}:19090}"
W623_TOKEN="${W623_TOKEN:-${EBPF_GUARD_TOKEN:-$(grep '^admin=' /var/lib/ebpf-guard/token 2>/dev/null | cut -d= -f2)}}"
W623_KUBECTL="${W623_KUBECTL:-/usr/local/bin/kubectl}"
W623_NS="${W623_NS:-w623}"
W623_WINDOW="${W623_WINDOW:-600}"
W623_GATE="${W623_GATE:-100}"
W623_GATE_FORMULA="${W623_GATE_FORMULA:-all}"
W623_CHURN_BUDGET="${W623_CHURN_BUDGET:-45}"
W623_PROFILE_SECS="${W623_PROFILE_SECS:-30}"
W623_SETUP="${W623_SETUP:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
W623_SETTLE="${W623_SETTLE:-20}"
W623_POS_TIMEOUT="${W623_POS_TIMEOUT:-120}"
W623_CHURN="${W623_CHURN:-3}"
W623_SVC="${W623_SVC:-ebpf-guard-test.service}"
W623_VERDICTS="${W623_VERDICTS:-/root/wave6.2.3-controls-verdicts.txt}"
# КАТАЛОГ АРТЕФАКТОВ — ВНЕ /root/, и это не вкусовщина, а вторая половина
# критерия 6.2.3.3 (открытый вопрос 16). drift_new_file_dir_sensitive стоит на
# префиксах /root/, /home/, /var/spool/cron/, /etc/cron.d/, /etc/systemd/system/
# (rules/drift-rules.txt), то есть КАЖДАЯ запись снимка метрик в /root/… по
# построению производит алерт, который контроль потом считает частью
# измеренной величины. Смок 06.09.2026 это и напечатал. Порядок операций
# (правка №242) сужает окно гонки, но не убирает источник; убирает его путь.
# /var/lib/ вне всех файловых префиксов правил (проверено grep по rules/:
# waagent/tomcat/mysql/…/docker/containerd/rancher/kubelet — ни один не наш).
W623_ART="${W623_ART:-/var/lib/w623-artifacts}"
W623_REPO="${W623_REPO:-/opt/ebpf-guard}"
W623_GO="${W623_GO:-/usr/local/go/bin/go}"
W623_SMOKE="${W623_SMOKE:-0}"
W623_QUIET_LEAD="${W623_QUIET_LEAD:-70}"
W623_OPEN_SETTLE="${W623_OPEN_SETTLE:-15}"

WAVE623_FAILS=0
# Артефакты пишутся в КАТАЛОГ ЭТОГО ПРОГОНА и он очищается на старте
# (находка №228).
rm -rf "$W623_ART" 2>/dev/null || true
mkdir -p "$W623_ART" 2>/dev/null || true

# №252: HOME контроля — В КАТАЛОГЕ АРТЕФАКТОВ, не /root. Каждый curl/kubectl/
# jq, запущенный из-под этого скрипта под root, пишет свой конфиг/кеш в
# $HOME (.curlrc читается curl, .kube/cache — kubectl, .cache/go-build — go
# tool pprof в критерии 6.2.3.8); при HOME=/root это ровно тот путь, за
# которым следит drift_new_file_dir_sensitive (rules/drift-rules.txt,
# префикс /root/), и запись в него сама производит алерт, входящий в
# измеренную величину. Экспортируется ДО первого curl/kubectl этого файла.
export HOME="$W623_ART"
mkdir -p "$HOME" 2>/dev/null || true

die() {
    echo "=== КОНТРОЛЬ ПРОВАЛЕН (прогон НЕ прерывается — волна 6.0m): $* ==="
    WAVE623_FAILS=$((WAVE623_FAILS + 1))
    {
        echo "критерий=$(printf '%s' "$*" | grep -oE '6\.2\.[123]\.[A-Za-z0-9]+' | head -1)"
        echo "время_UTC=$(date -u +%FT%TZ)"
        echo "причина: $*"
        echo "---"
    } >> "$W623_VERDICTS" 2>/dev/null || true
    return 0
}
pass() { echo "OK: $*"; }

: > "$W623_VERDICTS" 2>/dev/null || true
echo "# wave6.2.3-controls.sh, прогон от $(date -u +%FT%TZ)" >> "$W623_VERDICTS"
echo "=== КОНТРОЛИ ВОЛНЫ 6.2.3 (долг прогона 6.2.2, находки №246…№252) ==="
echo "режим: $([ "$W623_SMOKE" = "1" ] && echo 'СМОК (короткие времена, все ветки исполняются)' || echo 'полный')"
echo "формула гейта (решение 1, №232/№248): $W623_GATE_FORMULA (all = включая severity=info, noinfo = без него; обе величины и величина (в) печатаются в любом случае)"
echo "HOME контроля (№252): $HOME"

# ─────────────────────────────────────────────────────────────────────────────
# ИЗМЕРИТЕЛЬНАЯ БИБЛИОТЕКА (№238/№239). Берётся source'ом, а не копией: у
# копии нет офлайн-сторожа, а у этого файла он есть и проходит на
# collect-6.2.1 (--self-test). Отсутствие библиотеки — не «работаем без
# разбивки», а неизмеримость критериев 6.2.2.2/6.2.2.3.
# ─────────────────────────────────────────────────────────────────────────────
W623_LIB="$W623_SETUP/wave6.2.3-metrics-lib.sh"
W623_LIB_OK=0
if [ -r "$W623_LIB" ]; then
    # shellcheck source=/dev/null
    . "$W623_LIB" && W623_LIB_OK=1
fi
# ВОССТАНОВЛЕНИЕ РЕЖИМА ОБОЛОЧКИ — не косметика, а дефект, пойманный смоком
# 06.09.2026 ДО прогона. wave6.2.3-metrics-lib.sh объявляет `set -euo pipefail`
# (правильно для самостоятельного файла со своим --self-test), но `source`
# переносит этот режим В ВЫЗЫВАЮЩИЙ скрипт. Контроли построены на том, что
# `grep`/`jq` без совпадения возвращают 1 и это НОРМАЛЬНЫЙ исход измерения
# («такого в журнале нет»), а не сбой: под `set -e` первый же такой grep убивал
# контроли МОЛЧА, посреди 6.2.1.6, и пайплайн спокойно собирал архив без
# единого критерия. Ровно тот класс, который ловит сама волна: измеритель,
# печатающий готовый вердикт по неполному прогону.
set +e +o pipefail
set -u
[ "$W623_LIB_OK" -eq 1 ] || die "6.2.2.2 НЕИЗМЕРИМ: не подключилась $W623_LIB — список срезанных правил и разбивка величины строились бы снова по стору, то есть воспроизвели бы дефекты №238/№239"

# Правила, для которых нода — единственный вход.
W623_K8S_RULES="cis_5_1_3_secret_access k8s_sa_token_read k8s_sa_token_projected_read k8s_hostpath_kubelet_access"
W623_HOST_RULES="cis_5_1_3_secret_access k8s_hostpath_kubelet_access"
W623_NODE_ACTORS="k3s-server kubelet containerd containerd-shim containerd-shim-runc-v2 runc runc:[1:CHILD] runc:[2:INIT] coredns local-path-prov kube-proxy pause iptables ip6tables kubectl flannel bridge loopback"

# ---------------------------------------------------------------------------
# №252: список comm ИЗМЕРИТЕЛЯ строится САМОСКАНИРОВАНИЕМ этого файла, а не
# задаётся руками. Находка №242 чинилась вручную дописанным cat/tail; находка
# №252 требует, чтобы список впредь не отставал от того, что скрипт реально
# запускает — кандидаты, найденные как отдельное слово (после пробела,
# `;`, `&`, `|`, `(` или `/`) где-то в тексте ЭТОГО файла, ВКЛЮЧАЮТСЯ
# автоматически. Список кандидатов конечен (это самоскан по словарю, а не
# полный статический анализ), но покрывает всё, чем контроль реально
# пользуется: sleep/setsid/sh/dd обязаны быть найдены — это явное требование
# критерия 6.2.3.3, и его отсутствие есть ПРОВАЛ преflight'а, а не тихая
# недостача.
# ---------------------------------------------------------------------------
W623_INSTR_CANDIDATES="curl jq bash sh head sed awk date tr sort systemctl journalctl cat tail stat find wc cut grep sleep setsid dd printf cp chmod mkdir rm seq pgrep readlink kubectl go"
W623_INSTR_COMMS_FLAT=""
W623_SELF="$W623_SETUP/wave6.2.3-controls.sh"
if [ -r "$W623_SELF" ]; then
    # Скан ИСПОЛНЯЕМОГО текста: строки-комментарии (включая эту преамбулу и
    # саму строку W623_INSTR_CANDIDATES, где перечислены ВСЕ кандидаты разом
    # и потому она тривиально "находит" каждый) вычищены — иначе самоскан
    # находит слово в СВОЁМ ЖЕ описании, а не в реальном вызове.
    _w623_selfcode=$(grep -vE '^[[:space:]]*#' "$W623_SELF" | grep -v '^W623_INSTR_CANDIDATES=')
    for _w623_c in $W623_INSTR_CANDIDATES; do
        if printf '%s\n' "$_w623_selfcode" | grep -qE "(^|[[:space:];&|(/])${_w623_c}([[:space:]\"'\`]|\$)" 2>/dev/null; then
            W623_INSTR_COMMS_FLAT="$W623_INSTR_COMMS_FLAT $_w623_c"
        fi
    done
fi
W623_INSTR_COMMS_FLAT="${W623_INSTR_COMMS_FLAT# }"
echo "  №252, список comm измерителя (самосканирование $W623_SELF): ${W623_INSTR_COMMS_FLAT:-ПУСТ}"
# ТРЕБОВАНИЕ КРИТЕРИЯ 6.2.3.3 (postановка): sleep/setsid/sh/dd обязаны
# присутствовать в списке. `dd` требуется здесь начиная с item 3 (6.2.3.5,
# №249, механизм немоты op=write — нагрузка `dd of=…`) — реальный вызов
# теперь есть в файле, страж больше не отложен.
for _w623_must in sleep setsid sh dd; do
    case " $W623_INSTR_COMMS_FLAT " in
        *" $_w623_must "*) ;;
        *) die "6.2.3.3 НЕИЗМЕРИМ: самоскан не нашёл '$_w623_must' в тексте $W623_SELF — обязательная команда списка (№252) не обнаружена; список comm измерителя неполон по построению" ;;
    esac
done
# Та же плоская строка — как JSON-массив, для jq (критерий 6.2.3.3).
W623_INSTR_COMMS=$(printf '%s\n' $W623_INSTR_COMMS_FLAT | jq -R . | jq -s -c . 2>/dev/null)
[ -n "${W623_INSTR_COMMS:-}" ] && [ "$W623_INSTR_COMMS" != "null" ] || W623_INSTR_COMMS='[]'

_w623_curl() { curl -s --max-time 30 -H "Authorization: Bearer $W623_TOKEN" "$@"; }
_w623_alerts() { _w623_curl "$W623_API/api/v1/alerts?limit=200000"; }
_w623_metrics() { _w623_curl "$W623_API/metrics"; }
# ЭПОХА — ВСТРОЕННЫМ printf, а не `date`. Каждый вызов внешнего `date` —
# это execve, а значит собственное событие измерителя: на прогоне 06.09.2026
# критерий 6.2.3.3 упал ровно на двух алертах comm=date, которые породил сам
# контроль строкой «окно открыто …» СРАЗУ ПОСЛЕ фиксации t0. Встроенный
# printf процесса не создаёт вовсе, поэтому источник исчезает, а не сдвигается.
# TZ=UTC экспортирован выше — форматы ниже эквивалентны `date -u`.
_w623_epoch() { local _e; printf -v _e '%(%s)T' -1; printf '%s' "$_e"; }
_w623_utc() { printf '%(%Y-%m-%dT%H:%M:%SZ)T' "$1"; }

# Сумма метрики по срезу. Прямая дельта двух срезов, а не строка таблицы:
# строка индексирована срезом лимитера (память f6b-table-indexed-by-limiter-cut).
_w623_metric_sum() { # $1=metric $2=список rule_id (пусто = все) [$3=файл среза]
    local metric="$1" ids="${2:-}" src="${3:-}"
    { [ -n "$src" ] && cat "$src" || _w623_metrics; } | awk -v m="$metric" -v ids="$ids" '
        BEGIN { n = split(ids, a, " ") }
        $0 ~ "^"m"[{ ]" {
            if (n == 0) { s += $NF; next }
            for (i = 1; i <= n; i++) if (index($0, "rule_id=\"" a[i] "\"")) { s += $NF; next }
        }
        END { printf "%d", s+0 }'
}
# Скалярная метрика без лейблов (process_*, go_*): $NF может быть в
# экспоненциальной записи (1.37413104e+08), поэтому печатается через %.0f.
_w623_metric_raw() { # $1=metric $2=файл среза
    awk -v m="$1" '$1 == m { printf "%.0f", $2+0; found=1; exit } END { if (!found) printf "" }' "$2" 2>/dev/null
}

# ---------------------------------------------------------------------------
# ОБЪЁМ И РЕШЕНИЕ №232.
#
# Формула 6.2.1 (№227) — alerts_total + alerts_filtered_total по всем
# severity. Находка №230 показала, что 94% величины прошлого прогона это
# severity=info, которого нет в сторе; №232 спрашивает владельца, считать ли
# его. Решение зафиксировано ДО прогона и в прогоне не меняется (критерий
# 6.2.3.1), но ОБЕ величины печатаются всегда: разница двух — это цена
# решения №232 числом, а не прогнозом.
#
# Почему вердикт по умолчанию по «all»: filtered_total — это то, что срезано
# min_severity. Формула без info позволяет «починить» шумное правило
# понижением его severity: величина упадёт, а работа агента (regex,
# обогащение, дедуп, кольцевой буфер) останется та же. Гейт перестал бы быть
# гейтом. См. plan.md, №232.
# ---------------------------------------------------------------------------
_w623_volume_all() { # $1=файл среза
    awk '/^ebpf_guard_alerts_total[{ ]/ || /^ebpf_guard_alerts_filtered_total[{ ]/ { s += $NF } END { printf "%d", s+0 }' "$1"
}
_w623_volume_noinfo() { # $1=файл среза
    awk '(/^ebpf_guard_alerts_total[{ ]/ || /^ebpf_guard_alerts_filtered_total[{ ]/) && !/severity="info"/ { s += $NF } END { printf "%d", s+0 }' "$1"
}
_w623_ratelimited() { _w623_metric_sum ebpf_guard_alerts_ratelimited_by_rule_total "${1:-}" "${2:-}"; }
# Потери событий БЕЗ path_denylist (№222): denylist — законный фильтр, а не
# потеря видимости.
_w623_real_drops() { # [$1=файл среза]
    { [ -n "${1:-}" ] && cat "$1" || _w623_metrics; } | awk '
        /^ebpf_guard_events_dropped_total\{/ && !/reason="path_denylist"/ { s += $NF }
        /^ebpf_guard_event_queue_dropped_total/ { s += $NF }
        END { printf "%d", s+0 }'
}
# Журнальный счётчик потерь (№222, второй слой). №240: журнал читается ОТ
# СТАРТА АГЕНТА, а не за всю историю юнита — иначе величина принадлежит
# прошлым прогонам.
_w623_journal_since() {
    if [ -s /root/agent-start-6.2.3.epoch ]; then
        echo "@$(cat /root/agent-start-6.2.3.epoch)"
    else
        systemctl show "$W623_SVC" -p ActiveEnterTimestampMonotonic --value >/dev/null 2>&1
        local t; t=$(systemctl show "$W623_SVC" -p ActiveEnterTimestamp --value 2>/dev/null)
        local e; e=$(date -d "$t" +%s 2>/dev/null)
        [ -n "${e:-}" ] && echo "@$e" || echo "-1 hour"
    fi
}
_w623_journal_drops() {
    journalctl -u "$W623_SVC" --since "$(_w623_journal_since)" --no-pager 2>/dev/null \
        | grep -o '"bulk_dropped_since_start":[0-9]*' | tail -1 | cut -d: -f2
}

# Смок-режим укорачивает ОЖИДАНИЯ, но не выкидывает блоки.
if [ "$W623_SMOKE" = "1" ]; then
    W623_SETTLE=5
    W623_POS_TIMEOUT=30
    W623_QUIET_LEAD=10
    W623_OPEN_SETTLE=5
fi

# ─────────────────────────────────────────────────────────────────────────────
# ПРЕFLIGHT. Провал здесь означает, что величины ниже нечем читать.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.2 преflight ---"
command -v jq >/dev/null 2>&1 || die "6.2.2 преflight ПРОВАЛЕН: нет jq — все величины по стору неизмеримы"

if [ ! -x "$W623_KUBECTL" ]; then
    die "6.2.2 преflight ПРОВАЛЕН: kubectl не найден ($W623_KUBECTL) — ноду нечем подать на вход, любой ноль ниже приборный"
else
    _w623_ready=$("$W623_KUBECTL" get nodes --no-headers 2>/dev/null | awk '$2=="Ready"{n++} END{print n+0}')
    if [ "${_w623_ready:-0}" -lt 1 ]; then
        die "6.2.2 преflight ПРОВАЛЕН: ни одна нода не Ready"
    else
        pass "6.2.2 преflight: нод Ready = $_w623_ready ($("$W623_KUBECTL" version -o json 2>/dev/null | jq -r '.serverVersion.gitVersion // "?"'))"
    fi
fi

_w623_cfg="${W623_CONFIG:-$W623_SETUP/config-test.yaml}"
_w623_k8s_block=$(awk '/^kubernetes:/{f=1;next} f && /^[a-zA-Z#]/{exit} f' "$_w623_cfg" 2>/dev/null)
_w623_drift_cfg=$(awk '/drift_baseline:/{f=1;next} f && /^[a-zA-Z]/{exit} f' "$_w623_cfg" 2>/dev/null)
echo "$_w623_k8s_block" | grep -qE '^[[:space:]]*enabled:[[:space:]]*true[[:space:]]*(#.*)?$' \
    && pass "6.2.2 преflight: kubernetes.enabled: true в $_w623_cfg" \
    || die "6.2.2 преflight ПРОВАЛЕН: kubernetes.enabled НЕ true — энричер не конструируется, pod_name пуст по построению (находка №216)"

# pprof: без него критерий 6.2.3.8 нереализуем в принципе (находка №244:
# enable_pprof по умолчанию false, и config-test.yaml её никогда не включал —
# /debug/pprof/* 404-ил на живом стенде).
grep -qE '^[[:space:]]*enable_pprof:[[:space:]]*true[[:space:]]*(#.*)?$' "$_w623_cfg" 2>/dev/null \
    && pass "6.2.2 преflight: enable_pprof: true — окно профиля 6.2.3.8 реализуемо" \
    || die "6.2.3.8 НЕИЗМЕРИМ: enable_pprof не true в $_w623_cfg — /debug/pprof/* ответит 404, профиль снять нечем (находка №244)"

_w623_src=$(journalctl -u "$W623_SVC" --since "$(_w623_journal_since)" --no-pager 2>/dev/null | grep -o '"msg":"runtime enricher active","source":"[a-z]*"' | tail -1 | grep -oE '"source":"[a-z]*"' | cut -d'"' -f4)
_w623_k8s_up=$(journalctl -u "$W623_SVC" --since "$(_w623_journal_since)" --no-pager 2>/dev/null | grep -c 'k8s enricher active')
echo "  источник runtime-обогащения: ${_w623_src:-НЕ НАПЕЧАТАН}; строк «k8s enricher active»: $_w623_k8s_up"
[ "${_w623_k8s_up:-0}" -ge 1 ] || die "6.2.2 преflight ПРОВАЛЕН: в журнале нет «k8s enricher active» — pod_name будет пуст по причине вне продукта"

# №240, часть 1: журнал вообще читается ОТ СТАРТА АГЕНТА. Прогон 6.2.1 привёз
# journal-agent-6.2.1.log нулевого размера и не заметил этого.
_w623_jsince=$(_w623_journal_since)
_w623_jlines=$(journalctl -u "$W623_SVC" --since "$_w623_jsince" --no-pager 2>/dev/null | wc -l)
echo "  журнал агента с $_w623_jsince: $_w623_jlines строк"
[ "${_w623_jlines:-0}" -ge 1 ] \
    && pass "6.2.2 преflight: journalctl --since «$_w623_jsince» даёт непустой журнал (№240: ISO-8601 «T…Z» systemd.time(7) НЕ разбирает, эпоха — разбирает)" \
    || die "6.2.2.4 ПРОВАЛЕН заранее: journalctl --since «$_w623_jsince» даёт ПУСТО — архив этого прогона будет нереплеиваемым, как collect-6.2.1 (№240)"

# №243, живой сторож. config-test.yaml не задаёт monitored_syscalls, значит
# используется DefaultMonitoredSyscalls() из sampling.go: 19 номеров после
# снятия chmod/fchmod/fchmodat (90/91/268), 22 до него. Число в журнале
# отличает ЗАДЕПЛОЕННУЮ правку от лежащей в дереве.
_w623_ms=$(journalctl -u "$W623_SVC" --since "$_w623_jsince" --no-pager 2>/dev/null \
    | grep -o '"monitored_syscalls":[0-9]*' | tail -1 | cut -d: -f2)
_w623_ms_want=$(awk '/^func DefaultMonitoredSyscalls/,/^}/' "$W623_REPO/internal/bpf/sampling.go" 2>/dev/null | grep -cE '^[[:space:]]+[0-9]+,')
echo "  №243: monitored_syscalls в журнале = ${_w623_ms:-НЕ НАПЕЧАТАН}; в дереве DefaultMonitoredSyscalls() = ${_w623_ms_want:-?}"
if [ -z "${_w623_ms:-}" ]; then
    die "6.2.1.9 (№243) НЕИЗМЕРИМ: строки kernel_filter с monitored_syscalls нет в журнале — задеплоена правка или нет, по этому прогону не установить"
elif [ "${_w623_ms_want:-0}" -gt 0 ] && [ "${_w623_ms:-0}" -ne "${_w623_ms_want:-0}" ]; then
    die "6.2.1.9 (№243) ПРОВАЛЕН: агент поднят на бинаре с ${_w623_ms} syscall'ами, а дерево описывает ${_w623_ms_want}. Правка №243 (снятие chmod с syscall-оси) НЕ задеплоена: chmod по-прежнему даёт второе, никем не читаемое событие, и цена ring buffer в 6.2.3.1 измеряется НЕ на том коде, что лежит в дереве"
else
    pass "6.2.1.9 (№243) ДОСТИГНУТО (половина «деплой»): monitored_syscalls=${_w623_ms} совпадает с деревом — chmod снят с syscall-оси на живом бинаре"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.1.6 РЕГРЕССИЯ: реестр немоты по среде (находка №225), ДО всякого замера.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.1.6 (регрессия): немота по среде ---"
_w623_unreach=$(journalctl -u "$W623_SVC" --since "$_w623_jsince" --no-pager 2>/dev/null | grep -o '"msg":"rules: syscall rules with no reachable nr in the kernel allowlist".*' | tail -1)
_w623_unreach_n=$(printf '%s' "$_w623_unreach" | grep -oE '"count":[0-9]+' | cut -d: -f2)
_w623_unreach_ids=$(printf '%s' "$_w623_unreach" | grep -oE '"rule_ids":\[[^]]*\]' | tr -d '"[]' | sed 's/rule_ids://')
_w623_kmod=$(journalctl -u "$W623_SVC" --since "$_w623_jsince" --no-pager 2>/dev/null | grep -c 'cgroup escape collector unavailable')
echo "  недостижимых syscall-правил: ${_w623_unreach_n:-0}"
echo "  поимённо: ${_w623_unreach_ids:-нет}"
echo "  kmod cgroup-escape коллектор недоступен: $([ "${_w623_kmod:-0}" -gt 0 ] && echo да || echo нет) (ядро $(uname -r))"
# №234/открытый вопрос 7: файловые правила, чей op не производит ни один хук
# сборки, теперь печатаются агентом при старте (UnreachableFileOpRules).
# Это немота ПО ПОСТРОЕНИЮ, и реплей обязан читать её так же, как syscall-ось.
_w623_unreach_f=$(journalctl -u "$W623_SVC" --since "$_w623_jsince" --no-pager 2>/dev/null | grep -o '"msg":"rules: file rules whose op condition names no operation any hook produces".*' | tail -1)
echo "  файловых правил с недостижимым op: ${_w623_unreach_f:-строки нет}"

_w623_registry="$W623_SETUP/attacks/silent-rules.txt"
_w623_reg_ids=$(grep -oE '^[A-Za-z0-9_]+ a$' "$_w623_registry" 2>/dev/null | awk '{print $1}' | sort -u)
_w623_reg_n=$(printf '%s\n' "$_w623_reg_ids" | grep -c .)
_w623_jrn_ids=$(printf '%s' "${_w623_unreach_ids:-}" | tr ',' '\n' | sed '/^$/d' | sort -u)
echo "  реестр (silent-rules.txt, категория а): ${_w623_reg_n} правил"
if [ -z "${_w623_unreach_n:-}" ]; then
    die "6.2.1.6 НЕИЗМЕРИМ: строки о недостижимых правилах нет в журнале — немоту по среде нечем отличить от регресса"
elif [ "$_w623_jrn_ids" != "$_w623_reg_ids" ]; then
    die "6.2.1.6 ПРОВАЛЕН: реестр (${_w623_reg_n} правил) разошёлся со стендом (${_w623_unreach_n} правил: ${_w623_unreach_ids:-нет}) — реплеи архивов этой волны читают расхождение как потерю/регресс"
elif [ "${_w623_kmod:-0}" -gt 0 ] && ! grep -q 'cgroup escape collector unavailable' "$_w623_registry" 2>/dev/null; then
    die "6.2.1.6 ПРОВАЛЕН: kmod cgroup-escape коллектор недоступен на этом ядре, но $_w623_registry не документирует этот факт"
else
    pass "6.2.1.6 ДОСТИГНУТО: реестр немоты по среде совпал со стендом (${_w623_unreach_n} правил + kmod)"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.3.0 ПРИБОРНОСТЬ (первая половина: ось пода).
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.3.0: приборность оси пода ---"
_w623_alerts > "$W623_ART/alerts-preflight.json"
_w623_pod_alerts=$(jq '[.[]|select(((.enrichment.pod_name // "") != "") and ((.enrichment.namespace // "") != ""))]|length' "$W623_ART/alerts-preflight.json" 2>/dev/null || echo 0)
_w623_ns_seen=$(jq -r '.[]|select((.enrichment.namespace // "")!="")|.enrichment.namespace' "$W623_ART/alerts-preflight.json" 2>/dev/null | sort -u | tr '\n' ' ')
echo "  алертов с непустыми namespace И pod_name: $_w623_pod_alerts; namespace'ы: ${_w623_ns_seen:-нет}"
W623_INSTRUMENTED=0
if [ "${_w623_pod_alerts:-0}" -lt 1 ]; then
    die "6.2.3.0 ПРОВАЛЕН: ни одного алерта с личностью пода. Дальше контроли оси пода НЕ ЧИТАЮТСЯ — их ноль был бы приборным"
else
    W623_INSTRUMENTED=1
    pass "6.2.3.0 ДОСТИГНУТО (половина «ось пода»): личность пода доезжает до алерта ($_w623_pod_alerts алертов)"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.3.A ДЛИНА ПРОЛОГА.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.3.A: длина пролога до открытия окна ---"
_w623_lp=$(echo "$_w623_drift_cfg" | grep -oE 'learning_period:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | head -1)
_w623_edp=$(echo "$_w623_drift_cfg" | grep -oE 'enforce_deadline_periods:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | head -1)
_w623_need=$(( ${_w623_lp:-600} * ${_w623_edp:-2} ))
_w623_started=$(systemctl show "$W623_SVC" -p ActiveEnterTimestamp --value 2>/dev/null)
_w623_started_s=$(date -d "$_w623_started" +%s 2>/dev/null || echo 0)
_w623_prologue=$(( $(date +%s) - _w623_started_s ))
echo "  агент поднят: ${_w623_started:-?}; пролог: ${_w623_prologue}s; требуется > ${_w623_need}s"
echo "  на этот момент: профилей $(_w623_metric_sum ebpf_guard_drift_baseline_profiles ""), из них в learning $(_w623_metric_sum ebpf_guard_drift_baseline_learning_workloads "")"
if [ "$_w623_started_s" -eq 0 ]; then
    die "6.2.3.A НЕИЗМЕРИМ: время старта сервиса не прочитано"
elif [ "$_w623_prologue" -le "$_w623_need" ]; then
    die "6.2.3.A ПРОВАЛЕН: пролог ${_w623_prologue}s не длиннее ${_w623_need}s — окно ниже меряет ОБУЧЕНИЕ, а не линию"
else
    pass "6.2.3.A ДОСТИГНУТО: пролог ${_w623_prologue}s > ${_w623_need}s"
fi

# ─────────────────────────────────────────────────────────────────────────────
# ТИХОЕ ОКНО ОБЪЁМА. Вход НЕ подаётся.
#
# №242, часть 2: t0 фиксируется ПОСЛЕДНИМ действием предоткрывающей
# последовательности. Каждый curl/journalctl этой последовательности — сам
# источник алертов (чтение /etc/passwd через NSS, чтение /var/log/journal);
# в 6.2.1 они стояли ПОСЛЕ фиксации t0 и потому падали внутрь окна
# (curl:3 journalctl:3 в вердикте архива). Закрытие окна такого дефекта не
# имело изначально — там t1 берётся первым; здесь открытие сделано
# симметрично закрытию.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.3.1/6.2.3.2/6.2.2.2/6.2.2.3/6.2.3.3/6.2.3.9: тихое окно ${W623_WINDOW}s ---"
_w623_drift_print() {
    echo "  дрейф[$1]: $(awk '/^ebpf_guard_drift_baseline_(profiles|learning_workloads|stuck_learning_workloads|learning_overdue_workloads|saturated_profiles|evictions_total|frozen_workloads|signature_cap_reached_total) /{printf "%s=%s ", $1, $2}' "$2")"
}
echo "  тишина перед открытием окна: ${W623_QUIET_LEAD}s (шум собственных curl'ов преflight'а уходит за границу t0)"
sleep "$W623_QUIET_LEAD"
_w623_metrics > "$W623_ART/metrics-window-start.txt"
_w623_jdrops0=$(_w623_journal_drops)
_w623_drift_print "открытие" "$W623_ART/metrics-window-start.txt"
# ОСЕДАНИЕ ПЕРЕД ФИКСАЦИЕЙ t0 (открытый вопрос 16, вторая половина). Перенос
# t0 в конец последовательности (правка №242) убирает СЕКУНДЫ выполнения
# curl/journalctl из окна, но не убирает задержку конвейера: событие
# предоткрывающего curl'а проходит ring buffer → корреляцию → стор уже после
# того, как команда вернулась, и его метка времени может лечь ПОСЛЕ t0.
# Смок 06.09.2026 напечатал ровно это (curl:1 внутри окна при верном
# порядке). Пауза даёт конвейеру осесть; величина взята с запасом от
# наблюдённой латентности (91–183 мкс на событие, но стор пишется пачками).
sleep "$W623_OPEN_SETTLE"
_w623_t0=$(_w623_epoch)
echo "  окно открыто $(_w623_utc "$_w623_t0") — до закрытия НЕ ПОДАВАТЬ вход (память ebpf-guard-measurement-hygiene, п.2/п.5)"
sleep "$W623_WINDOW"
_w623_t1=$(_w623_epoch)
_w623_metrics > "$W623_ART/metrics-window-end.txt"
_w623_jdrops1=$(_w623_journal_drops)
_w623_drift_print "закрытие" "$W623_ART/metrics-window-end.txt"
_w623_alerts > "$W623_ART/alerts-window-end.json"
# №240/открытый вопрос 14: границы окна выносятся наружу файлом-мостом —
# пайплайну нечем иначе проверить, что журнал ПОКРЫВАЕТ окно (критерий
# 6.2.2.4), потому что эпохи считаются здесь и наружу не возвращаются.
printf 't0=%s\nt1=%s\n' "$_w623_t0" "$_w623_t1" > "$W623_ART/window-epoch.txt"

# ---- 6.2.3.0, вторая половина: потери событий за окно (№222) ----
_w623_dr0=$(_w623_real_drops "$W623_ART/metrics-window-start.txt")
_w623_dr1=$(_w623_real_drops "$W623_ART/metrics-window-end.txt")
_w623_dr=$(( _w623_dr1 - _w623_dr0 ))
_w623_jdr=$(( ${_w623_jdrops1:-0} - ${_w623_jdrops0:-0} ))
echo "  потери событий за окно: метрика (без path_denylist) = $_w623_dr; журнал bulk_dropped = $_w623_jdr"
if [ "$_w623_dr" -gt 0 ] || [ "$_w623_jdr" -gt 0 ]; then
    die "6.2.3.0 ПРОВАЛЕН (половина «потери»): за окно потеряно событий — метрика $_w623_dr, журнал $_w623_jdr. Величина 6.2.3.1 срезана ПОТЕРЕЙ, а не только лимитером (находка №222). Окно НЕИЗМЕРИМО"
elif [ "$_w623_jdr" -eq 0 ] && [ "$_w623_dr" -eq 0 ]; then
    pass "6.2.3.0 ДОСТИГНУТО (половина «потери»): за окно ни метрика, ни журнал не показали потерь"
fi
if { [ "$_w623_jdr" -gt 0 ] && [ "$_w623_dr" -eq 0 ]; } || { [ "$_w623_dr" -gt 0 ] && [ "$_w623_jdr" -eq 0 ]; }; then
    die "6.2.3.0 ПРОВАЛЕН (сверка прибора): журнал говорит $_w623_jdr потерь, метрика — $_w623_dr. Потеря видимости молчалива в метриках (второй слой находки №222)"
fi

# ---- 6.2.3.1: объём ПРЯМОЙ ДЕЛЬТОЙ ДВУХ МЕТРИК, обе формулы (№227/№232),
#      плюс ВСЕ ЧЕТЫРЕ СЛОЯ и величина (в) — решение 1, №248 ----
_w623_alerts_total_d=$(_w623_metric_sum ebpf_guard_alerts_total "" "$W623_ART/metrics-window-end.txt")
_w623_alerts_total_s=$(_w623_metric_sum ebpf_guard_alerts_total "" "$W623_ART/metrics-window-start.txt")
_w623_filtered_d=$(_w623_metric_sum ebpf_guard_alerts_filtered_total "" "$W623_ART/metrics-window-end.txt")
_w623_filtered_s=$(_w623_metric_sum ebpf_guard_alerts_filtered_total "" "$W623_ART/metrics-window-start.txt")
_w623_layer_total=$(( _w623_alerts_total_d - _w623_alerts_total_s ))
_w623_layer_filtered=$(( _w623_filtered_d - _w623_filtered_s ))
_w623_vol_all=$(( $(_w623_volume_all "$W623_ART/metrics-window-end.txt") - $(_w623_volume_all "$W623_ART/metrics-window-start.txt") ))
_w623_vol_ni=$(( $(_w623_volume_noinfo "$W623_ART/metrics-window-end.txt") - $(_w623_volume_noinfo "$W623_ART/metrics-window-start.txt") ))
_w623_rl0=$(_w623_ratelimited "" "$W623_ART/metrics-window-start.txt")
_w623_rl1=$(_w623_ratelimited "" "$W623_ART/metrics-window-end.txt")
_w623_rl=$(( _w623_rl1 - _w623_rl0 ))
# Четвёртый слой (решение 3): дедуп остаётся механизмом ДОСТАВКИ, в величину
# гейта (а) не входит, но обязателен в (в) — числа №248 показали, что это
# самая устойчивая величина всего прогона (5702/5696 на двух окнах).
_w623_dd0=$(_w623_metric_sum ebpf_guard_alerts_dedup_dropped_total "" "$W623_ART/metrics-window-start.txt")
_w623_dd1=$(_w623_metric_sum ebpf_guard_alerts_dedup_dropped_total "" "$W623_ART/metrics-window-end.txt")
_w623_dd=$(( _w623_dd1 - _w623_dd0 ))
_w623_hour() { awk -v n="$1" -v w="$W623_WINDOW" 'BEGIN{printf "%.0f", n*3600.0/w}'; }
_w623_all_hour=$(_w623_hour "$_w623_vol_all")
_w623_ni_hour=$(_w623_hour "$_w623_vol_ni")
echo "  слой 1 alerts_total (Δ):             $_w623_layer_total"
echo "  слой 2 alerts_filtered_total (Δ):    $_w623_layer_filtered"
echo "  слой 3 alerts_ratelimited_by_rule (Δ): $_w623_rl"
echo "  слой 4 alerts_dedup_dropped (Δ):     $_w623_dd"
echo "  объём ВСЁ, формула (а) = слой1+слой2:        $_w623_vol_all → $_w623_all_hour/ч"
echo "  объём БЕЗ info, формула (б, ОТВЕРГНУТА реш.1): $_w623_vol_ni → $_w623_ni_hour/ч"
echo "  цена решения №232 числом:      $(( _w623_vol_all - _w623_vol_ni )) алертов severity=info за окно"
if [ "$W623_GATE_FORMULA" = "noinfo" ]; then
    _w623_vol=$_w623_vol_ni; _w623_vol_hour=$_w623_ni_hour
else
    _w623_vol=$_w623_vol_all; _w623_vol_hour=$_w623_all_hour
fi
_w623_true_hour=$(_w623_hour "$(( _w623_vol + _w623_rl ))")
# Величина (в) — решение 1: сумма ВСЕХ четырёх слоёв, порог НЕ назначается
# (правило 5.9.6 — впервые измеренной величине порог не даётся). Печатается
# ОБЯЗАТЕЛЬНО и всегда, вне зависимости от того, взят ли критерий 6.2.3.1.
_w623_v_total=$(( _w623_layer_total + _w623_layer_filtered + _w623_rl + _w623_dd ))
_w623_v_hour=$(_w623_hour "$_w623_v_total")
echo "  ← ВЕЛИЧИНА КРИТЕРИЯ 6.2.3.1 (формула $W623_GATE_FORMULA): $_w623_vol_hour/ч при гейте ${W623_GATE}/ч"
echo "  срез лимитера за окно (alerts_ratelimited_by_rule_total): $_w623_rl"
echo "  нижняя оценка РЕАЛЬНОГО числа срабатываний (а+срез лимитера): $(( _w623_vol + _w623_rl )) → $_w623_true_hour/ч"
echo "  ← ВЕЛИЧИНА (в) [решение 1, №248, БЕЗ ПОРОГА]: слой1+слой2+слой3+слой4 = $_w623_v_total → ${_w623_v_hour}/ч"

# ---- 6.2.2.2: список срезанных правил ПО МЕТРИКЕ (№238) ----
echo "--- 6.2.2.2: правила со срезом лимитера за окно (по метрике, не по стору) ---"
_w623_rl_list=""
if [ "$W623_LIB_OK" -eq 1 ]; then
    _w623_rl_list=$(w623_ratelimited_by_rule "$W623_ART/metrics-window-start.txt" "$W623_ART/metrics-window-end.txt")
    printf '%s\n' "${_w623_rl_list:-  (ни одно правило не срезано)}" | sed 's/^/    /'
    printf '%s\n' "$_w623_rl_list" > "$W623_ART/ratelimited-by-rule.txt"
fi
_w623_rl_n=$(printf '%s' "$_w623_rl_list" | grep -c . )
if [ "$W623_LIB_OK" -ne 1 ]; then
    die "6.2.2.2 НЕИЗМЕРИМ: библиотека не подключилась (см. преflight)"
elif [ "$_w623_rl" -gt 0 ] && [ "${_w623_rl_n:-0}" -eq 0 ]; then
    die "6.2.2.2 ПРОВАЛЕН (дефект ИЗМЕРИТЕЛЯ, не продукта): сумма среза лимитера за окно = $_w623_rl, а поимённый список ПУСТ. Это ровно находка №238: «нет срезанных» при ненулевом срезе означает, что цикл не видел правил, а не что их нет"
elif [ "$_w623_rl" -eq 0 ] && [ "${_w623_rl_n:-0}" -eq 0 ]; then
    pass "6.2.2.2 ДОСТИГНУТО: срез лимитера за окно нулевой, и поимённый список пуст согласованно (сумма 0 = список пуст)"
else
    pass "6.2.2.2 ДОСТИГНУТО: $_w623_rl_n правил со срезом напечатаны поимённо при сумме среза $_w623_rl (6.2.1 печатала «нет» при срезе +530)"
fi

# ---- 6.2.2.3: разбивка величины покрывает её саму (№239) ----
echo "--- 6.2.2.3: разбивка величины по правилам (по метрике) ---"
if [ "$W623_LIB_OK" -eq 1 ]; then
    w623_volume_by_rule "$W623_ART/metrics-window-start.txt" "$W623_ART/metrics-window-end.txt" > "$W623_ART/volume-by-rule.txt"
    head -20 "$W623_ART/volume-by-rule.txt" | sed 's/^/    /'
    _w623_sum=$(awk '{s+=$2} END{printf "%d", s+0}' "$W623_ART/volume-by-rule.txt")
    echo "  прямая дельта объёма (формула all): $_w623_vol_all; сумма разбивки: $_w623_sum"
    if [ "$_w623_vol_all" -le 0 ]; then
        die "6.2.2.3 НЕИЗМЕРИМ: прямая дельта объёма за окно не положительна ($_w623_vol_all) — покрытие считать не от чего"
    else
        _w623_cov=$(awk -v s="$_w623_sum" -v v="$_w623_vol_all" 'BEGIN{printf "%.1f", 100.0*s/v}')
        echo "  покрытие разбивки: ${_w623_cov}% (требуется ≥ 95%; версия 6.2.1 давала 4.3%)"
        if awk -v s="$_w623_sum" -v v="$_w623_vol_all" 'BEGIN{exit !(s >= 0.95*v)}'; then
            pass "6.2.2.3 ДОСТИГНУТО: разбивка покрывает ${_w623_cov}% величины — это законный вход для сужения"
        else
            die "6.2.2.3 ПРОВАЛЕН: разбивка покрывает лишь ${_w623_cov}% величины ($_w623_sum из $_w623_vol_all). Сужение по такой разбивке — работа вслепую (находка №239), правки на её основании запрещены"
        fi
    fi
else
    die "6.2.2.3 НЕИЗМЕРИМ: библиотека не подключилась"
fi

# Сторовая разбивка по comm — СПРАВОЧНО. Ни у alerts_total, ни у
# alerts_filtered_total нет лейбла comm, метрикой эту ось не восстановить.
_w623_new=$(jq --argjson t0 "$_w623_t0" --argjson t1 "$_w623_t1" --arg actors "$W623_NODE_ACTORS" '
    [ .[] | select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t0) and ((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) <= $t1))
      | select(((.enrichment.namespace // "") != "") or ((.comm) as $c | ($actors|split(" "))|index($c))) ]
    ' "$W623_ART/alerts-window-end.json" 2>/dev/null)
echo "  (справочно, сторовый счёт нодовых алертов окна: $(echo "${_w623_new:-[]}" | jq 'length' 2>/dev/null) — вердикта не выносит, находки №227/№239)"
echo "  разбивка по comm (стор, справочно — метрикой эта ось не восстановима):"
echo "${_w623_new:-[]}" | jq -r 'group_by(.comm)|map({c:.[0].comm,n:length})|sort_by(-.n)[]|"    \(.c): \(.n)"' 2>/dev/null | head -15

# ---------------------------------------------------------------------------
# 6.2.3.2: РАЗБИВКА РАНЖИРУЕТ ПО (в), А НЕ ПО ОСТАТКУ ПОСЛЕ ЛИМИТЕРА (№248).
#
# 6.2.2.3 выше ранжирует то, что ДОЕХАЛО до alerts_total/alerts_filtered_total
# (формула (а)) — и это подменяет собой настоящую верхушку шума, потому что
# правила, упёршиеся в лимитер (10/60с) и дедуп, показывают в (а) только
# ОСТАТОК. w623_value_v_by_rule (wave6.2.3-metrics-lib.sh) складывает ТРИ
# компонента на каждый rule_id — (а)-разбивку, срез лимитера, срез дедупа —
# и ранжирует по их сумме. Офлайн-сторож (--self-test на ОБОИХ архивах
# 6.2.2) проверяет, что первыми встают sigma_failed_login_syscall_daemon и
# rootkit_pam_module_added_daemon, а не c2_periodic_beacon_pattern.
# ---------------------------------------------------------------------------
echo "--- 6.2.3.2: разбивка по (в) — полная сумма совпадений правил (№248) ---"
if [ "$W623_LIB_OK" -eq 1 ]; then
    w623_value_v_by_rule "$W623_ART/metrics-window-start.txt" "$W623_ART/metrics-window-end.txt" > "$W623_ART/value-v-by-rule.txt"
    head -20 "$W623_ART/value-v-by-rule.txt" | sed 's/^/    /'
    _w623_v_sum=$(awk '{s+=$2} END{printf "%d", s+0}' "$W623_ART/value-v-by-rule.txt")
    _w623_v_top=$(head -1 "$W623_ART/value-v-by-rule.txt" | awk '{print $1}')
    echo "  прямая величина (в) за окно: $_w623_v_total; сумма разбивки по (в): $_w623_v_sum; вершина: ${_w623_v_top:-нет}"
    if [ "$_w623_v_total" -le 0 ]; then
        die "6.2.3.2 НЕИЗМЕРИМ: величина (в) за окно не положительна ($_w623_v_total) — ранжировать нечего"
    else
        _w623_v_cov=$(awk -v s="$_w623_v_sum" -v v="$_w623_v_total" 'BEGIN{printf "%.1f", 100.0*s/v}')
        echo "  покрытие разбивки по (в): ${_w623_v_cov}% (требуется ≥ 95%)"
        if awk -v s="$_w623_v_sum" -v v="$_w623_v_total" 'BEGIN{exit !(s >= 0.95*v)}'; then
            pass "6.2.3.2 ДОСТИГНУТО: разбивка по (в) покрывает ${_w623_v_cov}% величины (вершина: ${_w623_v_top:-нет}) — законный вход для сужения верхушки шума (item 4 постановки, ещё не сделан)"
        else
            die "6.2.3.2 ПРОВАЛЕН: разбивка по (в) покрывает лишь ${_w623_v_cov}% величины ($_w623_v_sum из $_w623_v_total)"
        fi
    fi
else
    die "6.2.3.2 НЕИЗМЕРИМ: библиотека не подключилась"
fi

# ---- 6.2.3.3: доля измерителя в окне = 0 (№242) ----
echo "--- 6.2.3.3: доля измерителя внутри окна (ВЕРДИКТ, а не поправка) ---"
_w623_instr=$(jq --argjson t0 "$_w623_t0" --argjson t1 "$_w623_t1" --argjson comms "$W623_INSTR_COMMS" '
    [ .[] | select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t0) and ((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) <= $t1))
      | select((.comm) as $c | ($comms|index($c))) ]
    | group_by(.comm)|map({c:.[0].comm,n:length})|sort_by(-.n)' "$W623_ART/alerts-window-end.json" 2>/dev/null)
_w623_instr_n=$(echo "${_w623_instr:-[]}" | jq '[.[].n]|add // 0' 2>/dev/null)
# Вторая половина критерия: алерты НА ПУТИ артефактов контроля. Файл
# metrics-window-start.txt создаётся в каталоге, за которым следит
# drift_new_file_dir_sensitive; правка №242 переносит запись ДО t0, но
# остаточная гонка (задержка ring buffer) аналитически не закрывается —
# открытый вопрос 16 требует проверить это ЖИВЫМ прогоном, здесь и сейчас.
_w623_artpath=$(jq --argjson t0 "$_w623_t0" --argjson t1 "$_w623_t1" --arg art "$W623_ART" '
    [ .[] | select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t0) and ((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) <= $t1))
      | select((.details["file.path"] // "") | startswith($art)) ] | length' "$W623_ART/alerts-window-end.json" 2>/dev/null)
echo "  алертов от comm измерителя внутри [t0,t1]: ${_w623_instr_n:-0} $(echo "${_w623_instr:-[]}" | jq -r 'map("\(.c):\(.n)")|join(" ")' 2>/dev/null)"
echo "  алертов на пути артефактов ($W623_ART) внутри [t0,t1]: ${_w623_artpath:-0}"
if [ "${_w623_instr_n:-0}" -eq 0 ] && [ "${_w623_artpath:-0}" -eq 0 ]; then
    pass "6.2.3.3 ДОСТИГНУТО: измеритель внутри окна не работал — ни одного его алерта, ни одного алерта на пути его артефактов (открытый вопрос 16 закрыт живым прогоном)"
else
    die "6.2.3.3 ПРОВАЛЕН: внутри окна ${_w623_instr_n:-0} алертов от comm измерителя и ${_w623_artpath:-0} на пути его артефактов. Это ЧАСТЬ измеренной величины 6.2.3.1, а не поправка к её чтению: контроль обязан не работать внутри окна вовсе (находка №242). Если ненулевая половина — путь артефактов, починка не в порядке операций, а в переносе снимков ВНЕ поддерева, за которым следит drift_new_file_dir_sensitive (открытый вопрос 16)"
fi

# ---- Вердикт 6.2.3.1. Порядок проверок: срез может только ЗАНИЗИТЬ, поэтому
#      превышение порога доказано и при срезе. «Неизмеримо» остаётся для
#      случая «порог не перешли, но прибор упёрт» (пункт Е). ----
if [ "$_w623_vol_hour" -gt "$W623_GATE" ]; then
    die "6.2.3.1 ПРОВАЛЕН (величина — НИЖНЯЯ оценка): цена ноды $_w623_vol_hour алертов/ч (формула $W623_GATE_FORMULA) при гейте волны 6 «не выше ${W623_GATE}/ч»; величина (в, без порога) — ${_w623_v_hour}/ч. Разбивка 6.2.3.2 (по в) — вход для сужения, а не повод понизить порог"
elif [ "${_w623_rl_n:-0}" -gt 0 ]; then
    die "6.2.3.1 НЕИЗМЕРИМ ПО БУКВЕ (СТРАЖ ЛОЖНОГО PASS, решение 1): величина (а) $_w623_vol_hour/ч порог не перешла, но $_w623_rl_n правил имеют НЕНУЛЕВОЙ срез лимитера за окно (список выше) — это признак упёршегося прибора, и «PASS по (а) при непустом списке срезанных правил» есть НЕИЗМЕРИМОСТЬ, а не взятый критерий. Величина (в, без порога, полная сумма четырёх слоёв) — ${_w623_v_hour}/ч"
else
    pass "6.2.3.1 ДОСТИГНУТО: цена ноды (формула а) $_w623_vol_hour алертов/ч ≤ ${W623_GATE}/ч (формула $W623_GATE_FORMULA), ни одно правило не срезано лимитером за окно — страж ложного PASS чист. Величина (в, без порога) — ${_w623_v_hour}/ч"
fi

# ---- 6.2.3.9: потолок ресурсов против лимита чарта (№244) ----
echo "--- 6.2.3.9: ресурсы агента на открытии и закрытии окна против лимита чарта ---"
_w623_values="$W623_REPO/deploy/helm/ebpf-guard/values.yaml"
# Берётся limits.memory ПЕРВОГО блока resources (сам агент), а не limits
# сайдкаров/тестовых подов ниже по файлу.
_w623_limit_h=$(awk '
    /^resources:/ { inres=1; next }
    inres && /^[A-Za-z#]/ { exit }                      # блок кончился — дальше чужие resources
    inres && /^[[:space:]]+limits:/ { inlim=1; next }
    inres && inlim && /^[[:space:]]+[a-z]+:[[:space:]]*$/ { exit }   # начался requests:
    inres && inlim && /memory:/ { print $2; exit }' "$_w623_values" 2>/dev/null)
_w623_limit_b=$(awk -v v="${_w623_limit_h:-}" 'BEGIN{
    if (v ~ /Mi$/) { sub(/Mi$/,"",v); printf "%d", v*1024*1024 }
    else if (v ~ /Gi$/) { sub(/Gi$/,"",v); printf "%d", v*1024*1024*1024 }
    else if (v ~ /M$/) { sub(/M$/,"",v); printf "%d", v*1000*1000 }
    else printf "0" }')
_w623_res_print() { # $1=метка $2=файл среза
    echo "  ресурсы[$1]: RSS=$(awk -v b="$(_w623_metric_raw process_resident_memory_bytes "$2")" 'BEGIN{printf "%.1f МиБ", b/1048576}')" \
         "heap=$(awk -v b="$(_w623_metric_raw go_memstats_heap_alloc_bytes "$2")" 'BEGIN{printf "%.1f МиБ", b/1048576}')" \
         "goroutines=$(_w623_metric_raw go_goroutines "$2")" \
         "cpu_total=$(_w623_metric_raw process_cpu_seconds_total "$2")s"
}
_w623_res_print "открытие" "$W623_ART/metrics-window-start.txt"
_w623_res_print "закрытие" "$W623_ART/metrics-window-end.txt"
_w623_rss1=$(_w623_metric_raw process_resident_memory_bytes "$W623_ART/metrics-window-end.txt")
_w623_rss0=$(_w623_metric_raw process_resident_memory_bytes "$W623_ART/metrics-window-start.txt")
_w623_lat_sum0=$(awk '$1=="ebpf_guard_correlation_latency_seconds_sum"{printf "%.6f", $2+0}' "$W623_ART/metrics-window-start.txt")
_w623_lat_cnt0=$(awk '$1=="ebpf_guard_correlation_latency_seconds_count"{printf "%.0f", $2+0}' "$W623_ART/metrics-window-start.txt")
_w623_lat_sum1=$(awk '$1=="ebpf_guard_correlation_latency_seconds_sum"{printf "%.6f", $2+0}' "$W623_ART/metrics-window-end.txt")
_w623_lat_cnt1=$(awk '$1=="ebpf_guard_correlation_latency_seconds_count"{printf "%.0f", $2+0}' "$W623_ART/metrics-window-end.txt")
echo "  латентность корреляции ЗА ОКНО: $(awk -v s0="${_w623_lat_sum0:-0}" -v s1="${_w623_lat_sum1:-0}" -v c0="${_w623_lat_cnt0:-0}" -v c1="${_w623_lat_cnt1:-0}" 'BEGIN{d=c1-c0; if(d>0) printf "%.1f мкс/событие (Δsum=%.3fs ÷ Δcount=%d)", (s1-s0)/d*1e6, s1-s0, d; else printf "НЕИЗМЕРИМА (Δcount=%d)", d}')"
echo "  распределение по бакетам (накопительно, закрытие окна):"
awk '/^ebpf_guard_correlation_latency_seconds_bucket/{gsub(/.*le="/,"");gsub(/"}/," ");printf "    le=%s\n", $0}' "$W623_ART/metrics-window-end.txt" | head -12
echo "  лимит чарта (deploy/helm/ebpf-guard/values.yaml, resources.limits.memory): ${_w623_limit_h:-НЕ ПРОЧИТАН}"
if [ -z "${_w623_rss1:-}" ] || [ "${_w623_limit_b:-0}" -le 0 ]; then
    die "6.2.3.9 НЕИЗМЕРИМ: RSS=${_w623_rss1:-нет} или лимит чарта=${_w623_limit_h:-нет} не прочитаны — «запас до лимита» считать не от чего"
else
    echo "  запас до лимита на закрытии: $(awk -v l="$_w623_limit_b" -v r="$_w623_rss1" 'BEGIN{printf "%.1f МиБ (%.1f%%)", (l-r)/1048576, 100.0*(l-r)/l}')"
    echo "  рост RSS за окно: $(awk -v a="${_w623_rss0:-0}" -v b="$_w623_rss1" 'BEGIN{printf "%+.1f МиБ", (b-a)/1048576}')"
    if [ "${_w623_rss1:-0}" -gt "${_w623_limit_b:-0}" ]; then
        die "6.2.3.9 ПРОВАЛЕН: RSS $(awk -v r="$_w623_rss1" 'BEGIN{printf "%.1f", r/1048576}') МиБ ВЫШЕ лимита чарта ${_w623_limit_h}. В DaemonSet это OOM-kill, а не «чуть больше»"
    else
        pass "6.2.3.9 ДОСТИГНУТО: RSS $(awk -v r="$_w623_rss1" 'BEGIN{printf "%.1f", r/1048576}') МиБ ниже лимита чарта ${_w623_limit_h}; порог не назначается (запрет 5.9.6), величина печатается"
    fi
fi

# ---- 6.2.3.11, пассивная половина: приращение счётчика заморозки (№237) ----
echo "--- 6.2.3.11 (наблюдение): потолки базы дрейфа за окно ---"
_w623_maxw=$(echo "$_w623_drift_cfg" | grep -oE 'max_workloads:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | head -1)
_w623_maxsig=$(echo "$_w623_drift_cfg" | grep -oE 'max_signatures_per_workload:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | head -1)
_w623_prof=$(_w623_metric_sum ebpf_guard_drift_baseline_profiles "" "$W623_ART/metrics-window-end.txt")
_w623_evict=$(_w623_metric_sum ebpf_guard_drift_baseline_evictions_total "" "$W623_ART/metrics-window-end.txt")
# №237, дефект 2: вердикт по РАЗНОСТИ ДВУХ СНИМКОВ, а не по наличию имени
# метрики в выдаче (Prometheus печатает нулевые счётчики всегда).
_w623_cap0=$(_w623_metric_sum ebpf_guard_drift_baseline_signature_cap_reached_total "" "$W623_ART/metrics-window-start.txt")
_w623_cap1=$(_w623_metric_sum ebpf_guard_drift_baseline_signature_cap_reached_total "" "$W623_ART/metrics-window-end.txt")
# №237, дефект 1: журнал ограничен ОКНОМ, а не всей историей юнита.
_w623_frozen_j=$(journalctl -u "$W623_SVC" --since "@$_w623_t0" --until "@$_w623_t1" --no-pager 2>/dev/null | grep -c 'workload signature cap reached')
echo "  профилей=$_w623_prof при max_workloads=${_w623_maxw:-?}; вытеснений=$_w623_evict"
echo "  max_signatures_per_workload=${_w623_maxsig:-?}; приращение signature_cap_reached_total ЗА ОКНО: $(( _w623_cap1 - _w623_cap0 )) (накопительно $_w623_cap1)"
echo "  строк «signature cap reached» в журнале ЗА ОКНО: $_w623_frozen_j"
echo "  6.2.3.11 (пассивная половина): наблюдение без порога — при max_signatures=${_w623_maxsig:-?} кап в тихом окне достигаться и не обязан. Вердикт выносит позитивный подконтроль в конце прогона"

# ---- 6.2.2.6, живая половина «фон молчит» ----
echo "--- 6.2.2.6 (живая половина 1/2): три правки условий на РЕАЛЬНОМ фоне ноды ---"
for _r in c2_periodic_beacon_pattern beacon_fixed_interval sigma_iptables_flush sigma_log_deletion; do
    _a0=$(_w623_metric_sum ebpf_guard_alerts_total "$_r" "$W623_ART/metrics-window-start.txt")
    _a1=$(_w623_metric_sum ebpf_guard_alerts_total "$_r" "$W623_ART/metrics-window-end.txt")
    _f0=$(_w623_metric_sum ebpf_guard_alerts_filtered_total "$_r" "$W623_ART/metrics-window-start.txt")
    _f1=$(_w623_metric_sum ebpf_guard_alerts_filtered_total "$_r" "$W623_ART/metrics-window-end.txt")
    _rl0=$(_w623_ratelimited "$_r" "$W623_ART/metrics-window-start.txt")
    _rl1=$(_w623_ratelimited "$_r" "$W623_ART/metrics-window-end.txt")
    echo "    $_r: за окно всего $(( (_a1 - _a0) + (_f1 - _f0) )) (экспортировано $(( _a1 - _a0 )), срезано min_severity $(( _f1 - _f0 )), срез лимитера $(( _rl1 - _rl0 )))"
done
echo "    (на окне 6.2.1 c2_periodic_beacon_pattern дал 602 — 71% всей величины прогона)"

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.3.8 ОКНО ПРОФИЛЯ (№244). ОТДЕЛЬНОЕ окно, сразу ПОСЛЕ окна объёма:
# `curl /debug/pprof/profile?seconds=30` — действие измерителя, и внутри окна
# объёма оно нарушило бы 6.2.3.3.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.3.8: окно профиля ${W623_PROFILE_SECS}s (ОТДЕЛЬНОЕ, после окна объёма) ---"
mkdir -p "$W623_ART/profile" 2>/dev/null
_w623_pcpu0=$(_w623_metric_raw process_cpu_seconds_total "$W623_ART/metrics-window-end.txt")
_w623_pt0=$(_w623_epoch)
# СОБСТВЕННЫЙ ТАЙМАУТ, а не общий. `_w623_curl` несёт --max-time 30, и запрос
# профиля на 30 с в него НЕ УКЛАДЫВАЕТСЯ по построению: сервер держит
# соединение ровно PROFILE_SECS и только потом отдаёт тело. Прогон 06.09.2026
# привёз из-за этого cpu.pprof НУЛЕВОГО РАЗМЕРА при исправном pprof (смок на
# 5 с проходил — дефект виден только на боевой длине окна).
curl -s --max-time "$(( W623_PROFILE_SECS + 60 ))" -H "Authorization: Bearer $W623_TOKEN" \
    "$W623_API/debug/pprof/profile?seconds=$W623_PROFILE_SECS" > "$W623_ART/profile/cpu.pprof" 2>/dev/null
_w623_curl "$W623_API/debug/pprof/heap" > "$W623_ART/profile/heap.pprof" 2>/dev/null
_w623_curl "$W623_API/debug/pprof/goroutine?debug=1" > "$W623_ART/profile/goroutine.txt" 2>/dev/null
_w623_metrics > "$W623_ART/profile/metrics-profile-end.txt"
_w623_pt1=$(_w623_epoch)
_w623_pcpu1=$(_w623_metric_raw process_cpu_seconds_total "$W623_ART/profile/metrics-profile-end.txt")
_w623_psize=$(wc -c < "$W623_ART/profile/cpu.pprof" 2>/dev/null | tr -d ' ')
echo "  профиль снят: cpu.pprof ${_w623_psize:-0} байт, heap.pprof $(wc -c < "$W623_ART/profile/heap.pprof" 2>/dev/null | tr -d ' ') байт"
echo "  дельта process_cpu_seconds_total за окно профиля: $(awk -v a="${_w623_pcpu0:-0}" -v b="${_w623_pcpu1:-0}" -v t="$(( _w623_pt1 - _w623_pt0 ))" 'BEGIN{if(t>0) printf "%.2f с за %d с = %.1f%% ядра", b-a, t, 100.0*(b-a)/t; else printf "НЕИЗМЕРИМА"}')"
if [ "${_w623_psize:-0}" -lt 1000 ]; then
    die "6.2.3.8 ПРОВАЛЕН: профиль не снят (cpu.pprof ${_w623_psize:-0} байт). «34% ядра» без разбора — не величина, а незнание (находка №244); отсутствие профиля в архиве есть провал критерия, а не оговорка"
else
    echo "  top-10 функций по CPU:"
    if [ -x "$W623_GO" ]; then
        "$W623_GO" tool pprof -top -nodecount=10 "$W623_REPO/build/ebpf-guard" "$W623_ART/profile/cpu.pprof" 2>/dev/null \
            | tee "$W623_ART/profile/top10.txt" | sed 's/^/    /'
    fi
    if [ -s "$W623_ART/profile/top10.txt" ]; then
        pass "6.2.3.8 ДОСТИГНУТО: профиль снят в отдельном окне и разобран top-10 (порог не назначается — запрет 5.9.6)"
    else
        die "6.2.3.8 ПРОВАЛЕН (половина «разбор»): профиль снят (${_w623_psize} байт), но top-10 не построен — go tool pprof недоступен ($W623_GO) или бинарь $W623_REPO/build/ebpf-guard не совпал с профилем. Профиль без разбора вердикта не даёт"
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# ВХОД ПОДАЁТСЯ ЗДЕСЬ, ПОСЛЕ ОБОИХ ОКОН (память
# control-after-attacks-hits-filled-limiter).
#
# №251, ГРАНИЦА ФАЗЫ АТАК (начало). Все позитивные контроли и инъекции ниже —
# до самого критерия 6.2.3.7 — есть штатное поведение ЭТОГО прогона
# (host-token-read, pod-token-probe, churn, инъекции 6.2.2.6), а не атака.
# Инцидент инцидентного слоя, чей корень — нодовый актор или сам измеритель
# и чьё время попадает в [attack_phase_start, attack_phase_end], есть
# ОЖИДАЕМЫЙ true positive; вне этого интервала — засчитывается как ложь.
# ─────────────────────────────────────────────────────────────────────────────
_w623_attack_phase_start=$(_w623_epoch)
echo "--- 6.2.1.2 (регрессия): сторож слепоты лимитера (хостовое чтение токена пода) ---"
W623_HOSTCAT_PODDED=0
if [ "$W623_INSTRUMENTED" -eq 1 ]; then
    _w623_target=$(find /var/lib/kubelet/pods -maxdepth 6 -type f -name token 2>/dev/null | head -1)
    [ -z "$_w623_target" ] && _w623_target=$(find /var/lib/kubelet/pods -maxdepth 4 -type f 2>/dev/null | head -1)
    if [ -z "$_w623_target" ]; then
        die "6.2.1.2 НЕИЗМЕРИМ: под /var/lib/kubelet/pods нет ни одного файла — хостовую половину нечем подать, ноль был бы приборным"
    else
        _w623_hrl0=$(_w623_ratelimited "$W623_HOST_RULES")
        cp /bin/cat /usr/local/bin/w623hostcat 2>/dev/null
        _w623_tn=$(_w623_epoch)
        _w623_bytes=$(/usr/local/bin/w623hostcat "$_w623_target" 2>/dev/null | wc -c)
        _w623_hits=0; _w623_waited=0
        while [ "$_w623_waited" -lt "$W623_POS_TIMEOUT" ]; do
            sleep "$W623_SETTLE"; _w623_waited=$(( _w623_waited + W623_SETTLE ))
            _w623_hits=$(_w623_alerts | jq --argjson t "$_w623_tn" --arg ids "$W623_HOST_RULES" \
                '[.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.comm=="w623hostcat") and (.rule_id as $r|($ids|split(" "))|index($r)))]|length' 2>/dev/null || echo 0)
            [ "${_w623_hits:-0}" -gt 0 ] && break
        done
        _w623_hrl1=$(_w623_ratelimited "$W623_HOST_RULES")
        _w623_all=$(_w623_alerts | jq --argjson t "$_w623_tn" '[.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.comm=="w623hostcat"))]|length' 2>/dev/null || echo 0)
        _w623_rules=$(_w623_alerts | jq -r --argjson t "$_w623_tn" '.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.comm=="w623hostcat"))|.rule_id' 2>/dev/null | sort -u | tr '\n' ' ')
        echo "  сторож результата: прочитано байт = $_w623_bytes (цель $_w623_target)"
        echo "  алертов от comm=w623hostcat: всего $_w623_all (правила: ${_w623_rules:-нет}); из них обязательных: $_w623_hits"
        echo "  срез лимитера обязательных правил за время контроля: $(( _w623_hrl1 - _w623_hrl0 ))"
        if [ "${_w623_bytes:-0}" -lt 1 ]; then
            die "6.2.1.2 НЕИЗМЕРИМ: хостовой читатель ничего не прочитал (байт=$_w623_bytes) — ноль приборный (память positive-control-needs-result-sentinel)"
        elif [ "${_w623_hits:-0}" -lt 1 ] && [ "$(( _w623_hrl1 - _w623_hrl0 ))" -gt 0 ]; then
            die "6.2.1.2 ПРОВАЛЕН (шум→слепота, регресс находки №221): хост прочитал токен ($_w623_bytes байт), обязательные правила не поднялись, И их лимитер срезал $(( _w623_hrl1 - _w623_hrl0 )) срабатываний"
        elif [ "${_w623_hits:-0}" -lt 1 ]; then
            die "6.2.1.2 ПРОВАЛЕН (детекта нет): хост прочитал токен пода ($_w623_bytes байт), обязательные правила не поднялись, лимитер их НЕ срезал"
        else
            pass "6.2.1.2 ДОСТИГНУТО: хостовое чтение токена пода подняло $_w623_hits обязательных алертов (${_w623_rules})"
        fi
        W623_HOSTCAT_PODDED=$(_w623_alerts | jq --argjson t "$_w623_tn" '[.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.comm=="w623hostcat") and ((.enrichment.pod_name // "")!=""))]|length' 2>/dev/null || echo 0)
        rm -f /usr/local/bin/w623hostcat 2>/dev/null
    fi
else
    echo "  ПРОПУЩЕН: 6.2.3.0 не взят"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.1.3 (регрессия) НЕГАТИВНЫЙ КОНТРОЛЬ НА ПОЛНОМ ОБЪЁМЕ (находка №227).
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.1.3 (регрессия): негативный контроль на полном объёме ---"
if [ "$W623_INSTRUMENTED" -eq 1 ]; then
    _w623_alerts > "$W623_ART/alerts-negative.json"
    echo "  comm, у которых ХОТЬ ОДИН алерт несёт pod_name (это обязаны быть только поды):"
    jq -r '[.[]|select((.enrichment.pod_name // "")!="")]|group_by(.comm)|map({c:.[0].comm,n:length})|sort_by(-.n)[]|"    \(.c): \(.n)"' "$W623_ART/alerts-negative.json" 2>/dev/null | head -20
    _w623_bad=$(jq -r '[.[]|select(((.enrichment.pod_name // "")!="") and ((.enrichment.container_id // "")==""))]|length' "$W623_ART/alerts-negative.json" 2>/dev/null || echo 0)
    _w623_hostpodded=$(jq -r --arg h "k3s-server iptables ip6tables systemd sshd cron kubectl systemd-logind" \
        '[.[]|select(((.enrichment.pod_name // "")!="") and ((.comm) as $c|($h|split(" "))|index($c)))]|length' "$W623_ART/alerts-negative.json" 2>/dev/null || echo 0)
    echo "  алертов с pod_name БЕЗ container_id: $_w623_bad"
    echo "  алертов с pod_name у заведомо хостовых comm: $_w623_hostpodded"
    echo "  алертов с pod_name у контрольного хостового читателя: ${W623_HOSTCAT_PODDED:-0}"
    if [ "${_w623_hostpodded:-0}" -gt 0 ] || [ "${W623_HOSTCAT_PODDED:-0}" -gt 0 ] || [ "${_w623_bad:-0}" -gt 0 ]; then
        die "6.2.1.3 ПРОВАЛЕН: хостовые процессы получили ЧУЖУЮ личность пода (хостовые comm: $_w623_hostpodded, без container_id: $_w623_bad, контрольный читатель: ${W623_HOSTCAT_PODDED:-0})"
    else
        pass "6.2.1.3 ДОСТИГНУТО: ни один хостовой процесс не получил личность пода"
    fi
else
    echo "  ПРОПУЩЕН: 6.2.3.0 не взят"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.1.2b (регрессия) ПОЗИТИВНЫЙ КОНТРОЛЬ ОСИ ПОДА.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.1.2b (регрессия): под читает свой SA-токен ---"
if [ "$W623_INSTRUMENTED" -eq 1 ]; then
    "$W623_KUBECTL" create namespace "$W623_NS" --dry-run=client -o yaml 2>/dev/null | "$W623_KUBECTL" apply -f - >/dev/null 2>&1
    "$W623_KUBECTL" -n "$W623_NS" delete pod w623-token-probe --ignore-not-found --wait=true >/dev/null 2>&1
    cat > "$W623_ART/w623-token-probe.yaml" <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: w623-token-probe
  labels:
    app: w623-token-probe
spec:
  restartPolicy: Never
  containers:
  - name: probe
    image: busybox:1.36
    command: ["sh","-c"]
    args:
      - |
        i=0
        while [ $i -lt 30 ]; do
          read t < /run/secrets/kubernetes.io/serviceaccount/token
          echo "W623-SENTINEL opener_comm=$(cat /proc/$$/comm) token_head=$(echo "$t" | cut -c1-12) token_len=${#t}"
          i=$((i+1)); sleep 2
        done
    volumeMounts:
    - name: satoken
      mountPath: /run/secrets/kubernetes.io/serviceaccount
      readOnly: true
  volumes:
  - name: satoken
    projected:
      sources:
      - serviceAccountToken:
          path: token
YAML
    _w623_tp=$(_w623_epoch)
    "$W623_KUBECTL" -n "$W623_NS" apply -f "$W623_ART/w623-token-probe.yaml" >/dev/null 2>&1
    "$W623_KUBECTL" -n "$W623_NS" wait --for=condition=Ready pod/w623-token-probe --timeout=90s >/dev/null 2>&1
    _w623_pdelta=0; _w623_waited=0
    while [ "$_w623_waited" -lt "$W623_POS_TIMEOUT" ]; do
        sleep "$W623_SETTLE"; _w623_waited=$(( _w623_waited + W623_SETTLE ))
        _w623_pdelta=$(_w623_alerts | jq --arg ids "$W623_K8S_RULES" --argjson t "$_w623_tp" \
            '[.[]|select((.rule_id as $r|($ids|split(" "))|index($r)) and ((.enrichment.pod_name // "")=="w623-token-probe") and ((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t))]|length' 2>/dev/null || echo 0)
        [ "${_w623_pdelta:-0}" -gt 0 ] && break
    done
    _w623_sent=$("$W623_KUBECTL" -n "$W623_NS" logs w623-token-probe 2>/dev/null | grep -m1 'W623-SENTINEL')
    _w623_phit=$(_w623_alerts | jq -r --arg ids "$W623_K8S_RULES" --argjson t "$_w623_tp" \
        '.[]|select((.rule_id as $r|($ids|split(" "))|index($r)) and ((.enrichment.pod_name // "")=="w623-token-probe") and ((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t))|.rule_id' 2>/dev/null | sort -u | tr '\n' ' ')
    echo "  ожидание записи в стор: ${_w623_waited}s"
    echo "  сторож результата: ${_w623_sent:-НЕ НАПЕЧАТАН}"
    echo "  алертов с pod_name=w623-token-probe: $_w623_pdelta (правила: ${_w623_phit:-нет})"
    _w623_len=$(printf '%s' "${_w623_sent:-}" | grep -oE 'token_len=[0-9]+' | cut -d= -f2)
    if [ -z "${_w623_len:-}" ] || [ "${_w623_len:-0}" -lt 100 ]; then
        die "6.2.1.2b НЕИЗМЕРИМ: сторож результата не напечатал прочитанный токен (token_len=${_w623_len:-нет}) — ноль правил приборный"
    elif [ "$_w623_pdelta" -lt 1 ]; then
        die "6.2.1.2b ПРОВАЛЕН: под прочитал токен (token_len=$_w623_len), а правила ${W623_K8S_RULES} не поднялись с его именем"
    else
        pass "6.2.1.2b ДОСТИГНУТО: чтение SA-токена подом подтверждено сторожем (token_len=$_w623_len) и подняло $_w623_pdelta алертов С ИМЕНЕМ ПОДА (${_w623_phit})"
    fi
else
    echo "  ПРОПУЩЕН: 6.2.3.0 не взят"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.3.10 ЦЕНА СТАРТА ПОДА — С ПОРОГОМ (№236).
# Порог 45/под = ceil(36 × 1.25): 36 измерено прогоном 6.2.1 (108 алертов на
# 3 оборота), 25% запаса на то, что величина снята ОДНИМ прогоном.
# Бюджет ОТДЕЛЬНЫЙ от 6.2.3.1: окна физически не пересекаются (churn идёт
# после тихого окна). Вопрос «как боевой часовой гейт учитывает непрерывный
# churn» этим порогом НЕ закрыт и остаётся открытым (пункт 10 plan.md).
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.3.10: цена одного старта пода, порог ${W623_CHURN_BUDGET}/под ---"
if [ "$W623_INSTRUMENTED" -eq 1 ]; then
    _w623_tc=$(_w623_epoch)
    for i in $(seq 1 "$W623_CHURN"); do
        "$W623_KUBECTL" -n "$W623_NS" run "w623-churn-$i" --image=busybox:1.36 --restart=Never --command -- sleep 15 >/dev/null 2>&1
    done
    sleep 45
    for i in $(seq 1 "$W623_CHURN"); do "$W623_KUBECTL" -n "$W623_NS" delete pod "w623-churn-$i" --ignore-not-found --wait=false >/dev/null 2>&1; done
    sleep $(( W623_SETTLE * 3 ))
    _w623_alerts > "$W623_ART/alerts-churn-end.json"
    _w623_churn=$(jq --argjson t "$_w623_tc" '[.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.comm|test("^(runc|containerd|conmon|crun|dockerd|pause)")))]' "$W623_ART/alerts-churn-end.json" 2>/dev/null)
    _w623_cn=$(echo "${_w623_churn:-[]}" | jq 'length' 2>/dev/null); _w623_cn=${_w623_cn:-0}
    _w623_per=$(awk -v n="$_w623_cn" -v p="$W623_CHURN" 'BEGIN{printf "%.1f", (p>0? n/p : 0)}')
    echo "  запущено и снято подов: $W623_CHURN; алертов от рантайм-comm: $_w623_cn → $_w623_per на под (порог ${W623_CHURN_BUDGET})"
    echo "${_w623_churn:-[]}" | jq -r 'group_by(.rule_id)|map({r:.[0].rule_id,n:length})|sort_by(-.n)[]|"    \(.r): \(.n)"' 2>/dev/null | head -25
    if awk -v v="$_w623_per" -v b="$W623_CHURN_BUDGET" 'BEGIN{exit !(v > b)}'; then
        die "6.2.3.10 ПРОВАЛЕН: старт пода стоит $_w623_per алертов при бюджете ${W623_CHURN_BUDGET}/под (36 × 1.25, №236). Глушить по comm=runc нельзя — это ровно те правила, что обязаны ловить контейнерный побег; чинится сужением условий, а не исключением"
    else
        pass "6.2.3.10 ДОСТИГНУТО: старт пода стоит $_w623_per алертов ≤ ${W623_CHURN_BUDGET}/под"
    fi
else
    echo "  ПРОПУЩЕН: 6.2.3.0 не взят"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.1.8 (регрессия) СЛОЙ 2: КЛЮЧ ИСКЛЮЧЕНИЯ, КОТОРЫЙ ПРОЦЕСС СЕБЕ НЕ НАЗНАЧАЕТ.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.1.8 (регрессия): образ процесса как ключ исключения ---"
if [ "$W623_INSTRUMENTED" -eq 1 ]; then
    W623_EXE_PREFIXES="/usr/ /bin/ /sbin/ /opt/ /var/lib/rancher/"
    _w623_exe_bad=""
    for _c in k3s-server containerd kubelet coredns; do
        _p=$(pgrep -x "$_c" 2>/dev/null | head -1)
        if [ -z "$_p" ]; then
            echo "  $_c: процесса нет на этой ноде (исключение для него на этом прогоне не проверяется)"
            continue
        fi
        _e=$(readlink "/proc/$_p/exe" 2>/dev/null)
        echo "  $_c: pid=$_p exe=${_e:-<не читается>}"
        [ "$_c" = "coredns" ] && continue
        _ok=0
        for _pre in $W623_EXE_PREFIXES; do
            case "${_e:-}" in "$_pre"*) _ok=1 ;; esac
        done
        [ "$_ok" -eq 1 ] || _w623_exe_bad="$_w623_exe_bad $_c(${_e:-<пусто>})"
    done
    echo "  обращений к /proc за образом (ebpf_guard_exe_path_lookups_total, накопительно): $(_w623_metric_sum ebpf_guard_exe_path_lookups_total "" 2>/dev/null)"
    if [ -n "$_w623_exe_bad" ]; then
        die "6.2.1.8 ПРОВАЛЕН (половина «покрытие»): образ демона(ов)$_w623_exe_bad не попадает ни под один префикс правил ($W623_EXE_PREFIXES) — исключения фона ноды для них НЕ ПРИМЕНЯЮТСЯ"
    else
        pass "6.2.1.8 ДОСТИГНУТО (половина «покрытие»): образы всех найденных хостовых демонов попадают под префиксы исключений"
    fi

    _w623_target8=$(find /var/lib/kubelet/pods -maxdepth 6 -type f -name token 2>/dev/null | head -1)
    [ -z "$_w623_target8" ] && _w623_target8=$(find /var/lib/kubelet/pods -maxdepth 4 -type f 2>/dev/null | head -1)
    if [ -z "$_w623_target8" ]; then
        die "6.2.1.8 НЕИЗМЕРИМ (половина «отказ обхода»): под /var/lib/kubelet/pods нет ни одного файла — подделке нечего читать"
    else
        # ИМЯ КОПИИ — РОВНО ИМЯ ДЕМОНА: comm ядро берёт из базового имени
        # образа в execve, `exec -a` подменяет только argv[0] (память
        # exec-a-argv0-spoof-kills-proc-args). Иначе исключение
        # node-host-daemon не применилось бы В ЛЮБОМ СЛУЧАЕ и контроль
        # проверял бы не слой 2.
        rm -rf /tmp/w623-bypass 2>/dev/null
        mkdir -p /tmp/w623-bypass 2>/dev/null
        cp /bin/cat /tmp/w623-bypass/k3s-server 2>/dev/null
        chmod 0755 /tmp/w623-bypass/k3s-server 2>/dev/null
        _w623_t8=$(_w623_epoch)
        ( exec -a k3s-server /tmp/w623-bypass/k3s-server "$_w623_target8" ) > /tmp/w623-bypass/out 2>/dev/null &
        _w623_p8=$!
        wait "$_w623_p8" 2>/dev/null
        _w623_b8=$(wc -c < /tmp/w623-bypass/out 2>/dev/null | tr -d ' ')
        _w623_h8=0; _w623_w8=0
        while [ "$_w623_w8" -lt "$W623_POS_TIMEOUT" ]; do
            sleep "$W623_SETTLE"; _w623_w8=$(( _w623_w8 + W623_SETTLE ))
            _w623_h8=$(_w623_alerts | jq --argjson t "$_w623_t8" --argjson p "${_w623_p8:-0}" --arg ids "$W623_HOST_RULES" \
                '[.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.pid == $p) and (.rule_id as $r|($ids|split(" "))|index($r)))]|length' 2>/dev/null || echo 0)
            [ "${_w623_h8:-0}" -gt 0 ] && break
        done
        _w623_c8=$(_w623_alerts | jq -r --argjson p "${_w623_p8:-0}" '[.[]|select(.pid == $p)][0].comm // "нет алертов от этого pid"' 2>/dev/null)
        echo "  сторож результата подделки: прочитано байт = $_w623_b8 (цель $_w623_target8)"
        echo "  подделка: pid=$_w623_p8, образ /tmp/w623-bypass/k3s-server, comm в сторе=$_w623_c8"
        echo "  алертов от подделки (по её pid): $_w623_h8 из обязательных ($W623_HOST_RULES)"
        if [ "${_w623_b8:-0}" -lt 1 ]; then
            die "6.2.1.8 НЕИЗМЕРИМ (половина «отказ обхода»): подделка не прочитала ни байта — ноль правил приборный"
        elif [ "$_w623_c8" != "k3s-server" ] && [ "${_w623_h8:-0}" -lt 1 ]; then
            die "6.2.1.8 НЕИЗМЕРИМ (половина «отказ обхода»): подделка не носит имени демона — стор знает её как «$_w623_c8». При таком comm исключение не применилось бы в любом случае, и слой 2 контроль не проверял"
        elif [ "${_w623_h8:-0}" -lt 1 ]; then
            die "6.2.1.8 ПРОВАЛЕН (половина «отказ обхода»): процесс, назвавшийся k3s-server и прочитавший токен пода ($_w623_b8 байт), НЕ поднял ни одного из $W623_HOST_RULES — исключение следует за именем, а не за образом"
        else
            pass "6.2.1.8 ДОСТИГНУТО (половина «отказ обхода»): подделка носила имя демона (comm=$_w623_c8), но не унаследовала его тишину — поднято $_w623_h8 обязательных правил"
        fi
        rm -rf /tmp/w623-bypass 2>/dev/null
    fi
else
    echo "  ПРОПУЩЕН: 6.2.3.0 не взят"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.1.9 (регрессия) СЛОЙ 3: СМЕНА ПРАВ НА ФАЙЛОВОЙ ОСИ + вторая половина
# №243 (chmod даёт ровно одно событие: syscall-ось его больше не производит).
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.1.9 (регрессия): chmod с разрешённым путём + №243 ---"
if [ "$W623_INSTRUMENTED" -eq 1 ]; then
    _w623_hook_ok=$(_w623_metrics | awk '/^ebpf_guard_file_hook_attach_total\{.*result="ok"/ {s+=$NF} END{printf "%d", s+0}')
    _w623_hook_err=$(_w623_metrics | awk '/^ebpf_guard_file_hook_attach_total\{.*result="(error|missing)"/ {s+=$NF} END{printf "%d", s+0}')
    echo "  привязка chmod-хуков: ok=$_w623_hook_ok, error+missing=$_w623_hook_err"
    echo "  chmod без разрешённого пути (накопительно): $(_w623_metric_sum ebpf_guard_file_chmod_unresolved_total "" 2>/dev/null)"

    # №243, вторая половина: syscall-события за серию chmod. До правки каждый
    # chmod давал ВТОРОЕ событие на syscall-оси, которое никто не читает.
    _w623_sysc_m0=$(_w623_metrics > "$W623_ART/metrics-chmod-0.txt"; awk '/^ebpf_guard_events_total\{.*type="syscall"/{s+=$NF} END{printf "%d", s+0}' "$W623_ART/metrics-chmod-0.txt")
    _w623_t9=$(_w623_epoch)
    mkdir -p /tmp/w623-chmod 2>/dev/null
    : > /tmp/w623-chmod/payload 2>/dev/null
    chmod 0755 /tmp/w623-chmod/payload 2>/dev/null
    _w623_m1=$(stat -c '%a' /tmp/w623-chmod/payload 2>/dev/null)
    cp /bin/cat /usr/local/bin/w623-chmod-bin 2>/dev/null
    chmod 0755 /usr/local/bin/w623-chmod-bin 2>/dev/null
    _w623_m2=$(stat -c '%a' /usr/local/bin/w623-chmod-bin 2>/dev/null)
    # Серия из 50 chmod по одному пути: на syscall-оси это дало бы +50 событий.
    for _i in $(seq 1 50); do chmod 0644 /tmp/w623-chmod/payload 2>/dev/null; chmod 0755 /tmp/w623-chmod/payload 2>/dev/null; done
    echo "  сторож результата: права /tmp/w623-chmod/payload = ${_w623_m1:-НЕ ПРОЧИТАНЫ}, /usr/local/bin/w623-chmod-bin = ${_w623_m2:-НЕ ПРОЧИТАНЫ}"

    _w623_c9=0; _w623_w9=0
    while [ "$_w623_w9" -lt "$W623_POS_TIMEOUT" ]; do
        sleep "$W623_SETTLE"; _w623_w9=$(( _w623_w9 + W623_SETTLE ))
        _w623_c9=$(_w623_alerts | jq --argjson t "$_w623_t9" \
            '[.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.rule_id|test("chmod")))]|length' 2>/dev/null || echo 0)
        [ "${_w623_c9:-0}" -gt 1 ] && break
    done
    _w623_r9=$(_w623_alerts | jq -r --argjson t "$_w623_t9" \
        '.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.rule_id|test("chmod")))|.rule_id' 2>/dev/null | sort -u | tr '\n' ' ')
    _w623_metrics > "$W623_ART/metrics-chmod-1.txt"
    _w623_sysc_m1=$(awk '/^ebpf_guard_events_total\{.*type="syscall"/{s+=$NF} END{printf "%d", s+0}' "$W623_ART/metrics-chmod-1.txt")
    echo "  алертов о смене прав после подачи: $_w623_c9 (правила: ${_w623_r9:-нет})"
    echo "  №243, наблюдение: syscall-событий за серию из 100 chmod: $(( _w623_sysc_m1 - _w623_sysc_m0 )) (при chmod на syscall-оси было бы ≥ 100; фон ноды сюда тоже входит, поэтому это наблюдение, а вердикт №243 выносит monitored_syscalls в преflight'е)"

    if [ -z "${_w623_m1:-}" ] || [ -z "${_w623_m2:-}" ]; then
        die "6.2.1.9 НЕИЗМЕРИМ: сторож результата не прочитал права после chmod — подача не состоялась, ноль правил приборный"
    elif [ "$_w623_hook_ok" -eq 0 ]; then
        die "6.2.1.9 ПРОВАЛЕН (приборный ноль): ни один chmod-хук не привязан (ok=0, error+missing=$_w623_hook_err) — три правила о смене прав НЕ МОГУТ сработать"
    elif ! printf '%s' "$_w623_r9" | grep -q 'sigma_chmod_executable_tmp'; then
        die "6.2.1.9 ПРОВАЛЕН: chmod +x в /tmp состоялся (права $_w623_m1), а sigma_chmod_executable_tmp не поднялся — тихая смерть правила"
    elif ! printf '%s' "$_w623_r9" | grep -q 'evasion_chmod_sensitive'; then
        die "6.2.1.9 ПРОВАЛЕН: chmod системного бинаря состоялся (права $_w623_m2), а evasion_chmod_sensitive не поднялся"
    else
        pass "6.2.1.9 ДОСТИГНУТО: смена прав видна с разрешённым путём, и каждое из двух мест подняло СВОЁ правило (${_w623_r9})"
    fi
    rm -rf /tmp/w623-chmod /usr/local/bin/w623-chmod-bin 2>/dev/null
else
    echo "  ПРОПУЩЕН: 6.2.3.0 не взят"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.3.5/6.2.3.6 (item 3 постановки, №249/решение 4). Механизм немоты
# op=write устанавливается ПОДАЧЕЙ, не рассуждением: `echo … >> path` (shell
# перенаправление — bash открывает файл на СВОЙ fd, dup2()'ит его на fd 1,
# пишет, восстанавливает fd 1) и `dd of=path` на ОДИН И ТОТ ЖЕ путь. Три
# исхода и что каждый значит (решение 4, plan.md §6.2.3):
#   обе молчат при подтверждённой записи → ось OP: сужение №234 (op in
#     [write]) в принципе не совпадает с этим write(), fd→path тут ни при
#     чём — откатывается сужение;
#   молчит echo, поднимает dd → FD→PATH: dup2/dup3 не хукнуты (или не
#     привязались на этом ядре) — sys_enter_write видит fd 1 БЕЗ записи в
#     fd_path_map, путь резолвится пустым, filename-префикс не совпадает;
#   поднимают обе → №246 была дефектом сборки на стенде, закрыта деплоем.
# 06.09.2026 живьём на ebaka2: strace дал третий, незапланированный вариант —
# GNU dd (`of=` задан) ТОЖЕ дублирует fd (open→dup2(fd,1)→write(1,…)), а не
# пишет напрямую в свой fd, как предполагала постановка. Это не отменяет
# третий исход выше — он остаётся законным различителем на системах, где dd
# пишет напрямую, — но означает, что на ЭТОМ стенде echo и dd проверяют
# ОДИН И ТОТ ЖЕ механизм (fd→path), а не два разных пути. Хуки
# sys_enter_dup{,2,3} (bpf/fileaccess.bpf.c, dup_commit) закрывают его для
# обеих подач одинаково.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.3.5/6.2.3.6: механизм немоты op=write — echo >> и dd of= на один путь (№249) ---"
# ОТКРЫТЫЙ ВОПРОС 6 (закрыт этим стражем). Блок НАМЕРЕННО пишет в /var/log и
# НАМЕРЕННО поднимает sigma_log_deletion — то есть производит алерты. Пока он
# стоит ПОСЛЕ тихого окна (после 6.2.1.9), в измеряемую величину они не
# попадают. Но это свойство ПОРЯДКА СТРОК в файле, а порядок правится молча:
# перенос блока выше по тексту сделает измеритель источником собственного
# шума — ровно класс находки №242, на котором волна 6.2.2 уже потеряла замер.
# Поэтому порядок здесь ПРОВЕРЯЕТСЯ, а не подразумевается: t1 (закрытие
# тихого окна) обязан быть в прошлом к моменту первой подачи.
_w623_now5=$(_w623_epoch)
if [ -z "${_w623_t1:-}" ]; then
    die "6.2.3.5 НЕИЗМЕРИМ: тихое окно не открывалось к моменту подачи write-механизма — порядок блоков нарушен, границы окна неизвестны"
    W623_WRITE_ORDER_OK=0
elif [ "$_w623_now5" -le "$_w623_t1" ]; then
    die "6.2.3.5 НЕИЗМЕРИМ (открытый вопрос 6): подача write-механизма идёт ВНУТРИ тихого окна (сейчас $(_w623_utc "$_w623_now5") ≤ t1 $(_w623_utc "$_w623_t1")). Блок намеренно поднимает sigma_log_deletion, и эти алерты попадут в величину 6.2.3.1/6.2.3.2 как шум продукта. Вернуть блок ПОСЛЕ 6.2.1.9"
    W623_WRITE_ORDER_OK=0
else
    echo "  порядок (открытый вопрос 6): подача идёт через $((_w623_now5 - _w623_t1)) с ПОСЛЕ закрытия тихого окна — собственные алерты блока вне измеряемой величины"
    W623_WRITE_ORDER_OK=1
fi
if [ "$W623_INSTRUMENTED" -eq 1 ]; then
    _w623_dup_ok=$(_w623_metrics | awk -F'[ }]' '/^ebpf_guard_file_hook_attach_total\{hook="sys_enter_dup[23]?",result="ok"\}/ {s+=$NF} END{printf "%d", s+0}')
    _w623_dup_bad=$(_w623_metrics | awk -F'[ }]' '/^ebpf_guard_file_hook_attach_total\{hook="sys_enter_dup[23]?",result="(error|missing)"\}/ {s+=$NF} END{printf "%d", s+0}')
    echo "  привязка dup/dup2/dup3-хуков: ok=$_w623_dup_ok, error+missing=$_w623_dup_bad"

    _w623_echo_path="/var/log/w623-write-mechanism-echo.log"
    _w623_dd_path="/var/log/w623-write-mechanism-dd.log"
    rm -f "$_w623_echo_path" "$_w623_dd_path" 2>/dev/null
    _w623_t5=$(_w623_epoch)
    echo 'w623-op-write-echo-payload' >> "$_w623_echo_path"
    _w623_echo_bytes=$(wc -c < "$_w623_echo_path" 2>/dev/null | tr -d ' ')
    dd if=/dev/zero of="$_w623_dd_path" bs=1 count=32 2>/dev/null
    _w623_dd_bytes=$(wc -c < "$_w623_dd_path" 2>/dev/null | tr -d ' ')
    echo "  сторож результата: echo записал ${_w623_echo_bytes:-0} байт в $_w623_echo_path, dd — ${_w623_dd_bytes:-0} байт в $_w623_dd_path"

    _w623_w5=0; _w623_echo_hit=0; _w623_dd_hit=0
    while [ "$_w623_w5" -lt "$W623_POS_TIMEOUT" ]; do
        sleep "$W623_SETTLE"; _w623_w5=$(( _w623_w5 + W623_SETTLE ))
        _w623_alerts > "$W623_ART/alerts-write-mechanism.json"
        _w623_echo_hit=$(jq --argjson t "$_w623_t5" --arg p "$_w623_echo_path" \
            '[.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and .rule_id=="sigma_log_deletion" and (.details["file.path"]==$p))]|length' \
            "$W623_ART/alerts-write-mechanism.json" 2>/dev/null || echo 0)
        _w623_dd_hit=$(jq --argjson t "$_w623_t5" --arg p "$_w623_dd_path" \
            '[.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and .rule_id=="sigma_log_deletion" and (.details["file.path"]==$p))]|length' \
            "$W623_ART/alerts-write-mechanism.json" 2>/dev/null || echo 0)
        [ "${_w623_echo_hit:-0}" -ge 1 ] && [ "${_w623_dd_hit:-0}" -ge 1 ] && break
    done
    echo "  6.2.3.5, исход подачи: echo→sigma_log_deletion=${_w623_echo_hit:-0}, dd→sigma_log_deletion=${_w623_dd_hit:-0}"

    if [ -z "${_w623_echo_bytes:-}" ] || [ "$_w623_echo_bytes" = "0" ] || [ -z "${_w623_dd_bytes:-}" ] || [ "$_w623_dd_bytes" = "0" ]; then
        die "6.2.3.5 НЕИЗМЕРИМ: сторож результата не подтвердил запись (echo=${_w623_echo_bytes:-0}Б, dd=${_w623_dd_bytes:-0}Б) — подача не состоялась, ноль правила приборный"
    elif [ "${_w623_echo_hit:-0}" -eq 0 ] && [ "${_w623_dd_hit:-0}" -eq 0 ]; then
        die "6.2.3.5 ПРОВАЛЕН: механизм — ОСЬ OP. Обе нагрузки молчат при подтверждённой записи — сужение №234 (op in [write]) в принципе не совпадает с этим write(), fd→path не при чём. Решение 4: откатить условие op у sigma_log_deletion"
    elif [ "${_w623_echo_hit:-0}" -eq 0 ] && [ "${_w623_dd_hit:-0}" -ge 1 ]; then
        die "6.2.3.5 ПРОВАЛЕН: механизм — FD→PATH. echo молчит, dd поднимает — dup2-хук не привязан или не переносит fd_path_map (ok=$_w623_dup_ok, error+missing=$_w623_dup_bad). Решение 4: хуки sys_enter_dup{,2,3} обязаны быть в сборке"
    else
        pass "6.2.3.6 ДОСТИГНУТО: sigma_log_deletion (op in [write]) поднимается НА ОБЕИХ подачах — echo и dd (на этом стенде dd тоже идёт через dup2, strace 06.09.2026) — механизм fd→path закрыт хуками sys_enter_dup{,2,3} (ok=$_w623_dup_ok, error+missing=$_w623_dup_bad)"
    fi
    rm -f "$_w623_echo_path" "$_w623_dd_path" 2>/dev/null
else
    echo "  ПРОПУЩЕН: 6.2.3.0 не взят"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.3.13 (item 4 постановки, №248): сужение верхушки разбивки (в) —
# sigma_failed_login_syscall_daemon и rootkit_pam_module_added_daemon сужены
# осью op=write (были: любой read/open от sshd|cron — 3090/2400 и 2970/2280
# алертов/окно на двух архивах 6.2.2, первые два источника разбивки 6.2.3.2).
# Юнит на ОБЕ половины: фон (штатные sshd/cron за тихое окно — читают PAM на
# каждом логине/job'е) обязан молчать; подделка identity (comm=sshd/cron),
# которая ДЕЙСТВИТЕЛЬНО пишет в PAM, обязана по-прежнему поднимать правило —
# иначе это не сужение, а немота (тот же класс проверки, что 6.2.1.8).
# Половина «фон» читает уже снятое тихое окно ($W623_ART/metrics-window-*)
# прямой дельтой (величина гейта — показание прибора, а не строка таблицы,
# память f6b-table-indexed-by-limiter-cut), не отдельное ожидание.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.3.13: сужение верхушки шума op=write — обе половины (№248) ---"
if [ "$W623_INSTRUMENTED" -eq 1 ] && [ -s "$W623_ART/metrics-window-start.txt" ] && [ -s "$W623_ART/metrics-window-end.txt" ]; then
    _w623_narrow_bg=0
    for _nr in sigma_failed_login_syscall_daemon rootkit_pam_module_added_daemon; do
        _a0=$(_w623_metric_sum ebpf_guard_alerts_total "$_nr" "$W623_ART/metrics-window-start.txt")
        _a1=$(_w623_metric_sum ebpf_guard_alerts_total "$_nr" "$W623_ART/metrics-window-end.txt")
        _f0=$(_w623_metric_sum ebpf_guard_alerts_filtered_total "$_nr" "$W623_ART/metrics-window-start.txt")
        _f1=$(_w623_metric_sum ebpf_guard_alerts_filtered_total "$_nr" "$W623_ART/metrics-window-end.txt")
        _d=$(( (_a1 - _a0) + (_f1 - _f0) ))
        echo "  фон, тихое окно, $_nr: +$_d за окно (было при op-фильтре ещё не введённом: 3090/2400 и 2970/2280 на архивах 6.2.2)"
        _w623_narrow_bg=$(( _w623_narrow_bg + (_d < 0 ? 0 : _d) ))
    done

    # Половина «цель»: comm=sshd/cron, ДЕЙСТВИТЕЛЬНО пишущий в PAM. comm
    # берётся из БАЗОВОГО ИМЕНИ ПУТИ execve (kbasename(bprm->filename)), не из
    # argv[0] — `exec -a name path` подставляет только argv[0] и оставляет
    # comm от path (см. образец 6.2.1.8): бинарь копируется в файл, названный
    # sshd/cron, и запускается ИМ САМИМ.
    mkdir -p "$W623_ART/spoof13" 2>/dev/null
    cp /bin/bash "$W623_ART/spoof13/sshd" 2>/dev/null
    cp /bin/bash "$W623_ART/spoof13/cron" 2>/dev/null
    chmod +x "$W623_ART/spoof13/sshd" "$W623_ART/spoof13/cron" 2>/dev/null
    _w623_pos1="/etc/pam.d/w623-narrow-spoof-sshd"
    _w623_pos2="/etc/security/w623-narrow-spoof-cron"
    rm -f "$_w623_pos1" "$_w623_pos2" 2>/dev/null
    _w623_t13=$(_w623_epoch)
    _w623_metrics > "$W623_ART/metrics-narrow-pos-0.txt"
    "$W623_ART/spoof13/sshd" -c "echo w623-narrow-spoof-payload >> $_w623_pos1" 2>/dev/null
    "$W623_ART/spoof13/cron" -c "echo w623-narrow-spoof-payload >> $_w623_pos2" 2>/dev/null
    _w623_pos_bytes=$(( $(wc -c < "$_w623_pos1" 2>/dev/null || echo 0) + $(wc -c < "$_w623_pos2" 2>/dev/null || echo 0) ))
    echo "  сторож результата: спуф-подача записала ${_w623_pos_bytes:-0} байт суммарно в $_w623_pos1/$_w623_pos2"

    _w623_w13=0; _w623_pos_hit=0
    while [ "$_w623_w13" -lt "$W623_POS_TIMEOUT" ]; do
        sleep "$W623_SETTLE"; _w623_w13=$(( _w623_w13 + W623_SETTLE ))
        _w623_metrics > "$W623_ART/metrics-narrow-pos-1.txt"
        _w623_pos_hit=0
        for _nr in sigma_failed_login_syscall_daemon rootkit_pam_module_added_daemon; do
            _pa0=$(_w623_metric_sum ebpf_guard_alerts_total "$_nr" "$W623_ART/metrics-narrow-pos-0.txt")
            _pa1=$(_w623_metric_sum ebpf_guard_alerts_total "$_nr" "$W623_ART/metrics-narrow-pos-1.txt")
            _pf0=$(_w623_metric_sum ebpf_guard_alerts_filtered_total "$_nr" "$W623_ART/metrics-narrow-pos-0.txt")
            _pf1=$(_w623_metric_sum ebpf_guard_alerts_filtered_total "$_nr" "$W623_ART/metrics-narrow-pos-1.txt")
            _w623_pos_hit=$(( _w623_pos_hit + (_pa1 - _pa0) + (_pf1 - _pf0) ))
        done
        [ "${_w623_pos_hit:-0}" -ge 1 ] && break
    done
    echo "  6.2.3.13, половина «цель»: +$_w623_pos_hit срабатываний двух правил на спуф-запись (comm=sshd/cron, op=write)"
    rm -f "$_w623_pos1" "$_w623_pos2" 2>/dev/null
    rm -rf "$W623_ART/spoof13" 2>/dev/null

    if [ -z "${_w623_pos_bytes:-}" ] || [ "$_w623_pos_bytes" = "0" ]; then
        die "6.2.3.13 НЕИЗМЕРИМ (половина «цель»): сторож результата не подтвердил запись — спуф не состоялся, ноль правил приборный"
    elif [ "$_w623_narrow_bg" -gt 0 ]; then
        die "6.2.3.13 ПРОВАЛЕН (половина «фон»): $_w623_narrow_bg алертов от двух сужённых правил за тихое окно — узкий op=write фильтр не убрал рутинное чтение PAM демоном, сужение №248 не сработало по существу"
    elif [ "${_w623_pos_hit:-0}" -eq 0 ]; then
        die "6.2.3.13 ПРОВАЛЕН (половина «цель»): подделка носила имя sshd/cron и подтверждённо ЗАПИСАЛА в PAM (${_w623_pos_bytes}Б), но ни sigma_failed_login_syscall_daemon, ни rootkit_pam_module_added_daemon не сработали — сужение выродилось в немоту, а не в фильтр по op"
    else
        pass "6.2.3.13 ДОСТИГНУТО: обе половины — фон (0 алертов за тихое окно) молчит, запись под именем sshd/cron (+$_w623_pos_hit) по-прежнему поднимает — сужение №248 сузило ось op, а не выключило правило"
    fi
else
    echo "  ПРОПУЩЕН: 6.2.3.0 не взят или тихое окно не снято"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.3.14 (item 5 постановки, №247/решение 2): c2_periodic_beacon_pattern
# получило исключение фона ноды (node-host-daemon/kube-system-pod — тот же
# образец, что beacon_fixed_interval уже несёт с волны 6.2.1). Решение 2
# требует ТРЕТИЙ контроль: подделка identity (comm=k3s-server) не должна
# наследовать тишину демона — на хосте cgroup-ось (container.id/k8s.pod)
# пуста одинаково у настоящего демона и у подделки, различает их только
# кернел-назначенный exe_path (слой 2, тот же принцип, что 6.2.1.8). Инъекция
# периодического трафика — тот же приём, что 6.2.2.6 использует для
# позитивной половины (setsid, вне дерева самого контроля — память
# observer-exclusion-blinds-controls; /dev/tcp/127.0.0.1/19090 — порт самого
# агента, заведомо принимающий соединения).
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.3.14: подделка identity демона (comm=k3s-server) не должна унаследовать тишину бикон-исключения (№247) ---"
if [ "$W623_INSTRUMENTED" -eq 1 ]; then
    mkdir -p "$W623_ART/spoof14" 2>/dev/null
    cp /bin/bash "$W623_ART/spoof14/k3s-server" 2>/dev/null
    chmod +x "$W623_ART/spoof14/k3s-server" 2>/dev/null
    _w623_beacon14_before=$(( $(_w623_metric_sum ebpf_guard_alerts_total "c2_periodic_beacon_pattern") + $(_w623_metric_sum ebpf_guard_alerts_filtered_total "c2_periodic_beacon_pattern") + $(_w623_ratelimited "c2_periodic_beacon_pattern") ))
    # exec -a ставит comm="k3s-server" (базовое имя пути execve), но
    # /proc/<pid>/exe остаётся в $W623_ART/spoof14 — мимо префиксов
    # исключения (/usr/, /bin/, /sbin/, /opt/, /var/lib/rancher/).
    ( setsid "$W623_ART/spoof14/k3s-server" -c 'for i in 1 2 3 4 5; do exec 9<>/dev/tcp/127.0.0.1/19090 2>/dev/null; exec 9>&-; sleep 6; done' >/dev/null 2>&1 & )
    _w623_beacon14_after=$_w623_beacon14_before
    _w623_w14=0
    while [ "$_w623_w14" -lt "$W623_POS_TIMEOUT" ]; do
        sleep "$W623_SETTLE"; _w623_w14=$(( _w623_w14 + W623_SETTLE ))
        _w623_beacon14_after=$(( $(_w623_metric_sum ebpf_guard_alerts_total "c2_periodic_beacon_pattern") + $(_w623_metric_sum ebpf_guard_alerts_filtered_total "c2_periodic_beacon_pattern") + $(_w623_ratelimited "c2_periodic_beacon_pattern") ))
        [ "$(( _w623_beacon14_after - _w623_beacon14_before ))" -ge 1 ] && break
    done
    _w623_c14=$(_w623_alerts | jq -r --arg rid "c2_periodic_beacon_pattern" '[.[]|select(.rule_id==$rid)][-1].comm // "нет алертов"' 2>/dev/null)
    rm -rf "$W623_ART/spoof14" 2>/dev/null
    _w623_d14=$(( _w623_beacon14_after - _w623_beacon14_before ))
    echo "  срабатываний c2_periodic_beacon_pattern после подделки (comm в последнем алерте: ${_w623_c14:-нет}): $_w623_d14"
    if [ "${_w623_d14:-0}" -lt 1 ]; then
        die "6.2.3.14 ПРОВАЛЕН: процесс, назвавшийся k3s-server (exe вне системных каталогов), НЕ поднял c2_periodic_beacon_pattern — исключение node-host-daemon следует за именем, а не за образом (№247, решение 2)"
    else
        pass "6.2.3.14 ДОСТИГНУТО: подделка носила имя демона, но не унаследовала его тишину — правило поднялось $_w623_d14 раз на подделанном образе"
    fi
else
    echo "  ПРОПУЩЕН: 6.2.3.0 не взят"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.2.6 ПРАВИЛО СОВПАДАЕТ НЕ ШИРЕ СВОЕГО ИМЕНИ (№231, №234 + sigma_iptables_flush).
#
# Критерий требует ОБЕ половины по каждому из трёх правил. Половины разнесены
# по способу проверки честно, а не по удобству:
#   * ЮНИТ — обязательная часть критерия («юнит, а не прогон»): он покрывает
#     и те половины, которые на живом стенде подать нельзя без вреда
#     (настоящий `iptables -F` на ноде k3s снёс бы её сеть — это не контроль,
#     а авария);
#   * ЖИВАЯ ЧАСТЬ — то, что подать можно: молчание фона (напечатано выше по
#     окну), инъекция периодического бикона, чтение и запись /var/log,
#     подделка строки iptables без самого flush.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.2.6 (половина 2/2): юнит + инъекции ---"
_w623_unit_out="$W623_ART/unit-6.2.2.6.txt"
if [ -x "$W623_GO" ] && [ -d "$W623_REPO/internal/correlator" ]; then
    ( cd "$W623_REPO" && "$W623_GO" test -count=1 -run 'Wave6_2_2|Wave6_2_1' ./internal/correlator/... ) > "$_w623_unit_out" 2>&1
    _w623_unit_rc=$?
    tail -5 "$_w623_unit_out" | sed 's/^/    /'
    if [ "$_w623_unit_rc" -eq 0 ]; then
        pass "6.2.2.6 ДОСТИГНУТО (половина «юнит»): обе половины трёх правок условий зелены (см. $_w623_unit_out)"
    else
        die "6.2.2.6 ПРОВАЛЕН (половина «юнит»): go test -run 'Wave6_2_2|Wave6_2_1' ./internal/correlator/... вернул $_w623_unit_rc — правки условий не держат ни фон, ни свой сценарий (см. $_w623_unit_out)"
    fi
else
    die "6.2.2.6 НЕИЗМЕРИМ (половина «юнит»): нет $W623_GO или дерева $W623_REPO/internal/correlator — юнит-половину критерия нечем взять"
fi

# Инъекция 1: периодический бикон. Одна и та же тройка (pid, daddr, dport),
# ≥3 соединения с ровным кадансом внутри 5 минут — ровно то, чего требует
# новое условие (conn_periodic_count_5m gt 2, conn_periodic_cv_5m lt 0.35).
# comm НЕ должен быть в списке исключений правила (curl/wget/... там есть),
# поэтому берётся копия оболочки с собственным именем.
# Алерт правила — severity=info, в стор он НЕ ПОПАДАЕТ (ровно причина, по
# которой сужение №220 по стору его не видело): читается ПО МЕТРИКЕ.
echo "  инъекция «периодический бикон» (одна тройка pid+addr+port, ровный каданс):"
_w623_beacon_before=$(( $(_w623_metric_sum ebpf_guard_alerts_total "c2_periodic_beacon_pattern beacon_fixed_interval") + $(_w623_metric_sum ebpf_guard_alerts_filtered_total "c2_periodic_beacon_pattern beacon_fixed_interval") + $(_w623_ratelimited "c2_periodic_beacon_pattern beacon_fixed_interval") ))
cp /bin/bash /usr/local/bin/w623beacon 2>/dev/null
# setsid уводит нагрузку из дерева самого контроля: исключение наблюдателя
# (5.9a) режет в ЯДРЕ и ослепило бы контроль (память
# observer-exclusion-blinds-controls) — ноль тогда был бы приборным.
setsid /usr/local/bin/w623beacon -c 'for i in 1 2 3 4 5; do exec 9<>/dev/tcp/127.0.0.1/19090 2>/dev/null; exec 9>&-; sleep 6; done' >/dev/null 2>&1
sleep "$W623_SETTLE"
_w623_beacon_after=$(( $(_w623_metric_sum ebpf_guard_alerts_total "c2_periodic_beacon_pattern beacon_fixed_interval") + $(_w623_metric_sum ebpf_guard_alerts_filtered_total "c2_periodic_beacon_pattern beacon_fixed_interval") + $(_w623_ratelimited "c2_periodic_beacon_pattern beacon_fixed_interval") ))
rm -f /usr/local/bin/w623beacon 2>/dev/null
echo "    срабатываний бикон-правил за инъекцию (по метрике, включая info): $(( _w623_beacon_after - _w623_beacon_before ))"
if [ "$(( _w623_beacon_after - _w623_beacon_before ))" -lt 1 ]; then
    die "6.2.2.6 ПРОВАЛЕН (половина «своё правило поднимается», инъекция бикона): пять соединений на один адрес:порт с кадансом 6с не подняли ни c2_periodic_beacon_pattern, ни beacon_fixed_interval. Порог периодичности (count>2, cv<0.35, окно 5 мин) выбран инженерной оценкой и живым трафиком до сих пор не проверялся (открытый вопрос 2) — этот ноль и есть его проверка"
else
    pass "6.2.2.6 ДОСТИГНУТО (половина «своё правило поднимается»): инъекция периодического бикона поднята правилом $(( _w623_beacon_after - _w623_beacon_before )) раз — порог периодичности подтверждён живым трафиком (открытый вопрос 2)"
fi

# Инъекция 2: sigma_log_deletion — обе половины (№234). Чтение /var/log
# молчит, запись поднимает.
echo "  инъекция «чтение против записи /var/log» (№234):"
_w623_ld_t=$(_w623_epoch)
journalctl -u "$W623_SVC" --since "-1 min" --no-pager >/dev/null 2>&1
sleep "$W623_SETTLE"
_w623_ld_read=$(_w623_alerts | jq --argjson t "$_w623_ld_t" '[.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.rule_id=="sigma_log_deletion") and (.comm=="journalctl"))]|length' 2>/dev/null || echo 0)
_w623_lw_t=$(_w623_epoch)
# Пачкой, а не одной записью: одиночная запись неотличима от потерянной
# сэмплированием (file_rate), и ноль был бы приборным.
setsid /bin/sh -c 'i=0; while [ $i -lt 300 ]; do echo w623-log-probe >> /var/log/w623-probe.log; i=$((i+1)); done' >/dev/null 2>&1
sleep "$W623_SETTLE"
_w623_ld_write=$(_w623_alerts | jq --argjson t "$_w623_lw_t" '[.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.rule_id=="sigma_log_deletion"))]|length' 2>/dev/null || echo 0)
# РАЗЛИЧИТЕЛЬ ПРИЧИНЫ. owasp_log_tampering стоит на том же пути, но БЕЗ
# условия на op. Если он поднялся, а sigma_log_deletion нет — событие дошло
# до движка, и немота у правила именно в оси op, а не в потере события,
# сэмплировании, исключении наблюдателя или неразрешённом пути. Без этой
# строки вердикт называл бы симптом и оставлял четыре объяснения.
_w623_ld_proof=$(_w623_alerts | jq --argjson t "$_w623_lw_t" '[.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.rule_id=="owasp_log_tampering") and ((.details["file.path"] // "")|test("w623-probe")))]|length' 2>/dev/null || echo 0)
rm -f /var/log/w623-probe.log 2>/dev/null
echo "    journalctl читает /var/log/journal → алертов sigma_log_deletion: $_w623_ld_read (обязан быть 0)"
echo "    300 записей в /var/log/w623-probe.log → алертов sigma_log_deletion: $_w623_ld_write (обязан быть ≥ 1)"
echo "    различитель: owasp_log_tampering на том же пути (условия на op НЕ имеет): ${_w623_ld_proof:-0}"
if [ "${_w623_ld_read:-0}" -gt 0 ]; then
    die "6.2.2.6 ПРОВАЛЕН (половина «фон молчит», №234): journalctl, ЧИТАЮЩИЙ /var/log/journal, поднял sigma_log_deletion $_w623_ld_read раз — правило по-прежнему совпадает шире своего имени"
elif [ "${_w623_ld_write:-0}" -lt 1 ]; then
    if [ "${_w623_ld_proof:-0}" -gt 0 ]; then
        die "6.2.2.6 ПРОВАЛЕН (половина «своё правило поднимается», №234): 300 записей в /var/log НЕ подняли sigma_log_deletion, при том что owasp_log_tampering на ТОМ ЖЕ пути поднялся $_w623_ld_proof раз. Событие дошло до движка с разрешённым путём — значит немота ровно в оси op: ни одно файловое событие этого пути не приходит с op=write, и сужение №234 сделало правило немым НА ЖИВОМ СТЕНДЕ, оставшись зелёным на юните (юнит строит событие с Op=write сам). Это находка о ПРОДУКТЕ, а не о контроле, и она же ставит под вопрос всякое правило вида «op in [write] + filename prefix»"
    else
        die "6.2.2.6 ПРОВАЛЕН (половина «своё правило поднимается», №234): 300 записей в /var/log не подняли ни sigma_log_deletion, ни owasp_log_tampering на том же пути — событие до движка не дошло вовсе (потеря, сэмплирование, исключение наблюдателя или неразрешённый путь), и ось op здесь ни при чём. Это НЕИЗМЕРИМОСТЬ подачи, а не вердикт правилу"
    fi
else
    pass "6.2.2.6 ДОСТИГНУТО (обе половины №234): чтение молчит ($_w623_ld_read), запись поднимает ($_w623_ld_write)"
fi

# Инъекция 3: sigma_iptables_flush — только НЕГАТИВНАЯ половина живьём.
# Позитивная (настоящий `iptables -F`) на ноде k3s снесла бы её сеть; она
# закрыта юнитом выше и подаваться на живой ноде НЕ ДОЛЖНА.
echo "  инъекция «строка iptables без flush» (№234-сосед, sigma_iptables_flush):"
_w623_ipt_t=$(_w623_epoch)
setsid /bin/sh -c 'grep iptables /etc/hosts; tar -F /tmp/w623-nope.txt' >/dev/null 2>&1
sleep "$W623_SETTLE"
_w623_ipt=$(_w623_alerts | jq --argjson t "$_w623_ipt_t" '[.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.rule_id=="sigma_iptables_flush"))]|length' 2>/dev/null || echo 0)
echo "    подделка «grep iptables …; tar -F …» → алертов sigma_iptables_flush: $_w623_ipt (обязан быть 0)"
echo "    позитивная половина (настоящий iptables -F) живьём НЕ подаётся: на ноде k3s это авария, а не контроль — она закрыта юнитом выше"
if [ "${_w623_ipt:-0}" -gt 0 ]; then
    die "6.2.2.6 ПРОВАЛЕН (половина «фон молчит», sigma_iptables_flush): строка, где iptables и -F принадлежат РАЗНЫМ командам, подняла правило $_w623_ipt раз — класс [^;|&] границу команды не удержал"
else
    pass "6.2.2.6 ДОСТИГНУТО (половина «фон молчит», sigma_iptables_flush): подделка через границу команды правило не подняла"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.3.7 ИНЦИДЕНТНЫЙ СЛОЙ ЗА ПРОГОН ЦЕЛИКОМ (№235, ПЕРЕСТРОЕН №251).
#
# №251: старая версия (6.2.2.9) проверяла корень инцидента только против
# runc:[...]/flannel/comm-измерителя и промахивалась мимо остального
# W623_NODE_ACTORS (containerd-shim, k3s-server, kubelet, coredns,
# local-path-prov, kube-proxy, pause, iptables/ip6tables, kubectl, bridge,
# loopback) — список УЖЕ БЫЛ в файле, цикл его не использовал. Здесь корень
# сверяется с ПОЛНЫМ W623_NODE_ACTORS ∪ W623_INSTR_COMMS_FLAT.
#
# Плюс разделение по фазам: инцидент таким корнем, чьё время попадает в
# [_w623_attack_phase_start, _w623_attack_phase_end] (окно позитивных
# контролей и инъекций этого же прогона), есть ОЖИДАЕМЫЙ true positive —
# печатается, но в ложь не засчитывается. Инцидент того же корня ВНЕ этого
# окна (то есть в тихом окне объёма, до открытия входа) — засчитывается:
# там штатная работа ноды не была спровоцирована ничем этого прогона, и
# incident_confirmed_attack на ней — ложь слоя, а не ожидаемый эффект
# инъекции. Не «величина без порога», как в 6.2.1.5: вердикт.
# ─────────────────────────────────────────────────────────────────────────────
_w623_attack_phase_end=$(_w623_epoch)
printf 'attack_phase_start=%s\nattack_phase_end=%s\n' "$_w623_attack_phase_start" "$_w623_attack_phase_end" >> "$W623_ART/window-epoch.txt"
echo "--- 6.2.3.7: инцидентный слой не называет атакой штатную работу ноды ---"
echo "  фаза атак (позитивные контроли+инъекции этого прогона): [$(_w623_utc "$_w623_attack_phase_start"), $(_w623_utc "$_w623_attack_phase_end")]"
_w623_alerts > "$W623_ART/alerts-incidents.json"
_w623_inc_all=$(jq '[.[]|select(.rule_id=="incident_confirmed_attack")]|length' "$W623_ART/alerts-incidents.json" 2>/dev/null || echo 0)
echo "  incident_confirmed_attack за прогон: $_w623_inc_all"
echo "  по корневому comm:"
jq -r '[.[]|select(.rule_id=="incident_confirmed_attack")]|group_by(.details.root_comm // .comm)|map({c:(.[0].details.root_comm // .[0].comm),n:length})|sort_by(-.n)[]|"    \(.c): \(.n)"' "$W623_ART/alerts-incidents.json" 2>/dev/null | head -15
_w623_inc_bad=$(jq --arg instr "$W623_INSTR_COMMS_FLAT" --arg actors "$W623_NODE_ACTORS" \
    --argjson ps "$_w623_attack_phase_start" --argjson pe "$_w623_attack_phase_end" '
    [ .[] | select(.rule_id=="incident_confirmed_attack")
      | select(((.details.root_comm // .comm) as $c
                | (($actors|split(" "))|index($c)) != null or (($instr|split(" "))|index($c)) != null))
      | select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // -1) as $t | $t < $ps or $t > $pe)) ] | length' "$W623_ART/alerts-incidents.json" 2>/dev/null || echo 0)
_w623_inc_expected=$(jq --arg instr "$W623_INSTR_COMMS_FLAT" --arg actors "$W623_NODE_ACTORS" \
    --argjson ps "$_w623_attack_phase_start" --argjson pe "$_w623_attack_phase_end" '
    [ .[] | select(.rule_id=="incident_confirmed_attack")
      | select(((.details.root_comm // .comm) as $c
                | (($actors|split(" "))|index($c)) != null or (($instr|split(" "))|index($c)) != null))
      | select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // -1) as $t | $t >= $ps and $t <= $pe)) ] | length' "$W623_ART/alerts-incidents.json" 2>/dev/null || echo 0)
_w623_inc_names=$(jq -r --arg instr "$W623_INSTR_COMMS_FLAT" --arg actors "$W623_NODE_ACTORS" \
    --argjson ps "$_w623_attack_phase_start" --argjson pe "$_w623_attack_phase_end" '
    [ .[] | select(.rule_id=="incident_confirmed_attack")
      | select(((.details.root_comm // .comm) as $c
                | (($actors|split(" "))|index($c)) != null or (($instr|split(" "))|index($c)) != null))
      | select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // -1) as $t | $t < $ps or $t > $pe))
      | (.details.root_comm // .comm) ] | unique | join(" ")' "$W623_ART/alerts-incidents.json" 2>/dev/null)
echo "  из них с корнем нодовый актор/измеритель ВНЕ фазы атак (ложь): $_w623_inc_bad (${_w623_inc_names:-нет})"
echo "  из них с корнем нодовый актор/измеритель ВНУТРИ фазы атак (ожидаемый TP, в ложь не идёт): $_w623_inc_expected"
if [ "${_w623_inc_all:-0}" -gt 0 ]; then
    echo "  доля ложных от всех инцидентов прогона: $(awk -v b="${_w623_inc_bad:-0}" -v n="$_w623_inc_all" 'BEGIN{printf "%.1f%%", 100.0*b/n}')"
fi
if [ "${_w623_inc_bad:-0}" -gt 0 ]; then
    die "6.2.3.7 ПРОВАЛЕН: инцидентный слой назвал подтверждённой атакой штатную работу ноды или работу самого измерителя ВНЕ окна позитивных контролей — $_w623_inc_bad инцидентов от ${_w623_inc_names}. Порог слою назначается ПОСЛЕ того, как ложь убрана, а не вместо этого (находка №235/№251)"
else
    pass "6.2.3.7 ДОСТИГНУТО: ни один incident_confirmed_attack ВНЕ фазы атак не имеет корнем нодового актора или comm измерителя (всего инцидентов-атак за прогон: $_w623_inc_all, из них ожидаемых true positive внутри фазы: $_w623_inc_expected)"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.3.11 ПОЗИТИВНЫЙ ПОДКОНТРОЛЬ ЗАМОРОЗКИ (№237, открытый вопрос 11).
#
# ПОЧЕМУ САМЫМ ПОСЛЕДНИМ. Подконтроль ВРЕМЕННО понижает
# max_signatures_per_workload и перезапускает агент: это обнуляет счётчики
# метрик и базу дрейфа. Любой контроль, стоящий после него, мерил бы уже
# другой агент. Конфиг восстанавливается и агент перезапускается обратно
# ВСЕГДА — в том числе если подконтроль провалится (trap).
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.3.11 (вердикт): заморозка доказывается приращением счётчика ---"
_w623_cfg_bak="$W623_ART/config-test.yaml.orig"
_w623_restore_cfg() {
    if [ -f "$_w623_cfg_bak" ]; then
        cp "$_w623_cfg_bak" "$_w623_cfg" 2>/dev/null
        systemctl restart "$W623_SVC" 2>/dev/null
        echo "  конфиг стенда восстановлен из $_w623_cfg_bak, агент перезапущен"
    fi
    rm -rf /root/w623-sig 2>/dev/null
    rm -f /usr/local/bin/w623sig 2>/dev/null
}
trap '_w623_restore_cfg' EXIT

if ! grep -qE '^\s*max_signatures_per_workload:' "$_w623_cfg" 2>/dev/null; then
    die "6.2.3.11 НЕИЗМЕРИМ: в $_w623_cfg нет ключа max_signatures_per_workload — понизить его нечем, и дельта 0 останется неотличима от «счётчик сломан» (находка №237)"
else
    cp "$_w623_cfg" "$_w623_cfg_bak" 2>/dev/null
    sed -i 's/^\(\s*\)max_signatures_per_workload:.*/\1max_signatures_per_workload: 3/' "$_w623_cfg"
    echo "  max_signatures_per_workload временно понижен до 3 (было ${_w623_maxsig:-?}), рестарт агента"
    systemctl restart "$W623_SVC" 2>/dev/null
    sleep "$W623_SETTLE"
    _w623_capA=$(_w623_metric_sum ebpf_guard_drift_baseline_signature_cap_reached_total "")
    # Нагрузка: один comm (=один WorkloadKey) открывает ДЕСЯТКИ РАЗНЫХ путей
    # под /root/ — каждый путь есть отдельная сигнатура drift_new_file_dir_sensitive
    # (normalizeDriftPath сохраняет путь целиком, схлопывая лишь числовые
    # сегменты). setsid — по той же причине, что у инъекции бикона.
    mkdir -p /root/w623-sig 2>/dev/null
    for _i in $(seq 1 40); do echo "s$_i" > "/root/w623-sig/f$_i" 2>/dev/null; done
    cp /bin/cat /usr/local/bin/w623sig 2>/dev/null
    _w623_sig_read=0
    for _i in $(seq 1 40); do
        _w623_sig_read=$(( _w623_sig_read + $(setsid /usr/local/bin/w623sig "/root/w623-sig/f$_i" 2>/dev/null | wc -c) ))
    done
    sleep "$W623_SETTLE"
    _w623_capB=$(_w623_metric_sum ebpf_guard_drift_baseline_signature_cap_reached_total "")
    _w623_capD=$(( _w623_capB - _w623_capA ))
    _w623_frozen_now=$(_w623_metric_sum ebpf_guard_drift_baseline_frozen_workloads "")
    echo "  сторож результата: прочитано байт нагрузкой = $_w623_sig_read (40 разных путей под /root/, один comm=w623sig)"
    echo "  приращение signature_cap_reached_total на подконтроле: $_w623_capD (было $_w623_capA, стало $_w623_capB); замороженных нагрузок сейчас: $_w623_frozen_now"
    if [ "${_w623_sig_read:-0}" -lt 1 ]; then
        die "6.2.3.11 НЕИЗМЕРИМ: нагрузка не прочитала ни байта — ноль приращения приборный, а не вердикт (память positive-control-needs-result-sentinel)"
    elif [ "$_w623_capD" -gt 0 ]; then
        pass "6.2.3.11 ДОСТИГНУТО: при max_signatures_per_workload=3 счётчик заморозки вырос на $_w623_capD — приращение ДОКАЗАНО, а не выведено из наличия имени метрики в выдаче (находка №237)"
    else
        die "6.2.3.11 ПРОВАЛЕН: нагрузка завела 40 различных сигнатур на ОДНУ нагрузку при потолке 3, а signature_cap_reached_total не вырос ни разу. Два возможных объяснения, и оба — находка: счётчик не движется, либо дерево нагрузки срезано в ядре исключением наблюдателя 5.9a (память observer-exclusion-blinds-controls) — тогда ноль приборный и контроль требует носителя вне дерева измерителя"
    fi
fi
_w623_restore_cfg
trap - EXIT

echo "--- уборка ---"
"$W623_KUBECTL" -n "$W623_NS" delete pod --all --ignore-not-found --wait=false >/dev/null 2>&1
rm -f /usr/local/bin/w623hostcat /usr/local/bin/w623sig /usr/local/bin/w623beacon 2>/dev/null
rm -rf /root/w623-sig /tmp/w623-bypass /tmp/w623-chmod 2>/dev/null

echo
echo "=== ИТОГ КОНТРОЛЕЙ ВОЛНЫ 6.2.3: проваленных $WAVE623_FAILS ==="
echo "артефакты: $W623_ART"
[ "$WAVE623_FAILS" -gt 0 ] && echo "вердикты: $W623_VERDICTS"
exit 0
