#!/bin/bash
# wave6.2.5-controls.sh — контроли волны 6.2.5 (долг прогона 6.2.4, находки
# №261…№270). Механический форк wave6.2.4-controls.sh (w624→w625,
# 6.2.4→6.2.5 всюду, КРОМЕ четырёх долговых меток 6.2.4.5/.6/.7/.12 — они
# сохраняют СВОИ номера намеренно, память criteria-index-pins-replay-labels).
#
# ЭТОТ ФОРК — РАБОТА ITEM 5 ПОСТАНОВКИ ВОЛНЫ (plan.md, §6.2.5, находки
# №267/№268): измеритель чинится по трём точкам.
#   (1) 6.2.5.1 получает три подпункта, потерянные в 6.2.4 (№268): сторож
#       нуля на всех четырёх правилах-двойниках №253 (w625_daemon_twin_exceptions,
#       wave6.2.5-metrics-lib.sh), ненулевой rule_exceptions_total по КАЖДОМУ
#       из четырёх rule_id (обоим именованным исключениям — verified-daemon-image
#       и новому verified-daemon-lineage, item 1 волны), и
#       exe_path_lookups_total{result} обеими границами окна.
#   (2) 6.2.5.11 зовёт _w625_metric_sum с фильтром по comm="w625sig" вместо
#       пустого аргумента (№267 — пустой фильтр суммировал ВСЕ comm, включая
#       позитивные контроли bash/sshd; сама возможность фильтровать в
#       _w625_metric_sum уже существовала).
#   (3) Новый критерий 6.2.5.15 печатает долю величины на нерезолвленном
#       образе (exe_path_lookups_total{unresolved}/(resolved+unresolved)) и
#       поимённый список comm тех алертов окна, чьё правило несёт исключение
#       на exe_path/lineage — диагностика гонки №261, порог не назначается.
#
# ВТОРОЙ ПРОХОД (08.09.2026): КРИТЕРИИ ITEMS 1/2/3/4 ВЖАТЫ В ЭТОТ ФАЙЛ.
#   6.2.4.5  — четыре половины исхода №253/№261, включая НОВУЮ четвёртую:
#              подачу от короткоживущего потомка cron (задание в /etc/cron.d)
#              и требование ненулевого rule_exceptions_total{verified-daemon-lineage}
#              как сторожа ложного нуля;
#   6.2.4.6  — заменяет 6.2.3.7 (метка сохранена, №269) и вычитает окно
#              стартов подов контроля 6.2.5.10 (item 3, №263);
#   6.2.4.7  — побег по-прежнему промотируется (отрицательный контроль item 2);
#   6.2.4.12 — время до заморозки на БОЕВОМ капе, поимённо, без порога;
#   6.2.5.16 — шлюз промоушена судится по корню; судит ОБА окна старта
#              контейнера — своё и вычтенное из 6.2.4.6 (item 3 ничего не теряет);
#   6.2.5.17 — stuck/overdue поимённо на обеих границах окна + именной
#              переход из журнала (item 4);
#   6.2.5.14 — сводный вердикт регрессионного пучка (реестр вынесенных меток).
#
# ITEM 6 (№269/№270 — страж полноты пайплайна, 6.2.5.18) ЖИВЁТ ВНЕ ЭТОГО
# ФАЙЛА: wave6.2.5-completeness-guard.sh, вызывается run-6.2.5-pipeline.sh
# ПОСЛЕ этого скрипта, сверяя таблицу меток постановки со списком меток, по
# которым здесь и в пайплайне реально вынесен вердикт (ПРОВАЛЕН/ДОСТИГНУТО/
# НЕИЗМЕРИМ в run-6.2.5.log). Расхождение — отказ собрать архив. Гейт
# офлайн-тестируем через `wave6.2.5-completeness-guard.sh --self-test`.
#
#
# ИСТОРИЯ, item 3 постановки 6.2.3 (№249 + решение 4 — механизм немоты op=write установлен подачей,
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
# ИСТОРИЯ, item 4 постановки 6.2.3 (№248, сужение верхушки шума, 06.09.2026): sigma_failed_login_syscall_daemon
# и rootkit_pam_module_added_daemon (rules/sigma-linux.yaml,
# rules/rootkit-detection.yaml) сужены осью op=write — были: любой read/open
# от sshd|cron, 3090/2400 и 2970/2280 алертов/окно на двух архивах 6.2.2,
# первые два источника разбивки (в) (6.2.5.2). Критерий 6.2.3.13 берёт обе
# половины живьём: фон (26 sshd-подключений за 90 с реального
# ssh-брутфорса на ebaka2) молчит; подделка identity (comm=sshd/cron через
# копию бинаря, а не `exec -a` — argv[0] не задаёт comm, задаёт basename
# пути execve), ДЕЙСТВИТЕЛЬНО пишущая в PAM, по-прежнему поднимает оба
# правила (severity=info, считаются в alerts_filtered_total, входят в
# формулу (а) — решение 1). Записи new-rules.txt датой 20260906.
#
# ИСТОРИЯ, item 1 постановки 6.2.3 (чинится измеритель — до всего остального):
#   №251  Инцидентный слой (6.2.2.9 → 6.2.3.7): вердикт строится на
#         ПОЛНОМ W625_NODE_ACTORS (список уже был в файле, цикл его не
#         использовал — критерий 6.2.2.9 проверял только
#         runc:[...]/flannel/comm измерителя и промахивался мимо
#         containerd-shim/k3s-server/kubelet/coredns/etc). Добавлено
#         разделение по фазам: инцидент с корнем из
#         W625_NODE_ACTORS∪W625_INSTR_COMMS_FLAT, чьё время попадает в окно
#         позитивных контролей [attack_phase_start, attack_phase_end], есть
#         ОЖИДАЕМЫЙ true positive и в ложь не засчитывается; вне окна —
#         засчитывается. Границы фазы пишутся эпохами в тот же
#         window-epoch.txt, что и границы тихого окна.
#   №252  HOME контроля — $W625_ART, а не /root (иначе .curlrc, .kube/cache,
#         .jq, .cache/go-build сами становятся источником алертов
#         drift_new_file_dir_sensitive, находка №252). Критерий доли
#         измерителя (6.2.2.5 → 6.2.5.3) проверяет ОБА пути — $W625_ART и
#         /root — и остаётся ВЕРДИКТОМ, а не поправкой к чтению. Список comm
#         измерителя (W625_INSTR_COMMS_FLAT) строится САМОСКАНИРОВАНИЕМ
#         текста этого файла (какие внешние команды он реально вызывает), а
#         не задаётся руками; sleep/setsid/sh/dd/printf обязаны быть
#         найдены — иначе преflight ПРОВАЛЕН.
#
# ИСТОРИЯ, item 2 постановки 6.2.3 (№248 + решение 1 — формула гейта закрывается):
#   Критерий 6.2.5.1 (было 6.2.2.1) печатает все ЧЕТЫРЕ слоя раздельно:
#   alerts_total, alerts_filtered_total, alerts_ratelimited_by_rule_total,
#   alerts_dedup_dropped_by_rule_total. Вердикт по-прежнему выносится
#   формулой (а) = alerts_total + alerts_filtered_total (info включительно,
#   решение 1: (б) без info отвергнута — переименование объёма, №232). Рядом
#   ОБЯЗАТЕЛЬНА величина (в) = сумма всех четырёх слоёв, БЕЗ порога (правило
#   5.9.6 — порог впервые измеренной величине не назначается). Страж ложного
#   PASS сохранён и уточнён: PASS по (а) при непустом списке правил с
#   ненулевым срезом лимитера ЗА ОКНО есть НЕИЗМЕРИМОСТЬ, а не взятый
#   критерий (FAIL при тех же условиях действителен). Новый критерий 6.2.5.2
#   ранжирует поимённую разбивку по (в) — через w625_value_v_by_rule
#   (wave6.2.5-metrics-lib.sh) — а не по остатку после лимитера, как делала
#   6.2.2.3; офлайн-сторож на ОБОИХ архивах 6.2.2 проверяет, что первыми
#   встают sigma_failed_login_syscall_daemon и rootkit_pam_module_added_daemon
#   (3090/2970 на collect-6.2.2-run1, 2400/2280 на collect-6.2.2), а не
#   c2_periodic_beacon_pattern (985/985) — см. --self-test в
#   wave6.2.5-metrics-lib.sh.
#
# ЧТО НАСЛЕДОВАНО БЕЗ ИЗМЕНЕНИЙ ИЗ 6.2.2 (перенумеровано механически, подача
# та же): №238 (список срезанных правил по метрике, w625_ratelimited_by_rule),
# №239 (разбивка величины по метрике, 6.2.2.3 остаётся под старым номером —
# критерий 6.2.3.12 в 6.2.3, регрессионный пучок этой волны — 6.2.5.14, ниже), №240 (эпоха вместо ISO-8601 для journalctl), №241
# (копия лога — последним действием, в пайплайне), №237 (заморозка базы
# дрейфа приращением счётчика), №236 (цена старта пода, порог 45/под), №244
# (профиль и потолок ресурсов пайплайном, 6.2.5.8/6.2.5.9), №243 (живой
# сторож monitored_syscalls).
#
# ЧТО ПЕРЕНЕСЕНО РЕГРЕССИЕЙ И ПОЧЕМУ СОХРАНИЛО СТАРЫЕ НОМЕРА. Контроли
# 6.2.1.2, 6.2.1.2b, 6.2.1.3, 6.2.1.6, 6.2.1.8, 6.2.1.9, 6.2.2.2, 6.2.2.3,
# 6.2.2.6, 6.2.3.5, 6.2.3.6, 6.2.3.13, 6.2.3.14 — тринадцать штук (плюс
# 6.2.4.6, инцидентный слой, ПЕРЕИМЕНОВАННЫЙ из 6.2.3.7 и дополненный
# вычитанием окна стартов подов — item 3) — стоят под СВОИМИ
# старыми метками (перечень зафиксирован постановкой волны 6.2.5, plan.md,
# критерий 6.2.5.14). Их метки НЕ перенумерованы намеренно (память
# criteria-index-pins-replay-labels): перенумерация меток — ровно то, что
# роняет преflight на прошлых архивах. Новые/изменённые критерии этой волны
# несут номера 6.2.5.*, и вердикт-файл читается однозначно.
#
# ЗАПУСК. Скрипт не самостоятелен: нужен живой агент с kubernetes.enabled:true
# и готовая нода. Провал контроля НЕ убивает чужой прогон (волна 6.0m,
# память die-only-for-unmeasurable-run); die() здесь только считает и пишет
# вердикт.
#   W625_API           — база HTTP API агента (http://<host>:19090)
#   W625_TOKEN         — bearer-токен (формат файла токена — admin=<...>)
#   W625_KUBECTL       — путь к kubectl
#   W625_NS            — namespace контролей (по умолчанию w625)
#   W625_WINDOW        — длина тихого окна объёма, с (по умолчанию 600)
#   W625_GATE          — гейт волны 6, алертов/ч (по умолчанию 100)
#   W625_GATE_FORMULA  — all | noinfo (решение по №232; по умолчанию all)
#   W625_CHURN_BUDGET  — порог цены старта пода (по умолчанию 45, №236)
#   W625_PROFILE_SECS  — длина окна pprof (по умолчанию 30, №244)
#   W625_SMOKE         — 1: смок-режим, все ветки исполняются на коротких
#                        временах; длинные ожидания укорочены, НИ ОДИН блок
#                        не пропускается (память smoke-only-does-not-cover-attack-window)
set -u
export TZ=UTC   # см. _w625_epoch/_w625_utc: встроенный printf вместо внешнего `date`

VPS_IP="${VPS_IP:-localhost}"
W625_API="${W625_API:-http://${VPS_IP}:19090}"
W625_TOKEN="${W625_TOKEN:-${EBPF_GUARD_TOKEN:-$(grep '^admin=' /var/lib/ebpf-guard/token 2>/dev/null | cut -d= -f2)}}"
W625_KUBECTL="${W625_KUBECTL:-/usr/local/bin/kubectl}"
W625_NS="${W625_NS:-w625}"
W625_WINDOW="${W625_WINDOW:-600}"
W625_GATE="${W625_GATE:-100}"
W625_GATE_FORMULA="${W625_GATE_FORMULA:-all}"
W625_CHURN_BUDGET="${W625_CHURN_BUDGET:-45}"
W625_PROFILE_SECS="${W625_PROFILE_SECS:-30}"
W625_SETUP="${W625_SETUP:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
W625_SETTLE="${W625_SETTLE:-20}"
W625_POS_TIMEOUT="${W625_POS_TIMEOUT:-120}"
W625_CHURN="${W625_CHURN:-3}"
W625_SVC="${W625_SVC:-ebpf-guard-test.service}"
W625_VERDICTS="${W625_VERDICTS:-/root/wave6.2.5-controls-verdicts.txt}"
# КАТАЛОГ АРТЕФАКТОВ — ВНЕ /root/, и это не вкусовщина, а вторая половина
# критерия 6.2.5.3 (открытый вопрос 16). drift_new_file_dir_sensitive стоит на
# префиксах /root/, /home/, /var/spool/cron/, /etc/cron.d/, /etc/systemd/system/
# (rules/drift-rules.txt), то есть КАЖДАЯ запись снимка метрик в /root/… по
# построению производит алерт, который контроль потом считает частью
# измеренной величины. Смок 06.09.2026 это и напечатал. Порядок операций
# (правка №242) сужает окно гонки, но не убирает источник; убирает его путь.
# /var/lib/ вне всех файловых префиксов правил (проверено grep по rules/:
# waagent/tomcat/mysql/…/docker/containerd/rancher/kubelet — ни один не наш).
W625_ART="${W625_ART:-/var/lib/w625-artifacts}"
W625_REPO="${W625_REPO:-/opt/ebpf-guard}"
W625_GO="${W625_GO:-/usr/local/go/bin/go}"
W625_SMOKE="${W625_SMOKE:-0}"
W625_QUIET_LEAD="${W625_QUIET_LEAD:-70}"
W625_OPEN_SETTLE="${W625_OPEN_SETTLE:-15}"

WAVE624_FAILS=0
# Артефакты пишутся в КАТАЛОГ ЭТОГО ПРОГОНА и он очищается на старте
# (находка №228).
rm -rf "$W625_ART" 2>/dev/null || true
mkdir -p "$W625_ART" 2>/dev/null || true

# №258 (item 8 постановки 6.2.5): ФИФО для read-based ожидания тихого окна
# создаётся ЗДЕСЬ, задолго до t0, а НЕ рядом с самим ожиданием. `mkfifo` —
# внешняя команда (execve, comm=mkfifo) не хуже `sleep` в этом смысле; если
# вызвать её после фиксации t0, она сама станет тем самым инструментальным
# событием ВНУТРИ окна, которое чинит вся эта правка. Once здесь, до
# преflight'а и открытия окна, mkfifo не попадает в измеряемый период вовсе.
W625_QUIET_FIFO="$W625_ART/.quiet-window-fifo"
mkfifo "$W625_QUIET_FIFO" 2>/dev/null || true

# №252: HOME контроля — В КАТАЛОГЕ АРТЕФАКТОВ, не /root. Каждый curl/kubectl/
# jq, запущенный из-под этого скрипта под root, пишет свой конфиг/кеш в
# $HOME (.curlrc читается curl, .kube/cache — kubectl, .cache/go-build — go
# tool pprof в критерии 6.2.5.8); при HOME=/root это ровно тот путь, за
# которым следит drift_new_file_dir_sensitive (rules/drift-rules.txt,
# префикс /root/), и запись в него сама производит алерт, входящий в
# измеренную величину. Экспортируется ДО первого curl/kubectl этого файла.
export HOME="$W625_ART"
mkdir -p "$HOME" 2>/dev/null || true

# РЕЕСТР ВЫНЕСЕННЫХ ВЕРДИКТОВ (критерий 6.2.5.14 + вход стража 6.2.5.18).
# Пишется ОБЕИМИ функциями вердикта, а не только die(): регрессионный пучок
# 6.2.5.14 обязан отличить «метка вынесла ДОСТИГНУТО» от «метка не вынесла
# ничего», а вердикт-файл до этой правки хранил только провалы, и по нему
# тринадцать регрессий были неотличимы от нереализованных (тот же класс, что
# №269/№270, только внутри одного скрипта).
W625_EMITTED="$W625_ART/emitted-labels.txt"
: > "$W625_EMITTED" 2>/dev/null || true
_w625_record_label() { # $1=OK|FAIL $2...=текст вердикта
    local _st="$1"; shift
    local _lbl
    _lbl=$(printf '%s' "$*" | grep -oE '6\.2\.[12345]\.[A-Za-z0-9]+' | head -1)
    [ -n "${_lbl:-}" ] && echo "$_lbl $_st" >> "$W625_EMITTED" 2>/dev/null
    return 0
}
die() {
    echo "=== КОНТРОЛЬ ПРОВАЛЕН (прогон НЕ прерывается — волна 6.0m): $* ==="
    WAVE624_FAILS=$((WAVE624_FAILS + 1))
    _w625_record_label FAIL "$*"
    {
        echo "критерий=$(printf '%s' "$*" | grep -oE '6\.2\.[12345]\.[A-Za-z0-9]+' | head -1)"
        echo "время_UTC=$(date -u +%FT%TZ)"
        echo "причина: $*"
        echo "---"
    } >> "$W625_VERDICTS" 2>/dev/null || true
    return 0
}
pass() { echo "OK: $*"; _w625_record_label OK "$*"; }

: > "$W625_VERDICTS" 2>/dev/null || true
echo "# wave6.2.5-controls.sh, прогон от $(date -u +%FT%TZ)" >> "$W625_VERDICTS"
echo "=== КОНТРОЛИ ВОЛНЫ 6.2.5 (долг прогона 6.2.3, находки №253…№260) ==="
echo "режим: $([ "$W625_SMOKE" = "1" ] && echo 'СМОК (короткие времена, все ветки исполняются)' || echo 'полный')"
echo "формула гейта (решение 1, №232/№248): $W625_GATE_FORMULA (all = включая severity=info, noinfo = без него; обе величины и величина (в) печатаются в любом случае)"
echo "HOME контроля (№252): $HOME"

# ─────────────────────────────────────────────────────────────────────────────
# ИЗМЕРИТЕЛЬНАЯ БИБЛИОТЕКА (№238/№239). Берётся source'ом, а не копией: у
# копии нет офлайн-сторожа, а у этого файла он есть и проходит на
# collect-6.2.1 (--self-test). Отсутствие библиотеки — не «работаем без
# разбивки», а неизмеримость критериев 6.2.2.2/6.2.2.3.
# ─────────────────────────────────────────────────────────────────────────────
W625_LIB="$W625_SETUP/wave6.2.5-metrics-lib.sh"
W625_LIB_OK=0
if [ -r "$W625_LIB" ]; then
    # shellcheck source=/dev/null
    . "$W625_LIB" && W625_LIB_OK=1
fi
# ВОССТАНОВЛЕНИЕ РЕЖИМА ОБОЛОЧКИ — не косметика, а дефект, пойманный смоком
# 06.09.2026 ДО прогона. wave6.2.5-metrics-lib.sh объявляет `set -euo pipefail`
# (правильно для самостоятельного файла со своим --self-test), но `source`
# переносит этот режим В ВЫЗЫВАЮЩИЙ скрипт. Контроли построены на том, что
# `grep`/`jq` без совпадения возвращают 1 и это НОРМАЛЬНЫЙ исход измерения
# («такого в журнале нет»), а не сбой: под `set -e` первый же такой grep убивал
# контроли МОЛЧА, посреди 6.2.1.6, и пайплайн спокойно собирал архив без
# единого критерия. Ровно тот класс, который ловит сама волна: измеритель,
# печатающий готовый вердикт по неполному прогону.
set +e +o pipefail
set -u
# Список правил-двойников №253 приходит из библиотеки (W625_TWIN_RULES).
# Дублируется значением по умолчанию: без библиотеки контроли ниже читают эту
# переменную под `set -u` и умерли бы на «unbound variable» посреди
# измерения, вместо того чтобы объявить критерий НЕИЗМЕРИМЫМ и идти дальше
# (память die-only-for-unmeasurable-run).
: "${W625_TWIN_RULES:=sigma_passwd_shadow_read_daemon sigma_log_deletion_daemon sigma_utmp_wtmp_modified_daemon sensitive_file_read_daemon}"
[ "$W625_LIB_OK" -eq 1 ] || die "6.2.2.2 НЕИЗМЕРИМ: не подключилась $W625_LIB — список срезанных правил и разбивка величины строились бы снова по стору, то есть воспроизвели бы дефекты №238/№239"

# Правила, для которых нода — единственный вход.
W625_K8S_RULES="cis_5_1_3_secret_access k8s_sa_token_read k8s_sa_token_projected_read k8s_hostpath_kubelet_access"
W625_HOST_RULES="cis_5_1_3_secret_access k8s_hostpath_kubelet_access"
W625_NODE_ACTORS="k3s-server kubelet containerd containerd-shim containerd-shim-runc-v2 runc runc:[1:CHILD] runc:[2:INIT] coredns local-path-prov kube-proxy pause iptables ip6tables kubectl flannel bridge loopback"

# ---------------------------------------------------------------------------
# №252: список comm ИЗМЕРИТЕЛЯ строится САМОСКАНИРОВАНИЕМ этого файла, а не
# задаётся руками. Находка №242 чинилась вручную дописанным cat/tail; находка
# №252 требует, чтобы список впредь не отставал от того, что скрипт реально
# запускает — кандидаты, найденные как отдельное слово (после пробела,
# `;`, `&`, `|`, `(` или `/`) где-то в тексте ЭТОГО файла, ВКЛЮЧАЮТСЯ
# автоматически. Список кандидатов конечен (это самоскан по словарю, а не
# полный статический анализ), но покрывает всё, чем контроль реально
# пользуется: sleep/setsid/sh/dd обязаны быть найдены — это явное требование
# критерия 6.2.5.3, и его отсутствие есть ПРОВАЛ преflight'а, а не тихая
# недостача.
# ---------------------------------------------------------------------------
W625_INSTR_CANDIDATES="curl jq bash sh head sed awk date tr sort systemctl journalctl cat tail stat find wc cut grep sleep setsid dd printf cp chmod mkdir rm seq pgrep readlink kubectl go"
W625_INSTR_COMMS_FLAT=""
W625_SELF="$W625_SETUP/wave6.2.5-controls.sh"
if [ -r "$W625_SELF" ]; then
    # Скан ИСПОЛНЯЕМОГО текста: строки-комментарии (включая эту преамбулу и
    # саму строку W625_INSTR_CANDIDATES, где перечислены ВСЕ кандидаты разом
    # и потому она тривиально "находит" каждый) вычищены — иначе самоскан
    # находит слово в СВОЁМ ЖЕ описании, а не в реальном вызове.
    _w625_selfcode=$(grep -vE '^[[:space:]]*#' "$W625_SELF" | grep -v '^W625_INSTR_CANDIDATES=')
    for _w625_c in $W625_INSTR_CANDIDATES; do
        if printf '%s\n' "$_w625_selfcode" | grep -qE "(^|[[:space:];&|(/])${_w625_c}([[:space:]\"'\`]|\$)" 2>/dev/null; then
            W625_INSTR_COMMS_FLAT="$W625_INSTR_COMMS_FLAT $_w625_c"
        fi
    done
fi
W625_INSTR_COMMS_FLAT="${W625_INSTR_COMMS_FLAT# }"
echo "  №252, список comm измерителя (самосканирование $W625_SELF): ${W625_INSTR_COMMS_FLAT:-ПУСТ}"
# ТРЕБОВАНИЕ КРИТЕРИЯ 6.2.5.3 (postановка): sleep/setsid/sh/dd обязаны
# присутствовать в списке. `dd` требуется здесь начиная с item 3 (6.2.3.5,
# №249, механизм немоты op=write — нагрузка `dd of=…`) — реальный вызов
# теперь есть в файле, страж больше не отложен.
for _w625_must in sleep setsid sh dd; do
    case " $W625_INSTR_COMMS_FLAT " in
        *" $_w625_must "*) ;;
        *) die "6.2.5.3 НЕИЗМЕРИМ: самоскан не нашёл '$_w625_must' в тексте $W625_SELF — обязательная команда списка (№252) не обнаружена; список comm измерителя неполон по построению" ;;
    esac
done
# Та же плоская строка — как JSON-массив, для jq (критерий 6.2.5.3).
W625_INSTR_COMMS=$(printf '%s\n' $W625_INSTR_COMMS_FLAT | jq -R . | jq -s -c . 2>/dev/null)
[ -n "${W625_INSTR_COMMS:-}" ] && [ "$W625_INSTR_COMMS" != "null" ] || W625_INSTR_COMMS='[]'

_w625_curl() { curl -s --max-time 30 -H "Authorization: Bearer $W625_TOKEN" "$@"; }
_w625_alerts() { _w625_curl "$W625_API/api/v1/alerts?limit=200000"; }
_w625_metrics() { _w625_curl "$W625_API/metrics"; }
# ЭПОХА — ВСТРОЕННЫМ printf, а не `date`. Каждый вызов внешнего `date` —
# это execve, а значит собственное событие измерителя: на прогоне 06.09.2026
# критерий 6.2.5.3 упал ровно на двух алертах comm=date, которые породил сам
# контроль строкой «окно открыто …» СРАЗУ ПОСЛЕ фиксации t0. Встроенный
# printf процесса не создаёт вовсе, поэтому источник исчезает, а не сдвигается.
# TZ=UTC экспортирован выше — форматы ниже эквивалентны `date -u`.
_w625_epoch() { local _e; printf -v _e '%(%s)T' -1; printf '%s' "$_e"; }
_w625_utc() { printf '%(%Y-%m-%dT%H:%M:%SZ)T' "$1"; }

# Сумма метрики по срезу. Прямая дельта двух срезов, а не строка таблицы:
# строка индексирована срезом лимитера (память f6b-table-indexed-by-limiter-cut).
_w625_metric_sum() { # $1=metric $2=список label-значений (rule_id ИЛИ comm; пусто = все) [$3=файл среза]
    # №267 (item 5): фильтр match'ит значение ЛЮБОГО лейбла в кавычках, а не
    # только rule_id="..." — иначе _w625_metric_sum не может выделить comm
    # для метрик без rule_id (ebpf_guard_drift_baseline_signature_cap_reached_total{comm=...}),
    # и вызывающая сторона (6.2.5.11) вынуждена звать её с пустым аргументом,
    # суммируя ВСЕ comm сразу. Возможность фильтровать уже была — не хватало
    # generic-совпадения по значению.
    # Само совпадение живёт в wave6.2.5-metrics-lib.sh (w625_metric_sum_file):
    # у библиотеки есть офлайн-сторож, который зовёт ИМЕННО ЭТУ функцию, а не
    # свою копию awk. Здесь остаётся только источник среза — живой /metrics
    # или файл. Откат на локальный awk — на случай, если библиотека не
    # подключилась (её отсутствие уже объявлено НЕИЗМЕРИМОСТЬЮ выше, но
    # молча падать на «команда не найдена» контроль не должен).
    local metric="$1" ids="${2:-}" src="${3:-}"
    if [ "$W625_LIB_OK" -eq 1 ]; then
        { [ -n "$src" ] && cat "$src" || _w625_metrics; } | w625_metric_sum_file "$metric" "$ids" -
    else
        # Откат на локальную копию: отсутствие библиотеки уже объявлено
        # НЕИЗМЕРИМОСТЬЮ выше, но контроль не должен падать «команда не
        # найдена» посреди измерения.
        { [ -n "$src" ] && cat "$src" || _w625_metrics; } | awk -v m="$metric" -v ids="$ids" '
            BEGIN { n = split(ids, a, " ") }
            $0 ~ "^"m"[{ ]" {
                if (n == 0) { s += $NF; next }
                for (i = 1; i <= n; i++) if (index($0, "\"" a[i] "\"")) { s += $NF; next }
            }
            END { printf "%d", s+0 }'
    fi
}
# Скалярная метрика без лейблов (process_*, go_*): $NF может быть в
# экспоненциальной записи (1.37413104e+08), поэтому печатается через %.0f.
_w625_metric_raw() { # $1=metric $2=файл среза
    awk -v m="$1" '$1 == m { printf "%.0f", $2+0; found=1; exit } END { if (!found) printf "" }' "$2" 2>/dev/null
}

# ---------------------------------------------------------------------------
# ОБЪЁМ И РЕШЕНИЕ №232.
#
# Формула 6.2.1 (№227) — alerts_total + alerts_filtered_total по всем
# severity. Находка №230 показала, что 94% величины прошлого прогона это
# severity=info, которого нет в сторе; №232 спрашивает владельца, считать ли
# его. Решение зафиксировано ДО прогона и в прогоне не меняется (критерий
# 6.2.5.1), но ОБЕ величины печатаются всегда: разница двух — это цена
# решения №232 числом, а не прогнозом.
#
# Почему вердикт по умолчанию по «all»: filtered_total — это то, что срезано
# min_severity. Формула без info позволяет «починить» шумное правило
# понижением его severity: величина упадёт, а работа агента (regex,
# обогащение, дедуп, кольцевой буфер) останется та же. Гейт перестал бы быть
# гейтом. См. plan.md, №232.
# ---------------------------------------------------------------------------
_w625_volume_all() { # $1=файл среза
    awk '/^ebpf_guard_alerts_total[{ ]/ || /^ebpf_guard_alerts_filtered_total[{ ]/ { s += $NF } END { printf "%d", s+0 }' "$1"
}
_w625_volume_noinfo() { # $1=файл среза
    awk '(/^ebpf_guard_alerts_total[{ ]/ || /^ebpf_guard_alerts_filtered_total[{ ]/) && !/severity="info"/ { s += $NF } END { printf "%d", s+0 }' "$1"
}
_w625_ratelimited() { _w625_metric_sum ebpf_guard_alerts_ratelimited_by_rule_total "${1:-}" "${2:-}"; }
# Потери событий БЕЗ path_denylist (№222): denylist — законный фильтр, а не
# потеря видимости.
_w625_real_drops() { # [$1=файл среза]
    { [ -n "${1:-}" ] && cat "$1" || _w625_metrics; } | awk '
        /^ebpf_guard_events_dropped_total\{/ && !/reason="path_denylist"/ { s += $NF }
        /^ebpf_guard_event_queue_dropped_total/ { s += $NF }
        END { printf "%d", s+0 }'
}
# Журнальный счётчик потерь (№222, второй слой). №240: журнал читается ОТ
# СТАРТА АГЕНТА, а не за всю историю юнита — иначе величина принадлежит
# прошлым прогонам.
_w625_journal_since() {
    if [ -s /root/agent-start-6.2.5.epoch ]; then
        echo "@$(cat /root/agent-start-6.2.5.epoch)"
    else
        systemctl show "$W625_SVC" -p ActiveEnterTimestampMonotonic --value >/dev/null 2>&1
        local t; t=$(systemctl show "$W625_SVC" -p ActiveEnterTimestamp --value 2>/dev/null)
        local e; e=$(date -d "$t" +%s 2>/dev/null)
        [ -n "${e:-}" ] && echo "@$e" || echo "-1 hour"
    fi
}
_w625_journal_drops() {
    journalctl -u "$W625_SVC" --since "$(_w625_journal_since)" --no-pager 2>/dev/null \
        | grep -o '"bulk_dropped_since_start":[0-9]*' | tail -1 | cut -d: -f2
}

# Смок-режим укорачивает ОЖИДАНИЯ, но не выкидывает блоки.
if [ "$W625_SMOKE" = "1" ]; then
    W625_SETTLE=5
    W625_POS_TIMEOUT=30
    W625_QUIET_LEAD=10
    W625_OPEN_SETTLE=5
fi

# ─────────────────────────────────────────────────────────────────────────────
# ПРЕFLIGHT. Провал здесь означает, что величины ниже нечем читать.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.2 преflight ---"
command -v jq >/dev/null 2>&1 || die "6.2.2 преflight ПРОВАЛЕН: нет jq — все величины по стору неизмеримы"

if [ ! -x "$W625_KUBECTL" ]; then
    die "6.2.2 преflight ПРОВАЛЕН: kubectl не найден ($W625_KUBECTL) — ноду нечем подать на вход, любой ноль ниже приборный"
else
    _w625_ready=$("$W625_KUBECTL" get nodes --no-headers 2>/dev/null | awk '$2=="Ready"{n++} END{print n+0}')
    if [ "${_w625_ready:-0}" -lt 1 ]; then
        die "6.2.2 преflight ПРОВАЛЕН: ни одна нода не Ready"
    else
        pass "6.2.2 преflight: нод Ready = $_w625_ready ($("$W625_KUBECTL" version -o json 2>/dev/null | jq -r '.serverVersion.gitVersion // "?"'))"
    fi
fi

_w625_cfg="${W625_CONFIG:-$W625_SETUP/config-test.yaml}"
_w625_k8s_block=$(awk '/^kubernetes:/{f=1;next} f && /^[a-zA-Z#]/{exit} f' "$_w625_cfg" 2>/dev/null)
_w625_drift_cfg=$(awk '/drift_baseline:/{f=1;next} f && /^[a-zA-Z]/{exit} f' "$_w625_cfg" 2>/dev/null)
echo "$_w625_k8s_block" | grep -qE '^[[:space:]]*enabled:[[:space:]]*true[[:space:]]*(#.*)?$' \
    && pass "6.2.2 преflight: kubernetes.enabled: true в $_w625_cfg" \
    || die "6.2.2 преflight ПРОВАЛЕН: kubernetes.enabled НЕ true — энричер не конструируется, pod_name пуст по построению (находка №216)"

# pprof: без него критерий 6.2.5.8 нереализуем в принципе (находка №244:
# enable_pprof по умолчанию false, и config-test.yaml её никогда не включал —
# /debug/pprof/* 404-ил на живом стенде).
grep -qE '^[[:space:]]*enable_pprof:[[:space:]]*true[[:space:]]*(#.*)?$' "$_w625_cfg" 2>/dev/null \
    && pass "6.2.2 преflight: enable_pprof: true — окно профиля 6.2.5.8 реализуемо" \
    || die "6.2.5.8 НЕИЗМЕРИМ: enable_pprof не true в $_w625_cfg — /debug/pprof/* ответит 404, профиль снять нечем (находка №244)"

_w625_src=$(journalctl -u "$W625_SVC" --since "$(_w625_journal_since)" --no-pager 2>/dev/null | grep -o '"msg":"runtime enricher active","source":"[a-z]*"' | tail -1 | grep -oE '"source":"[a-z]*"' | cut -d'"' -f4)
_w625_k8s_up=$(journalctl -u "$W625_SVC" --since "$(_w625_journal_since)" --no-pager 2>/dev/null | grep -c 'k8s enricher active')
echo "  источник runtime-обогащения: ${_w625_src:-НЕ НАПЕЧАТАН}; строк «k8s enricher active»: $_w625_k8s_up"
[ "${_w625_k8s_up:-0}" -ge 1 ] || die "6.2.2 преflight ПРОВАЛЕН: в журнале нет «k8s enricher active» — pod_name будет пуст по причине вне продукта"

# №240, часть 1: журнал вообще читается ОТ СТАРТА АГЕНТА. Прогон 6.2.1 привёз
# journal-agent-6.2.1.log нулевого размера и не заметил этого.
_w625_jsince=$(_w625_journal_since)
_w625_jlines=$(journalctl -u "$W625_SVC" --since "$_w625_jsince" --no-pager 2>/dev/null | wc -l)
echo "  журнал агента с $_w625_jsince: $_w625_jlines строк"
[ "${_w625_jlines:-0}" -ge 1 ] \
    && pass "6.2.2 преflight: journalctl --since «$_w625_jsince» даёт непустой журнал (№240: ISO-8601 «T…Z» systemd.time(7) НЕ разбирает, эпоха — разбирает)" \
    || die "6.2.2.4 ПРОВАЛЕН заранее: journalctl --since «$_w625_jsince» даёт ПУСТО — архив этого прогона будет нереплеиваемым, как collect-6.2.1 (№240)"

# №243, живой сторож. config-test.yaml не задаёт monitored_syscalls, значит
# используется DefaultMonitoredSyscalls() из sampling.go: 19 номеров после
# снятия chmod/fchmod/fchmodat (90/91/268), 22 до него. Число в журнале
# отличает ЗАДЕПЛОЕННУЮ правку от лежащей в дереве.
_w625_ms=$(journalctl -u "$W625_SVC" --since "$_w625_jsince" --no-pager 2>/dev/null \
    | grep -o '"monitored_syscalls":[0-9]*' | tail -1 | cut -d: -f2)
_w625_ms_want=$(awk '/^func DefaultMonitoredSyscalls/,/^}/' "$W625_REPO/internal/bpf/sampling.go" 2>/dev/null | grep -cE '^[[:space:]]+[0-9]+,')
echo "  №243: monitored_syscalls в журнале = ${_w625_ms:-НЕ НАПЕЧАТАН}; в дереве DefaultMonitoredSyscalls() = ${_w625_ms_want:-?}"
if [ -z "${_w625_ms:-}" ]; then
    die "6.2.1.9 (№243) НЕИЗМЕРИМ: строки kernel_filter с monitored_syscalls нет в журнале — задеплоена правка или нет, по этому прогону не установить"
elif [ "${_w625_ms_want:-0}" -gt 0 ] && [ "${_w625_ms:-0}" -ne "${_w625_ms_want:-0}" ]; then
    die "6.2.1.9 (№243) ПРОВАЛЕН: агент поднят на бинаре с ${_w625_ms} syscall'ами, а дерево описывает ${_w625_ms_want}. Правка №243 (снятие chmod с syscall-оси) НЕ задеплоена: chmod по-прежнему даёт второе, никем не читаемое событие, и цена ring buffer в 6.2.5.1 измеряется НЕ на том коде, что лежит в дереве"
else
    pass "6.2.1.9 (№243) ДОСТИГНУТО (половина «деплой»): monitored_syscalls=${_w625_ms} совпадает с деревом — chmod снят с syscall-оси на живом бинаре"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.1.6 РЕГРЕССИЯ: реестр немоты по среде (находка №225), ДО всякого замера.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.1.6 (регрессия): немота по среде ---"
_w625_unreach=$(journalctl -u "$W625_SVC" --since "$_w625_jsince" --no-pager 2>/dev/null | grep -o '"msg":"rules: syscall rules with no reachable nr in the kernel allowlist".*' | tail -1)
_w625_unreach_n=$(printf '%s' "$_w625_unreach" | grep -oE '"count":[0-9]+' | cut -d: -f2)
_w625_unreach_ids=$(printf '%s' "$_w625_unreach" | grep -oE '"rule_ids":\[[^]]*\]' | tr -d '"[]' | sed 's/rule_ids://')
_w625_kmod=$(journalctl -u "$W625_SVC" --since "$_w625_jsince" --no-pager 2>/dev/null | grep -c 'cgroup escape collector unavailable')
echo "  недостижимых syscall-правил: ${_w625_unreach_n:-0}"
echo "  поимённо: ${_w625_unreach_ids:-нет}"
echo "  kmod cgroup-escape коллектор недоступен: $([ "${_w625_kmod:-0}" -gt 0 ] && echo да || echo нет) (ядро $(uname -r))"
# №234/открытый вопрос 7: файловые правила, чей op не производит ни один хук
# сборки, теперь печатаются агентом при старте (UnreachableFileOpRules).
# Это немота ПО ПОСТРОЕНИЮ, и реплей обязан читать её так же, как syscall-ось.
_w625_unreach_f=$(journalctl -u "$W625_SVC" --since "$_w625_jsince" --no-pager 2>/dev/null | grep -o '"msg":"rules: file rules whose op condition names no operation any hook produces".*' | tail -1)
echo "  файловых правил с недостижимым op: ${_w625_unreach_f:-строки нет}"

_w625_registry="$W625_SETUP/attacks/silent-rules.txt"
_w625_reg_ids=$(grep -oE '^[A-Za-z0-9_]+ a$' "$_w625_registry" 2>/dev/null | awk '{print $1}' | sort -u)
_w625_reg_n=$(printf '%s\n' "$_w625_reg_ids" | grep -c .)
_w625_jrn_ids=$(printf '%s' "${_w625_unreach_ids:-}" | tr ',' '\n' | sed '/^$/d' | sort -u)
echo "  реестр (silent-rules.txt, категория а): ${_w625_reg_n} правил"
if [ -z "${_w625_unreach_n:-}" ]; then
    die "6.2.1.6 НЕИЗМЕРИМ: строки о недостижимых правилах нет в журнале — немоту по среде нечем отличить от регресса"
elif [ "$_w625_jrn_ids" != "$_w625_reg_ids" ]; then
    die "6.2.1.6 ПРОВАЛЕН: реестр (${_w625_reg_n} правил) разошёлся со стендом (${_w625_unreach_n} правил: ${_w625_unreach_ids:-нет}) — реплеи архивов этой волны читают расхождение как потерю/регресс"
elif [ "${_w625_kmod:-0}" -gt 0 ] && ! grep -q 'cgroup escape collector unavailable' "$_w625_registry" 2>/dev/null; then
    die "6.2.1.6 ПРОВАЛЕН: kmod cgroup-escape коллектор недоступен на этом ядре, но $_w625_registry не документирует этот факт"
else
    pass "6.2.1.6 ДОСТИГНУТО: реестр немоты по среде совпал со стендом (${_w625_unreach_n} правил + kmod)"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.5.0 ПРИБОРНОСТЬ (первая половина: ось пода).
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.5.0: приборность оси пода ---"
_w625_alerts > "$W625_ART/alerts-preflight.json"
_w625_pod_alerts=$(jq '[.[]|select(((.enrichment.pod_name // "") != "") and ((.enrichment.namespace // "") != ""))]|length' "$W625_ART/alerts-preflight.json" 2>/dev/null || echo 0)
_w625_ns_seen=$(jq -r '.[]|select((.enrichment.namespace // "")!="")|.enrichment.namespace' "$W625_ART/alerts-preflight.json" 2>/dev/null | sort -u | tr '\n' ' ')
echo "  алертов с непустыми namespace И pod_name: $_w625_pod_alerts; namespace'ы: ${_w625_ns_seen:-нет}"
W625_INSTRUMENTED=0
if [ "${_w625_pod_alerts:-0}" -lt 1 ]; then
    die "6.2.5.0 ПРОВАЛЕН: ни одного алерта с личностью пода. Дальше контроли оси пода НЕ ЧИТАЮТСЯ — их ноль был бы приборным"
else
    W625_INSTRUMENTED=1
    pass "6.2.5.0 ДОСТИГНУТО (половина «ось пода»): личность пода доезжает до алерта ($_w625_pod_alerts алертов)"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.5.A ДЛИНА ПРОЛОГА.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.5.A: длина пролога до открытия окна ---"
_w625_lp=$(echo "$_w625_drift_cfg" | grep -oE 'learning_period:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | head -1)
_w625_edp=$(echo "$_w625_drift_cfg" | grep -oE 'enforce_deadline_periods:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | head -1)
_w625_need=$(( ${_w625_lp:-600} * ${_w625_edp:-2} ))
_w625_started=$(systemctl show "$W625_SVC" -p ActiveEnterTimestamp --value 2>/dev/null)
_w625_started_s=$(date -d "$_w625_started" +%s 2>/dev/null || echo 0)
_w625_prologue=$(( $(date +%s) - _w625_started_s ))
echo "  агент поднят: ${_w625_started:-?}; пролог: ${_w625_prologue}s; требуется > ${_w625_need}s"
echo "  на этот момент: профилей $(_w625_metric_sum ebpf_guard_drift_baseline_profiles ""), из них в learning $(_w625_metric_sum ebpf_guard_drift_baseline_learning_workloads "")"
if [ "$_w625_started_s" -eq 0 ]; then
    die "6.2.5.A НЕИЗМЕРИМ: время старта сервиса не прочитано"
elif [ "$_w625_prologue" -le "$_w625_need" ]; then
    die "6.2.5.A ПРОВАЛЕН: пролог ${_w625_prologue}s не длиннее ${_w625_need}s — окно ниже меряет ОБУЧЕНИЕ, а не линию"
else
    pass "6.2.5.A ДОСТИГНУТО: пролог ${_w625_prologue}s > ${_w625_need}s"
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
echo "--- 6.2.5.1/6.2.5.2/6.2.2.2/6.2.2.3/6.2.5.3/6.2.5.9: тихое окно ${W625_WINDOW}s ---"
_w625_drift_print() {
    echo "  дрейф[$1]: $(awk '/^ebpf_guard_drift_baseline_(profiles|learning_workloads|stuck_learning_workloads|learning_overdue_workloads|saturated_profiles|evictions_total|frozen_workloads|signature_cap_reached_total) /{printf "%s=%s ", $1, $2}' "$2")"
}
# ---- 6.2.5.13, первая половина (№260, item 7 постановки): observer_exclude
#      доказан выключенным ДО открытия окна, а не предполагается ----
# `/var/lib/ebpf-guard/observer-root-pid` — файл, которым волна 5.9a
# вооружает срез дерева измерителя В ЯДРЕ; волна 6.2.3 записала намерением
# «observer_exclude не вооружаем», но стража на это намерение не поставила
# (находка №260) — стоячий файл от прошлой сессии срезал бы дерево молча, и
# 6.2.5.3 показывал бы ноль не потому, что измеритель тих, а потому, что его
# не видно. Печать здесь — ДО ЛЮБОГО измерения, пока причина ещё читаема.
_w625_orpf=/var/lib/ebpf-guard/observer-root-pid
if [ -e "$_w625_orpf" ]; then
    echo "  6.2.5.13 (наблюдение): $_w625_orpf СУЩЕСТВУЕТ, содержимое: $(cat "$_w625_orpf" 2>/dev/null || echo 'нечитаемо')"
else
    echo "  6.2.5.13 (наблюдение): $_w625_orpf отсутствует"
fi
echo "  тишина перед открытием окна: ${W625_QUIET_LEAD}s (шум собственных curl'ов преflight'а уходит за границу t0)"
sleep "$W625_QUIET_LEAD"
_w625_metrics > "$W625_ART/metrics-window-start.txt"
# 6.2.5.17 (№265, item 4 волны 6.2.5): ПОИМЁННЫЙ разрез базы дрейфа на
# границе окна. /metrics отдаёт только счётчики состояний, а вопрос «какие
# ИМЕННО 13 нагрузок стоят в stuck» по ним неразрешим — на нём и встал разбор
# архива 6.2.3. /debug/state.drift_baseline.workloads[] несёт (workload, comm,
# state, signatures, samples, saturated) на каждый профиль. Снимок берётся
# ВМЕСТЕ с метриками, до фиксации t0, — тем же curl'ом преflight'а, внутрь
# окна не попадает.
_w625_curl "$W625_API/debug/state" > "$W625_ART/debug-state-window-start.json" 2>/dev/null
_w625_jdrops0=$(_w625_journal_drops)
_w625_drift_print "открытие" "$W625_ART/metrics-window-start.txt"

# ---- 6.2.5.A, продолжение (№257, item 6 постановки): потери за ПРОЛОГ ----
# `_w625_real_drops` уже читает "потери без path_denylist" на любом файле
# среза; здесь он читается на снимке, который пайплайн взял СРАЗУ после
# старта агента (W625_PROLOGUE_METRICS, ДО 1800-секундного ожидания), а не
# на t0. Архив 6.2.3 потерял 1336 файловых событий именно в этом промежутке
# и ни один вердикт этого не показал — сторож смотрел только [t0,t1]
# (находка №257). Порог не назначается (5.9.6): ненулевая дельта не валит
# 6.2.5.A, но печатается как ограничение полноты базы дрейфа, обучавшейся
# на неполном потоке.
if [ -n "${W625_PROLOGUE_METRICS:-}" ] && [ -s "${W625_PROLOGUE_METRICS:-}" ]; then
    _w625_dr_prologue_start=$(_w625_real_drops "$W625_PROLOGUE_METRICS")
    _w625_dr_prologue_end=$(_w625_real_drops "$W625_ART/metrics-window-start.txt")
    _w625_dr_prologue=$(( _w625_dr_prologue_end - _w625_dr_prologue_start ))
    echo "  6.2.5.A (продолжение, №257): потери за пролог [старт агента, t0] = $_w625_dr_prologue (метрика, без path_denylist)"
    if [ "$_w625_dr_prologue" -gt 0 ]; then
        echo "    ОГРАНИЧЕНИЕ ПОЛНОТЫ: база дрейфа доучивалась с дырой в $_w625_dr_prologue событий — 6.2.5.A остаётся ДОСТИГНУТО по длине, но не гарантирует полноту (находка №257)"
    else
        echo "    пролог чист: 6.2.5.A — гарантия, а не только измерение длины"
    fi
else
    echo "  6.2.5.A (продолжение, №257) НЕИЗМЕРИМ: снимок пролога (W625_PROLOGUE_METRICS) не передан пайплайном или пуст — потери за [старт агента, t0] нечем читать, СТОРОЖ №257 НЕ РАБОТАЕТ"
fi

# ОСЕДАНИЕ ПЕРЕД ФИКСАЦИЕЙ t0 (открытый вопрос 16, вторая половина). Перенос
# t0 в конец последовательности (правка №242) убирает СЕКУНДЫ выполнения
# curl/journalctl из окна, но не убирает задержку конвейера: событие
# предоткрывающего curl'а проходит ring buffer → корреляцию → стор уже после
# того, как команда вернулась, и его метка времени может лечь ПОСЛЕ t0.
# Смок 06.09.2026 напечатал ровно это (curl:1 внутри окна при верном
# порядке). Пауза даёт конвейеру осесть; величина взята с запасом от
# наблюдённой латентности (91–183 мкс на событие, но стор пишется пачками).
# ---- №242, вторая правка (смок 07.09.2026): АТРИБУЦИЯ измерителя ----
# Список W625_INSTR_COMMS состоит из РОДОВЫХ имён (sh, grep, awk, date…), и
# смок этой волны показал, что по нему в «работу измерителя» попадает фон
# САМОЙ НОДЫ: 6.2.5.3 провалился на `grep /proc/cpuinfo`, который в 19:27:02
# запустил systemd-таймер `motd-news.service` (журнал таймеров сверен), пока
# измеритель спал на ФИФО и не делал ни одного execve. Верный признак «это
# наш процесс» — не имя, а ПРИНАДЛЕЖНОСТЬ ДЕРЕВУ: pid алерта лежит в цепочке
# предков этого скрипта либо среди её потомков. Набор снимается ДО t0 —
# внутри окна измеритель не порождает процессов вовсе (item 8, ФИФО), а
# значит новых своих pid'ов там взяться не может.
_w625_pids_file="$W625_ART/measurer-pids.txt"
{
    _w625_p=$$
    while [ -n "$_w625_p" ] && [ "$_w625_p" != "0" ] && [ "$_w625_p" != "1" ]; do
        echo "$_w625_p"
        _w625_p=$(awk '/^PPid:/{print $2}' "/proc/$_w625_p/status" 2>/dev/null)
    done
    ps -eo pid,ppid --no-headers 2>/dev/null | awk -v s="$$" '$2==s{print $1}'
} 2>/dev/null | sort -un > "$_w625_pids_file"
_w625_pids_json=$(awk '{printf "%s%s", (NR>1?",":"["), $1} END{printf "%s\n", (NR?"]":"[]")}' "$_w625_pids_file" 2>/dev/null)
[ -n "${_w625_pids_json:-}" ] || _w625_pids_json='[]'
# СТОРОЖ ЛОЖНОГО НУЛЯ к этому же правилу (память positive-control-needs-result-sentinel):
# принадлежность дереву не увидит процесс, который измеритель ПОРОДИЛ БЫ
# внутри окна (его pid в наборе отсутствует по определению). Приращение
# cutime+cstime собственной оболочки — прямое доказательство обратного: оно
# растёт только когда шелл пожал реального потомка. Читается встроенным
# `read` из /proc/self/stat — без execve и без форка внутри окна.
# ВАЖНО: значение возвращается ГЛОБАЛЬНОЙ переменной, а не через $( ). В
# подстановке команд шелл форкается, и /proc/self внутри неё — уже потомок,
# у которого cutime обнулён форком: сторож печатал бы 0 всегда.
_w625_reaped() {
    local _st
    _W625_REAPED=0
    read -r _st < /proc/self/stat 2>/dev/null || return 0
    # shellcheck disable=SC2086
    set -- ${_st#*") "}
    _W625_REAPED=$(( ${14:-0} + ${15:-0} ))
}

sleep "$W625_OPEN_SETTLE"
_w625_t0=$(_w625_epoch)
echo "  окно открыто $(_w625_utc "$_w625_t0") — до закрытия НЕ ПОДАВАТЬ вход (память ebpf-guard-measurement-hygiene, п.2/п.5)"
# №258 (item 8 постановки 6.2.5): внешний `sleep` — это execve, то есть
# собственное событие измерителя внутри окна, которое в архиве 6.2.3 в
# одиночку провалило критерий доли измерителя (comm=sleep, единственный
# алерт измерителя в [t0,t1]). Замена — `read -t` НА ФИФО (W625_QUIET_FIFO,
# создана ДО t0, см. начало файла), а не на /dev/null: `read -t N </dev/null`
# возвращается СРАЗУ (открытие /dev/null на чтение даёт мгновенный EOF),
# проверено эмпирически перед правкой — «read -t с /dev/null», который
# называла сама находка №258 как пример, не ждёт вовсе и превратил бы
# 600-секундное окно в нулевое. ФИФО, открытая read+write на СВОЙ ЖЕ
# дескриптор, не даёт EOF (запись всегда возможна, раз писатель — сам
# процесс), и `read -u` блокируется РОВНО на таймаут — ни одного execve
# внутри окна, 0% CPU, exec/read — синтаксис шелла, не новый процесс.
# Съём сторожа — ВПЛОТНУЮ к ожиданию, ПОСЛЕ всех подстановок команд выше:
# `sleep` осадки и $( ) метки t0 сами суть пожатые потомки, и захват раньше
# приписал бы их тики окну (смок 07.09.2026 напечатал ровно этот ложный +1).
_w625_reaped; _w625_reaped0=$_W625_REAPED
if [ -p "$W625_QUIET_FIFO" ]; then
    exec 8<>"$W625_QUIET_FIFO"
    read -r -t "$W625_WINDOW" -u 8 _w625_qdummy
    exec 8<&-
else
    echo "  ФИФО ожидания недоступна ($W625_QUIET_FIFO не создана заранее) — откат на встроенный таймер SECONDS (по-прежнему без execve, но занимает CPU busy-wait'ом)"
    SECONDS=0
    while [ "$SECONDS" -lt "$W625_WINDOW" ]; do :; done
fi
_w625_reaped; _w625_reaped1=$_W625_REAPED
_w625_t1=$(_w625_epoch)
_w625_metrics > "$W625_ART/metrics-window-end.txt"
_w625_curl "$W625_API/debug/state" > "$W625_ART/debug-state-window-end.json" 2>/dev/null
_w625_jdrops1=$(_w625_journal_drops)
_w625_drift_print "закрытие" "$W625_ART/metrics-window-end.txt"
_w625_alerts > "$W625_ART/alerts-window-end.json"
# №240/открытый вопрос 14: границы окна выносятся наружу файлом-мостом —
# пайплайну нечем иначе проверить, что журнал ПОКРЫВАЕТ окно (критерий
# 6.2.2.4), потому что эпохи считаются здесь и наружу не возвращаются.
printf 't0=%s\nt1=%s\n' "$_w625_t0" "$_w625_t1" > "$W625_ART/window-epoch.txt"

# ---- 6.2.5.13, вторая половина (№260): серия печатается ЯВНЫМ ЧИСЛОМ на
#      обеих границах окна, а не пропускается ----
# `ebpf_guard_events_excluded_total{reason="observer_tree"}` теперь
# пре-регистрируется движком безусловно (internal/correlator/engine.go,
# item 7 офлайн-правки волны 6.2.5) — серия читается как 0, если и правда
# ничего не исключалось, а не отсутствует. Отсутствие серии в снимке при
# этом ОСТАЁТСЯ отдельным сигналом: значит агент собран без этой правки.
_w625_obs_metric() { # $1=файл среза
    awk '/^ebpf_guard_events_excluded_total\{.*reason="observer_tree"/{print $NF; f=1} END{if(!f) print ""}' "$1" 2>/dev/null
}
_w625_obs0=$(_w625_obs_metric "$W625_ART/metrics-window-start.txt")
_w625_obs1=$(_w625_obs_metric "$W625_ART/metrics-window-end.txt")
echo "  6.2.5.13: ebpf_guard_events_excluded_total{reason=\"observer_tree\"} открытие=${_w625_obs0:-ОТСУТСТВУЕТ} закрытие=${_w625_obs1:-ОТСУТСТВУЕТ}"
if [ -z "${_w625_obs0:-}" ] || [ -z "${_w625_obs1:-}" ]; then
    die "6.2.5.13 НЕИЗМЕРИМ: серия observer_tree отсутствует хотя бы на одной границе окна — агент собран без пре-регистрации (item 7 правки не задеплоены), отсутствие среза дерева измерителя доказать нечем"
else
    _w625_obs_delta=$(( _w625_obs1 - _w625_obs0 ))
    if [ "$_w625_obs_delta" -gt 0 ]; then
        die "6.2.5.13 ПРОВАЛЕН: observer_tree исключил $_w625_obs_delta событий за окно — дерево измерителя резалось В ЯДРЕ, прогон НЕИЗМЕРИМ (часть величины 6.2.5.1 уехала вместе с исключением, находка №260)"
    else
        pass "6.2.5.13 ДОСТИГНУТО: observer_tree за окно = 0 — фильтр либо выключен, либо не резал ничего, и это доказано числом, а не отсутствием серии"
    fi
fi

# ---- 6.2.5.0, вторая половина: потери событий за окно (№222) ----
_w625_dr0=$(_w625_real_drops "$W625_ART/metrics-window-start.txt")
_w625_dr1=$(_w625_real_drops "$W625_ART/metrics-window-end.txt")
_w625_dr=$(( _w625_dr1 - _w625_dr0 ))
_w625_jdr=$(( ${_w625_jdrops1:-0} - ${_w625_jdrops0:-0} ))
echo "  потери событий за окно: метрика (без path_denylist) = $_w625_dr; журнал bulk_dropped = $_w625_jdr"
if [ "$_w625_dr" -gt 0 ] || [ "$_w625_jdr" -gt 0 ]; then
    die "6.2.5.0 ПРОВАЛЕН (половина «потери»): за окно потеряно событий — метрика $_w625_dr, журнал $_w625_jdr. Величина 6.2.5.1 срезана ПОТЕРЕЙ, а не только лимитером (находка №222). Окно НЕИЗМЕРИМО"
elif [ "$_w625_jdr" -eq 0 ] && [ "$_w625_dr" -eq 0 ]; then
    pass "6.2.5.0 ДОСТИГНУТО (половина «потери»): за окно ни метрика, ни журнал не показали потерь"
fi
if { [ "$_w625_jdr" -gt 0 ] && [ "$_w625_dr" -eq 0 ]; } || { [ "$_w625_dr" -gt 0 ] && [ "$_w625_jdr" -eq 0 ]; }; then
    die "6.2.5.0 ПРОВАЛЕН (сверка прибора): журнал говорит $_w625_jdr потерь, метрика — $_w625_dr. Потеря видимости молчалива в метриках (второй слой находки №222)"
fi

# ---- 6.2.5.1: объём ПРЯМОЙ ДЕЛЬТОЙ ДВУХ МЕТРИК, обе формулы (№227/№232),
#      плюс ВСЕ ЧЕТЫРЕ СЛОЯ и величина (в) — решение 1, №248 ----
_w625_alerts_total_d=$(_w625_metric_sum ebpf_guard_alerts_total "" "$W625_ART/metrics-window-end.txt")
_w625_alerts_total_s=$(_w625_metric_sum ebpf_guard_alerts_total "" "$W625_ART/metrics-window-start.txt")
_w625_filtered_d=$(_w625_metric_sum ebpf_guard_alerts_filtered_total "" "$W625_ART/metrics-window-end.txt")
_w625_filtered_s=$(_w625_metric_sum ebpf_guard_alerts_filtered_total "" "$W625_ART/metrics-window-start.txt")
_w625_layer_total=$(( _w625_alerts_total_d - _w625_alerts_total_s ))
_w625_layer_filtered=$(( _w625_filtered_d - _w625_filtered_s ))
_w625_vol_all=$(( $(_w625_volume_all "$W625_ART/metrics-window-end.txt") - $(_w625_volume_all "$W625_ART/metrics-window-start.txt") ))
_w625_vol_ni=$(( $(_w625_volume_noinfo "$W625_ART/metrics-window-end.txt") - $(_w625_volume_noinfo "$W625_ART/metrics-window-start.txt") ))
_w625_rl0=$(_w625_ratelimited "" "$W625_ART/metrics-window-start.txt")
_w625_rl1=$(_w625_ratelimited "" "$W625_ART/metrics-window-end.txt")
_w625_rl=$(( _w625_rl1 - _w625_rl0 ))
# Четвёртый слой (решение 3): дедуп остаётся механизмом ДОСТАВКИ, в величину
# гейта (а) не входит, но обязателен в (в) — числа №248 показали, что это
# самая устойчивая величина всего прогона (5702/5696 на двух окнах).
_w625_dd0=$(_w625_metric_sum ebpf_guard_alerts_dedup_dropped_total "" "$W625_ART/metrics-window-start.txt")
_w625_dd1=$(_w625_metric_sum ebpf_guard_alerts_dedup_dropped_total "" "$W625_ART/metrics-window-end.txt")
_w625_dd=$(( _w625_dd1 - _w625_dd0 ))
_w625_hour() { awk -v n="$1" -v w="$W625_WINDOW" 'BEGIN{printf "%.0f", n*3600.0/w}'; }
_w625_all_hour=$(_w625_hour "$_w625_vol_all")
_w625_ni_hour=$(_w625_hour "$_w625_vol_ni")
echo "  слой 1 alerts_total (Δ):             $_w625_layer_total"
echo "  слой 2 alerts_filtered_total (Δ):    $_w625_layer_filtered"
echo "  слой 3 alerts_ratelimited_by_rule (Δ): $_w625_rl"
echo "  слой 4 alerts_dedup_dropped (Δ):     $_w625_dd"
echo "  объём ВСЁ, формула (а) = слой1+слой2:        $_w625_vol_all → $_w625_all_hour/ч"
echo "  объём БЕЗ info, формула (б, ОТВЕРГНУТА реш.1): $_w625_vol_ni → $_w625_ni_hour/ч"
echo "  цена решения №232 числом:      $(( _w625_vol_all - _w625_vol_ni )) алертов severity=info за окно"
if [ "$W625_GATE_FORMULA" = "noinfo" ]; then
    _w625_vol=$_w625_vol_ni; _w625_vol_hour=$_w625_ni_hour
else
    _w625_vol=$_w625_vol_all; _w625_vol_hour=$_w625_all_hour
fi
_w625_true_hour=$(_w625_hour "$(( _w625_vol + _w625_rl ))")
# Величина (в) — решение 1: сумма ВСЕХ четырёх слоёв, порог НЕ назначается
# (правило 5.9.6 — впервые измеренной величине порог не даётся). Печатается
# ОБЯЗАТЕЛЬНО и всегда, вне зависимости от того, взят ли критерий 6.2.5.1.
_w625_v_total=$(( _w625_layer_total + _w625_layer_filtered + _w625_rl + _w625_dd ))
_w625_v_hour=$(_w625_hour "$_w625_v_total")
echo "  ← ВЕЛИЧИНА КРИТЕРИЯ 6.2.5.1 (формула $W625_GATE_FORMULA): $_w625_vol_hour/ч при гейте ${W625_GATE}/ч"
echo "  срез лимитера за окно (alerts_ratelimited_by_rule_total): $_w625_rl"
echo "  нижняя оценка РЕАЛЬНОГО числа срабатываний (а+срез лимитера): $(( _w625_vol + _w625_rl )) → $_w625_true_hour/ч"
echo "  ← ВЕЛИЧИНА (в) [решение 1, №248, БЕЗ ПОРОГА]: слой1+слой2+слой3+слой4 = $_w625_v_total → ${_w625_v_hour}/ч"

# ---- 6.2.2.2: список срезанных правил ПО МЕТРИКЕ (№238) ----
echo "--- 6.2.2.2: правила со срезом лимитера за окно (по метрике, не по стору) ---"
_w625_rl_list=""
if [ "$W625_LIB_OK" -eq 1 ]; then
    _w625_rl_list=$(w625_ratelimited_by_rule "$W625_ART/metrics-window-start.txt" "$W625_ART/metrics-window-end.txt")
    printf '%s\n' "${_w625_rl_list:-  (ни одно правило не срезано)}" | sed 's/^/    /'
    printf '%s\n' "$_w625_rl_list" > "$W625_ART/ratelimited-by-rule.txt"
fi
_w625_rl_n=$(printf '%s' "$_w625_rl_list" | grep -c . )
if [ "$W625_LIB_OK" -ne 1 ]; then
    die "6.2.2.2 НЕИЗМЕРИМ: библиотека не подключилась (см. преflight)"
elif [ "$_w625_rl" -gt 0 ] && [ "${_w625_rl_n:-0}" -eq 0 ]; then
    die "6.2.2.2 ПРОВАЛЕН (дефект ИЗМЕРИТЕЛЯ, не продукта): сумма среза лимитера за окно = $_w625_rl, а поимённый список ПУСТ. Это ровно находка №238: «нет срезанных» при ненулевом срезе означает, что цикл не видел правил, а не что их нет"
elif [ "$_w625_rl" -eq 0 ] && [ "${_w625_rl_n:-0}" -eq 0 ]; then
    pass "6.2.2.2 ДОСТИГНУТО: срез лимитера за окно нулевой, и поимённый список пуст согласованно (сумма 0 = список пуст)"
else
    pass "6.2.2.2 ДОСТИГНУТО: $_w625_rl_n правил со срезом напечатаны поимённо при сумме среза $_w625_rl (6.2.1 печатала «нет» при срезе +530)"
fi

# ---- 6.2.2.3: разбивка величины покрывает её саму (№239) ----
echo "--- 6.2.2.3: разбивка величины по правилам (по метрике) ---"
if [ "$W625_LIB_OK" -eq 1 ]; then
    w625_volume_by_rule "$W625_ART/metrics-window-start.txt" "$W625_ART/metrics-window-end.txt" > "$W625_ART/volume-by-rule.txt"
    head -20 "$W625_ART/volume-by-rule.txt" | sed 's/^/    /'
    _w625_sum=$(awk '{s+=$2} END{printf "%d", s+0}' "$W625_ART/volume-by-rule.txt")
    echo "  прямая дельта объёма (формула all): $_w625_vol_all; сумма разбивки: $_w625_sum"
    if [ "$_w625_vol_all" -le 0 ]; then
        die "6.2.2.3 НЕИЗМЕРИМ: прямая дельта объёма за окно не положительна ($_w625_vol_all) — покрытие считать не от чего"
    else
        _w625_cov=$(awk -v s="$_w625_sum" -v v="$_w625_vol_all" 'BEGIN{printf "%.1f", 100.0*s/v}')
        echo "  покрытие разбивки: ${_w625_cov}% (требуется ≥ 95%; версия 6.2.1 давала 4.3%)"
        if awk -v s="$_w625_sum" -v v="$_w625_vol_all" 'BEGIN{exit !(s >= 0.95*v)}'; then
            pass "6.2.2.3 ДОСТИГНУТО: разбивка покрывает ${_w625_cov}% величины — это законный вход для сужения"
        else
            die "6.2.2.3 ПРОВАЛЕН: разбивка покрывает лишь ${_w625_cov}% величины ($_w625_sum из $_w625_vol_all). Сужение по такой разбивке — работа вслепую (находка №239), правки на её основании запрещены"
        fi
    fi
else
    die "6.2.2.3 НЕИЗМЕРИМ: библиотека не подключилась"
fi

# Сторовая разбивка по comm — СПРАВОЧНО. Ни у alerts_total, ни у
# alerts_filtered_total нет лейбла comm, метрикой эту ось не восстановить.
_w625_new=$(jq --argjson t0 "$_w625_t0" --argjson t1 "$_w625_t1" --arg actors "$W625_NODE_ACTORS" '
    [ .[] | select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t0) and ((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) <= $t1))
      | select(((.enrichment.namespace // "") != "") or ((.comm) as $c | ($actors|split(" "))|index($c))) ]
    ' "$W625_ART/alerts-window-end.json" 2>/dev/null)
echo "  (справочно, сторовый счёт нодовых алертов окна: $(echo "${_w625_new:-[]}" | jq 'length' 2>/dev/null) — вердикта не выносит, находки №227/№239)"
echo "  разбивка по comm (стор, справочно — метрикой эта ось не восстановима):"
echo "${_w625_new:-[]}" | jq -r 'group_by(.comm)|map({c:.[0].comm,n:length})|sort_by(-.n)[]|"    \(.c): \(.n)"' 2>/dev/null | head -15

# ---------------------------------------------------------------------------
# 6.2.5.2: РАЗБИВКА РАНЖИРУЕТ ПО (в), А НЕ ПО ОСТАТКУ ПОСЛЕ ЛИМИТЕРА (№248).
#
# 6.2.2.3 выше ранжирует то, что ДОЕХАЛО до alerts_total/alerts_filtered_total
# (формула (а)) — и это подменяет собой настоящую верхушку шума, потому что
# правила, упёршиеся в лимитер (10/60с) и дедуп, показывают в (а) только
# ОСТАТОК. w625_value_v_by_rule (wave6.2.5-metrics-lib.sh) складывает ТРИ
# компонента на каждый rule_id — (а)-разбивку, срез лимитера, срез дедупа —
# и ранжирует по их сумме. Офлайн-сторож (--self-test на ОБОИХ архивах
# 6.2.2) проверяет, что первыми встают sigma_failed_login_syscall_daemon и
# rootkit_pam_module_added_daemon, а не c2_periodic_beacon_pattern.
# ---------------------------------------------------------------------------
echo "--- 6.2.5.2: разбивка по (в) — полная сумма совпадений правил (№248) ---"
if [ "$W625_LIB_OK" -eq 1 ]; then
    w625_value_v_by_rule "$W625_ART/metrics-window-start.txt" "$W625_ART/metrics-window-end.txt" > "$W625_ART/value-v-by-rule.txt"
    head -20 "$W625_ART/value-v-by-rule.txt" | sed 's/^/    /'
    _w625_v_sum=$(awk '{s+=$2} END{printf "%d", s+0}' "$W625_ART/value-v-by-rule.txt")
    _w625_v_top=$(head -1 "$W625_ART/value-v-by-rule.txt" | awk '{print $1}')
    echo "  прямая величина (в) за окно: $_w625_v_total; сумма разбивки по (в): $_w625_v_sum; вершина: ${_w625_v_top:-нет}"
    if [ "$_w625_v_total" -le 0 ]; then
        die "6.2.5.2 НЕИЗМЕРИМ: величина (в) за окно не положительна ($_w625_v_total) — ранжировать нечего"
    else
        _w625_v_cov=$(awk -v s="$_w625_v_sum" -v v="$_w625_v_total" 'BEGIN{printf "%.1f", 100.0*s/v}')
        echo "  покрытие разбивки по (в): ${_w625_v_cov}% (требуется ≥ 95%)"
        if awk -v s="$_w625_v_sum" -v v="$_w625_v_total" 'BEGIN{exit !(s >= 0.95*v)}'; then
            pass "6.2.5.2 ДОСТИГНУТО: разбивка по (в) покрывает ${_w625_v_cov}% величины (вершина: ${_w625_v_top:-нет}) — законный вход для сужения верхушки шума (item 4 постановки, ещё не сделан)"
        else
            die "6.2.5.2 ПРОВАЛЕН: разбивка по (в) покрывает лишь ${_w625_v_cov}% величины ($_w625_v_sum из $_w625_v_total)"
        fi
    fi
else
    die "6.2.5.2 НЕИЗМЕРИМ: библиотека не подключилась"
fi

# ---- 6.2.5.3: доля измерителя в окне = 0 (№242) ----
echo "--- 6.2.5.3: доля измерителя внутри окна (ВЕРДИКТ, а не поправка) ---"
_w625_instr=$(jq --argjson t0 "$_w625_t0" --argjson t1 "$_w625_t1" --argjson comms "$W625_INSTR_COMMS" '
    [ .[] | select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t0) and ((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) <= $t1))
      | select((.comm) as $c | ($comms|index($c))) ]
    | group_by(.comm)|map({c:.[0].comm,n:length})|sort_by(-.n)' "$W625_ART/alerts-window-end.json" 2>/dev/null)
_w625_instr_n=$(echo "${_w625_instr:-[]}" | jq '[.[].n]|add // 0' 2>/dev/null)
# Вторая половина критерия: алерты НА ПУТИ артефактов контроля. Файл
# metrics-window-start.txt создаётся в каталоге, за которым следит
# drift_new_file_dir_sensitive; правка №242 переносит запись ДО t0, но
# остаточная гонка (задержка ring buffer) аналитически не закрывается —
# открытый вопрос 16 требует проверить это ЖИВЫМ прогоном, здесь и сейчас.
_w625_artpath=$(jq --argjson t0 "$_w625_t0" --argjson t1 "$_w625_t1" --arg art "$W625_ART" '
    [ .[] | select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t0) and ((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) <= $t1))
      | select((.details["file.path"] // "") | startswith($art)) ] | length' "$W625_ART/alerts-window-end.json" 2>/dev/null)
echo "  алертов от comm измерителя внутри [t0,t1]: ${_w625_instr_n:-0} $(echo "${_w625_instr:-[]}" | jq -r 'map("\(.c):\(.n)")|join(" ")' 2>/dev/null)"
# АТРИБУЦИЯ (№242, вторая правка). Из тех же алертов выделяются те, чей pid
# принадлежит ДЕРЕВУ ИЗМЕРИТЕЛЯ, снятому до t0. Только они — работа
# измерителя; остальное с родовым comm есть фон ноды (смок 07.09.2026:
# `grep /proc/cpuinfo` от systemd-таймера motd-news.service).
_w625_instr_own=$(jq --argjson t0 "$_w625_t0" --argjson t1 "$_w625_t1" --argjson comms "$W625_INSTR_COMMS" --argjson pids "${_w625_pids_json:-[]}" '
    [ .[] | select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t0) and ((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) <= $t1))
      | select((.pid) as $p | ($pids|index($p))) ]' "$W625_ART/alerts-window-end.json" 2>/dev/null)
_w625_instr_own_n=$(echo "${_w625_instr_own:-[]}" | jq 'length' 2>/dev/null)
echo "  из них pid принадлежит дереву измерителя: ${_w625_instr_own_n:-0} $(echo "${_w625_instr_own:-[]}" | jq -r 'map("\(.comm):\(.rule_id)")|join(" ")' 2>/dev/null)"
echo "  остальные — фон ноды с родовым comm (не измеритель): $(( ${_w625_instr_n:-0} - ${_w625_instr_own_n:-0} ))"
_w625_reap_delta=$(( ${_w625_reaped1:-0} - ${_w625_reaped0:-0} ))
echo "  сторож ложного нуля: приращение cutime+cstime оболочки контроля за окно = ${_w625_reap_delta} тиков (>0 ⇒ измеритель ПОРОДИЛ процесс внутри окна, и pid-набор его не увидел бы)"
echo "  алертов на пути артефактов ($W625_ART) внутри [t0,t1]: ${_w625_artpath:-0}"
# РАЗЛИЧИТЕЛЬ ИСТОЧНИКА (смок 06.09.2026, ДО прогона). Список comm измерителя
# состоит из РОДОВЫХ имён (sh, bash, awk, grep, date, cut, …), и ровно те же
# имена порождает ЛЮБОЙ интерактивный вход по ssh: pam запускает
# /etc/update-motd.d/* — run-parts → 00-header → uname, landscape-sysin, grep
# /proc/cpuinfo, date, pgrep. То есть чужой вход внутрь окна печатается этим
# критерием как «доля измерителя», хотя измеритель спал. Смок этой волны упал
# ровно так: 7 алертов sh/awk/bash/date/grep/pgrep — это была цепочка MOTD
# оператора, зашедшего посмотреть прогресс (нарушение п.2/п.5 памяти
# ebpf-guard-measurement-hygiene, а не дефект контроля).
# Вердикт от этого НЕ смягчается: алерты входа — часть измеренной величины
# 6.2.5.1 и окно испорчено в любом случае. Но причина обязана быть НАЗВАНА,
# иначе следующий читатель полдня ищет несуществующую работу измерителя.
_w625_login_in_win=$(jq --argjson t0 "$_w625_t0" --argjson t1 "$_w625_t1" '
    [ .[] | select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t0) and ((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) <= $t1))
      | select((.comm) as $c | (["sshd","run-parts","landscape-sysin","00-header","91-release-upgr","50-motd-news","login"]|index($c))) ] | length' \
    "$W625_ART/alerts-window-end.json" 2>/dev/null)
echo "  различитель источника: алертов входа/MOTD (sshd, run-parts, landscape-sysin, 00-header, …) внутри окна: ${_w625_login_in_win:-0}"
# MOTD-цепочку порождает не только вход: `motd-news.timer` дёргает
# /etc/update-motd.d/50-motd-news по расписанию, БЕЗ всякого ssh (смок
# 07.09.2026: таймер сработал в 19:27:02 ровно внутри окна). Поэтому
# «вход» отделяется от «таймера» по наличию sshd/login: иначе штатный фон
# ноды объявляется нарушением гигиены и следующий читатель ищет
# несуществующее подключение.
_w625_login_ssh=$(jq --argjson t0 "$_w625_t0" --argjson t1 "$_w625_t1" '
    [ .[] | select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t0) and ((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) <= $t1))
      | select((.comm) as $c | (["sshd","login"]|index($c))) ] | length' \
    "$W625_ART/alerts-window-end.json" 2>/dev/null)
if [ "${_w625_login_ssh:-0}" -gt 0 ]; then
    echo "  ВНИМАНИЕ: внутрь окна попал ИНТЕРАКТИВНЫЙ ВХОД (алертов sshd/login: ${_w625_login_ssh}). Родовые comm (sh/bash/awk/grep/date/pgrep) принадлежат его цепочке MOTD, а не работе измерителя — окно испорчено посторонним подключением (п.2/п.5 гигиены), и величина 6.2.5.1 этого прогона завышена на его вклад"
elif [ "${_w625_login_in_win:-0}" -gt 0 ]; then
    echo "  примечание: MOTD-цепочка внутри окна есть, а sshd/login нет — это systemd-таймер ноды (motd-news.timer и соседи), штатный фон, а не чужой вход и не измеритель"
fi
if [ "${_w625_instr_own_n:-0}" -eq 0 ] && [ "${_w625_artpath:-0}" -eq 0 ] && [ "${_w625_reap_delta:-0}" -le 0 ]; then
    pass "6.2.5.3 ДОСТИГНУТО: измеритель внутри окна не работал — ни одного алерта из его дерева, ни одного алерта на пути его артефактов, ни одного пожатого потомка (родовых comm фона ноды внутри окна: ${_w625_instr_n:-0} — это не он, см. атрибуцию выше)"
else
    die "6.2.5.3 ПРОВАЛЕН: внутри окна ${_w625_instr_own_n:-0} алертов ИЗ ДЕРЕВА измерителя (родовых comm всего ${_w625_instr_n:-0}), ${_w625_artpath:-0} на пути его артефактов, приращение потомков ${_w625_reap_delta:-0} тиков. Это ЧАСТЬ измеренной величины 6.2.5.1, а не поправка к её чтению: контроль обязан не работать внутри окна вовсе (находка №242). Если ненулевая половина — путь артефактов, починка не в порядке операций, а в переносе снимков ВНЕ поддерева, за которым следит drift_new_file_dir_sensitive (открытый вопрос 16)"
fi

# ---------------------------------------------------------------------------
# ITEM 5 (№268): ТРИ ПОДПУНКТА 6.2.5.1, ПОТЕРЯННЫЕ В 6.2.4.
#
# Постановка требует печатать (1) сторож нуля на четырёх правилах-двойниках
# №253, (2) ненулевой rule_exceptions_total по КАЖДОМУ из четырёх rule_id —
# доказательство, что объём ПЕРЕЕХАЛ в исключение, а не исчез, (3)
# exe_path_lookups_total{result} обеими границами. Без этого из вердикта
# 6.2.5.1 невозможно отличить «исключение задеплоено и работает» от
# «исключение не задеплоено вовсе» — ровно дефект №268.
# ---------------------------------------------------------------------------
echo "--- 6.2.5.1 подпункт (1)/(2), №268: сторож нуля + rule_exceptions_total на четырёх двойниках №253 ---"
if [ "$W625_LIB_OK" -eq 1 ]; then
    _w625_twin_out=$(w625_daemon_twin_exceptions "$W625_ART/metrics-window-start.txt" "$W625_ART/metrics-window-end.txt")
    printf '%s\n' "$_w625_twin_out" | sed 's/^/    /'
    printf '%s\n' "$_w625_twin_out" > "$W625_ART/daemon-twin-exceptions.txt"
    _w625_twin_zero=$(printf '%s\n' "$_w625_twin_out" | awk '$NF ~ /total=0$/' | grep -c . || true)
    if [ "${_w625_twin_zero:-0}" -gt 0 ]; then
        die "6.2.5.1 подпункт (1)/(2) ПРОВАЛЕН (№268): хотя бы один из четырёх двойников №253 дал НУЛЕВОЙ срез по ОБОИМ исключениям (verified-daemon-image + verified-daemon-lineage) за окно — исключение на нём выключено или не задеплоено, объём НЕ переехал, а исчез бесследно"
    else
        pass "6.2.5.1 подпункт (1)/(2) ДОСТИГНУТО (№268): все четыре двойника №253 дали ненулевой срез rule_exceptions_total за окно — объём переехал в исключение, а не пропал"
    fi
else
    die "6.2.5.1 подпункт (1)/(2) НЕИЗМЕРИМ: библиотека не подключилась"
fi

echo "--- 6.2.5.1 подпункт (3), №268: exe_path_lookups_total{result} обеими границами ---"
_w625_exe_res0=$(awk '/^ebpf_guard_exe_path_lookups_total\{result="resolved"\}/{print $NF}' "$W625_ART/metrics-window-start.txt")
_w625_exe_res1=$(awk '/^ebpf_guard_exe_path_lookups_total\{result="resolved"\}/{print $NF}' "$W625_ART/metrics-window-end.txt")
_w625_exe_unres0=$(awk '/^ebpf_guard_exe_path_lookups_total\{result="unresolved"\}/{print $NF}' "$W625_ART/metrics-window-start.txt")
_w625_exe_unres1=$(awk '/^ebpf_guard_exe_path_lookups_total\{result="unresolved"\}/{print $NF}' "$W625_ART/metrics-window-end.txt")
echo "  открытие: resolved=${_w625_exe_res0:-ОТСУТСТВУЕТ} unresolved=${_w625_exe_unres0:-ОТСУТСТВУЕТ}"
echo "  закрытие: resolved=${_w625_exe_res1:-ОТСУТСТВУЕТ} unresolved=${_w625_exe_unres1:-ОТСУТСТВУЕТ}"
if [ -z "${_w625_exe_res0:-}" ] || [ -z "${_w625_exe_res1:-}" ] || [ -z "${_w625_exe_unres0:-}" ] || [ -z "${_w625_exe_unres1:-}" ]; then
    die "6.2.5.1 подпункт (3) НЕИЗМЕРИМ (№268): серия ebpf_guard_exe_path_lookups_total{result} отсутствует хотя бы на одной границе окна"
else
    pass "6.2.5.1 подпункт (3) ДОСТИГНУТО (№268): exe_path_lookups_total{result} напечатан обеими границами окна"
fi

# ---------------------------------------------------------------------------
# ITEM 5 (№261, критерий 6.2.5.15, НОВЫЙ). Доля величины на нерезолвленном
# образе — диагностика гонки, порог не назначается (5.9.6).
# ---------------------------------------------------------------------------
echo "--- 6.2.5.15: доля величины на нерезолвленном образе (№261) ---"
if [ "$W625_LIB_OK" -eq 1 ]; then
    _w625_exe_frac=$(w625_exe_path_lookup_fraction "$W625_ART/metrics-window-start.txt" "$W625_ART/metrics-window-end.txt")
    echo "  $_w625_exe_frac"
else
    echo "  НЕИЗМЕРИМ: библиотека не подключилась"
fi
# Поимённый список comm тех алертов окна, чьё правило несёт исключение на
# exe_path/lineage (четыре двойника №253) — если он ПУСТ при ненулевой доле
# unresolved выше, ось применяется всюду, где нужна (постановка 6.2.5.15).
_w625_exe_exc_comms=$(jq --argjson t0 "$_w625_t0" --argjson t1 "$_w625_t1" --argjson rules "$(printf '%s\n' $W625_TWIN_RULES | jq -R . | jq -s .)" '
    [ .[] | select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t0) and ((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) <= $t1))
      | select((.rule_id) as $r | ($rules|index($r))) ]
    | group_by(.comm)|map({c:.[0].comm,n:length})|sort_by(-.n)' "$W625_ART/alerts-window-end.json" 2>/dev/null)
echo "  алерты окна от правил с exe_path/lineage-исключением, поимённо по comm:"
echo "${_w625_exe_exc_comms:-[]}" | jq -r 'map("\(.c): \(.n)")|join(", ")' 2>/dev/null | sed 's/^/    /'
if [ "$(echo "${_w625_exe_exc_comms:-[]}" | jq 'length' 2>/dev/null)" = "0" ]; then
    echo "  диагностика: список пуст — при ненулевой доле unresolved выше это значит, что вторая ось (parent_exe_path/lineage) закрывает всё, что теряет гонку первая (ось применяется всюду, где нужна)"
fi
if [ "$W625_LIB_OK" -eq 1 ]; then
    pass "6.2.5.15 ИЗМЕРЕНО (диагностика гонки №261, порог не назначается, 5.9.6): $_w625_exe_frac"
else
    die "6.2.5.15 НЕИЗМЕРИМ: библиотека не подключилась — доля unresolved и список правил-исключений не сняты"
fi

# ---- Вердикт 6.2.5.1. Порядок проверок: срез может только ЗАНИЗИТЬ, поэтому
#      превышение порога доказано и при срезе. «Неизмеримо» остаётся для
#      случая «порог не перешли, но прибор упёрт» (пункт Е). ----
if [ "$_w625_vol_hour" -gt "$W625_GATE" ]; then
    die "6.2.5.1 ПРОВАЛЕН (величина — НИЖНЯЯ оценка): цена ноды $_w625_vol_hour алертов/ч (формула $W625_GATE_FORMULA) при гейте волны 6 «не выше ${W625_GATE}/ч»; величина (в, без порога) — ${_w625_v_hour}/ч. Разбивка 6.2.5.2 (по в) — вход для сужения, а не повод понизить порог"
elif [ "${_w625_rl_n:-0}" -gt 0 ]; then
    die "6.2.5.1 НЕИЗМЕРИМ ПО БУКВЕ (СТРАЖ ЛОЖНОГО PASS, решение 1): величина (а) $_w625_vol_hour/ч порог не перешла, но $_w625_rl_n правил имеют НЕНУЛЕВОЙ срез лимитера за окно (список выше) — это признак упёршегося прибора, и «PASS по (а) при непустом списке срезанных правил» есть НЕИЗМЕРИМОСТЬ, а не взятый критерий. Величина (в, без порога, полная сумма четырёх слоёв) — ${_w625_v_hour}/ч"
else
    pass "6.2.5.1 ДОСТИГНУТО: цена ноды (формула а) $_w625_vol_hour алертов/ч ≤ ${W625_GATE}/ч (формула $W625_GATE_FORMULA), ни одно правило не срезано лимитером за окно — страж ложного PASS чист. Величина (в, без порога) — ${_w625_v_hour}/ч"
fi

# ---- 6.2.5.9: потолок ресурсов против лимита чарта (№244) ----
echo "--- 6.2.5.9: ресурсы агента на открытии и закрытии окна против лимита чарта ---"
_w625_values="$W625_REPO/deploy/helm/ebpf-guard/values.yaml"
# Берётся limits.memory ПЕРВОГО блока resources (сам агент), а не limits
# сайдкаров/тестовых подов ниже по файлу.
_w625_limit_h=$(awk '
    /^resources:/ { inres=1; next }
    inres && /^[A-Za-z#]/ { exit }                      # блок кончился — дальше чужие resources
    inres && /^[[:space:]]+limits:/ { inlim=1; next }
    inres && inlim && /^[[:space:]]+[a-z]+:[[:space:]]*$/ { exit }   # начался requests:
    inres && inlim && /memory:/ { print $2; exit }' "$_w625_values" 2>/dev/null)
_w625_limit_b=$(awk -v v="${_w625_limit_h:-}" 'BEGIN{
    if (v ~ /Mi$/) { sub(/Mi$/,"",v); printf "%d", v*1024*1024 }
    else if (v ~ /Gi$/) { sub(/Gi$/,"",v); printf "%d", v*1024*1024*1024 }
    else if (v ~ /M$/) { sub(/M$/,"",v); printf "%d", v*1000*1000 }
    else printf "0" }')
_w625_res_print() { # $1=метка $2=файл среза
    echo "  ресурсы[$1]: RSS=$(awk -v b="$(_w625_metric_raw process_resident_memory_bytes "$2")" 'BEGIN{printf "%.1f МиБ", b/1048576}')" \
         "heap=$(awk -v b="$(_w625_metric_raw go_memstats_heap_alloc_bytes "$2")" 'BEGIN{printf "%.1f МиБ", b/1048576}')" \
         "goroutines=$(_w625_metric_raw go_goroutines "$2")" \
         "cpu_total=$(_w625_metric_raw process_cpu_seconds_total "$2")s"
}
_w625_res_print "открытие" "$W625_ART/metrics-window-start.txt"
_w625_res_print "закрытие" "$W625_ART/metrics-window-end.txt"
_w625_rss1=$(_w625_metric_raw process_resident_memory_bytes "$W625_ART/metrics-window-end.txt")
_w625_rss0=$(_w625_metric_raw process_resident_memory_bytes "$W625_ART/metrics-window-start.txt")
_w625_lat_sum0=$(awk '$1=="ebpf_guard_correlation_latency_seconds_sum"{printf "%.6f", $2+0}' "$W625_ART/metrics-window-start.txt")
_w625_lat_cnt0=$(awk '$1=="ebpf_guard_correlation_latency_seconds_count"{printf "%.0f", $2+0}' "$W625_ART/metrics-window-start.txt")
_w625_lat_sum1=$(awk '$1=="ebpf_guard_correlation_latency_seconds_sum"{printf "%.6f", $2+0}' "$W625_ART/metrics-window-end.txt")
_w625_lat_cnt1=$(awk '$1=="ebpf_guard_correlation_latency_seconds_count"{printf "%.0f", $2+0}' "$W625_ART/metrics-window-end.txt")
echo "  латентность корреляции ЗА ОКНО: $(awk -v s0="${_w625_lat_sum0:-0}" -v s1="${_w625_lat_sum1:-0}" -v c0="${_w625_lat_cnt0:-0}" -v c1="${_w625_lat_cnt1:-0}" 'BEGIN{d=c1-c0; if(d>0) printf "%.1f мкс/событие (Δsum=%.3fs ÷ Δcount=%d)", (s1-s0)/d*1e6, s1-s0, d; else printf "НЕИЗМЕРИМА (Δcount=%d)", d}')"
echo "  распределение по бакетам (накопительно, закрытие окна):"
awk '/^ebpf_guard_correlation_latency_seconds_bucket/{gsub(/.*le="/,"");gsub(/"}/," ");printf "    le=%s\n", $0}' "$W625_ART/metrics-window-end.txt" | head -12
echo "  лимит чарта (deploy/helm/ebpf-guard/values.yaml, resources.limits.memory): ${_w625_limit_h:-НЕ ПРОЧИТАН}"
if [ -z "${_w625_rss1:-}" ] || [ "${_w625_limit_b:-0}" -le 0 ]; then
    die "6.2.5.9 НЕИЗМЕРИМ: RSS=${_w625_rss1:-нет} или лимит чарта=${_w625_limit_h:-нет} не прочитаны — «запас до лимита» считать не от чего"
else
    echo "  запас до лимита на закрытии: $(awk -v l="$_w625_limit_b" -v r="$_w625_rss1" 'BEGIN{printf "%.1f МиБ (%.1f%%)", (l-r)/1048576, 100.0*(l-r)/l}')"
    echo "  рост RSS за окно: $(awk -v a="${_w625_rss0:-0}" -v b="$_w625_rss1" 'BEGIN{printf "%+.1f МиБ", (b-a)/1048576}')"
    if [ "${_w625_rss1:-0}" -gt "${_w625_limit_b:-0}" ]; then
        die "6.2.5.9 ПРОВАЛЕН: RSS $(awk -v r="$_w625_rss1" 'BEGIN{printf "%.1f", r/1048576}') МиБ ВЫШЕ лимита чарта ${_w625_limit_h}. В DaemonSet это OOM-kill, а не «чуть больше»"
    else
        pass "6.2.5.9 ДОСТИГНУТО: RSS $(awk -v r="$_w625_rss1" 'BEGIN{printf "%.1f", r/1048576}') МиБ ниже лимита чарта ${_w625_limit_h}; порог не назначается (запрет 5.9.6), величина печатается"
    fi
fi

# ---- 6.2.5.11, пассивная половина: приращение счётчика заморозки (№237) ----
echo "--- 6.2.5.11 (наблюдение): потолки базы дрейфа за окно ---"
_w625_maxw=$(echo "$_w625_drift_cfg" | grep -oE 'max_workloads:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | head -1)
_w625_maxsig=$(echo "$_w625_drift_cfg" | grep -oE 'max_signatures_per_workload:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | head -1)
_w625_prof=$(_w625_metric_sum ebpf_guard_drift_baseline_profiles "" "$W625_ART/metrics-window-end.txt")
_w625_evict=$(_w625_metric_sum ebpf_guard_drift_baseline_evictions_total "" "$W625_ART/metrics-window-end.txt")
# №237, дефект 2: вердикт по РАЗНОСТИ ДВУХ СНИМКОВ, а не по наличию имени
# метрики в выдаче (Prometheus печатает нулевые счётчики всегда).
_w625_cap0=$(_w625_metric_sum ebpf_guard_drift_baseline_signature_cap_reached_total "" "$W625_ART/metrics-window-start.txt")
_w625_cap1=$(_w625_metric_sum ebpf_guard_drift_baseline_signature_cap_reached_total "" "$W625_ART/metrics-window-end.txt")
# №237, дефект 1: журнал ограничен ОКНОМ, а не всей историей юнита.
_w625_frozen_j=$(journalctl -u "$W625_SVC" --since "@$_w625_t0" --until "@$_w625_t1" --no-pager 2>/dev/null | grep -c 'workload signature cap reached')
echo "  профилей=$_w625_prof при max_workloads=${_w625_maxw:-?}; вытеснений=$_w625_evict"
echo "  max_signatures_per_workload=${_w625_maxsig:-?}; приращение signature_cap_reached_total ЗА ОКНО: $(( _w625_cap1 - _w625_cap0 )) (накопительно $_w625_cap1)"
echo "  строк «signature cap reached» в журнале ЗА ОКНО: $_w625_frozen_j"
echo "  6.2.5.11 (пассивная половина): наблюдение без порога — при max_signatures=${_w625_maxsig:-?} кап в тихом окне достигаться и не обязан. Вердикт выносит позитивный подконтроль в конце прогона"

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.5.17 (№265, item 4 постановки) — `stuck`/`overdue` РАЗБИРАЮТСЯ ПОИМЁННО.
#
# Что чинится. Прогон 6.2.3 напечатал «13 нагрузок в stuck» и разобрать их
# поимённо было НЕЧЕМ: /metrics отдаёт три счётчика состояний, и «сколько» без
# «кто» не отличает слепое пятно продукта от нагрузки, которая просто ещё
# учится (память drift-baseline-has-no-per-workload-observability). Здесь
# читаются ОБЕ границы окна из /debug/state (боковой разрез существует с
# волны 6.0b) плюс ЖУРНАЛ: item 4 этой волны добавил в продукт строку на
# КАЖДЫЙ переход в stuck с именем нагрузки (logNewlyStuckWorkloads,
# internal/profiler/driftbaseline.go) — раньше переход был чистой функцией
# времени и не отмечался ничем (память drift-stuck-is-lazily-evaluated), из-за
# чего «0 → 2 за десять тихих минут» нельзя было привязать к нагрузкам.
#
# ПОРОГ НЕ НАЗНАЧАЕТСЯ (5.9.6): критерий требует НАЗВАТЬ нагрузки, а не
# уложиться в число. Невозможность назвать = НЕИЗМЕРИМ.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.5.17: stuck/overdue поимённо на обеих границах окна (№265) ---"
_w625_drift_names() { # $1=файл снимка /debug/state $2=состояние
    jq -r --arg st "$2" '[.drift_baseline.workloads[]? | select(.state==$st)
        | "\(.comm)(sig=\(.signatures),smp=\(.samples))"] | sort | join(" ")' "$1" 2>/dev/null
}
_w625_drift_rows() { # $1=файл снимка — сколько строк вообще пришло
    jq -r '[.drift_baseline.workloads[]?] | length' "$1" 2>/dev/null
}
_w625_ds0="$W625_ART/debug-state-window-start.json"
_w625_ds1="$W625_ART/debug-state-window-end.json"
_w625_ds_rows0=$(_w625_drift_rows "$_w625_ds0"); _w625_ds_rows1=$(_w625_drift_rows "$_w625_ds1")
if [ -z "${_w625_ds_rows0:-}" ] || [ -z "${_w625_ds_rows1:-}" ] || [ "${_w625_ds_rows0:-0}" -lt 1 ] || [ "${_w625_ds_rows1:-0}" -lt 1 ]; then
    die "6.2.5.17 НЕИЗМЕРИМ: /debug/state не отдал разрез drift_baseline.workloads хотя бы на одной границе окна (строк: открытие=${_w625_ds_rows0:-нет}, закрытие=${_w625_ds_rows1:-нет}) — назвать нагрузки в stuck/overdue нечем, а счётчик без имён этот критерий не закрывает (server.enable_debug выключен либо profiler.drift_baseline отключён)"
else
    for _w625_st in learning stuck overdue enforcing; do
        echo "  [$_w625_st] открытие: $(_w625_drift_names "$_w625_ds0" "$_w625_st" | cut -c1-400)"
        echo "  [$_w625_st] закрытие: $(_w625_drift_names "$_w625_ds1" "$_w625_st" | cut -c1-400)"
    done
    # Переходы ВНУТРИ тихого окна — из журнала, поимённо (item 4).
    _w625_stuck_j=$(journalctl -u "$W625_SVC" --since "@$_w625_t0" --until "@$_w625_t1" --no-pager 2>/dev/null \
        | grep 'entering stuck (blind spot)' | grep -oE 'workload=[^ ]+' | sed 's/^workload=//' | sort | uniq -c | awk '{printf "%s×%s ", $1, $2}')
    _w625_stuck_m0=$(_w625_metric_sum ebpf_guard_drift_baseline_stuck_learning_workloads "" "$W625_ART/metrics-window-start.txt")
    _w625_stuck_m1=$(_w625_metric_sum ebpf_guard_drift_baseline_stuck_learning_workloads "" "$W625_ART/metrics-window-end.txt")
    echo "  переходы в stuck ВНУТРИ окна (журнал, поимённо): ${_w625_stuck_j:-нет}"
    echo "  сверка с метрикой: stuck_learning_workloads открытие=$_w625_stuck_m0 закрытие=$_w625_stuck_m1 (дельта $(( _w625_stuck_m1 - _w625_stuck_m0 )))"
    _w625_stuck_n1=$(jq -r '[.drift_baseline.workloads[]? | select(.state=="stuck")] | length' "$_w625_ds1" 2>/dev/null)
    if [ "${_w625_stuck_m1:-0}" -gt 0 ] && [ "${_w625_stuck_n1:-0}" -eq 0 ]; then
        die "6.2.5.17 НЕИЗМЕРИМ: метрика показывает ${_w625_stuck_m1} нагрузок в stuck на закрытии окна, а поимённый разрез /debug/state — ни одной. Прибор расходится сам с собой, и «кто» по-прежнему неизвестно"
    elif [ "$(( _w625_stuck_m1 - _w625_stuck_m0 ))" -gt 0 ] && [ -z "${_w625_stuck_j:-}" ]; then
        die "6.2.5.17 НЕИЗМЕРИМ: stuck вырос на $(( _w625_stuck_m1 - _w625_stuck_m0 )) внутри окна, а ни один ИМЕННОЙ переход в журнале не напечатан — правка item 4 (logNewlyStuckWorkloads) не задеплоена, и рост снова не разбирается поимённо (ровно форма находки №265)"
    else
        pass "6.2.5.17 ИЗМЕРЕНО (порог не назначается, 5.9.6): на закрытии окна в stuck ${_w625_stuck_n1:-0} нагрузок поимённо, переходы внутри окна: ${_w625_stuck_j:-нет}"
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.4.12 (долг 6.2.4, метка сохранена) — ВРЕМЯ ДО ЗАМОРОЗКИ НА БОЕВОМ КАПЕ.
#
# Наблюдение без порога (5.9.6). Позитивный подконтроль 6.2.5.11 в конце
# прогона ПОНИЖАЕТ max_signatures_per_workload до 3 и доказывает, что
# счётчик движется; этот критерий — о другом: на БОЕВОМ капе (256) —
# сколько времени проходит от старта агента до первой заморозки и КАКИЕ
# нагрузки замерзают. Читается ДО подконтроля, иначе величина принадлежала
# бы капу 3, а не боевому.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.4.12: время до заморозки на боевом капе max_signatures=${_w625_maxsig:-?} (без порога) ---"
_w625_agent_epoch=$(cat /root/agent-start-6.2.5.epoch 2>/dev/null)
_w625_cap_first=$(journalctl -u "$W625_SVC" --since "$(_w625_journal_since)" --no-pager -o short-unix 2>/dev/null \
    | grep -m1 'workload signature cap reached' | awk '{printf "%d", $1}')
_w625_cap_names=$(journalctl -u "$W625_SVC" --since "$(_w625_journal_since)" --no-pager 2>/dev/null \
    | grep 'workload signature cap reached' | grep -oE 'workload=[^ ]+' | sed 's/^workload=//' | sort -u | tr '\n' ' ')
_w625_cap_metric=$(awk '/^ebpf_guard_drift_baseline_signature_cap_reached_total\{/{
        if (match($0, /comm="[^"]*"/)) printf "%s=%s ", substr($0, RSTART+6, RLENGTH-7), $NF }' \
    "$W625_ART/metrics-window-end.txt" 2>/dev/null)
_w625_sat_names=$(jq -r '[.drift_baseline.workloads[]? | select(.saturated==true) | .comm] | sort | join(" ")' "$_w625_ds1" 2>/dev/null)
echo "  замороженные нагрузки по метрике (comm=приращений): ${_w625_cap_metric:-нет}"
echo "  замороженные нагрузки по /debug/state на закрытии окна (saturated=true): ${_w625_sat_names:-нет}"
echo "  имена из журнала за прогон: ${_w625_cap_names:-нет}"
if [ -z "${_w625_maxsig:-}" ]; then
    die "6.2.4.12 НЕИЗМЕРИМ: max_signatures_per_workload не прочитан из $_w625_cfg — «боевой кап» назвать нечем, и величина принадлежала бы неизвестному потолку"
elif [ -z "${_w625_cap_first:-}" ]; then
    pass "6.2.4.12 ИЗМЕРЕНО (порог не назначается, 5.9.6): при боевом капе ${_w625_maxsig} за прогон (пролог+окно) НИ ОДНА нагрузка не заморозилась — время до заморозки больше длины прогона. Это величина, а не провал: порог этому критерию не назначен"
else
    pass "6.2.4.12 ИЗМЕРЕНО (порог не назначается, 5.9.6): при боевом капе ${_w625_maxsig} первая заморозка через $(( _w625_cap_first - ${_w625_agent_epoch:-_w625_cap_first} ))s после старта агента; замороженные нагрузки: ${_w625_cap_names:-нет}"
fi

# ---- 6.2.2.6, живая половина «фон молчит» ----
echo "--- 6.2.2.6 (живая половина 1/2): три правки условий на РЕАЛЬНОМ фоне ноды ---"
for _r in c2_periodic_beacon_pattern beacon_fixed_interval sigma_iptables_flush sigma_log_deletion; do
    _a0=$(_w625_metric_sum ebpf_guard_alerts_total "$_r" "$W625_ART/metrics-window-start.txt")
    _a1=$(_w625_metric_sum ebpf_guard_alerts_total "$_r" "$W625_ART/metrics-window-end.txt")
    _f0=$(_w625_metric_sum ebpf_guard_alerts_filtered_total "$_r" "$W625_ART/metrics-window-start.txt")
    _f1=$(_w625_metric_sum ebpf_guard_alerts_filtered_total "$_r" "$W625_ART/metrics-window-end.txt")
    _rl0=$(_w625_ratelimited "$_r" "$W625_ART/metrics-window-start.txt")
    _rl1=$(_w625_ratelimited "$_r" "$W625_ART/metrics-window-end.txt")
    echo "    $_r: за окно всего $(( (_a1 - _a0) + (_f1 - _f0) )) (экспортировано $(( _a1 - _a0 )), срезано min_severity $(( _f1 - _f0 )), срез лимитера $(( _rl1 - _rl0 )))"
done
echo "    (на окне 6.2.1 c2_periodic_beacon_pattern дал 602 — 71% всей величины прогона)"

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.5.8 ОКНО ПРОФИЛЯ (№244). ОТДЕЛЬНОЕ окно, сразу ПОСЛЕ окна объёма:
# `curl /debug/pprof/profile?seconds=30` — действие измерителя, и внутри окна
# объёма оно нарушило бы 6.2.5.3.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.5.8: окно профиля ${W625_PROFILE_SECS}s (ОТДЕЛЬНОЕ, после окна объёма) ---"
mkdir -p "$W625_ART/profile" 2>/dev/null
_w625_pcpu0=$(_w625_metric_raw process_cpu_seconds_total "$W625_ART/metrics-window-end.txt")
_w625_pt0=$(_w625_epoch)
# СОБСТВЕННЫЙ ТАЙМАУТ, а не общий. `_w625_curl` несёт --max-time 30, и запрос
# профиля на 30 с в него НЕ УКЛАДЫВАЕТСЯ по построению: сервер держит
# соединение ровно PROFILE_SECS и только потом отдаёт тело. Прогон 06.09.2026
# привёз из-за этого cpu.pprof НУЛЕВОГО РАЗМЕРА при исправном pprof (смок на
# 5 с проходил — дефект виден только на боевой длине окна).
curl -s --max-time "$(( W625_PROFILE_SECS + 60 ))" -H "Authorization: Bearer $W625_TOKEN" \
    "$W625_API/debug/pprof/profile?seconds=$W625_PROFILE_SECS" > "$W625_ART/profile/cpu.pprof" 2>/dev/null
_w625_curl "$W625_API/debug/pprof/heap" > "$W625_ART/profile/heap.pprof" 2>/dev/null
_w625_curl "$W625_API/debug/pprof/goroutine?debug=1" > "$W625_ART/profile/goroutine.txt" 2>/dev/null
_w625_metrics > "$W625_ART/profile/metrics-profile-end.txt"
_w625_pt1=$(_w625_epoch)
_w625_pcpu1=$(_w625_metric_raw process_cpu_seconds_total "$W625_ART/profile/metrics-profile-end.txt")
_w625_psize=$(wc -c < "$W625_ART/profile/cpu.pprof" 2>/dev/null | tr -d ' ')
echo "  профиль снят: cpu.pprof ${_w625_psize:-0} байт, heap.pprof $(wc -c < "$W625_ART/profile/heap.pprof" 2>/dev/null | tr -d ' ') байт"
echo "  дельта process_cpu_seconds_total за окно профиля: $(awk -v a="${_w625_pcpu0:-0}" -v b="${_w625_pcpu1:-0}" -v t="$(( _w625_pt1 - _w625_pt0 ))" 'BEGIN{if(t>0) printf "%.2f с за %d с = %.1f%% ядра", b-a, t, 100.0*(b-a)/t; else printf "НЕИЗМЕРИМА"}')"
if [ "${_w625_psize:-0}" -lt 1000 ]; then
    die "6.2.5.8 ПРОВАЛЕН: профиль не снят (cpu.pprof ${_w625_psize:-0} байт). «34% ядра» без разбора — не величина, а незнание (находка №244); отсутствие профиля в архиве есть провал критерия, а не оговорка"
else
    echo "  top-10 функций по CPU:"
    if [ -x "$W625_GO" ]; then
        "$W625_GO" tool pprof -top -nodecount=10 "$W625_REPO/build/ebpf-guard" "$W625_ART/profile/cpu.pprof" 2>/dev/null \
            | tee "$W625_ART/profile/top10.txt" | sed 's/^/    /'
    fi
    if [ -s "$W625_ART/profile/top10.txt" ]; then
        pass "6.2.5.8 ДОСТИГНУТО: профиль снят в отдельном окне и разобран top-10 (порог не назначается — запрет 5.9.6)"
    else
        die "6.2.5.8 ПРОВАЛЕН (половина «разбор»): профиль снят (${_w625_psize} байт), но top-10 не построен — go tool pprof недоступен ($W625_GO) или бинарь $W625_REPO/build/ebpf-guard не совпал с профилем. Профиль без разбора вердикта не даёт"
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
_w625_attack_phase_start=$(_w625_epoch)
echo "--- 6.2.1.2 (регрессия): сторож слепоты лимитера (хостовое чтение токена пода) ---"
W625_HOSTCAT_PODDED=0
if [ "$W625_INSTRUMENTED" -eq 1 ]; then
    _w625_target=$(find /var/lib/kubelet/pods -maxdepth 6 -type f -name token 2>/dev/null | head -1)
    [ -z "$_w625_target" ] && _w625_target=$(find /var/lib/kubelet/pods -maxdepth 4 -type f 2>/dev/null | head -1)
    if [ -z "$_w625_target" ]; then
        die "6.2.1.2 НЕИЗМЕРИМ: под /var/lib/kubelet/pods нет ни одного файла — хостовую половину нечем подать, ноль был бы приборным"
    else
        _w625_hrl0=$(_w625_ratelimited "$W625_HOST_RULES")
        cp /bin/cat /usr/local/bin/w625hostcat 2>/dev/null
        _w625_tn=$(_w625_epoch)
        _w625_bytes=$(/usr/local/bin/w625hostcat "$_w625_target" 2>/dev/null | wc -c)
        _w625_hits=0; _w625_waited=0
        while [ "$_w625_waited" -lt "$W625_POS_TIMEOUT" ]; do
            sleep "$W625_SETTLE"; _w625_waited=$(( _w625_waited + W625_SETTLE ))
            _w625_hits=$(_w625_alerts | jq --argjson t "$_w625_tn" --arg ids "$W625_HOST_RULES" \
                '[.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.comm=="w625hostcat") and (.rule_id as $r|($ids|split(" "))|index($r)))]|length' 2>/dev/null || echo 0)
            [ "${_w625_hits:-0}" -gt 0 ] && break
        done
        _w625_hrl1=$(_w625_ratelimited "$W625_HOST_RULES")
        _w625_all=$(_w625_alerts | jq --argjson t "$_w625_tn" '[.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.comm=="w625hostcat"))]|length' 2>/dev/null || echo 0)
        _w625_rules=$(_w625_alerts | jq -r --argjson t "$_w625_tn" '.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.comm=="w625hostcat"))|.rule_id' 2>/dev/null | sort -u | tr '\n' ' ')
        echo "  сторож результата: прочитано байт = $_w625_bytes (цель $_w625_target)"
        echo "  алертов от comm=w625hostcat: всего $_w625_all (правила: ${_w625_rules:-нет}); из них обязательных: $_w625_hits"
        echo "  срез лимитера обязательных правил за время контроля: $(( _w625_hrl1 - _w625_hrl0 ))"
        if [ "${_w625_bytes:-0}" -lt 1 ]; then
            die "6.2.1.2 НЕИЗМЕРИМ: хостовой читатель ничего не прочитал (байт=$_w625_bytes) — ноль приборный (память positive-control-needs-result-sentinel)"
        elif [ "${_w625_hits:-0}" -lt 1 ] && [ "$(( _w625_hrl1 - _w625_hrl0 ))" -gt 0 ]; then
            die "6.2.1.2 ПРОВАЛЕН (шум→слепота, регресс находки №221): хост прочитал токен ($_w625_bytes байт), обязательные правила не поднялись, И их лимитер срезал $(( _w625_hrl1 - _w625_hrl0 )) срабатываний"
        elif [ "${_w625_hits:-0}" -lt 1 ]; then
            die "6.2.1.2 ПРОВАЛЕН (детекта нет): хост прочитал токен пода ($_w625_bytes байт), обязательные правила не поднялись, лимитер их НЕ срезал"
        else
            pass "6.2.1.2 ДОСТИГНУТО: хостовое чтение токена пода подняло $_w625_hits обязательных алертов (${_w625_rules})"
        fi
        W625_HOSTCAT_PODDED=$(_w625_alerts | jq --argjson t "$_w625_tn" '[.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.comm=="w625hostcat") and ((.enrichment.pod_name // "")!=""))]|length' 2>/dev/null || echo 0)
        rm -f /usr/local/bin/w625hostcat 2>/dev/null
    fi
else
    echo "  ПРОПУЩЕН: 6.2.5.0 не взят"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.1.3 (регрессия) НЕГАТИВНЫЙ КОНТРОЛЬ НА ПОЛНОМ ОБЪЁМЕ (находка №227).
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.1.3 (регрессия): негативный контроль на полном объёме ---"
if [ "$W625_INSTRUMENTED" -eq 1 ]; then
    _w625_alerts > "$W625_ART/alerts-negative.json"
    echo "  comm, у которых ХОТЬ ОДИН алерт несёт pod_name (это обязаны быть только поды):"
    jq -r '[.[]|select((.enrichment.pod_name // "")!="")]|group_by(.comm)|map({c:.[0].comm,n:length})|sort_by(-.n)[]|"    \(.c): \(.n)"' "$W625_ART/alerts-negative.json" 2>/dev/null | head -20
    _w625_bad=$(jq -r '[.[]|select(((.enrichment.pod_name // "")!="") and ((.enrichment.container_id // "")==""))]|length' "$W625_ART/alerts-negative.json" 2>/dev/null || echo 0)
    _w625_hostpodded=$(jq -r --arg h "k3s-server iptables ip6tables systemd sshd cron kubectl systemd-logind" \
        '[.[]|select(((.enrichment.pod_name // "")!="") and ((.comm) as $c|($h|split(" "))|index($c)))]|length' "$W625_ART/alerts-negative.json" 2>/dev/null || echo 0)
    echo "  алертов с pod_name БЕЗ container_id: $_w625_bad"
    echo "  алертов с pod_name у заведомо хостовых comm: $_w625_hostpodded"
    echo "  алертов с pod_name у контрольного хостового читателя: ${W625_HOSTCAT_PODDED:-0}"
    if [ "${_w625_hostpodded:-0}" -gt 0 ] || [ "${W625_HOSTCAT_PODDED:-0}" -gt 0 ] || [ "${_w625_bad:-0}" -gt 0 ]; then
        die "6.2.1.3 ПРОВАЛЕН: хостовые процессы получили ЧУЖУЮ личность пода (хостовые comm: $_w625_hostpodded, без container_id: $_w625_bad, контрольный читатель: ${W625_HOSTCAT_PODDED:-0})"
    else
        pass "6.2.1.3 ДОСТИГНУТО: ни один хостовой процесс не получил личность пода"
    fi
else
    echo "  ПРОПУЩЕН: 6.2.5.0 не взят"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.1.2b (регрессия) ПОЗИТИВНЫЙ КОНТРОЛЬ ОСИ ПОДА.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.1.2b (регрессия): под читает свой SA-токен ---"
if [ "$W625_INSTRUMENTED" -eq 1 ]; then
    "$W625_KUBECTL" create namespace "$W625_NS" --dry-run=client -o yaml 2>/dev/null | "$W625_KUBECTL" apply -f - >/dev/null 2>&1
    "$W625_KUBECTL" -n "$W625_NS" delete pod w625-token-probe --ignore-not-found --wait=true >/dev/null 2>&1
    cat > "$W625_ART/w625-token-probe.yaml" <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: w625-token-probe
  labels:
    app: w625-token-probe
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
          echo "W624-SENTINEL opener_comm=$(cat /proc/$$/comm) token_head=$(echo "$t" | cut -c1-12) token_len=${#t}"
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
    _w625_tp=$(_w625_epoch)
    "$W625_KUBECTL" -n "$W625_NS" apply -f "$W625_ART/w625-token-probe.yaml" >/dev/null 2>&1
    "$W625_KUBECTL" -n "$W625_NS" wait --for=condition=Ready pod/w625-token-probe --timeout=90s >/dev/null 2>&1
    _w625_pdelta=0; _w625_waited=0
    while [ "$_w625_waited" -lt "$W625_POS_TIMEOUT" ]; do
        sleep "$W625_SETTLE"; _w625_waited=$(( _w625_waited + W625_SETTLE ))
        _w625_pdelta=$(_w625_alerts | jq --arg ids "$W625_K8S_RULES" --argjson t "$_w625_tp" \
            '[.[]|select((.rule_id as $r|($ids|split(" "))|index($r)) and ((.enrichment.pod_name // "")=="w625-token-probe") and ((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t))]|length' 2>/dev/null || echo 0)
        [ "${_w625_pdelta:-0}" -gt 0 ] && break
    done
    _w625_sent=$("$W625_KUBECTL" -n "$W625_NS" logs w625-token-probe 2>/dev/null | grep -m1 'W624-SENTINEL')
    _w625_phit=$(_w625_alerts | jq -r --arg ids "$W625_K8S_RULES" --argjson t "$_w625_tp" \
        '.[]|select((.rule_id as $r|($ids|split(" "))|index($r)) and ((.enrichment.pod_name // "")=="w625-token-probe") and ((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t))|.rule_id' 2>/dev/null | sort -u | tr '\n' ' ')
    echo "  ожидание записи в стор: ${_w625_waited}s"
    echo "  сторож результата: ${_w625_sent:-НЕ НАПЕЧАТАН}"
    echo "  алертов с pod_name=w625-token-probe: $_w625_pdelta (правила: ${_w625_phit:-нет})"
    _w625_len=$(printf '%s' "${_w625_sent:-}" | grep -oE 'token_len=[0-9]+' | cut -d= -f2)
    if [ -z "${_w625_len:-}" ] || [ "${_w625_len:-0}" -lt 100 ]; then
        die "6.2.1.2b НЕИЗМЕРИМ: сторож результата не напечатал прочитанный токен (token_len=${_w625_len:-нет}) — ноль правил приборный"
    elif [ "$_w625_pdelta" -lt 1 ]; then
        die "6.2.1.2b ПРОВАЛЕН: под прочитал токен (token_len=$_w625_len), а правила ${W625_K8S_RULES} не поднялись с его именем"
    else
        pass "6.2.1.2b ДОСТИГНУТО: чтение SA-токена подом подтверждено сторожем (token_len=$_w625_len) и подняло $_w625_pdelta алертов С ИМЕНЕМ ПОДА (${_w625_phit})"
    fi
else
    echo "  ПРОПУЩЕН: 6.2.5.0 не взят"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.5.10 ЦЕНА СТАРТА ПОДА — С ПОРОГОМ (№236).
# Порог 45/под = ceil(36 × 1.25): 36 измерено прогоном 6.2.1 (108 алертов на
# 3 оборота), 25% запаса на то, что величина снята ОДНИМ прогоном.
# Бюджет ОТДЕЛЬНЫЙ от 6.2.5.1: окна физически не пересекаются (churn идёт
# после тихого окна). Вопрос «как боевой часовой гейт учитывает непрерывный
# churn» этим порогом НЕ закрыт и остаётся открытым (пункт 10 plan.md).
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.5.10: цена одного старта пода, порог ${W625_CHURN_BUDGET}/под ---"
if [ "$W625_INSTRUMENTED" -eq 1 ]; then
    _w625_tc=$(_w625_epoch)
    # ITEM 3 (№263): фаза стартов подов ЭТОГО контроля объявляется ТРЕТЬИМ
    # именованным окном, рядом с [t0,t1] (тихое окно объёма) и
    # [attack_phase_start, attack_phase_end] (окно позитивных контролей).
    # Постановка 6.2.4.6 требует «ноль инцидентов с корнем нодового актора ЗА
    # ПРОГОН ЦЕЛИКОМ», а контроль 6.2.5.10 обязан подать 3 старта пода — то
    # есть по построению произвести containerd-shim/runc-инциденты, которых
    # 6.2.4.6 не имеет права прощать фазой атак (в этом и отличие от старого
    # 6.2.3.7). Противоречие снимается вычитанием ИМЕННО этого окна:
    # инцидент внутри него печатается ОТДЕЛЬНОЙ строкой и в вердикт не идёт,
    # тот же корень вне его — засчитывается.
    _w625_pod_start_phase_start=$_w625_tc
    for i in $(seq 1 "$W625_CHURN"); do
        "$W625_KUBECTL" -n "$W625_NS" run "w625-churn-$i" --image=busybox:1.36 --restart=Never --command -- sleep 15 >/dev/null 2>&1
    done
    sleep 45
    for i in $(seq 1 "$W625_CHURN"); do "$W625_KUBECTL" -n "$W625_NS" delete pod "w625-churn-$i" --ignore-not-found --wait=false >/dev/null 2>&1; done
    sleep $(( W625_SETTLE * 3 ))
    _w625_pod_start_phase_end=$(_w625_epoch)
    _w625_alerts > "$W625_ART/alerts-churn-end.json"
    _w625_churn=$(jq --argjson t "$_w625_tc" '[.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.comm|test("^(runc|containerd|conmon|crun|dockerd|pause)")))]' "$W625_ART/alerts-churn-end.json" 2>/dev/null)
    _w625_cn=$(echo "${_w625_churn:-[]}" | jq 'length' 2>/dev/null); _w625_cn=${_w625_cn:-0}
    _w625_per=$(awk -v n="$_w625_cn" -v p="$W625_CHURN" 'BEGIN{printf "%.1f", (p>0? n/p : 0)}')
    echo "  запущено и снято подов: $W625_CHURN; алертов от рантайм-comm: $_w625_cn → $_w625_per на под (порог ${W625_CHURN_BUDGET})"
    echo "${_w625_churn:-[]}" | jq -r 'group_by(.rule_id)|map({r:.[0].rule_id,n:length})|sort_by(-.n)[]|"    \(.r): \(.n)"' 2>/dev/null | head -25
    if awk -v v="$_w625_per" -v b="$W625_CHURN_BUDGET" 'BEGIN{exit !(v > b)}'; then
        die "6.2.5.10 ПРОВАЛЕН: старт пода стоит $_w625_per алертов при бюджете ${W625_CHURN_BUDGET}/под (36 × 1.25, №236). Глушить по comm=runc нельзя — это ровно те правила, что обязаны ловить контейнерный побег; чинится сужением условий, а не исключением"
    else
        pass "6.2.5.10 ДОСТИГНУТО: старт пода стоит $_w625_per алертов ≤ ${W625_CHURN_BUDGET}/под"
    fi
else
    echo "  ПРОПУЩЕН: 6.2.5.0 не взят"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.1.8 (регрессия) СЛОЙ 2: КЛЮЧ ИСКЛЮЧЕНИЯ, КОТОРЫЙ ПРОЦЕСС СЕБЕ НЕ НАЗНАЧАЕТ.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.1.8 (регрессия): образ процесса как ключ исключения ---"
if [ "$W625_INSTRUMENTED" -eq 1 ]; then
    W625_EXE_PREFIXES="/usr/ /bin/ /sbin/ /opt/ /var/lib/rancher/"
    _w625_exe_bad=""
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
        for _pre in $W625_EXE_PREFIXES; do
            case "${_e:-}" in "$_pre"*) _ok=1 ;; esac
        done
        [ "$_ok" -eq 1 ] || _w625_exe_bad="$_w625_exe_bad $_c(${_e:-<пусто>})"
    done
    echo "  обращений к /proc за образом (ebpf_guard_exe_path_lookups_total, накопительно): $(_w625_metric_sum ebpf_guard_exe_path_lookups_total "" 2>/dev/null)"
    if [ -n "$_w625_exe_bad" ]; then
        die "6.2.1.8 ПРОВАЛЕН (половина «покрытие»): образ демона(ов)$_w625_exe_bad не попадает ни под один префикс правил ($W625_EXE_PREFIXES) — исключения фона ноды для них НЕ ПРИМЕНЯЮТСЯ"
    else
        pass "6.2.1.8 ДОСТИГНУТО (половина «покрытие»): образы всех найденных хостовых демонов попадают под префиксы исключений"
    fi

    _w625_target8=$(find /var/lib/kubelet/pods -maxdepth 6 -type f -name token 2>/dev/null | head -1)
    [ -z "$_w625_target8" ] && _w625_target8=$(find /var/lib/kubelet/pods -maxdepth 4 -type f 2>/dev/null | head -1)
    if [ -z "$_w625_target8" ]; then
        die "6.2.1.8 НЕИЗМЕРИМ (половина «отказ обхода»): под /var/lib/kubelet/pods нет ни одного файла — подделке нечего читать"
    else
        # ИМЯ КОПИИ — РОВНО ИМЯ ДЕМОНА: comm ядро берёт из базового имени
        # образа в execve, `exec -a` подменяет только argv[0] (память
        # exec-a-argv0-spoof-kills-proc-args). Иначе исключение
        # node-host-daemon не применилось бы В ЛЮБОМ СЛУЧАЕ и контроль
        # проверял бы не слой 2.
        rm -rf /tmp/w625-bypass 2>/dev/null
        mkdir -p /tmp/w625-bypass 2>/dev/null
        cp /bin/cat /tmp/w625-bypass/k3s-server 2>/dev/null
        chmod 0755 /tmp/w625-bypass/k3s-server 2>/dev/null
        _w625_t8=$(_w625_epoch)
        ( exec -a k3s-server /tmp/w625-bypass/k3s-server "$_w625_target8" ) > /tmp/w625-bypass/out 2>/dev/null &
        _w625_p8=$!
        wait "$_w625_p8" 2>/dev/null
        _w625_b8=$(wc -c < /tmp/w625-bypass/out 2>/dev/null | tr -d ' ')
        _w625_h8=0; _w625_w8=0
        while [ "$_w625_w8" -lt "$W625_POS_TIMEOUT" ]; do
            sleep "$W625_SETTLE"; _w625_w8=$(( _w625_w8 + W625_SETTLE ))
            _w625_h8=$(_w625_alerts | jq --argjson t "$_w625_t8" --argjson p "${_w625_p8:-0}" --arg ids "$W625_HOST_RULES" \
                '[.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.pid == $p) and (.rule_id as $r|($ids|split(" "))|index($r)))]|length' 2>/dev/null || echo 0)
            [ "${_w625_h8:-0}" -gt 0 ] && break
        done
        _w625_c8=$(_w625_alerts | jq -r --argjson p "${_w625_p8:-0}" '[.[]|select(.pid == $p)][0].comm // "нет алертов от этого pid"' 2>/dev/null)
        echo "  сторож результата подделки: прочитано байт = $_w625_b8 (цель $_w625_target8)"
        echo "  подделка: pid=$_w625_p8, образ /tmp/w625-bypass/k3s-server, comm в сторе=$_w625_c8"
        echo "  алертов от подделки (по её pid): $_w625_h8 из обязательных ($W625_HOST_RULES)"
        if [ "${_w625_b8:-0}" -lt 1 ]; then
            die "6.2.1.8 НЕИЗМЕРИМ (половина «отказ обхода»): подделка не прочитала ни байта — ноль правил приборный"
        elif [ "$_w625_c8" != "k3s-server" ] && [ "${_w625_h8:-0}" -lt 1 ]; then
            die "6.2.1.8 НЕИЗМЕРИМ (половина «отказ обхода»): подделка не носит имени демона — стор знает её как «$_w625_c8». При таком comm исключение не применилось бы в любом случае, и слой 2 контроль не проверял"
        elif [ "${_w625_h8:-0}" -lt 1 ]; then
            die "6.2.1.8 ПРОВАЛЕН (половина «отказ обхода»): процесс, назвавшийся k3s-server и прочитавший токен пода ($_w625_b8 байт), НЕ поднял ни одного из $W625_HOST_RULES — исключение следует за именем, а не за образом"
        else
            pass "6.2.1.8 ДОСТИГНУТО (половина «отказ обхода»): подделка носила имя демона (comm=$_w625_c8), но не унаследовала его тишину — поднято $_w625_h8 обязательных правил"
        fi
        rm -rf /tmp/w625-bypass 2>/dev/null
    fi
else
    echo "  ПРОПУЩЕН: 6.2.5.0 не взят"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.1.9 (регрессия) СЛОЙ 3: СМЕНА ПРАВ НА ФАЙЛОВОЙ ОСИ + вторая половина
# №243 (chmod даёт ровно одно событие: syscall-ось его больше не производит).
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.1.9 (регрессия): chmod с разрешённым путём + №243 ---"
if [ "$W625_INSTRUMENTED" -eq 1 ]; then
    _w625_hook_ok=$(_w625_metrics | awk '/^ebpf_guard_file_hook_attach_total\{.*result="ok"/ {s+=$NF} END{printf "%d", s+0}')
    _w625_hook_err=$(_w625_metrics | awk '/^ebpf_guard_file_hook_attach_total\{.*result="(error|missing)"/ {s+=$NF} END{printf "%d", s+0}')
    echo "  привязка chmod-хуков: ok=$_w625_hook_ok, error+missing=$_w625_hook_err"
    echo "  chmod без разрешённого пути (накопительно): $(_w625_metric_sum ebpf_guard_file_chmod_unresolved_total "" 2>/dev/null)"

    # №243, вторая половина: syscall-события за серию chmod. До правки каждый
    # chmod давал ВТОРОЕ событие на syscall-оси, которое никто не читает.
    _w625_sysc_m0=$(_w625_metrics > "$W625_ART/metrics-chmod-0.txt"; awk '/^ebpf_guard_events_total\{.*type="syscall"/{s+=$NF} END{printf "%d", s+0}' "$W625_ART/metrics-chmod-0.txt")
    _w625_t9=$(_w625_epoch)
    mkdir -p /tmp/w625-chmod 2>/dev/null
    : > /tmp/w625-chmod/payload 2>/dev/null
    chmod 0755 /tmp/w625-chmod/payload 2>/dev/null
    _w625_m1=$(stat -c '%a' /tmp/w625-chmod/payload 2>/dev/null)
    cp /bin/cat /usr/local/bin/w625-chmod-bin 2>/dev/null
    chmod 0755 /usr/local/bin/w625-chmod-bin 2>/dev/null
    _w625_m2=$(stat -c '%a' /usr/local/bin/w625-chmod-bin 2>/dev/null)
    # Серия из 50 chmod по одному пути: на syscall-оси это дало бы +50 событий.
    for _i in $(seq 1 50); do chmod 0644 /tmp/w625-chmod/payload 2>/dev/null; chmod 0755 /tmp/w625-chmod/payload 2>/dev/null; done
    echo "  сторож результата: права /tmp/w625-chmod/payload = ${_w625_m1:-НЕ ПРОЧИТАНЫ}, /usr/local/bin/w625-chmod-bin = ${_w625_m2:-НЕ ПРОЧИТАНЫ}"

    _w625_c9=0; _w625_w9=0
    while [ "$_w625_w9" -lt "$W625_POS_TIMEOUT" ]; do
        sleep "$W625_SETTLE"; _w625_w9=$(( _w625_w9 + W625_SETTLE ))
        _w625_c9=$(_w625_alerts | jq --argjson t "$_w625_t9" \
            '[.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.rule_id|test("chmod")))]|length' 2>/dev/null || echo 0)
        [ "${_w625_c9:-0}" -gt 1 ] && break
    done
    _w625_r9=$(_w625_alerts | jq -r --argjson t "$_w625_t9" \
        '.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.rule_id|test("chmod")))|.rule_id' 2>/dev/null | sort -u | tr '\n' ' ')
    _w625_metrics > "$W625_ART/metrics-chmod-1.txt"
    _w625_sysc_m1=$(awk '/^ebpf_guard_events_total\{.*type="syscall"/{s+=$NF} END{printf "%d", s+0}' "$W625_ART/metrics-chmod-1.txt")
    echo "  алертов о смене прав после подачи: $_w625_c9 (правила: ${_w625_r9:-нет})"
    echo "  №243, наблюдение: syscall-событий за серию из 100 chmod: $(( _w625_sysc_m1 - _w625_sysc_m0 )) (при chmod на syscall-оси было бы ≥ 100; фон ноды сюда тоже входит, поэтому это наблюдение, а вердикт №243 выносит monitored_syscalls в преflight'е)"

    if [ -z "${_w625_m1:-}" ] || [ -z "${_w625_m2:-}" ]; then
        die "6.2.1.9 НЕИЗМЕРИМ: сторож результата не прочитал права после chmod — подача не состоялась, ноль правил приборный"
    elif [ "$_w625_hook_ok" -eq 0 ]; then
        die "6.2.1.9 ПРОВАЛЕН (приборный ноль): ни один chmod-хук не привязан (ok=0, error+missing=$_w625_hook_err) — три правила о смене прав НЕ МОГУТ сработать"
    elif ! printf '%s' "$_w625_r9" | grep -q 'sigma_chmod_executable_tmp'; then
        die "6.2.1.9 ПРОВАЛЕН: chmod +x в /tmp состоялся (права $_w625_m1), а sigma_chmod_executable_tmp не поднялся — тихая смерть правила"
    elif ! printf '%s' "$_w625_r9" | grep -q 'evasion_chmod_sensitive'; then
        die "6.2.1.9 ПРОВАЛЕН: chmod системного бинаря состоялся (права $_w625_m2), а evasion_chmod_sensitive не поднялся"
    else
        pass "6.2.1.9 ДОСТИГНУТО: смена прав видна с разрешённым путём, и каждое из двух мест подняло СВОЁ правило (${_w625_r9})"
    fi
    rm -rf /tmp/w625-chmod /usr/local/bin/w625-chmod-bin 2>/dev/null
else
    echo "  ПРОПУЩЕН: 6.2.5.0 не взят"
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
_w625_now5=$(_w625_epoch)
if [ -z "${_w625_t1:-}" ]; then
    die "6.2.3.5 НЕИЗМЕРИМ: тихое окно не открывалось к моменту подачи write-механизма — порядок блоков нарушен, границы окна неизвестны"
    W625_WRITE_ORDER_OK=0
elif [ "$_w625_now5" -le "$_w625_t1" ]; then
    die "6.2.3.5 НЕИЗМЕРИМ (открытый вопрос 6): подача write-механизма идёт ВНУТРИ тихого окна (сейчас $(_w625_utc "$_w625_now5") ≤ t1 $(_w625_utc "$_w625_t1")). Блок намеренно поднимает sigma_log_deletion, и эти алерты попадут в величину 6.2.5.1/6.2.5.2 как шум продукта. Вернуть блок ПОСЛЕ 6.2.1.9"
    W625_WRITE_ORDER_OK=0
else
    echo "  порядок (открытый вопрос 6): подача идёт через $((_w625_now5 - _w625_t1)) с ПОСЛЕ закрытия тихого окна — собственные алерты блока вне измеряемой величины"
    W625_WRITE_ORDER_OK=1
fi
if [ "$W625_INSTRUMENTED" -eq 1 ]; then
    _w625_dup_ok=$(_w625_metrics | awk -F'[ }]' '/^ebpf_guard_file_hook_attach_total\{hook="sys_enter_dup[23]?",result="ok"\}/ {s+=$NF} END{printf "%d", s+0}')
    _w625_dup_bad=$(_w625_metrics | awk -F'[ }]' '/^ebpf_guard_file_hook_attach_total\{hook="sys_enter_dup[23]?",result="(error|missing)"\}/ {s+=$NF} END{printf "%d", s+0}')
    echo "  привязка dup/dup2/dup3-хуков: ok=$_w625_dup_ok, error+missing=$_w625_dup_bad"

    _w625_echo_path="/var/log/w625-write-mechanism-echo.log"
    _w625_dd_path="/var/log/w625-write-mechanism-dd.log"
    rm -f "$_w625_echo_path" "$_w625_dd_path" 2>/dev/null
    _w625_t5=$(_w625_epoch)
    echo 'w625-op-write-echo-payload' >> "$_w625_echo_path"
    _w625_echo_bytes=$(wc -c < "$_w625_echo_path" 2>/dev/null | tr -d ' ')
    dd if=/dev/zero of="$_w625_dd_path" bs=1 count=32 2>/dev/null
    _w625_dd_bytes=$(wc -c < "$_w625_dd_path" 2>/dev/null | tr -d ' ')
    echo "  сторож результата: echo записал ${_w625_echo_bytes:-0} байт в $_w625_echo_path, dd — ${_w625_dd_bytes:-0} байт в $_w625_dd_path"

    _w625_w5=0; _w625_echo_hit=0; _w625_dd_hit=0
    while [ "$_w625_w5" -lt "$W625_POS_TIMEOUT" ]; do
        sleep "$W625_SETTLE"; _w625_w5=$(( _w625_w5 + W625_SETTLE ))
        _w625_alerts > "$W625_ART/alerts-write-mechanism.json"
        _w625_echo_hit=$(jq --argjson t "$_w625_t5" --arg p "$_w625_echo_path" \
            '[.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and .rule_id=="sigma_log_deletion" and (.details["file.path"]==$p))]|length' \
            "$W625_ART/alerts-write-mechanism.json" 2>/dev/null || echo 0)
        _w625_dd_hit=$(jq --argjson t "$_w625_t5" --arg p "$_w625_dd_path" \
            '[.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and .rule_id=="sigma_log_deletion" and (.details["file.path"]==$p))]|length' \
            "$W625_ART/alerts-write-mechanism.json" 2>/dev/null || echo 0)
        [ "${_w625_echo_hit:-0}" -ge 1 ] && [ "${_w625_dd_hit:-0}" -ge 1 ] && break
    done
    echo "  6.2.3.5, исход подачи: echo→sigma_log_deletion=${_w625_echo_hit:-0}, dd→sigma_log_deletion=${_w625_dd_hit:-0}"

    if [ -z "${_w625_echo_bytes:-}" ] || [ "$_w625_echo_bytes" = "0" ] || [ -z "${_w625_dd_bytes:-}" ] || [ "$_w625_dd_bytes" = "0" ]; then
        die "6.2.3.5 НЕИЗМЕРИМ: сторож результата не подтвердил запись (echo=${_w625_echo_bytes:-0}Б, dd=${_w625_dd_bytes:-0}Б) — подача не состоялась, ноль правила приборный"
        die "6.2.3.6 НЕИЗМЕРИМ: та же подача — без подтверждённой записи вердикт правилу вынести не на чем"
    elif [ "${_w625_echo_hit:-0}" -eq 0 ] && [ "${_w625_dd_hit:-0}" -eq 0 ]; then
        die "6.2.3.5 ПРОВАЛЕН: механизм — ОСЬ OP. Обе нагрузки молчат при подтверждённой записи — сужение №234 (op in [write]) в принципе не совпадает с этим write(), fd→path не при чём. Решение 4: откатить условие op у sigma_log_deletion"
        die "6.2.3.6 ПРОВАЛЕН: sigma_log_deletion не поднимается НИ НА ОДНОЙ подаче (echo=${_w625_echo_hit:-0}, dd=${_w625_dd_hit:-0}) — своя метка выносит свой вердикт, а не наследует его у 6.2.3.5"
    elif [ "${_w625_echo_hit:-0}" -eq 0 ] && [ "${_w625_dd_hit:-0}" -ge 1 ]; then
        die "6.2.3.5 ПРОВАЛЕН: механизм — FD→PATH. echo молчит, dd поднимает — dup2-хук не привязан или не переносит fd_path_map (ok=$_w625_dup_ok, error+missing=$_w625_dup_bad). Решение 4: хуки sys_enter_dup{,2,3} обязаны быть в сборке"
        die "6.2.3.6 ПРОВАЛЕН: sigma_log_deletion поднимается только на одной подаче из двух (echo=${_w625_echo_hit:-0}, dd=${_w625_dd_hit:-0})"
    else
        # 6.2.3.5 и 6.2.3.6 — ДВЕ РАЗНЫЕ МЕТКИ на одной подаче: 6.2.3.5
        # спрашивает «назван ли МЕХАНИЗМ немоты» (ось op против fd→path),
        # 6.2.3.6 — «поднимается ли правило на обеих подачах». В прогоне
        # 6.2.4 успешный исход печатал ТОЛЬКО 6.2.3.6, и 6.2.3.5 своего
        # вердикта не выносила (постановка 6.2.5.14 требует, чтобы вынесла:
        # метка без вердикта неотличима от нереализованной — №269/№270).
        pass "6.2.3.5 ДОСТИГНУТО: механизм немоты op=write назван подачей — обе нагрузки (echo=${_w625_echo_hit:-0}, dd=${_w625_dd_hit:-0}) поднимают правило, то есть ни ось op, ни fd→path немоты не дают на этом стенде"
        pass "6.2.3.6 ДОСТИГНУТО: sigma_log_deletion (op in [write]) поднимается НА ОБЕИХ подачах — echo и dd (на этом стенде dd тоже идёт через dup2, strace 06.09.2026) — механизм fd→path закрыт хуками sys_enter_dup{,2,3} (ok=$_w625_dup_ok, error+missing=$_w625_dup_bad)"
    fi
    rm -f "$_w625_echo_path" "$_w625_dd_path" 2>/dev/null
else
    echo "  ПРОПУЩЕН: 6.2.5.0 не взят"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.3.13 (item 4 постановки, №248): сужение верхушки разбивки (в) —
# sigma_failed_login_syscall_daemon и rootkit_pam_module_added_daemon сужены
# осью op=write (были: любой read/open от sshd|cron — 3090/2400 и 2970/2280
# алертов/окно на двух архивах 6.2.2, первые два источника разбивки 6.2.5.2).
# Юнит на ОБЕ половины: фон (штатные sshd/cron за тихое окно — читают PAM на
# каждом логине/job'е) обязан молчать; подделка identity (comm=sshd/cron),
# которая ДЕЙСТВИТЕЛЬНО пишет в PAM, обязана по-прежнему поднимать правило —
# иначе это не сужение, а немота (тот же класс проверки, что 6.2.1.8).
# Половина «фон» читает уже снятое тихое окно ($W625_ART/metrics-window-*)
# прямой дельтой (величина гейта — показание прибора, а не строка таблицы,
# память f6b-table-indexed-by-limiter-cut), не отдельное ожидание.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.3.13: сужение верхушки шума op=write — обе половины (№248) ---"
if [ "$W625_INSTRUMENTED" -eq 1 ] && [ -s "$W625_ART/metrics-window-start.txt" ] && [ -s "$W625_ART/metrics-window-end.txt" ]; then
    _w625_narrow_bg=0
    for _nr in sigma_failed_login_syscall_daemon rootkit_pam_module_added_daemon; do
        _a0=$(_w625_metric_sum ebpf_guard_alerts_total "$_nr" "$W625_ART/metrics-window-start.txt")
        _a1=$(_w625_metric_sum ebpf_guard_alerts_total "$_nr" "$W625_ART/metrics-window-end.txt")
        _f0=$(_w625_metric_sum ebpf_guard_alerts_filtered_total "$_nr" "$W625_ART/metrics-window-start.txt")
        _f1=$(_w625_metric_sum ebpf_guard_alerts_filtered_total "$_nr" "$W625_ART/metrics-window-end.txt")
        _d=$(( (_a1 - _a0) + (_f1 - _f0) ))
        echo "  фон, тихое окно, $_nr: +$_d за окно (было при op-фильтре ещё не введённом: 3090/2400 и 2970/2280 на архивах 6.2.2)"
        _w625_narrow_bg=$(( _w625_narrow_bg + (_d < 0 ? 0 : _d) ))
    done

    # Половина «цель»: comm=sshd/cron, ДЕЙСТВИТЕЛЬНО пишущий в PAM. comm
    # берётся из БАЗОВОГО ИМЕНИ ПУТИ execve (kbasename(bprm->filename)), не из
    # argv[0] — `exec -a name path` подставляет только argv[0] и оставляет
    # comm от path (см. образец 6.2.1.8): бинарь копируется в файл, названный
    # sshd/cron, и запускается ИМ САМИМ.
    mkdir -p "$W625_ART/spoof13" 2>/dev/null
    cp /bin/bash "$W625_ART/spoof13/sshd" 2>/dev/null
    cp /bin/bash "$W625_ART/spoof13/cron" 2>/dev/null
    chmod +x "$W625_ART/spoof13/sshd" "$W625_ART/spoof13/cron" 2>/dev/null
    _w625_pos1="/etc/pam.d/w625-narrow-spoof-sshd"
    _w625_pos2="/etc/security/w625-narrow-spoof-cron"
    rm -f "$_w625_pos1" "$_w625_pos2" 2>/dev/null
    _w625_t13=$(_w625_epoch)
    _w625_metrics > "$W625_ART/metrics-narrow-pos-0.txt"
    "$W625_ART/spoof13/sshd" -c "echo w625-narrow-spoof-payload >> $_w625_pos1" 2>/dev/null
    "$W625_ART/spoof13/cron" -c "echo w625-narrow-spoof-payload >> $_w625_pos2" 2>/dev/null
    _w625_pos_bytes=$(( $(wc -c < "$_w625_pos1" 2>/dev/null || echo 0) + $(wc -c < "$_w625_pos2" 2>/dev/null || echo 0) ))
    echo "  сторож результата: спуф-подача записала ${_w625_pos_bytes:-0} байт суммарно в $_w625_pos1/$_w625_pos2"

    _w625_w13=0; _w625_pos_hit=0
    while [ "$_w625_w13" -lt "$W625_POS_TIMEOUT" ]; do
        sleep "$W625_SETTLE"; _w625_w13=$(( _w625_w13 + W625_SETTLE ))
        _w625_metrics > "$W625_ART/metrics-narrow-pos-1.txt"
        _w625_pos_hit=0
        for _nr in sigma_failed_login_syscall_daemon rootkit_pam_module_added_daemon; do
            _pa0=$(_w625_metric_sum ebpf_guard_alerts_total "$_nr" "$W625_ART/metrics-narrow-pos-0.txt")
            _pa1=$(_w625_metric_sum ebpf_guard_alerts_total "$_nr" "$W625_ART/metrics-narrow-pos-1.txt")
            _pf0=$(_w625_metric_sum ebpf_guard_alerts_filtered_total "$_nr" "$W625_ART/metrics-narrow-pos-0.txt")
            _pf1=$(_w625_metric_sum ebpf_guard_alerts_filtered_total "$_nr" "$W625_ART/metrics-narrow-pos-1.txt")
            _w625_pos_hit=$(( _w625_pos_hit + (_pa1 - _pa0) + (_pf1 - _pf0) ))
        done
        [ "${_w625_pos_hit:-0}" -ge 1 ] && break
    done
    echo "  6.2.3.13, половина «цель»: +$_w625_pos_hit срабатываний двух правил на спуф-запись (comm=sshd/cron, op=write)"
    rm -f "$_w625_pos1" "$_w625_pos2" 2>/dev/null
    rm -rf "$W625_ART/spoof13" 2>/dev/null

    # Половины «фон» и «цель» НЕЗАВИСИМЫ и судятся порознь — та же правка, что
    # и у 6.2.4.5 (смок 6.2.5): в цепочке elif провал «фона» гасил вердикт по
    # «цели», и критерий, обещающий «обе половины», отчитывался об одной.
    _w625_t13_fails=""; _w625_t13_unmeas=""
    if [ -z "${_w625_pos_bytes:-}" ] || [ "$_w625_pos_bytes" = "0" ]; then
        _w625_t13_unmeas=" [цель] сторож результата не подтвердил запись — спуф не состоялся, ноль правил приборный;"
    elif [ "${_w625_pos_hit:-0}" -eq 0 ]; then
        _w625_t13_fails="$_w625_t13_fails [цель] подделка носила имя sshd/cron и подтверждённо ЗАПИСАЛА в PAM (${_w625_pos_bytes}Б), но ни sigma_failed_login_syscall_daemon, ни rootkit_pam_module_added_daemon не сработали — сужение выродилось в немоту, а не в фильтр по op;"
    else
        echo "  половина «цель» ВЗЯТА: +$_w625_pos_hit срабатываний на спуф-запись"
    fi
    if [ "$_w625_narrow_bg" -gt 0 ]; then
        _w625_t13_fails="$_w625_t13_fails [фон] $_w625_narrow_bg алертов от двух сужённых правил за тихое окно — узкий op=write фильтр не убрал рутинное чтение PAM демоном, сужение №248 не сработало по существу;"
    else
        echo "  половина «фон» ВЗЯТА: 0 алертов двух сужённых правил за тихое окно"
    fi
    if [ -n "$_w625_t13_fails" ]; then
        die "6.2.3.13 ПРОВАЛЕН, половины:$_w625_t13_fails${_w625_t13_unmeas:+ НЕИЗМЕРИМЫ:$_w625_t13_unmeas}"
    elif [ -n "$_w625_t13_unmeas" ]; then
        die "6.2.3.13 НЕИЗМЕРИМ, половины:$_w625_t13_unmeas"
    else
        pass "6.2.3.13 ДОСТИГНУТО: обе половины — фон (0 алертов за тихое окно) молчит, запись под именем sshd/cron (+$_w625_pos_hit) по-прежнему поднимает — сужение №248 сузило ось op, а не выключило правило"
    fi
else
    echo "  ПРОПУЩЕН: 6.2.5.0 не взят или тихое окно не снято"
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
if [ "$W625_INSTRUMENTED" -eq 1 ]; then
    mkdir -p "$W625_ART/spoof14" 2>/dev/null
    cp /bin/bash "$W625_ART/spoof14/k3s-server" 2>/dev/null
    chmod +x "$W625_ART/spoof14/k3s-server" 2>/dev/null
    _w625_beacon14_before=$(( $(_w625_metric_sum ebpf_guard_alerts_total "c2_periodic_beacon_pattern") + $(_w625_metric_sum ebpf_guard_alerts_filtered_total "c2_periodic_beacon_pattern") + $(_w625_ratelimited "c2_periodic_beacon_pattern") ))
    # exec -a ставит comm="k3s-server" (базовое имя пути execve), но
    # /proc/<pid>/exe остаётся в $W625_ART/spoof14 — мимо префиксов
    # исключения (/usr/, /bin/, /sbin/, /opt/, /var/lib/rancher/).
    ( setsid "$W625_ART/spoof14/k3s-server" -c 'for i in 1 2 3 4 5; do exec 9<>/dev/tcp/127.0.0.1/19090 2>/dev/null; exec 9>&-; sleep 6; done' >/dev/null 2>&1 & )
    _w625_beacon14_after=$_w625_beacon14_before
    _w625_w14=0
    while [ "$_w625_w14" -lt "$W625_POS_TIMEOUT" ]; do
        sleep "$W625_SETTLE"; _w625_w14=$(( _w625_w14 + W625_SETTLE ))
        _w625_beacon14_after=$(( $(_w625_metric_sum ebpf_guard_alerts_total "c2_periodic_beacon_pattern") + $(_w625_metric_sum ebpf_guard_alerts_filtered_total "c2_periodic_beacon_pattern") + $(_w625_ratelimited "c2_periodic_beacon_pattern") ))
        [ "$(( _w625_beacon14_after - _w625_beacon14_before ))" -ge 1 ] && break
    done
    _w625_c14=$(_w625_alerts | jq -r --arg rid "c2_periodic_beacon_pattern" '[.[]|select(.rule_id==$rid)][-1].comm // "нет алертов"' 2>/dev/null)
    rm -rf "$W625_ART/spoof14" 2>/dev/null
    _w625_d14=$(( _w625_beacon14_after - _w625_beacon14_before ))
    echo "  срабатываний c2_periodic_beacon_pattern после подделки (comm в последнем алерте: ${_w625_c14:-нет}): $_w625_d14"
    if [ "${_w625_d14:-0}" -lt 1 ]; then
        die "6.2.3.14 ПРОВАЛЕН: процесс, назвавшийся k3s-server (exe вне системных каталогов), НЕ поднял c2_periodic_beacon_pattern — исключение node-host-daemon следует за именем, а не за образом (№247, решение 2)"
    else
        pass "6.2.3.14 ДОСТИГНУТО: подделка носила имя демона, но не унаследовала его тишину — правило поднялось $_w625_d14 раз на подделанном образе"
    fi
else
    echo "  ПРОПУЩЕН: 6.2.5.0 не взят"
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
_w625_unit_out="$W625_ART/unit-6.2.2.6.txt"
if [ -x "$W625_GO" ] && [ -d "$W625_REPO/internal/correlator" ]; then
    ( cd "$W625_REPO" && "$W625_GO" test -count=1 -run 'Wave6_2_2|Wave6_2_1' ./internal/correlator/... ) > "$_w625_unit_out" 2>&1
    _w625_unit_rc=$?
    tail -5 "$_w625_unit_out" | sed 's/^/    /'
    if [ "$_w625_unit_rc" -eq 0 ]; then
        pass "6.2.2.6 ДОСТИГНУТО (половина «юнит»): обе половины трёх правок условий зелены (см. $_w625_unit_out)"
    else
        die "6.2.2.6 ПРОВАЛЕН (половина «юнит»): go test -run 'Wave6_2_2|Wave6_2_1' ./internal/correlator/... вернул $_w625_unit_rc — правки условий не держат ни фон, ни свой сценарий (см. $_w625_unit_out)"
    fi
else
    die "6.2.2.6 НЕИЗМЕРИМ (половина «юнит»): нет $W625_GO или дерева $W625_REPO/internal/correlator — юнит-половину критерия нечем взять"
fi

# Инъекция 1: периодический бикон. Одна и та же тройка (pid, daddr, dport),
# ≥3 соединения с ровным кадансом внутри 5 минут — ровно то, чего требует
# новое условие (conn_periodic_count_5m gt 2, conn_periodic_cv_5m lt 0.35).
# comm НЕ должен быть в списке исключений правила (curl/wget/... там есть),
# поэтому берётся копия оболочки с собственным именем.
# Алерт правила — severity=info, в стор он НЕ ПОПАДАЕТ (ровно причина, по
# которой сужение №220 по стору его не видело): читается ПО МЕТРИКЕ.
echo "  инъекция «периодический бикон» (одна тройка pid+addr+port, ровный каданс):"
_w625_beacon_before=$(( $(_w625_metric_sum ebpf_guard_alerts_total "c2_periodic_beacon_pattern beacon_fixed_interval") + $(_w625_metric_sum ebpf_guard_alerts_filtered_total "c2_periodic_beacon_pattern beacon_fixed_interval") + $(_w625_ratelimited "c2_periodic_beacon_pattern beacon_fixed_interval") ))
cp /bin/bash /usr/local/bin/w625beacon 2>/dev/null
# setsid уводит нагрузку из дерева самого контроля: исключение наблюдателя
# (5.9a) режет в ЯДРЕ и ослепило бы контроль (память
# observer-exclusion-blinds-controls) — ноль тогда был бы приборным.
setsid /usr/local/bin/w625beacon -c 'for i in 1 2 3 4 5; do exec 9<>/dev/tcp/127.0.0.1/19090 2>/dev/null; exec 9>&-; sleep 6; done' >/dev/null 2>&1
sleep "$W625_SETTLE"
_w625_beacon_after=$(( $(_w625_metric_sum ebpf_guard_alerts_total "c2_periodic_beacon_pattern beacon_fixed_interval") + $(_w625_metric_sum ebpf_guard_alerts_filtered_total "c2_periodic_beacon_pattern beacon_fixed_interval") + $(_w625_ratelimited "c2_periodic_beacon_pattern beacon_fixed_interval") ))
rm -f /usr/local/bin/w625beacon 2>/dev/null
echo "    срабатываний бикон-правил за инъекцию (по метрике, включая info): $(( _w625_beacon_after - _w625_beacon_before ))"
if [ "$(( _w625_beacon_after - _w625_beacon_before ))" -lt 1 ]; then
    die "6.2.2.6 ПРОВАЛЕН (половина «своё правило поднимается», инъекция бикона): пять соединений на один адрес:порт с кадансом 6с не подняли ни c2_periodic_beacon_pattern, ни beacon_fixed_interval. Порог периодичности (count>2, cv<0.35, окно 5 мин) выбран инженерной оценкой и живым трафиком до сих пор не проверялся (открытый вопрос 2) — этот ноль и есть его проверка"
else
    pass "6.2.2.6 ДОСТИГНУТО (половина «своё правило поднимается»): инъекция периодического бикона поднята правилом $(( _w625_beacon_after - _w625_beacon_before )) раз — порог периодичности подтверждён живым трафиком (открытый вопрос 2)"
fi

# Инъекция 2: sigma_log_deletion — обе половины (№234). Чтение /var/log
# молчит, запись поднимает.
echo "  инъекция «чтение против записи /var/log» (№234):"
_w625_ld_t=$(_w625_epoch)
journalctl -u "$W625_SVC" --since "-1 min" --no-pager >/dev/null 2>&1
sleep "$W625_SETTLE"
_w625_ld_read=$(_w625_alerts | jq --argjson t "$_w625_ld_t" '[.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.rule_id=="sigma_log_deletion") and (.comm=="journalctl"))]|length' 2>/dev/null || echo 0)
_w625_lw_t=$(_w625_epoch)
# Пачкой, а не одной записью: одиночная запись неотличима от потерянной
# сэмплированием (file_rate), и ноль был бы приборным.
setsid /bin/sh -c 'i=0; while [ $i -lt 300 ]; do echo w625-log-probe >> /var/log/w625-probe.log; i=$((i+1)); done' >/dev/null 2>&1
sleep "$W625_SETTLE"
_w625_ld_write=$(_w625_alerts | jq --argjson t "$_w625_lw_t" '[.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.rule_id=="sigma_log_deletion"))]|length' 2>/dev/null || echo 0)
# РАЗЛИЧИТЕЛЬ ПРИЧИНЫ. owasp_log_tampering стоит на том же пути, но БЕЗ
# условия на op. Если он поднялся, а sigma_log_deletion нет — событие дошло
# до движка, и немота у правила именно в оси op, а не в потере события,
# сэмплировании, исключении наблюдателя или неразрешённом пути. Без этой
# строки вердикт называл бы симптом и оставлял четыре объяснения.
_w625_ld_proof=$(_w625_alerts | jq --argjson t "$_w625_lw_t" '[.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.rule_id=="owasp_log_tampering") and ((.details["file.path"] // "")|test("w625-probe")))]|length' 2>/dev/null || echo 0)
rm -f /var/log/w625-probe.log 2>/dev/null
echo "    journalctl читает /var/log/journal → алертов sigma_log_deletion: $_w625_ld_read (обязан быть 0)"
echo "    300 записей в /var/log/w625-probe.log → алертов sigma_log_deletion: $_w625_ld_write (обязан быть ≥ 1)"
echo "    различитель: owasp_log_tampering на том же пути (условия на op НЕ имеет): ${_w625_ld_proof:-0}"
if [ "${_w625_ld_read:-0}" -gt 0 ]; then
    die "6.2.2.6 ПРОВАЛЕН (половина «фон молчит», №234): journalctl, ЧИТАЮЩИЙ /var/log/journal, поднял sigma_log_deletion $_w625_ld_read раз — правило по-прежнему совпадает шире своего имени"
elif [ "${_w625_ld_write:-0}" -lt 1 ]; then
    if [ "${_w625_ld_proof:-0}" -gt 0 ]; then
        die "6.2.2.6 ПРОВАЛЕН (половина «своё правило поднимается», №234): 300 записей в /var/log НЕ подняли sigma_log_deletion, при том что owasp_log_tampering на ТОМ ЖЕ пути поднялся $_w625_ld_proof раз. Событие дошло до движка с разрешённым путём — значит немота ровно в оси op: ни одно файловое событие этого пути не приходит с op=write, и сужение №234 сделало правило немым НА ЖИВОМ СТЕНДЕ, оставшись зелёным на юните (юнит строит событие с Op=write сам). Это находка о ПРОДУКТЕ, а не о контроле, и она же ставит под вопрос всякое правило вида «op in [write] + filename prefix»"
    else
        die "6.2.2.6 ПРОВАЛЕН (половина «своё правило поднимается», №234): 300 записей в /var/log не подняли ни sigma_log_deletion, ни owasp_log_tampering на том же пути — событие до движка не дошло вовсе (потеря, сэмплирование, исключение наблюдателя или неразрешённый путь), и ось op здесь ни при чём. Это НЕИЗМЕРИМОСТЬ подачи, а не вердикт правилу"
    fi
else
    pass "6.2.2.6 ДОСТИГНУТО (обе половины №234): чтение молчит ($_w625_ld_read), запись поднимает ($_w625_ld_write)"
fi

# Инъекция 3: sigma_iptables_flush — только НЕГАТИВНАЯ половина живьём.
# Позитивная (настоящий `iptables -F`) на ноде k3s снесла бы её сеть; она
# закрыта юнитом выше и подаваться на живой ноде НЕ ДОЛЖНА.
echo "  инъекция «строка iptables без flush» (№234-сосед, sigma_iptables_flush):"
_w625_ipt_t=$(_w625_epoch)
setsid /bin/sh -c 'grep iptables /etc/hosts; tar -F /tmp/w625-nope.txt' >/dev/null 2>&1
sleep "$W625_SETTLE"
_w625_ipt=$(_w625_alerts | jq --argjson t "$_w625_ipt_t" '[.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.rule_id=="sigma_iptables_flush"))]|length' 2>/dev/null || echo 0)
echo "    подделка «grep iptables …; tar -F …» → алертов sigma_iptables_flush: $_w625_ipt (обязан быть 0)"
echo "    позитивная половина (настоящий iptables -F) живьём НЕ подаётся: на ноде k3s это авария, а не контроль — она закрыта юнитом выше"
if [ "${_w625_ipt:-0}" -gt 0 ]; then
    die "6.2.2.6 ПРОВАЛЕН (половина «фон молчит», sigma_iptables_flush): строка, где iptables и -F принадлежат РАЗНЫМ командам, подняла правило $_w625_ipt раз — класс [^;|&] границу команды не удержал"
else
    pass "6.2.2.6 ДОСТИГНУТО (половина «фон молчит», sigma_iptables_flush): подделка через границу команды правило не подняла"
fi

# ═════════════════════════════════════════════════════════════════════════════
# 6.2.4.5 (долг 6.2.4, метка сохранена) — ИСХОД РАЗВИЛОК №253/№261, ЧЕТЫРЕ
# ПОЛОВИНЫ. Ни один архив этот критерий не содержит: в 6.2.4 он не был вжит
# в пайплайн вовсе (находка №269), а правка №253 была признана работающей
# РУКАМИ по срезам метрик. Здесь он исполняется впервые.
#
#   (1) НЕГАТИВНАЯ  — четыре двойника молчат в тихом окне ПРИ НЕНУЛЕВОМ
#       rule_exceptions_total по каждому (иначе тишина означает выключенное
#       правило, а не переехавший объём). Обе половины уже сняты выше
#       (подпункт 6.2.5.1 (1)/(2) и список comm 6.2.5.15) — здесь они
#       сводятся в вердикт СВОЕЙ метки.
#   (2) ПОЗИТИВНАЯ  — родительские правила поднимаются на подаче НЕ от
#       демона: обычный процесс, читающий /etc/shadow, обязан поднять
#       sigma_passwd_shadow_read/sensitive_file_read.
#   (3) НА ПОДДЕЛКУ  — копия /bin/cat с ИМЕНЕМ демона (comm=cron, образ
#       чужой) обязана поднять ДВОЙНИКА: ось идёт за образом, а не за именем.
#       Артефакт — вне /root (память control-artifacts-must-live-outside-root),
#       со сторожем результата на прочитанные байты (память
#       positive-control-needs-result-sentinel): execve ENOENT дал бы ноль,
#       неотличимый от вердикта.
#   (4) НОВАЯ (№261) — подача от КОРОТКОЖИВУЩЕГО ПОТОМКА ДЕМОНА. Ровно тот
#       механизм, который съел весь остаток гейта: ежеминутный fork cron'а
#       читает /etc/passwd в PAM/NSS-lookup'е ДО execve и умирает за единицы
#       миллисекунд, поэтому readlink("/proc/<pid>/exe") проигрывает гонку и
#       verified-daemon-image не применяется. Ось item 1 (verified-daemon-lineage,
#       proc.parent_exe_path) обязана примениться к ШТАТНОМУ потомку демона
#       и НЕ примениться к подделке из (3).
# ═════════════════════════════════════════════════════════════════════════════
echo "--- 6.2.4.5: исход развилок №253/№261, четыре половины (долг 6.2.4) ---"
W625_TWIN_PARENT_RULES="sigma_passwd_shadow_read sensitive_file_read"
_w625_t45_start=$(_w625_epoch)

# ---- половина (1): негативная, по уже снятому тихому окну ----
_w625_h1_alerts=$(printf '%s' "${_w625_exe_exc_comms:-[]}" | jq 'map(.n)|add // 0' 2>/dev/null)
_w625_h1_exc_ok=$([ "${_w625_twin_zero:-1}" -eq 0 ] && echo 1 || echo 0)
echo "  (1) негативная: алертов четырёх двойников в тихом окне = ${_w625_h1_alerts:-?}; все четыре дали ненулевой rule_exceptions_total: $([ "$_w625_h1_exc_ok" -eq 1 ] && echo да || echo НЕТ)"

# ---- половина (2): позитивная, подача НЕ от демона ----
#
# СМОК 6.2.5 (08.09.2026) вскрыл здесь ЛОЖНЫЙ НОЛЬ: половина ждала стор
# ФИКСИРОВАННЫМ `sleep $W625_SETTLE` (в смоке — 5 с) и объявляла 0 алертов
# провалом сужения. Живая перепроверка той же подачи показала, что правило
# СРАБОТАЛО (`ebpf_guard_alerts_total{rule_id="sensitive_file_read"}` +2,
# ни лимитера, ни дедупа, ни фильтра severity), а алерт доехал до стора
# позже окна ожидания. Все прочие позитивные контроли файла ждут результата
# ЦИКЛОМ до W625_POS_TIMEOUT — эта половина была единственной с голым sleep.
#
# Вторая правка того же места: ВХОД ВЕРДИКТА — МЕТРИКА, А НЕ СТОР (память
# narrowing-input-must-be-metric-not-store). Один из двух родителей,
# `sigma_passwd_shadow_read`, имеет severity=info, а `store.min_severity` на
# стенде = warning: в стор он не попадает НИКОГДА и по построению. Стор здесь
# годится как подтверждение, но не как источник нуля — поэтому дельта
# `alerts_total` + `alerts_filtered_total` по обоим родителям снимается
# всегда и именно она выносит вердикт.
#
# ТРЕТЬЯ правка того же места (смок №2): ноль стора здесь оказался СРЕЗОМ
# ЛИМИТЕРА, а не отставанием записи — за подачу лимитер срезал 26 алертов
# родительских правил (память control-after-attacks-hits-filled-limiter:
# ноль контроля, идущего после атак, может быть срезом, а не вердиктом).
# Поэтому подача ПОВТОРЯЕТСЯ через окно лимитера (10 алертов/правило/60 с),
# а ноль атрибутируется поимённо: срез → НЕИЗМЕРИМ, немота метрики → ПРОВАЛ.
#
# Про метрику честно: `alerts_total` НЕ несёт лейбла comm, поэтому её
# приращение доказывает лишь, что правила не немы ГЛОБАЛЬНО, и не может
# доказать, что сработала ИМЕННО эта подача. Comm-адресный источник здесь
# один — стор; метрика отделяет «правило молчит» от «алерт не дошёл».
cp /bin/cat "$W625_ART/w625shadow" 2>/dev/null
chmod +x "$W625_ART/w625shadow" 2>/dev/null
_w625_h2_tries=$([ "$W625_SMOKE" = "1" ] && echo 2 || echo 3)
_w625_h2_hits=0; _w625_h2_waited=0; _w625_h2_md=0; _w625_h2_rld=0; _w625_h2_try=0
while [ "$_w625_h2_try" -lt "$_w625_h2_tries" ]; do
    _w625_h2_try=$(( _w625_h2_try + 1 ))
    _w625_h2_m0=$(( $(_w625_metric_sum ebpf_guard_alerts_total "$W625_TWIN_PARENT_RULES") \
                  + $(_w625_metric_sum ebpf_guard_alerts_filtered_total "$W625_TWIN_PARENT_RULES") ))
    _w625_h2_rl0=$(_w625_ratelimited "$W625_TWIN_PARENT_RULES")
    _w625_h2_bytes=$("$W625_ART/w625shadow" /etc/shadow 2>/dev/null | wc -c)
    _w625_h2_w=0
    while [ "$_w625_h2_w" -lt "$W625_POS_TIMEOUT" ]; do
        sleep "$W625_SETTLE"; _w625_h2_w=$(( _w625_h2_w + W625_SETTLE ))
        _w625_h2_hits=$(_w625_alerts | jq --arg ids "$W625_TWIN_PARENT_RULES" --argjson t "$_w625_t45_start" \
            '[.[]|select((.rule_id as $r|($ids|split(" "))|index($r)) and ((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.comm=="w625shadow"))]|length' 2>/dev/null || echo 0)
        [ "${_w625_h2_hits:-0}" -gt 0 ] && break
    done
    _w625_h2_m1=$(( $(_w625_metric_sum ebpf_guard_alerts_total "$W625_TWIN_PARENT_RULES") \
                  + $(_w625_metric_sum ebpf_guard_alerts_filtered_total "$W625_TWIN_PARENT_RULES") ))
    _w625_h2_rl1=$(_w625_ratelimited "$W625_TWIN_PARENT_RULES")
    _w625_h2_md=$(( _w625_h2_md + _w625_h2_m1 - _w625_h2_m0 ))
    _w625_h2_rld=$(( _w625_h2_rld + _w625_h2_rl1 - _w625_h2_rl0 ))
    _w625_h2_waited=$(( _w625_h2_waited + _w625_h2_w ))
    [ "${_w625_h2_hits:-0}" -gt 0 ] && break
    # Ноль не от лимитера — повтор его не изменит, ждать 60 с незачем.
    [ "$(( _w625_h2_rl1 - _w625_h2_rl0 ))" -gt 0 ] || break
    echo "      (подача $_w625_h2_try дала 0 при срезе лимитера $(( _w625_h2_rl1 - _w625_h2_rl0 )) — пережидаю окно лимитера 60с и повторяю)"
    sleep 60
done
echo "  (2) позитивная: обычный процесс (comm=w625shadow) прочитал ${_w625_h2_bytes}Б /etc/shadow → алертов родительских правил: ${_w625_h2_hits:-0} (стор, подач $_w625_h2_try, ожидание ${_w625_h2_waited}s)"
echo "      срез лимитера за подачи = $_w625_h2_rld; приращение alerts_total+alerts_filtered_total по ($W625_TWIN_PARENT_RULES) = $_w625_h2_md"
echo "      (метрика без лейбла comm — доказывает лишь ненемоту правил, не факт этой подачи; info-родитель sigma_passwd_shadow_read при store.min_severity=warning в стор не попадает по построению)"

# ---- половины (3) и (4, отрицательная сторона): подделка ИМЕНИ демона ----
# comm задаёт basename ПУТИ execve, а не argv[0] (память
# exec-a-argv0-spoof-kills-proc-args), поэтому подделка — КОПИЯ бинаря с
# именем cron, а не `exec -a cron`.
_w625_t45_spoof=$(_w625_epoch)
cp /bin/cat "$W625_ART/cron" 2>/dev/null
chmod +x "$W625_ART/cron" 2>/dev/null
_w625_h3_m0=$(( $(_w625_metric_sum ebpf_guard_alerts_total "$W625_TWIN_RULES") \
              + $(_w625_metric_sum ebpf_guard_alerts_filtered_total "$W625_TWIN_RULES") ))
_w625_h3_rl0=$(_w625_ratelimited "$W625_TWIN_RULES")
_w625_h3_bytes=$("$W625_ART/cron" /etc/shadow 2>/dev/null | wc -c)
# Тот же ложный ноль, что и у половины (2): ждать результата циклом, а не
# фиксированным sleep. В смоке 6.2.5 эта половина дала 1 по везению — стор
# успел; на боевой длине везение не гарантия.
_w625_h3_hits=0; _w625_h3_waited=0
while [ "$_w625_h3_waited" -lt "$W625_POS_TIMEOUT" ]; do
    sleep "$W625_SETTLE"; _w625_h3_waited=$(( _w625_h3_waited + W625_SETTLE ))
    _w625_h3_hits=$(_w625_alerts | jq --arg ids "$W625_TWIN_RULES" --argjson t "$_w625_t45_spoof" \
        '[.[]|select((.rule_id as $r|($ids|split(" "))|index($r)) and ((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.comm=="cron"))]|length' 2>/dev/null || echo 0)
    [ "${_w625_h3_hits:-0}" -gt 0 ] && break
done
_w625_h3_m1=$(( $(_w625_metric_sum ebpf_guard_alerts_total "$W625_TWIN_RULES") \
              + $(_w625_metric_sum ebpf_guard_alerts_filtered_total "$W625_TWIN_RULES") ))
_w625_h3_rl1=$(_w625_ratelimited "$W625_TWIN_RULES")
_w625_h3_md=$(( _w625_h3_m1 - _w625_h3_m0 ))
_w625_h3_rld=$(( _w625_h3_rl1 - _w625_h3_rl0 ))
_w625_h3_comm=$(_w625_alerts | jq -r --argjson t "$_w625_t45_spoof" \
    '[.[]|select((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t)|.comm]|unique|join(" ")' 2>/dev/null)
echo "  (3) на подделку: копия /bin/cat с именем cron прочитала ${_w625_h3_bytes}Б /etc/shadow → алертов двойников с comm=cron: ${_w625_h3_hits:-0} (ожидание ${_w625_h3_waited}s; comm алертов периода: ${_w625_h3_comm:-нет})"
echo "      метрика двойников за подачу (подтверждение, не вердикт): приращение alerts_total+alerts_filtered_total = $_w625_h3_md; срез лимитера = $_w625_h3_rld"

# ---- половина (4): ШТАТНЫЙ короткоживущий потомок демона ----
# Подача — настоящий cron: задание в /etc/cron.d заставляет его форкаться
# ежеминутно, и это ровно та форма, что дала 30 алертов окна в архиве 6.2.4
# (comm=cron, свежие pid'ы по ~3 мс). Своего execve потомок до чтения
# /etc/passwd не делает, поэтому оси exe_path он недоступен ПО ПОСТРОЕНИЮ, и
# единственное, что может его закрыть, — ось родителя (item 1).
_w625_t45_cron=$(_w625_epoch)
_w625_cron_lineage0=$(_w625_metric_sum ebpf_guard_rule_exceptions_total "verified-daemon-lineage")
# Ноль алертов здесь — направление ПРОХОДА, поэтому он обязан быть подтверждён
# метрикой: ноль стора может быть отставанием записи, и тогда половина (4)
# прошла бы ЛОЖНО — ровно тот класс, что смок нашёл у половины (2), только в
# сторону ложного PASS.
_w625_h4_m0=$(( $(_w625_metric_sum ebpf_guard_alerts_total "$W625_TWIN_RULES") \
              + $(_w625_metric_sum ebpf_guard_alerts_filtered_total "$W625_TWIN_RULES") ))
printf '* * * * * root /bin/cat /etc/shadow > /dev/null 2>&1\n' > /etc/cron.d/w625-lineage 2>/dev/null
chmod 0644 /etc/cron.d/w625-lineage 2>/dev/null
_w625_cron_wait=130
echo "  (4) ожидание ежеминутного форка cron: ${_w625_cron_wait}s (задание /etc/cron.d/w625-lineage)"
sleep "$_w625_cron_wait"
rm -f /etc/cron.d/w625-lineage 2>/dev/null
_w625_cron_lineage1=$(_w625_metric_sum ebpf_guard_rule_exceptions_total "verified-daemon-lineage")
_w625_cron_lineage_d=$(( ${_w625_cron_lineage1:-0} - ${_w625_cron_lineage0:-0} ))
_w625_h4_alerts=$(_w625_alerts | jq --arg ids "$W625_TWIN_RULES" --argjson t "$_w625_t45_cron" \
    '[.[]|select((.rule_id as $r|($ids|split(" "))|index($r)) and ((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.comm=="cron"))]|length' 2>/dev/null)
_w625_h4_m1=$(( $(_w625_metric_sum ebpf_guard_alerts_total "$W625_TWIN_RULES") \
              + $(_w625_metric_sum ebpf_guard_alerts_filtered_total "$W625_TWIN_RULES") ))
_w625_h4_md=$(( _w625_h4_m1 - _w625_h4_m0 ))
echo "  (4) штатный потомок: приращение rule_exceptions_total{verified-daemon-lineage} = $_w625_cron_lineage_d; алертов двойников с comm=cron за период: ${_w625_h4_alerts:-0}"
echo "      сторож ложного PASS: приращение метрики двойников за тот же период = $_w625_h4_md (ноль стора при ненулевой метрике = стор слеп, а не тишина)"

# ---- ВЕРДИКТ 6.2.4.5: ЧЕТЫРЕ НЕЗАВИСИМЫЕ ПОЛОВИНЫ ----
#
# СМОК 6.2.5 (08.09.2026), второй дефект этого блока: вердикт был цепочкой
# `if/elif`, и ПЕРВАЯ сработавшая ветка гасила все последующие. Половины же
# независимы — они проверяют РАЗНЫЕ свойства одной правки, и провал одной
# ничего не говорит об остальных. На смоке провалилась половина (1) (остаток
# гейта, продуктовая величина, на боевом прогоне ожидается снова), и из-за
# этого половины (2), (3), (4) не вынесли вердикта вовсе — включая половину
# (4), которая и есть ГЛАВНАЯ проверка волны (ось verified-daemon-lineage,
# №261). То есть боевой прогон почти наверняка не измерил бы то, ради чего
# запущен, и лог выглядел бы как «один честный провал».
#
# Теперь каждая половина судится сама, печатает свою строку, и метка получает
# РОВНО ОДИН вердикт (иначе счётчик провалов считал бы один критерий четырежды).
_w625_t45_fails=""
_w625_t45_unmeas=""
# Приборность подачи — общая для (2) и (3): без подтверждённого чтения любой
# ноль ниже приборный (память positive-control-needs-result-sentinel).
if [ "${_w625_h2_bytes:-0}" -lt 1 ] || [ "${_w625_h3_bytes:-0}" -lt 1 ]; then
    _w625_t45_unmeas="$_w625_t45_unmeas [подача] сторож результата не подтвердил чтение (позитивная ${_w625_h2_bytes:-0}Б, подделка ${_w625_h3_bytes:-0}Б);"
fi
# --- половина (1) ---
if [ "$_w625_h1_exc_ok" -ne 1 ]; then
    _w625_t45_fails="$_w625_t45_fails [1] тишина двойников в окне НЕ подтверждена ненулевым rule_exceptions_total по каждому из четырёх — правило выключено, а не сужено;"
elif [ "${_w625_h1_alerts:-0}" -gt 0 ]; then
    # Правила-двойники по построению совпадают только на именах демонов, и
    # исключение обязано снять их ВСЕ: остаток — это ровно те 30 алертов
    # окна, что составляли весь остаток гейта в архиве 6.2.4 (№261).
    _w625_t45_fails="$_w625_t45_fails [1] четыре двойника дали ${_w625_h1_alerts} алертов ВНУТРИ тихого окна при работающих исключениях — часть фона ноды исключение не покрывает (поимённо по comm см. подпункт разбивки выше); это остаток гейта, а не погрешность;"
else
    echo "  (1) ВЗЯТА: двойники молчат в окне при ненулевом исключении на каждом"
fi
# --- половина (2): вердикт по МЕТРИКЕ, стор — подтверждение ---
if [ "${_w625_h2_bytes:-0}" -lt 1 ]; then
    :   # неизмерима, уже записано выше
elif [ "${_w625_h2_hits:-0}" -gt 0 ]; then
    echo "  (2) ВЗЯТА: обычный процесс поднимает родительские правила (стор $_w625_h2_hits за $_w625_h2_try подач)"
elif [ "${_w625_h2_rld:-0}" -gt 0 ]; then
    _w625_t45_unmeas="$_w625_t45_unmeas [2] за $_w625_h2_try подач стор дал 0, но лимитер срезал $_w625_h2_rld алертов родительских правил — ноль здесь СРЕЗ, а не вердикт (память control-after-attacks-hits-filled-limiter); немотой сужения №253 это НЕ является;"
elif [ "${_w625_h2_md:-0}" -lt 1 ]; then
    _w625_t45_fails="$_w625_t45_fails [2] обычный процесс прочитал /etc/shadow (${_w625_h2_bytes}Б), лимитер не срезал ничего, а родительские правила ($W625_TWIN_PARENT_RULES) не выросли НИ НА ОДНО совпадение по метрике — сужение №253 выродилось в немоту всего класса, а не в исключение фона ноды;"
else
    _w625_t45_unmeas="$_w625_t45_unmeas [2] правила не немы (метрика +$_w625_h2_md, без лейбла comm), лимитер не резал, но за ${_w625_h2_waited}s алерт ЭТОЙ подачи в стор не доехал — половина неизмерима по стору;"
fi
# --- половина (3) ---
if [ "${_w625_h3_bytes:-0}" -lt 1 ]; then
    :
elif [ "${_w625_h3_hits:-0}" -gt 0 ]; then
    echo "  (3) ВЗЯТА: подделка имени демона поднимает двойника (стор $_w625_h3_hits, метрика +$_w625_h3_md)"
elif [ "${_w625_h3_rld:-0}" -gt 0 ]; then
    _w625_t45_unmeas="$_w625_t45_unmeas [3] стор дал 0, но лимитер срезал $_w625_h3_rld алертов двойников — ноль здесь СРЕЗ, а не вердикт;"
elif [ "${_w625_h3_md:-0}" -lt 1 ]; then
    _w625_t45_fails="$_w625_t45_fails [3] подделка носила ИМЯ демона (comm=cron) при чужом образе ($W625_ART/cron) и прочитала ${_w625_h3_bytes}Б /etc/shadow, а двойники не поднялись (стор 0, метрика 0, лимитер не резал) — исключение идёт за ИМЕНЕМ, а не за образом (немой обход, память comm-not-in-is-a-mute-bypass);"
else
    _w625_t45_unmeas="$_w625_t45_unmeas [3] двойники не немы (метрика +$_w625_h3_md, без лейбла comm), но за ${_w625_h3_waited}s алерт этой подделки в стор не доехал;"
fi
# --- половина (4), №261: ГЛАВНАЯ проверка волны ---
if [ "$_w625_cron_lineage_d" -lt 1 ]; then
    _w625_t45_unmeas="$_w625_t45_unmeas [4] за ${_w625_cron_wait}s с заданием в /etc/cron.d приращение rule_exceptions_total{verified-daemon-lineage} = 0: либо ось item 1 не задеплоена, либо cron не форкнулся — ноль алертов был бы приборным, а не доказательством, что гонка вылечена;"
elif [ "${_w625_h4_alerts:-0}" -gt 0 ]; then
    _w625_t45_fails="$_w625_t45_fails [4] штатный короткоживущий потомок cron поднял ${_w625_h4_alerts} алертов двойников при работающей оси родословной (+$_w625_cron_lineage_d применений) — гонка readlink НЕ вылечена, и остаток гейта (30 алертов/окно в архиве 6.2.4) остаётся на месте;"
elif [ "${_w625_h4_md:-0}" -gt 0 ]; then
    _w625_t45_unmeas="$_w625_t45_unmeas [4] стор дал 0 алертов двойников, но метрика за тот же период выросла на $_w625_h4_md — ноль стора здесь был бы ЛОЖНЫМ ПРОХОДОМ, половина неизмерима;"
else
    echo "  (4) ВЗЯТА: штатный короткоживущий потомок cron закрыт осью родословной (+$_w625_cron_lineage_d применений, 0 алертов, метрика 0)"
fi
# --- один вердикт на метку ---
if [ -n "$_w625_t45_fails" ]; then
    die "6.2.4.5 ПРОВАЛЕН, половины:$_w625_t45_fails${_w625_t45_unmeas:+ НЕИЗМЕРИМЫ:$_w625_t45_unmeas}"
elif [ -n "$_w625_t45_unmeas" ]; then
    die "6.2.4.5 НЕИЗМЕРИМ, половины:$_w625_t45_unmeas"
else
    pass "6.2.4.5 ДОСТИГНУТО: все четыре половины — (1) двойники молчат в окне при ненулевом исключении на каждом; (2) обычный процесс поднимает родительские правила (метрика +$_w625_h2_md, стор ${_w625_h2_hits}); (3) подделка имени демона поднимает двойника (${_w625_h3_hits}); (4) штатный короткоживущий потомок cron закрыт осью родословной (+$_w625_cron_lineage_d применений, 0 алертов) — ось идёт за образом и за родителем, но не за именем"
fi
rm -f "$W625_ART/w625shadow" "$W625_ART/cron" 2>/dev/null

# ═════════════════════════════════════════════════════════════════════════════
# ПОДАЧИ ДЛЯ 6.2.4.7 и 6.2.5.16 (вердикты выносятся ниже, вместе с 6.2.4.6 —
# им нужен один и тот же снимок инцидентов).
#
# 6.2.4.7 — ПОБЕГ ПО-ПРЕЖНЕМУ ПРОМОТИРУЕТСЯ. Item 2 волны сузил шлюз
# промоушена (лист внутри доверенного контейнерного дерева больше не взводит
# HasUntrustedSignal в одиночку). Этот контроль — его отрицательный контроль:
# правка обязана убрать ЛОЖЬ, а не ДЕТЕКТ. Подача — настоящий вход в хостовые
# namespace'ы (setns/nsenter) и чтение /proc/modules, то есть ровно те
# правила, которыми ложь и печаталась.
#
# 6.2.5.16 — ШЛЮЗ СУДИТСЯ ПО КОРНЮ. Подача формы архива живьём: старт пода
# даёт container_escape_*/rootkit_* рутиной инициализации namespace под
# containerd-shim/runc. Инцидент обязан остаться suspicious.
# ═════════════════════════════════════════════════════════════════════════════
echo "--- подача 6.2.4.7: побег (setns в хостовый namespace, /proc/modules) ---"
W625_ESCAPE_RULES="container_escape_nsenter container_escape_mount container_escape_pivot_root escape_pivot_root container_escape_unshare_user rootkit_proc_modules_read container_escape_cap_sys_admin"
_w625_t47=$(_w625_epoch)
_w625_esc_done=0
if command -v nsenter >/dev/null 2>&1; then
    nsenter -t 1 -m -u -i -n -p /bin/true >/dev/null 2>&1 && _w625_esc_done=$(( _w625_esc_done + 1 ))
fi
if command -v unshare >/dev/null 2>&1; then
    unshare -Ur /bin/true >/dev/null 2>&1 && _w625_esc_done=$(( _w625_esc_done + 1 ))
fi
_w625_mod_bytes=$(cat /proc/modules 2>/dev/null | wc -c)
[ "${_w625_mod_bytes:-0}" -gt 0 ] && _w625_esc_done=$(( _w625_esc_done + 1 ))
sleep "$W625_SETTLE"
echo "  подач побега состоялось: $_w625_esc_done (nsenter/unshare/чтение /proc/modules, ${_w625_mod_bytes:-0}Б)"

echo "--- подача 6.2.5.16: инициализация контейнера (старт пода) ---"
_w625_t516=$(_w625_epoch)
if [ "$W625_INSTRUMENTED" -eq 1 ]; then
    "$W625_KUBECTL" -n "$W625_NS" delete pod w625-init-probe --ignore-not-found --wait=false >/dev/null 2>&1
    "$W625_KUBECTL" -n "$W625_NS" run w625-init-probe --image=busybox:1.36 --restart=Never --command -- sleep 20 >/dev/null 2>&1
    sleep 45
    "$W625_KUBECTL" -n "$W625_NS" delete pod w625-init-probe --ignore-not-found --wait=false >/dev/null 2>&1
    sleep "$W625_SETTLE"
fi
_w625_t516_end=$(_w625_epoch)

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.4.6 ИНЦИДЕНТНЫЙ СЛОЙ ЗА ПРОГОН ЦЕЛИКОМ (№235, ПЕРЕСТРОЕН №251,
# ПЕРЕИМЕНОВАН И ДОПОЛНЕН ITEM 3 ВОЛНЫ 6.2.5).
#
# МЕТКА. Постановка волны 6.2.5 требует критерий 6.2.4.6 (долг волны 6.2.4,
# метка сохранена намеренно — память criteria-index-pins-replay-labels), и
# он ЗАМЕНЯЕТ 6.2.3.7. Прогон 6.2.4 напечатал здесь старую метку 6.2.3.7 —
# это и есть находка №269 («метка, реализованная под чужим номером, считается
# отсутствующей»), и страж полноты 6.2.5.18 её ловит. Отличие 6.2.4.6 от
# 6.2.3.7 по существу: прощения фазой атак больше нет, вычитается ТОЛЬКО
# окно собственных стартов подов контроля 6.2.5.10 (item 3, №263).
#
# №251: старая версия (6.2.2.9) проверяла корень инцидента только против
# runc:[...]/flannel/comm-измерителя и промахивалась мимо остального
# W625_NODE_ACTORS (containerd-shim, k3s-server, kubelet, coredns,
# local-path-prov, kube-proxy, pause, iptables/ip6tables, kubectl, bridge,
# loopback) — список УЖЕ БЫЛ в файле, цикл его не использовал. Здесь корень
# сверяется с ПОЛНЫМ W625_NODE_ACTORS ∪ W625_INSTR_COMMS_FLAT.
#
# Плюс разделение по фазам: инцидент таким корнем, чьё время попадает в
# [_w625_attack_phase_start, _w625_attack_phase_end] (окно позитивных
# контролей и инъекций этого же прогона), есть ОЖИДАЕМЫЙ true positive —
# печатается, но в ложь не засчитывается. Инцидент того же корня ВНЕ этого
# окна (то есть в тихом окне объёма, до открытия входа) — засчитывается:
# там штатная работа ноды не была спровоцирована ничем этого прогона, и
# incident_confirmed_attack на ней — ложь слоя, а не ожидаемый эффект
# инъекции. Не «величина без порога», как в 6.2.1.5: вердикт.
# ─────────────────────────────────────────────────────────────────────────────
_w625_attack_phase_end=$(_w625_epoch)
printf 'attack_phase_start=%s\nattack_phase_end=%s\n' "$_w625_attack_phase_start" "$_w625_attack_phase_end" >> "$W625_ART/window-epoch.txt"
echo "--- 6.2.4.6: инцидентный слой не называет атакой штатную работу ноды (долг 6.2.4, заменяет 6.2.3.7) ---"
# Окно стартов подов 6.2.5.10 (item 3). Если контроль churn не исполнялся
# (прогон неприборный), окно пустое — вычитать нечего, и вердикт выносится за
# прогон целиком, как того и требует постановка.
: "${_w625_pod_start_phase_start:=0}"
: "${_w625_pod_start_phase_end:=0}"
printf 'pod_start_phase_start=%s\npod_start_phase_end=%s\n' "$_w625_pod_start_phase_start" "$_w625_pod_start_phase_end" >> "$W625_ART/window-epoch.txt"
echo "  окно стартов подов контроля 6.2.5.10 (item 3, вычитается из вердикта): [$(_w625_utc "${_w625_pod_start_phase_start:-0}"), $(_w625_utc "${_w625_pod_start_phase_end:-0}")]"
echo "  фаза атак (позитивные контроли+инъекции этого прогона): [$(_w625_utc "$_w625_attack_phase_start"), $(_w625_utc "$_w625_attack_phase_end")]"
_w625_alerts > "$W625_ART/alerts-incidents.json"
_w625_inc_all=$(jq '[.[]|select(.rule_id=="incident_confirmed_attack")]|length' "$W625_ART/alerts-incidents.json" 2>/dev/null || echo 0)
echo "  incident_confirmed_attack за прогон: $_w625_inc_all"
echo "  по корневому comm:"
jq -r '[.[]|select(.rule_id=="incident_confirmed_attack")]|group_by(.details.root_comm // .comm)|map({c:(.[0].details.root_comm // .[0].comm),n:length})|sort_by(-.n)[]|"    \(.c): \(.n)"' "$W625_ART/alerts-incidents.json" 2>/dev/null | head -15
# ─── ДВА КЛАССА КОРНЯ СУДЯТСЯ ПО-РАЗНОМУ (правка смока 06.09.2026, ДО прогона).
#
# Первая версия этого блока судила ОБА класса корня одним правилом «вне фазы
# атак = ложь». Смок показал, что правило неисполнимо по построению, и оба
# провала были СВОИМИ:
#   * инцидент 14:26:57, цепочка bash → bash → bash → bash → cut — это
#     преflight самого измерителя (churn подов, kubectl), до открытия окна;
#   * инцидент 14:28:33, цепочка bash → … → cat, comm=ld — это окно профиля
#     (`go tool pprof`), между закрытием тихого окна и началом фазы атак.
# Измеритель РАБОТАЕТ вне фазы атак — в прологе, в преflight'е, между окнами и
# после фазы; ни один из этих отрезков не был в [attack_phase_start,
# attack_phase_end], и его собственные цепочки печатались как ложь продукта.
# Комментарий выше называет умысел прямо: «вне этого окна (ТО ЕСТЬ В ТИХОМ
# ОКНЕ ОБЪЁМА)». Тихое окно и «всё вне фазы атак» — не одно и то же, и здесь
# восстановлен умысел, а не смягчён критерий.
#
#   КОРЕНЬ-ИЗМЕРИТЕЛЬ  → ложь ТОЛЬКО внутри [t0,t1]. Там измеритель обязан не
#                        работать вовсе (это же и меряет 6.2.5.3), поэтому
#                        инцидент с его корнем в окне есть дефект; вне окна —
#                        его штатная работа, печатается и в ложь не идёт.
#   КОРЕНЬ-НОДА        → ложь ЗА ПРОГОН ЦЕЛИКОМ, как требует постановка
#                        («корень которого в W625_NODE_ACTORS — ноль»).
#                        Прежняя реализация прощала их внутри фазы атак — но
#                        containerd-shim, поднимающий контейнер, есть штатная
#                        работа ноды независимо от того, чей kubectl попросил
#                        под. Прощение внутри фазы выхолащивало критерий ровно
#                        там, где живёт находка №250: смок дал 5 таких
#                        инцидентов (containerd-shim 4, k3s-server 1) и все
#                        пять были списаны в «ожидаемый TP».
# Пересечение списков (kubectl входит в оба) разрешается в пользу измерителя —
# на этом стенде kubectl зовёт только он; имена пересечения печатаются.
_w625_inc_jq_root='(.details.root_comm // .comm)'
_w625_inc_count() { # $1=класс (instr|node) $2=режим (win|outwin|phase|outphase|podstart|outpodstart|all)
    # Сам счёт живёт в wave6.2.5-metrics-lib.sh (w625_incident_roots): у
    # библиотеки есть офлайн-сторож на архиве collect-6.2.4, где обе лжи
    # инцидентного слоя известны поимённо. Критерий этого блока переписывался
    # четыре волны подряд и ни разу не проверялся до стенда — теперь
    # проверяется.
    w625_incident_roots "$W625_ART/alerts-incidents.json" "$1" "$2" \
        "${_w625_t0:-0}" "${_w625_t1:-0}" \
        "$_w625_attack_phase_start" "$_w625_attack_phase_end" \
        "${_w625_pod_start_phase_start:-0}" "${_w625_pod_start_phase_end:-0}" \
        "$W625_INSTR_COMMS_FLAT" "$W625_NODE_ACTORS"
}
_w625_inc_node_all=$(_w625_inc_count node all | jq 'length' 2>/dev/null)
_w625_inc_node_names=$(_w625_inc_count node all | jq -r 'unique|join(" ")' 2>/dev/null)
_w625_inc_node_phase=$(_w625_inc_count node phase | jq 'length' 2>/dev/null)
# ITEM 3 (№263): вердиктная величина 6.2.4.6 — нодовые корни ВНЕ окна
# собственных стартов подов; внутри него ложь считается и печатается, но в
# вердикт не идёт (цена старта пода — предмет отдельного критерия 6.2.5.10 со
# своим порогом, а не повод простить весь прогон).
_w625_inc_node_podstart=$(_w625_inc_count node podstart | jq 'length' 2>/dev/null)
_w625_inc_node_podstart_names=$(_w625_inc_count node podstart | jq -r 'unique|join(" ")' 2>/dev/null)
_w625_inc_node_out=$(_w625_inc_count node outpodstart | jq 'length' 2>/dev/null)
_w625_inc_node_out_names=$(_w625_inc_count node outpodstart | jq -r 'unique|join(" ")' 2>/dev/null)
_w625_inc_instr_win=$(_w625_inc_count instr win | jq 'length' 2>/dev/null)
_w625_inc_instr_win_names=$(_w625_inc_count instr win | jq -r 'unique|join(" ")' 2>/dev/null)
_w625_inc_instr_out=$(_w625_inc_count instr outwin | jq 'length' 2>/dev/null)
# Пересечение — чистой оболочкой, без внешних команд: любой лишний execve
# здесь есть собственное событие измерителя (тот же принцип, что у встроенного
# printf в _w625_epoch).
_w625_inc_overlap=""
for _w625_ov in $W625_INSTR_COMMS_FLAT; do
    case " $W625_NODE_ACTORS " in *" $_w625_ov "*) _w625_inc_overlap="$_w625_inc_overlap $_w625_ov" ;; esac
done
_w625_inc_overlap="${_w625_inc_overlap# }"
_w625_inc_bad=$(( ${_w625_inc_node_out:-0} + ${_w625_inc_instr_win:-0} ))
_w625_inc_names="${_w625_inc_node_out_names:-}${_w625_inc_instr_win_names:+ }${_w625_inc_instr_win_names:-}"
echo "  корень НОДОВЫЙ АКТОР, за прогон целиком: ${_w625_inc_node_all:-0} (${_w625_inc_node_names:-нет})"
echo "    из них внутри фазы атак: ${_w625_inc_node_phase:-0} — 6.2.3.7 прощала именно их; 6.2.4.6 прощения фазой атак НЕ делает"
echo "    из них ВНУТРИ окна стартов подов 6.2.5.10 (item 3, печатается, в вердикт НЕ идёт): ${_w625_inc_node_podstart:-0} (${_w625_inc_node_podstart_names:-нет})"
echo "    ВЕРДИКТНАЯ величина 6.2.4.6 — нодовые корни ВНЕ окна стартов подов: ${_w625_inc_node_out:-0} (${_w625_inc_node_out_names:-нет})"
echo "  корень ИЗМЕРИТЕЛЬ внутри тихого окна [t0,t1] (ложь): ${_w625_inc_instr_win:-0} (${_w625_inc_instr_win_names:-нет})"
echo "  корень ИЗМЕРИТЕЛЬ вне тихого окна (его штатная работа — печатается, в ложь не идёт): ${_w625_inc_instr_out:-0}"
echo "  пересечение списков (разрешено в пользу измерителя): ${_w625_inc_overlap:-нет}"
if [ "${_w625_inc_all:-0}" -gt 0 ]; then
    echo "  доля ложных от всех инцидентов прогона: $(awk -v b="${_w625_inc_bad:-0}" -v n="$_w625_inc_all" 'BEGIN{printf "%.1f%%", 100.0*b/n}')"
fi
if [ "${_w625_inc_bad:-0}" -gt 0 ]; then
    die "6.2.4.6 ПРОВАЛЕН: инцидентный слой назвал подтверждённой атакой штатную работу ноды (${_w625_inc_node_out:-0} вне окна стартов подов; всего за прогон ${_w625_inc_node_all:-0}) или работу измерителя внутри тихого окна (${_w625_inc_instr_win:-0}) — корни: ${_w625_inc_names:-?}. Порог слою назначается ПОСЛЕ того, как ложь убрана, а не вместо этого (находка №235/№251)"
else
    pass "6.2.4.6 ДОСТИГНУТО: ни один incident_confirmed_attack не имеет корнем нодового актора вне окна стартов подов (внутри него — ${_w625_inc_node_podstart:-0}, item 3) и ни один — корнем измерителя внутри тихого окна (всего инцидентов-атак за прогон: $_w625_inc_all, из них работа измерителя вне окна: ${_w625_inc_instr_out:-0})"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.4.7 (долг 6.2.4) — ПОБЕГ ПО-ПРЕЖНЕМУ ПРОМОТИРУЕТСЯ.
#
# Отрицательный контроль правки item 2: она обязана убрать ЛОЖЬ, а не ДЕТЕКТ.
# Подача сделана выше (setns в хостовые namespace'ы, user-namespace, чтение
# /proc/modules). Читается двумя ступенями, и порядок ступеней — часть
# критерия: сначала «правила вообще поднялись» (иначе ноль ниже приборный:
# нет хука — нет события — нет промоушена, и item 2 тут ни при чём), и лишь
# затем «инцидент промотирован в attack».
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.4.7: побег из-под пода по-прежнему промотируется (долг 6.2.4) ---"
_w625_esc_hits=$(jq --arg ids "$W625_ESCAPE_RULES" --argjson t "$_w625_t47" \
    '[.[]|select((.rule_id as $r|($ids|split(" "))|index($r)) and ((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t))]|length' \
    "$W625_ART/alerts-incidents.json" 2>/dev/null)
_w625_esc_rules=$(jq -r --arg ids "$W625_ESCAPE_RULES" --argjson t "$_w625_t47" \
    '[.[]|select((.rule_id as $r|($ids|split(" "))|index($r)) and ((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t))|.rule_id]|unique|join(" ")' \
    "$W625_ART/alerts-incidents.json" 2>/dev/null)
_w625_esc_inc=$(jq --argjson t "$_w625_t47" \
    '[.[]|select(.rule_id=="incident_confirmed_attack" and ((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t))]|length' \
    "$W625_ART/alerts-incidents.json" 2>/dev/null)
_w625_esc_inc_roots=$(jq -r --argjson t "$_w625_t47" \
    '[.[]|select(.rule_id=="incident_confirmed_attack" and ((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t))|(.details.root_comm // .comm)]|unique|join(" ")' \
    "$W625_ART/alerts-incidents.json" 2>/dev/null)
echo "  подач состоялось: ${_w625_esc_done:-0}; алертов правил побега после подачи: ${_w625_esc_hits:-0} (${_w625_esc_rules:-нет})"
echo "  incident_confirmed_attack после подачи: ${_w625_esc_inc:-0} (корни: ${_w625_esc_inc_roots:-нет})"
if [ "${_w625_esc_done:-0}" -lt 1 ]; then
    die "6.2.4.7 НЕИЗМЕРИМ: ни одна подача побега не состоялась (нет nsenter/unshare, /proc/modules не прочитан) — ноль алертов приборный, а не вердикт"
elif [ "${_w625_esc_hits:-0}" -lt 1 ]; then
    die "6.2.4.7 НЕИЗМЕРИМ: подача побега состоялась (${_w625_esc_done} из трёх), а ни одно правило класса побега не поднялось. Это неизмеримость ПОДАЧИ (нет привязки хука setns/файлового чтения), а не вердикт item 2: инцидентному слою нечего было промотировать"
elif [ "${_w625_esc_inc:-0}" -lt 1 ]; then
    die "6.2.4.7 ПРОВАЛЕН: правила побега поднялись (${_w625_esc_hits} алертов: ${_w625_esc_rules}), но НИ ОДИН инцидент не промотирован в attack — правка item 2 (containerInitTrustedRoot в шлюзе Add) вырезала ДЕТЕКТ, а не ложь. Это ровно тот исход, ради которого критерий заведён отдельной меткой"
else
    pass "6.2.4.7 ДОСТИГНУТО: подача побега подняла ${_w625_esc_hits} алертов (${_w625_esc_rules}) и дала ${_w625_esc_inc} incident_confirmed_attack (корни: ${_w625_esc_inc_roots}) — сужение шлюза промоушена детект не вырезало"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.5.16 (№262, новый) — ШЛЮЗ ПРОМОУШЕНА СУДИТСЯ ПО КОРНЮ.
#
# Форма архива collect-6.2.4 живьём: старт пода даёт container_escape_*/
# rootkit_* рутиной инициализации namespace (mount/pivot_root/cap_sys_admin/
# proc_modules_read под containerd-shim → runc → runc:[N:STAGE]), и до item 2
# лист этого дерева (cat/mount/loopback) в одиночку взводил HasUntrustedSignal
# и переводил инцидент в attack. Инцидент обязан остаться suspicious.
#
# ОБЕ ПОЛОВИНЫ ЧИТАЮТСЯ ВМЕСТЕ: этот критерий взят только при взятом 6.2.4.7,
# иначе «инцидента нет» означает не «шлюз судит по корню», а «детекта нет
# вовсе» — постановка требует ровно этой связки.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.5.16: шлюз промоушена судится по корню (№262) ---"
_w625_init_hits=$(jq --arg ids "$W625_ESCAPE_RULES" --argjson t0 "$_w625_t516" --argjson t1 "$_w625_t516_end" \
    '[.[]|select((.rule_id as $r|($ids|split(" "))|index($r))
        and ((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t0)
        and ((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) <= $t1)
        and (.comm|test("^(runc|containerd|conmon|crun|dockerd|pause)")))]|length' \
    "$W625_ART/alerts-incidents.json" 2>/dev/null)
_w625_init_attack=$(jq --argjson t0 "$_w625_t516" --argjson t1 "$_w625_t516_end" --arg actors "$W625_NODE_ACTORS" \
    '[.[]|select(.rule_id=="incident_confirmed_attack"
        and ((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t0)
        and ((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) <= $t1)
        and (((.details.root_comm // .comm) as $c | (($actors|split(" "))|index($c))) != null))]|length' \
    "$W625_ART/alerts-incidents.json" 2>/dev/null)
_w625_init_attack_roots=$(jq -r --argjson t0 "$_w625_t516" --argjson t1 "$_w625_t516_end" --arg actors "$W625_NODE_ACTORS" \
    '[.[]|select(.rule_id=="incident_confirmed_attack"
        and ((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t0)
        and ((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) <= $t1)
        and (((.details.root_comm // .comm) as $c | (($actors|split(" "))|index($c))) != null))
      | "\((.details.root_comm // .comm))[\(.details.process_chain // [] | join("→"))]"]|unique|join(" ")' \
    "$W625_ART/alerts-incidents.json" 2>/dev/null)
# ОКНО СТАРТОВ ПОДОВ 6.2.5.10 СУДИТСЯ ЗДЕСЬ ЖЕ. Item 3 вычитает его из
# вердикта 6.2.4.6 (там оно — цена старта пода, а не ложь слоя), и без этой
# половины оно не судилось бы НИЧЕМ: ровно та форма, что дала обе лжи архива
# collect-6.2.4 (containerd-shim→runc→runc:[1:CHILD] в 20:35:37 и
# k3s-server→containerd→flannel→bridge в 20:35:36 — оба внутри фазы churn).
# Вычитание из 6.2.4.6 не имеет права ничего терять: что там прощено как
# «цена старта пода», здесь обязано быть suspicious.
_w625_init_attack_churn=$(jq --argjson t0 "${_w625_pod_start_phase_start:-0}" --argjson t1 "${_w625_pod_start_phase_end:-0}" --arg actors "$W625_NODE_ACTORS"     '[.[]|select(.rule_id=="incident_confirmed_attack"
        and ($t1 > 0)
        and ((.timestamp|sub("\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t0)
        and ((.timestamp|sub("\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) <= $t1)
        and (((.details.root_comm // .comm) as $c | (($actors|split(" "))|index($c))) != null))]|length'     "$W625_ART/alerts-incidents.json" 2>/dev/null)
echo "  окно подачи [$(_w625_utc "$_w625_t516"), $(_w625_utc "$_w625_t516_end")]"
echo "  incident_confirmed_attack с корнем-нодовым актором внутри окна стартов подов 6.2.5.10 (item 3 вычел их из 6.2.4.6 — судятся здесь): ${_w625_init_attack_churn:-0}"
echo "  алертов класса побега/руткита от рантайм-comm внутри подачи: ${_w625_init_hits:-0}"
echo "  incident_confirmed_attack с корнем-нодовым актором внутри подачи: ${_w625_init_attack:-0} (${_w625_init_attack_roots:-нет})"
if [ "$W625_INSTRUMENTED" -ne 1 ]; then
    die "6.2.5.16 НЕИЗМЕРИМ: прогон неприборный (6.2.5.0 не взят) — под не стартовал, форму архива подать нечем"
elif [ "${_w625_init_hits:-0}" -lt 1 ]; then
    die "6.2.5.16 НЕИЗМЕРИМ: старт пода не дал НИ ОДНОГО алерта класса container_escape_*/rootkit_* от рантайм-comm — форма архива не воспроизведена, и «инцидента нет» ничего не доказывает (ноль приборный)"
elif [ "${_w625_init_attack:-0}" -gt 0 ] || [ "${_w625_init_attack_churn:-0}" -gt 0 ]; then
    die "6.2.5.16 ПРОВАЛЕН (№262): рутинная инициализация контейнера дала ${_w625_init_attack} incident_confirmed_attack с корнем нодового актора в окне подачи (${_w625_init_attack_roots}) и ${_w625_init_attack_churn:-0} в окне стартов подов 6.2.5.10 — шлюз промоушена по-прежнему судит по листу, а не по корню дерева"
elif [ "${_w625_esc_inc:-0}" -lt 1 ]; then
    die "6.2.5.16 НЕИЗМЕРИМ: инициализация контейнера в attack не промотирована, но и 6.2.4.7 не взят — по этому прогону нельзя отличить «шлюз судит по корню» от «детект вырезан целиком» (постановка требует читать обе половины вместе)"
else
    pass "6.2.5.16 ДОСТИГНУТО: ${_w625_init_hits} алертов класса побега от рантайм-comm при старте пода не дали ни одного incident_confirmed_attack с корнем нодового актора (ни в окне подачи, ни в окне стартов подов 6.2.5.10), и при этом настоящий побег (6.2.4.7) промотирован — шлюз судится по корню дерева, а не по листу"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.5.11 ПОЗИТИВНЫЙ ПОДКОНТРОЛЬ ЗАМОРОЗКИ (№237, открытый вопрос 11).
#
# ПОЧЕМУ САМЫМ ПОСЛЕДНИМ. Подконтроль ВРЕМЕННО понижает
# max_signatures_per_workload и перезапускает агент: это обнуляет счётчики
# метрик и базу дрейфа. Любой контроль, стоящий после него, мерил бы уже
# другой агент. Конфиг восстанавливается и агент перезапускается обратно
# ВСЕГДА — в том числе если подконтроль провалится (trap).
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.5.11 (вердикт): заморозка доказывается приращением счётчика ---"
_w625_cfg_bak="$W625_ART/config-test.yaml.orig"
_w625_restore_cfg() {
    if [ -f "$_w625_cfg_bak" ]; then
        cp "$_w625_cfg_bak" "$_w625_cfg" 2>/dev/null
        systemctl restart "$W625_SVC" 2>/dev/null
        echo "  конфиг стенда восстановлен из $_w625_cfg_bak, агент перезапущен"
    fi
    rm -rf /root/w625-sig 2>/dev/null
    rm -f /usr/local/bin/w625sig 2>/dev/null
}
trap '_w625_restore_cfg' EXIT

if ! grep -qE '^\s*max_signatures_per_workload:' "$_w625_cfg" 2>/dev/null; then
    die "6.2.5.11 НЕИЗМЕРИМ: в $_w625_cfg нет ключа max_signatures_per_workload — понизить его нечем, и дельта 0 останется неотличима от «счётчик сломан» (находка №237)"
else
    cp "$_w625_cfg" "$_w625_cfg_bak" 2>/dev/null
    sed -i 's/^\(\s*\)max_signatures_per_workload:.*/\1max_signatures_per_workload: 3/' "$_w625_cfg"
    echo "  max_signatures_per_workload временно понижен до 3 (было ${_w625_maxsig:-?}), рестарт агента"
    systemctl restart "$W625_SVC" 2>/dev/null
    sleep "$W625_SETTLE"
    # №267 (item 5): фильтр по comm="w625sig" — иначе рост bash/sshd от
    # прочих контролей внутри того же 20-секундного settle засчитывается в
    # приращение подконтроля, и «+2» верно совпадает со счётом случайно, а не
    # доказательно (архив 6.2.4: +2 = 1×bash + 1×w624sig). _w625_metric_sum
    # теперь матчит значение ЛЮБОГО лейбла в кавычках (см. правку выше).
    _w625_capA=$(_w625_metric_sum ebpf_guard_drift_baseline_signature_cap_reached_total "w625sig")
    # Нагрузка: один comm (=один WorkloadKey) открывает ДЕСЯТКИ РАЗНЫХ путей
    # под /root/ — каждый путь есть отдельная сигнатура drift_new_file_dir_sensitive
    # (normalizeDriftPath сохраняет путь целиком, схлопывая лишь числовые
    # сегменты). setsid — по той же причине, что у инъекции бикона.
    mkdir -p /root/w625-sig 2>/dev/null
    for _i in $(seq 1 40); do echo "s$_i" > "/root/w625-sig/f$_i" 2>/dev/null; done
    cp /bin/cat /usr/local/bin/w625sig 2>/dev/null
    _w625_sig_read=0
    for _i in $(seq 1 40); do
        _w625_sig_read=$(( _w625_sig_read + $(setsid /usr/local/bin/w625sig "/root/w625-sig/f$_i" 2>/dev/null | wc -c) ))
    done
    sleep "$W625_SETTLE"
    _w625_capB=$(_w625_metric_sum ebpf_guard_drift_baseline_signature_cap_reached_total "w625sig")
    _w625_capD=$(( _w625_capB - _w625_capA ))
    _w625_frozen_now=$(_w625_metric_sum ebpf_guard_drift_baseline_frozen_workloads "")
    echo "  сторож результата: прочитано байт нагрузкой = $_w625_sig_read (40 разных путей под /root/, один comm=w625sig)"
    echo "  приращение signature_cap_reached_total НА СВОЕЙ НАГРУЗКЕ (comm=w625sig, №267): $_w625_capD (было $_w625_capA, стало $_w625_capB); замороженных нагрузок сейчас: $_w625_frozen_now"
    if [ "${_w625_sig_read:-0}" -lt 1 ]; then
        die "6.2.5.11 НЕИЗМЕРИМ: нагрузка не прочитала ни байта — ноль приращения приборный, а не вердикт (память positive-control-needs-result-sentinel)"
    elif [ "$_w625_capD" -gt 0 ]; then
        pass "6.2.5.11 ДОСТИГНУТО: при max_signatures_per_workload=3 счётчик заморозки вырос на $_w625_capD — приращение ДОКАЗАНО, а не выведено из наличия имени метрики в выдаче (находка №237)"
    else
        die "6.2.5.11 ПРОВАЛЕН: нагрузка завела 40 различных сигнатур на ОДНУ нагрузку при потолке 3, а signature_cap_reached_total не вырос ни разу. Два возможных объяснения, и оба — находка: счётчик не движется, либо дерево нагрузки срезано в ядре исключением наблюдателя 5.9a (память observer-exclusion-blinds-controls) — тогда ноль приборный и контроль требует носителя вне дерева измерителя"
    fi
fi
_w625_restore_cfg
trap - EXIT

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.5.14 — РЕГРЕССИОННЫЙ ПУЧОК ВОЛН 6.2.1/6.2.2/6.2.3, СВОДНЫЙ ВЕРДИКТ.
#
# Постановка называет тринадцать меток и требует, чтобы КАЖДАЯ вынесла СВОЙ
# вердикт (6.2.3.5 в прогоне 6.2.4 своего вердикта не вынесла — была свёрнута
# в 6.2.3.6). Сама метка 6.2.5.14 при этом в прогоне 6.2.4-форка не
# печаталась вовсе, то есть страж полноты 6.2.5.18 обязан был бы объявить её
# отсутствующей. Здесь она сводит тринадцать в одну строку — не заменяя их
# собственные вердикты, а проверяя, что они есть.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.5.14: регрессионный пучок волн 6.2.1/6.2.2/6.2.3 (тринадцать меток) ---"
W625_REGRESSION_LABELS="6.2.1.2 6.2.1.2b 6.2.1.3 6.2.1.6 6.2.1.8 6.2.1.9 6.2.2.2 6.2.2.3 6.2.2.6 6.2.3.5 6.2.3.6 6.2.3.13 6.2.3.14"
_w625_reg_missing=""; _w625_reg_failed=""; _w625_reg_ok=0
for _w625_rl in $W625_REGRESSION_LABELS; do
    if ! grep -qE "^${_w625_rl//./\\.} " "$W625_EMITTED" 2>/dev/null; then
        _w625_reg_missing="$_w625_reg_missing $_w625_rl"
    elif grep -qE "^${_w625_rl//./\\.} FAIL$" "$W625_EMITTED" 2>/dev/null; then
        _w625_reg_failed="$_w625_reg_failed $_w625_rl"
    else
        _w625_reg_ok=$(( _w625_reg_ok + 1 ))
    fi
done
echo "  вынесли ДОСТИГНУТО: $_w625_reg_ok из 13; провалены:${_w625_reg_failed:- нет}; БЕЗ вердикта:${_w625_reg_missing:- нет}"
if [ -n "${_w625_reg_missing:-}" ]; then
    die "6.2.5.14 НЕИЗМЕРИМ: регрессионные метки${_w625_reg_missing} не вынесли СВОЕГО вердикта в этом прогоне — ровно то, что 6.2.3.5 сделала в прогоне 6.2.4 (свёрнута в 6.2.3.6). Пучок нельзя считать взятым по меткам, которых в логе нет"
elif [ -n "${_w625_reg_failed:-}" ]; then
    die "6.2.5.14 ПРОВАЛЕН: регрессия волн 6.2.1/6.2.2/6.2.3 не удержана —${_w625_reg_failed} (собственные вердикты этих меток см. выше)"
else
    pass "6.2.5.14 ДОСТИГНУТО: все тринадцать регрессионных меток вынесли свой вердикт и ни одна не провалена"
fi

echo "--- уборка ---"
"$W625_KUBECTL" -n "$W625_NS" delete pod --all --ignore-not-found --wait=false >/dev/null 2>&1
rm -f /usr/local/bin/w625hostcat /usr/local/bin/w625sig /usr/local/bin/w625beacon 2>/dev/null
rm -rf /root/w625-sig /tmp/w625-bypass /tmp/w625-chmod 2>/dev/null
rm -f /etc/cron.d/w625-lineage 2>/dev/null   # подача половины (4) критерия 6.2.4.5

echo
echo "=== ИТОГ КОНТРОЛЕЙ ВОЛНЫ 6.2.5: проваленных $WAVE624_FAILS ==="
echo "артефакты: $W625_ART"
[ "$WAVE624_FAILS" -gt 0 ] && echo "вердикты: $W625_VERDICTS"
exit 0
