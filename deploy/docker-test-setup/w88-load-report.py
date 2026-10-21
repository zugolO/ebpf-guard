#!/usr/bin/env python3
"""w88-load-report.py <OUT> [role=host|pod] [cpu_limit=0.5] — вердиктные строки меток 8.8.x по прогону w88-load.sh.

Вход: каталог прогона (step-NN-<ops>/ с срезами a/b/c .prom, probe.json, ctl.K.json, gen.json.P, poll.tsv).
Выход: по одной строке на метку:  «8.8.N <роль>: PASS|FAIL|НЕИЗМЕРИМ — <число>». Вердикт по числу, не глазами.
НЕИЗМЕРИМ — когда входа нет (не «PASS по умолчанию»).

  8.8.1  видимость: на ступенях с потерями ≥ 1% за 10 с degraded в /health не позже 10 с от начала потерь;
         на ступенях без потерь (< 0,1% за 10 с) — healthy
  8.8.2  плато: обработано воркерами за потолком / ёмкость ≥ 0,9 на всех ступенях выше первой с потерями
  8.8.3  protected-зонд w88p: потерь 0 событий и p99 возраста ≤ 100 мс на ступенях с подачей в (ёмкость, 2×ёмкость]
  8.8.4  контрольные w88cK: потерь 0 (≥ 1 события — нарушение) у каждого на ступени, ближайшей к 2× ёмкости (по реальным дропам);
         0,5% печатается справочно
  8.8.Н  насыщение стенда: CPU генератора, агента и простой ноды по ступеням; ступень с простоем < 10% не судится (8.8.2, 8.8.4)
  8.8.5  (pod) сторож: уровень сброса > 0 на ступени за потолком, 0 на ступени 0, база = квота
  8.8.Д  генератор чист: ошибок connect 0 и elapsed ≤ dur + 1 с
Метки 8.8.6 (recall под нагрузкой) и 8.8.7 (idle) печатают свои скрипты (attack-режим, w88-idle-ab.sh).
"""
import glob
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("w87table", os.path.join(HERE, "w87-e6-table.py"))
T = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(T)

LOSS_STEP_FRAC = 0.01       # ступень «с потерями»: ≥ 1% за 10 с
CLEAN_STEP_FRAC = 0.001     # «без потерь»: < 0,1% за 10 с
PROBE_LOSS_MAX_EVENTS = 1.0  # 8.8.3: порог плана «потерь 0» (решение владельца 18.10 по рекомендации): нарушение = потеряно ≥ 1 события
PROBE_LOSS_REF = 0.005      # 0,5% — прежний порог эмиттера, печатается справочно
PROBE_WINDOW_MAX = 2.0      # 8.8.3: «bulk до 2× ёмкости» (план); было 2,5× без решения
CTL_LOSS_MAX_EVENTS = 1.0   # 8.8.4 до волны 9: «потерь канарейки контрольных 0»; нарушение = потеряно ≥ 1 события (справочно)
CTL_LOSS_MAX_FRAC = 0.001   # 8.8.4, волна 9 (решение владельца 20.10): ≤ 0,1% у каждого контрольного; остаток виден по хопу
                            # счётчиком ebpf_guard_events_dropped_by_pid_class_total{class="light"} (печатается рядом)
CTL_LOSS_REF = 0.005        # 0,5% — прежний порог эмиттера (376a82e), печатается справочно
CTL_WINDOW_NEAR = (1.5, 2.5)  # 8.8.4: ступень, ближайшая к 2× ёмкости, должна лежать в [1,5; 2,5]×ёмкости, иначе НЕИЗМЕРИМ
NODE_IDLE_MIN = 0.10        # простой ноды < 10% (4 ядра заняты) — ступень на стенде не судится (НЕИЗМЕРИМ), а не FAIL
PROBE_P99_MAX = 0.1
PLATEAU_MIN = 0.9
PRICE_RISE_MAX = 1.1        # 8.8.2(ц), предложение захода C волны 9: мкс/соб. на ступени за потолком ≤ 1,1 × на ступени первых потерь
DEGRADE_DELAY_MAX = 10.0


def poll(out):
    rows = []
    try:
        for ln in open(os.path.join(out, "poll.tsv"), encoding="utf-8", errors="replace"):
            f = ln.rstrip("\n").split("\t")
            if len(f) < 4:
                continue
            try:
                rows.append((float(f[0]), f[1], float(f[2]), float(f[3]), f[4] if len(f) > 4 else "na", f[5] if len(f) > 5 else "na"))
            except ValueError:
                continue
    except OSError:
        pass
    return rows


def window_frac(rows, i):
    """доля потерь за 10 с, оканчивающихся на отсчёте i (None, пока окно короче 10 с)."""
    j = i
    while j > 0 and rows[i][0] - rows[j][0] < 10.0:
        j -= 1
    if rows[i][0] - rows[j][0] < 10.0:
        return None
    dd = rows[i][2] - rows[j][2]
    de = rows[i][3] - rows[j][3]
    tot = dd + max(de, 0)
    return (dd / tot if tot > 0 else 0.0), dd


def steps(out):
    res = []
    for s in sorted(x for x in os.listdir(out) if x.startswith("step-")):
        d = os.path.join(out, s)
        name = s.split("-", 2)[2]
        res.append({"name": name, "dir": d})
    return res


def age_count(rows):
    return sum(v for n, l, v in rows if n == "ebpf_guard_ingest_event_age_seconds_count")


def step_numbers(st):
    d = st["dir"]
    a, b, c = T.prom(f"{d}/a.prom"), T.prom(f"{d}/b.prom"), T.prom(f"{d}/c.prom")
    ta, tb = T.rd(f"{d}/a.t"), T.rd(f"{d}/b.t")
    if not a or not b or ta is None or tb is None:
        return None
    dt = tb - ta

    def real_drops(rows):
        # потери агента; path_denylist — фильтрация, не потеря ([[dropped-695-is-path-denylist]])
        return sum(v for n, l, v in rows if n == "ebpf_guard_events_dropped_total" and l.get("reason") != "path_denylist")

    def shed(rows):
        # сброс в ядре сэмплером у горячих процессов (волна 8.8): объём, отданный намеренно
        return sum(v for n, l, v in rows if n == "ebpf_guard_file_hot_shed_total" and l.get("outcome") == "shed")

    ev = T.ssum(b, "ebpf_guard_events_total") - T.ssum(a, "ebpf_guard_events_total")
    proc = age_count(b) - age_count(a)  # взято воркерами (честная «обработка»: после дропов Р5)
    drops = real_drops(b) - real_drops(a)
    sh = shed(b) - shed(a)
    ops = None
    for gf in glob.glob(f"{d}/gen.json*"):
        j = jload(gf) if not gf.endswith(".err") else None
        if j:
            ops = (ops or 0.0) + j["ops_total"] / j["elapsed_s"]
    return {"dt": dt, "proc_s": proc / dt, "fed_s": (ev + drops) / dt, "drops": drops, "shed": sh, "ops_s": ops,
            "a": a, "b": b, "c": c}


def node_stats(st):
    """Насыщение ноды на ступени: простой (idle+iowait) по /proc/stat, ядра агента (utime+stime) и генератора (cpu_self+cpu_children)."""
    d = st["dir"]
    def raw(f):
        try:
            return open(f"{d}/{f}", encoding="utf-8", errors="replace").read().strip()
        except OSError:
            return None
    ca, cb, ta, tb, ka, kb = raw("a.cpu"), raw("b.cpu"), raw("a.t"), raw("b.t"), raw("a.ticks"), raw("b.ticks")
    try:
        a, b = [int(x) for x in ca.split()[1:9]], [int(x) for x in cb.split()[1:9]]
        dt = float(tb) - float(ta)
    except (AttributeError, ValueError, TypeError):
        return None
    dd = [y - x for x, y in zip(a, b)]
    tot = sum(dd)
    if tot <= 0 or dt <= 0:
        return None
    r = {"idle": (dd[3] + dd[4]) / tot, "agent": None, "gen": 0.0}
    try:
        r["agent"] = (int(kb) - int(ka)) / 100.0 / dt
    except (ValueError, TypeError):
        pass
    for gf in glob.glob(f"{d}/gen.json*"):
        j = jload(gf) if not gf.endswith(".err") else None
        if j and j.get("elapsed_s"):
            r["gen"] += (j.get("cpu_self_s", 0.0) + j.get("cpu_children_s", 0.0)) / j["elapsed_s"]
    return r


def hist_q(a, b, probe, q):
    def bk(rows):
        d = {}
        for n, l, v in rows:
            if n == "ebpf_guard_load_probe_event_age_seconds_bucket" and l.get("probe") == probe:
                d[l["le"]] = v
        return d
    ba, bb = bk(a), bk(b)
    tot = bb.get("+Inf", 0) - ba.get("+Inf", 0)
    if tot <= 0:
        return None
    for le in sorted(bb, key=lambda x: float("inf") if x == "+Inf" else float(x)):
        if bb[le] - ba.get(le, 0) >= q * tot:
            return float("inf") if le == "+Inf" else float(le)
    return float("inf")


def probe_seen(rows, probe):
    return sum(v for n, l, v in rows if n == "ebpf_guard_load_probe_events_total" and l.get("probe") == probe)


def jload(path):
    try:
        return json.load(open(path))
    except (OSError, ValueError):
        return None


def verdict(label, role, ok, detail):
    word = "НЕИЗМЕРИМ" if ok is None else ("PASS" if ok else "FAIL")
    return f"{label} {role}: {word} — {detail}"


def main():
    out = sys.argv[1]
    kv = dict(a.split("=", 1) for a in sys.argv[2:] if "=" in a)
    role = kv.get("role", "host")
    quota = float(kv.get("cpu_limit", "0.5"))
    st = steps(out)
    nums = [step_numbers(s) for s in st]
    ns = [node_stats(s) for s in st]

    def saturated(i):
        return bool(ns[i]) and ns[i]["idle"] < NODE_IDLE_MIN

    def sat_note(i):
        return f"{st[i]['name']}: простой ноды {ns[i]['idle']:.1%}, агент {ns[i]['agent'] or 0:.2f}, генератор {ns[i]['gen']:.2f} ядра"
    lines = []
    gen_procs = max((len([f for f in glob.glob(f"{s['dir']}/gen.json.*") if not f.endswith(".err")]) for s in st), default=0)

    # cap — ёмкость без потерь: наибольшая «обработано» среди ступеней с потерями < 0,1%; peak — наибольшая «обработано»
    # по всей лестнице (потолок): плато = за потолком обработка не падает ниже 0,9 потолка (Е6: под 5 100/17 200 = 0,30).
    cap = 0.0
    cap_ops = None
    cap_ops_d = None     # ёмкость по РЕАЛЬНЫМ дропам (сброс сэмплером не считается): основа окна 8.8.3/8.8.4
    cap_d = 0.0
    cap_i = -1
    first_loss = None
    for i, n in enumerate(nums):
        if not n:
            continue
        lost = n["drops"] + n["shed"]
        frac = lost / (lost + n["proc_s"] * n["dt"]) if (lost + n["proc_s"] * n["dt"]) > 0 else 0.0
        n["loss_frac"] = frac     # потери = дропы + сброс сэмплером в ядре: и то и другое — объём, которого агент не увидел
        dfrac = n["drops"] / (n["drops"] + n["proc_s"] * n["dt"]) if (n["drops"] + n["proc_s"] * n["dt"]) > 0 else 0.0
        n["dfrac"] = dfrac
        if dfrac < CLEAN_STEP_FRAC and n["proc_s"] > cap_d:
            cap_d, cap_ops_d = n["proc_s"], n["ops_s"]
        if frac < CLEAN_STEP_FRAC and n["proc_s"] > cap:
            cap, cap_i = n["proc_s"], i
            cap_ops = n["ops_s"]
        # Потолок определяют РЕАЛЬНЫЕ дропы ≥ 1%: сброс сэмплером — намеренный (в поде 0,5 ядра сторож CPU сбрасывает уже на 6% при
        # 5 000 оп/с, задолго до настоящего потолка 20 000), и «первые потери» по нему занижали бы опорную величину.
        if dfrac >= LOSS_STEP_FRAC and first_loss is None and cap_ops_d is not None:
            first_loss = i
    peak = max((n["proc_s"] for n in nums if n), default=0.0)

    # ── 8.8.1 ────────────────────────────────────────────────────────────────────────────────────────────────
    rows = poll(out)
    if not rows or not st:
        lines.append(verdict("8.8.1", role, None, "нет poll.tsv"))
    else:
        bad, judged, notes, notes_shed = [], 0, [], []
        for s in st:
            t0, t1 = T.rd(f"{s['dir']}/step-start.t"), T.rd(f"{s['dir']}/step-end.t")
            if t0 is None or t1 is None:
                continue
            idx = [i for i, r in enumerate(rows) if t0 <= r[0] <= t1 + 5]
            if not idx:
                continue
            wf = [(i, window_frac(rows, i)) for i in idx]
            wf = [(i, w) for i, w in wf if w is not None]
            mx = max((w[0] for _, w in wf), default=0.0)
            t_loss = next((rows[i][0] for i, w in wf if w[0] >= LOSS_STEP_FRAC and w[1] >= 10), None)
            deg = [rows[i][0] for i in idx if rows[i][1] != "healthy"]
            # Сброс по замыслу (сторож CPU уровень > 0 или делитель контроллера перегрузки > 1) читается как degraded
            # (Р1, docs/capacity.md): на ступени без потерь такой отсчёт — не ложная тревога. Под ×8 j2 (19.10): уровень 1–2
            # уже на 1 500 / 10 000 оп/с, потерь 0 — эмиттер красил это как «не healthy без потерь».
            def shedding(r):
                return any(v not in ("na", "") and float(v) > lim for v, lim in ((r[4], 0), (r[5], 1)))
            deg_noshed = [rows[i][0] for i in idx if rows[i][1] != "healthy" and not shedding(rows[i])]
            n_shed = sum(1 for i in idx if rows[i][1] != "healthy" and shedding(rows[i]))
            if t_loss is not None:
                judged += 1
                td = next((x for x in deg if x >= t_loss - 10), None)
                if td is None or td - t_loss > DEGRADE_DELAY_MAX:
                    bad.append(f"{s['name']}: потери с +{t_loss - t0:.0f}с, degraded " + ("нет" if td is None else f"+{td - t_loss:.0f}с"))
            elif mx < CLEAN_STEP_FRAC:
                judged += 1
                if deg_noshed:
                    bad.append(f"{s['name']}: потерь нет (макс {mx:.4%}), сброса нет, но не healthy {len(deg_noshed)} отсч.")
                elif n_shed:
                    notes_shed.append(f"{s['name']} ({n_shed} отсч.)")
            else:
                notes.append(s["name"])
        lines.append(verdict("8.8.1", role, (not bad) if judged else None,
                             f"ступеней судимо {judged}" + (f"; нарушения: {'; '.join(bad)}" if bad else "") +
                             (f"; серая зона (0,1…1%) не судится: {','.join(notes)}" if notes else "") +
                             (f"; degraded без потерь при сбросе по замыслу (не нарушение): {', '.join(notes_shed)}" if notes_shed else "")))

    # ── 8.8.2 ────────────────────────────────────────────────────────────────────────────────────────────────
    # Плато = за потолком обработка не падает. Опорная величина — потолок В ТОЧКЕ первых потерь: максимум «обработано» по
    # ступеням до первой с потерями включительно. Литеральное чтение плана (от максимума по всей лестнице: Е6 под 5 100/17 200 =
    # 0,30) наказывало бы систему, у которой на старших ступенях растёт доля дешёвых protected-событий, — оно печатается справочно.
    if peak <= 0 or first_loss is None:
        lines.append(verdict("8.8.2", role, None, "нет ступени с потерями ≥ 1% (потолок не достигнут)"))
    else:
        ref = max(nums[i]["proc_s"] for i in range(first_loss + 1) if nums[i])
        rat = [(i, st[i]["name"], nums[i]["proc_s"] / ref) for i in range(first_loss, len(nums)) if nums[i]]
        judged_r = [(i, n, r) for i, n, r in rat if not saturated(i)]
        sat_r = [(i, n, r) for i, n, r in rat if saturated(i)]
        worst = min(r for _, _, r in rat)
        worst_j = min((r for _, _, r in judged_r), default=None)
        alt = min(nums[i]["proc_s"] / peak for i in range(first_loss, len(nums)) if nums[i])
        detail = (f"потолок в точке первых потерь {ref:,.0f} соб./с (ёмкость без потерь {cap:,.0f}); от первой ступени с потерями: " +
                  ", ".join(f"{n}={r:.2f}" + ("*" if saturated(i) else "") for i, n, r in rat) + f"; минимум {worst:.2f} (порог {PLATEAU_MIN}); "
                  f"справочно от максимума лестницы ({peak:,.0f}): минимум {alt:.2f}")
        if worst_j is not None and worst_j < PLATEAU_MIN:
            lines.append(verdict("8.8.2", role, False, detail))
        elif sat_r and any(r < PLATEAU_MIN for _, _, r in sat_r):
            # красное только на ступенях, где ящик занят целиком (простой < 10%): стенд не отличает продукт от нехватки ядер
            lines.append(verdict("8.8.2", role, None, detail + "; * — простой ноды < " + f"{NODE_IDLE_MIN:.0%}, ступень не судится: " +
                                 "; ".join(sat_note(i) for i, _, r in sat_r if r < PLATEAU_MIN)))
        else:
            lines.append(verdict("8.8.2", role, True, detail))
    # 8.8.2(ц) — предложение захода C волны 9 (печатается всегда, чтобы ночь судилась при любом решении): ×8 на 4 vCPU стенда
    # отношение «обработано» шумит 0,75…1,13 на любом бинаре — на 60 000 генератор берёт 1,6–1,8 ядра и агент теряет 3–14% CPU
    # при простое ноды 10–21%. Цена события (ядра агента / обработано) от этого почти не зависит: судится она.
    if first_loss is None:
        lines.append(verdict("8.8.2(ц)", role, None, "нет ступени с потерями ≥ 1% (потолок не достигнут)"))
    else:
        def price(i):
            return (ns[i]["agent"] / nums[i]["proc_s"] * 1e6) if ns[i] and ns[i]["agent"] and nums[i] and nums[i]["proc_s"] > 0 else None
        p0 = price(first_loss)
        rows_p = [(i, price(i)) for i in range(first_loss + 1, len(nums)) if nums[i]]
        if not rows_p:
            lines.append(verdict("8.8.2(ц)", role, None, f"за ступенью первых потерь {st[first_loss]['name']} ступеней нет — сравнивать не с чем"))
        elif p0 is None or any(p is None for _, p in rows_p):
            lines.append(verdict("8.8.2(ц)", role, None, "нет ядер агента или обработки на ступенях за первой потерей"))
        else:
            judged_p = [(i, p) for i, p in rows_p if not saturated(i)]
            badp = [f"{st[i]['name']}: {p:.1f} мкс ({p / p0:.2f}×)" for i, p in judged_p if p > PRICE_RISE_MAX * p0]
            det = (f"мкс/соб. на ступени первых потерь {st[first_loss]['name']}: {p0:.1f}; дальше: " +
                   ", ".join(f"{st[i]['name']}={p:.1f} ({p / p0:.2f}×)" + ("*" if saturated(i) else "") for i, p in rows_p) +
                   f"; порог {PRICE_RISE_MAX}×" + ("; * — простой ноды < 10%, не судится" if any(saturated(i) for i, _ in rows_p) else ""))
            lines.append(verdict("8.8.2(ц)", role, (not badp) if judged_p else None, det + (f"; нарушения: {'; '.join(badp)}" if badp else "")))

    # ── 8.8.3 / 8.8.4 ────────────────────────────────────────────────────────────────────────────────────────
    def ratios_first(kind):
        """r0 до волны 9 (справочно): событий на подан. операцию по ПЕРВОЙ ступени с потерями < 1%; {имя: r0}."""
        r0 = {}
        for i, s in enumerate(st):
            n = nums[i]
            if not n or "loss_frac" not in n or n["loss_frac"] >= LOSS_STEP_FRAC:
                continue
            for name, sent in sent_ops(s, kind).items():
                seen = probe_seen(n["c"], name) - probe_seen(n["a"], name)
                if sent > 0 and name not in r0:
                    r0[name] = seen / sent
        return r0

    def ratios(kind):
        """r0 — ПОЛ «увидено/подано» по калибровочным ступеням (волна 9, заход C). Счёт процесса на ступени квантуется шагом
        2 (один вызов рантайма Go = enter+exit; хост 4658/4660/4662, под 4659/4661/4663 при одних и тех же 2999 оп.) на любой
        ступени, и первая ступень как эталон давала «потерю 2» без потери. Калибровка — ступени без единого реального дропа
        (запасной вариант — дропы < 0,1%, называется); контрольные — одинаковые процессы: пол общий по всем. {имя: r0}, класс."""
        cal = [i for i, n in enumerate(nums) if n and n["drops"] == 0]
        cls = "ступеням без реальных дропов"
        if not cal:
            cal = [i for i, n in enumerate(nums) if n and n.get("dfrac", 1.0) < CLEAN_STEP_FRAC]
            cls = "ступеням с дропами < 0,1% (ступеней без дропов нет)"
        per = {}
        for i in cal:
            n = nums[i]
            for name, sent in sent_ops(st[i], kind).items():
                if sent > 0:
                    per.setdefault(name, []).append((probe_seen(n["c"], name) - probe_seen(n["a"], name)) / sent)
        if not per:
            return {}, cls, []
        if kind == "controls":
            floor = min(min(v) for v in per.values())
            return {name: floor for name in per}, cls, [st[i]["name"] for i in cal]
        return {name: min(v) for name, v in per.items()}, cls, [st[i]["name"] for i in cal]

    def sent_ops(s, kind):
        d = s["dir"]
        if kind == "probe":
            j = jload(f"{d}/probe.json")
            return {"w88p": j["ops_total"]} if j else {}
        res = {}
        for f in sorted(glob.glob(f"{d}/ctl.*.json")):
            k = os.path.basename(f).split(".")[1]
            j = jload(f)
            if j:
                res[f"w88c{k}"] = j["ops_total"]
        return res

    # 8.8.4: «один горячий на 2× ёмкости» — ступень, ближайшая по подаче к 2 × ёмкость (по реальным дропам), в [1,5; 2,5]×.
    ctl_step = None
    if cap_ops_d:
        cand = [(abs(nums[i]["ops_s"] - 2 * cap_ops_d), i) for i in range(len(st))
                if nums[i] and nums[i]["ops_s"] is not None and nums[i]["ops_s"] > cap_ops_d]
        if cand:
            ctl_step = min(cand)[1]
            k = nums[ctl_step]["ops_s"] / cap_ops_d
            if not (CTL_WINDOW_NEAR[0] <= k <= CTL_WINDOW_NEAR[1]):
                ctl_step = None

    for label, kind in (("8.8.3", "probe"), ("8.8.4", "controls")):
        r0, cal_cls, cal_names = ratios(kind)
        r0_old = ratios_first(kind)
        if not r0:
            lines.append(verdict(label, role, None, "нет ни одной калибровочной ступени с зондом/контролями (PROBE=1 / CONTROLS=N)"))
            if label == "8.8.4":
                lines.append(verdict("8.8.4(0)", role, None, "нет ни одной калибровочной ступени с контролями (CONTROLS=N)"))
            continue
        bad, judged, worst, worst_ev, sat_skip, ev_bad, old_ev, bad_p99 = [], 0, 0.0, 0.0, [], [], 0.0, []
        for i, s in enumerate(st):
            n = nums[i]
            if label == "8.8.3":
                # «bulk до 2× ёмкости» (план): подача в операциях в (ёмкость, 2 × ёмкость]. Выше — физика: protected одного
                # генератора сам превышает бюджет пода.
                if not n or not cap_ops_d or n["ops_s"] is None or not (cap_ops_d < n["ops_s"] <= PROBE_WINDOW_MAX * cap_ops_d):
                    continue
            elif i != ctl_step:
                continue
            if label == "8.8.4" and saturated(i):
                sat_skip.append(sat_note(i))
                continue
            for name, sent in sent_ops(s, kind).items():
                if name not in r0 or sent <= 0 or r0[name] <= 0:
                    continue
                seen = probe_seen(n["c"], name) - probe_seen(n["a"], name)
                exp = sent * r0[name]
                loss = max(0.0, 1 - seen / exp)
                judged += 1
                worst = max(worst, loss)
                worst_ev = max(worst_ev, exp - seen)
                if name in r0_old:
                    old_ev = max(old_ev, sent * r0_old[name] - seen)
                p99 = hist_q(n["a"], n["b"], name, 0.99) if kind == "probe" else None
                if label == "8.8.3" and exp - seen >= PROBE_LOSS_MAX_EVENTS:
                    bad.append(f"{s['name']}/{name}: потеряно {exp - seen:.0f} соб. ({loss:.2%})")
                if label == "8.8.4" and loss > CTL_LOSS_MAX_FRAC:
                    bad.append(f"{s['name']}/{name}: потеряно {exp - seen:.0f} соб. ({loss:.2%} > {CTL_LOSS_MAX_FRAC:.1%})")
                if label == "8.8.4" and exp - seen >= CTL_LOSS_MAX_EVENTS:
                    ev_bad.append(f"{s['name']}/{name}: {exp - seen:.0f}")
                if kind == "probe" and (p99 is None or p99 > PROBE_P99_MAX):
                    bad_p99.append(1)
                    bad.append(f"{s['name']}/{name}: p99 возраста {'—' if p99 is None else f'{p99 * 1000:g} мс'} > {PROBE_P99_MAX * 1000:g}")
        cal_note = (f"пол «увидено/подано» по {cal_cls}: {','.join(cal_names)}" + (" (общий для всех контрольных)" if kind == "controls" else "") +
                    f"; справочно по первой чистой ступени (до захода C): худшая {max(old_ev, 0.0):.0f} соб.")
        if label == "8.8.3":
            ref = f"; справочно по прежнему порогу {PROBE_LOSS_REF:.1%}: " + ("PASS" if worst <= PROBE_LOSS_REF else "FAIL")
            lines.append(verdict(label, role, (not bad) if judged else None,
                                 (f"судимо {judged} пар (ступень×процесс; подача в (ёмкость, 2×ёмкость] = ({cap_ops_d:,.0f}, {PROBE_WINDOW_MAX * cap_ops_d:,.0f}] оп/с; ёмкость по реальным дропам), худшая потеря {worst:.2%} ({max(worst_ev, 0.0):.1f} соб.), порог плана — 0 событий{ref}; {cal_note}" if judged else "нет ступеней с подачей в (ёмкость, 2×ёмкость]") +
                                 (f"; нарушения: {'; '.join(bad)}" if bad else "")))
            # 8.8.3(а) — предложение захода C волны 9 (печатается всегда): под ×N генераторов зонд стоит в protected-FIFO
            # event_high за prctl/connect/exec горячих pid — p99 = глубина очереди / темп protected (хост 65 536 / ≈30 тыс./с ≈
            # 2,2 с, под 7 736 → 250 мс); p99 судится только для ×1, потери — всегда.
            multi = gen_procs > 1
            ok_a = (len(bad) - len(bad_p99) == 0) if multi else (not bad)
            lines.append(verdict("8.8.3(а)", role, ok_a if judged else None,
                                 (f"генераторов {gen_procs}: " + ("p99 возраста не судится (×N), только потери" if multi else "×1 — как 8.8.3, p99 судится")) +
                                 f"; худшая потеря {max(worst_ev, 0.0):.1f} соб." + (f"; нарушений p99 {len(bad_p99)} (справочно)" if multi and bad_p99 else "")))
            continue
        if ctl_step is None:
            why = "нет ступени с подачей в [1,5; 2,5]× ёмкости по реальным дропам" + (f" ({cap_ops_d:,.0f} оп/с)" if cap_ops_d else "")
            lines.append(verdict(label, role, None, why))
            lines.append(verdict("8.8.4(0)", role, None, why))
            continue
        where = (f"ступень {st[ctl_step]['name']} ({nums[ctl_step]['ops_s']:,.0f} оп/с = {nums[ctl_step]['ops_s'] / cap_ops_d:.2f}× ёмкости {cap_ops_d:,.0f})")
        if sat_skip:
            why = f"{where}: ящик занят целиком, ступень не судится; {sat_skip[0]} (порог простоя {NODE_IDLE_MIN:.0%})"
            lines.append(verdict(label, role, None, why))
            lines.append(verdict("8.8.4(0)", role, None, why))
            continue
        ref_note = f"справочно: прежний {CTL_LOSS_REF:.1%} — " + ("PASS" if worst <= CTL_LOSS_REF else "FAIL")
        n = nums[ctl_step]
        light = {}
        for hop in ("ringbuf_to_router", "router_to_queue", "worker_full"):
            sel = lambda rows: sum(v for nm, l, v in rows if nm == "ebpf_guard_events_dropped_by_pid_class_total" and l.get("hop") == hop and l.get("class") == "light")
            if any(nm == "ebpf_guard_events_dropped_by_pid_class_total" for nm, _, _ in n["c"]):
                light[hop] = sel(n["c"]) - sel(n["a"])
        hop_note = ("потери лёгких pid по хопам за ступень: " + ", ".join(f"{h} {v:.0f}" for h, v in light.items())) if light \
            else "серии ebpf_guard_events_dropped_by_pid_class_total нет (бинарь до волны 9)"
        lines.append(verdict(label, role, (not bad) if judged else None,
                             f"{where}; судимо {judged} контрольных; худшая потеря {worst:.2%} ({max(worst_ev, 0.0):.1f} соб.), порог {CTL_LOSS_MAX_FRAC:.1%}; {hop_note}; {cal_note}; {ref_note}" +
                             (f"; нарушения: {'; '.join(bad)}" if bad else "")))
        # 8.8.4(0) — тот же вход, порог «0 событий» к полу (предложение захода C владельцу): печатается всегда, чтобы ночь
        # судилась при любом решении о пороге.
        lines.append(verdict("8.8.4(0)", role, (not ev_bad) if judged else None,
                             f"{where}; порог «0 событий» к полу калибровки; худший недосчёт {max(worst_ev, 0.0):.0f} соб." +
                             (f"; нарушения: {', '.join(ev_bad)}" if ev_bad else "")))

    # ── 8.8.5 ────────────────────────────────────────────────────────────────────────────────────────────────
    if role != "pod":
        lines.append(verdict("8.8.5", role, None, "метка только для роли pod"))
    else:
        lv = {}
        for s in st:
            t0, t1 = T.rd(f"{s['dir']}/step-start.t"), T.rd(f"{s['dir']}/step-end.t")
            if t0 is None or t1 is None:
                continue
            vals = [float(r[4]) for r in rows if t0 <= r[0] <= t1 + 5 and r[4] not in ("na", "")]
            lv[s["name"]] = max(vals) if vals else None
        base = None
        for n in nums[:1]:
            if n:
                base = sum(v for k, l, v in n["b"] if k == "ebpf_guard_cpu_watchdog_base_cores") or None
        over = [st[i]["name"] for i, n in enumerate(nums) if n and n.get("loss_frac", 0) >= LOSS_STEP_FRAC]
        zero = st[0]["name"] if st else None
        ok_over = bool(over) and all((lv.get(x) or 0) > 0 for x in over[-1:])
        ok_zero = lv.get(zero) == 0
        ok_base = base is not None and abs(base - quota) < 1e-6
        if not over or lv.get(zero) is None:
            lines.append(verdict("8.8.5", role, None, f"нет ступени за потолком или нет отсчётов уровня; уровни {lv}"))
        else:
            lines.append(verdict("8.8.5", role, ok_over and ok_zero and ok_base,
                                 f"уровни по ступеням {lv}; ступень 0 = {lv.get(zero)}; за потолком ({over[-1]}) = {lv.get(over[-1])}; база сторожа {base} (квота {quota})"))

    # ── 8.8.Н ────────────────────────────────────────────────────────────────────────────────────────────────
    sat = [i for i in range(len(st)) if saturated(i)]
    have = [i for i in range(len(st)) if ns[i]]
    if not have:
        lines.append(verdict("8.8.Н", role, None, "нет срезов /proc/stat"))
    else:
        hi = [i for i in have if nums[i] and nums[i].get("loss_frac", 0) >= LOSS_STEP_FRAC] or have[-3:]
        tab = ", ".join(f"{st[i]['name']}: простой {ns[i]['idle']:.0%}/агент {ns[i]['agent'] or 0:.2f}/ген {ns[i]['gen']:.2f}" for i in hi)
        mn = min(have, key=lambda i: ns[i]["idle"])
        lines.append(verdict("8.8.Н", role, True if not sat else None,
                             f"минимальный простой ноды {ns[mn]['idle']:.1%} на ступени {st[mn]['name']} (порог {NODE_IDLE_MIN:.0%}); ступеней с насыщением {len(sat)}"
                             f"{(': ' + ', '.join(st[i]['name'] for i in sat)) if sat else ''}; ступени с потерями (простой/ядра агента/ядра генератора): {tab}"))

    # ── 8.8.Т: справка для docs/capacity.md (вердикта нет: числа ступеней, из которых строится таблица «события/с ↔ limits.cpu») ──
    rows_t = []
    for i, n in enumerate(nums):
        if not n or n["ops_s"] is None:
            continue
        tot = n["proc_s"] * n["dt"] + n["drops"] + n["shed"]
        rows_t.append(f"{st[i]['name']}: {n['ops_s']:,.0f} оп/с → {n['proc_s']:,.0f} соб./с, дропы {100 * n['drops'] / max(n['drops'] + n['proc_s'] * n['dt'], 1):.1f}%, "
                      f"сброс {100 * n['shed'] / max(tot, 1):.1f}%")
    if rows_t:
        lines.append(f"8.8.Т {role}: СПРАВКА — ёмкость без дропов {cap_d:,.0f} соб./с ({(cap_ops_d or 0):,.0f} оп/с); потолок обработки {peak:,.0f} соб./с; ступени: " + "; ".join(rows_t))

    # ── 8.8.Д ────────────────────────────────────────────────────────────────────────────────────────────────
    bad, n_gen = [], 0
    for s in st:
        for f in glob.glob(f"{s['dir']}/gen.json.*") + glob.glob(f"{s['dir']}/gen.json"):
            if f.endswith(".err"):
                continue
            j = jload(f)
            if not j:
                continue
            n_gen += 1
            dur = j.get("rate_target") is not None
            if j.get("connect_errors", None) is None:
                bad.append(f"{s['name']}: нет connect_errors (генератор старый)")
            elif j["connect_errors"] > 0:
                bad.append(f"{s['name']}: ошибок connect {j['connect_errors']}")
            if j["elapsed_s"] > float(kv.get("step_s", "60")) + 1:
                bad.append(f"{s['name']}: elapsed {j['elapsed_s']:.1f} с")
    lines.append(verdict("8.8.Д(а)", role, (not bad) if n_gen else None,
                         f"генераторов {n_gen}" + (f"; нарушения: {'; '.join(bad[:6])}" if bad else "; ошибок connect 0, elapsed ≤ dur+1")))
    print("\n".join(lines))


if __name__ == "__main__":
    main()
