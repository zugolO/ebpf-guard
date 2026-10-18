#!/usr/bin/env python3
"""w88-load-report.py <OUT> [role=host|pod] [cpu_limit=0.5] — вердиктные строки меток 8.8.x по прогону w88-load.sh.

Вход: каталог прогона (step-NN-<ops>/ с срезами a/b/c .prom, probe.json, ctl.K.json, gen.json.P, poll.tsv).
Выход: по одной строке на метку:  «8.8.N <роль>: PASS|FAIL|НЕИЗМЕРИМ — <число>». Вердикт по числу, не глазами.
НЕИЗМЕРИМ — когда входа нет (не «PASS по умолчанию»).

  8.8.1  видимость: на ступенях с потерями ≥ 1% за 10 с degraded в /health не позже 10 с от начала потерь;
         на ступенях без потерь (< 0,1% за 10 с) — healthy
  8.8.2  плато: обработано воркерами за потолком / ёмкость ≥ 0,9 на всех ступенях выше первой с потерями
  8.8.3  protected-зонд w88p: потерь ≤ 0,5% и p99 возраста ≤ 100 мс на ступенях с bulk ≥ ёмкости
  8.8.4  контрольные w88cK: потерь ≤ 0,5% у каждого на ступенях с bulk ≥ ёмкости
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
PROBE_LOSS_MAX = 0.005
PROBE_P99_MAX = 0.1
PLATEAU_MIN = 0.9
DEGRADE_DELAY_MAX = 10.0


def poll(out):
    rows = []
    try:
        for ln in open(os.path.join(out, "poll.tsv"), encoding="utf-8", errors="replace"):
            f = ln.rstrip("\n").split("\t")
            if len(f) < 4:
                continue
            try:
                rows.append((float(f[0]), f[1], float(f[2]), float(f[3]), f[4] if len(f) > 4 else "na"))
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
    lines = []

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
        bad, judged, notes = [], 0, []
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
            if t_loss is not None:
                judged += 1
                td = next((x for x in deg if x >= t_loss - 10), None)
                if td is None or td - t_loss > DEGRADE_DELAY_MAX:
                    bad.append(f"{s['name']}: потери с +{t_loss - t0:.0f}с, degraded " + ("нет" if td is None else f"+{td - t_loss:.0f}с"))
            elif mx < CLEAN_STEP_FRAC:
                judged += 1
                if deg:
                    bad.append(f"{s['name']}: потерь нет (макс {mx:.4%}), но не healthy {len(deg)} отсч.")
            else:
                notes.append(s["name"])
        lines.append(verdict("8.8.1", role, (not bad) if judged else None,
                             f"ступеней судимо {judged}" + (f"; нарушения: {'; '.join(bad)}" if bad else "") +
                             (f"; серая зона (0,1…1%) не судится: {','.join(notes)}" if notes else "")))

    # ── 8.8.2 ────────────────────────────────────────────────────────────────────────────────────────────────
    # Плато = за потолком обработка не падает. Опорная величина — потолок В ТОЧКЕ первых потерь: максимум «обработано» по
    # ступеням до первой с потерями включительно. Литеральное чтение плана (от максимума по всей лестнице: Е6 под 5 100/17 200 =
    # 0,30) наказывало бы систему, у которой на старших ступенях растёт доля дешёвых protected-событий, — оно печатается справочно.
    if peak <= 0 or first_loss is None:
        lines.append(verdict("8.8.2", role, None, "нет ступени с потерями ≥ 1% (потолок не достигнут)"))
    else:
        ref = max(nums[i]["proc_s"] for i in range(first_loss + 1) if nums[i])
        rat = [(st[i]["name"], nums[i]["proc_s"] / ref) for i in range(first_loss, len(nums)) if nums[i]]
        worst = min(r for _, r in rat)
        alt = min(nums[i]["proc_s"] / peak for i in range(first_loss, len(nums)) if nums[i])
        lines.append(verdict("8.8.2", role, worst >= PLATEAU_MIN,
                             f"потолок в точке первых потерь {ref:,.0f} соб./с (ёмкость без потерь {cap:,.0f}); от первой ступени с потерями: " +
                             ", ".join(f"{n}={r:.2f}" for n, r in rat) + f"; минимум {worst:.2f} (порог {PLATEAU_MIN}); "
                             f"справочно от максимума лестницы ({peak:,.0f}): минимум {alt:.2f}"))

    # ── 8.8.3 / 8.8.4 ────────────────────────────────────────────────────────────────────────────────────────
    def ratios(kind):
        """r0 (событий на подан. операцию) калибруется на ступени 0 и на нижних; возвращает {имя: r0}."""
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

    for label, kind in (("8.8.3", "probe"), ("8.8.4", "controls")):
        r0 = ratios(kind)
        if not r0:
            lines.append(verdict(label, role, None, "нет ни одной калибровочной ступени с зондом/контролями (PROBE=1 / CONTROLS=N)"))
            continue
        bad, judged, worst = [], 0, 0.0
        for i, s in enumerate(st):
            n = nums[i]
            # «bulk до 2× ёмкости» (план): подача в операциях в (ёмкость, 2,5 × ёмкость]; шаг лестницы грубый, 2,5 — чтобы в окно
            # попала ступень, ближайшая к 2×. Выше — физика: protected одного генератора сам превышает бюджет пода.
            if not n or not cap_ops_d or n["ops_s"] is None or not (cap_ops_d < n["ops_s"] <= 2.5 * cap_ops_d):
                continue
            for name, sent in sent_ops(s, kind).items():
                if name not in r0 or sent <= 0 or r0[name] <= 0:
                    continue
                seen = probe_seen(n["c"], name) - probe_seen(n["a"], name)
                loss = max(0.0, 1 - seen / (sent * r0[name]))
                judged += 1
                worst = max(worst, loss)
                p99 = hist_q(n["a"], n["b"], name, 0.99) if kind == "probe" else None
                if loss > PROBE_LOSS_MAX:
                    bad.append(f"{s['name']}/{name}: потеря {loss:.2%}")
                if kind == "probe" and (p99 is None or p99 > PROBE_P99_MAX):
                    bad.append(f"{s['name']}/{name}: p99 возраста {'—' if p99 is None else f'{p99 * 1000:g} мс'} > {PROBE_P99_MAX * 1000:g}")
        lines.append(verdict(label, role, (not bad) if judged else None,
                             (f"судимо {judged} пар (ступень×процесс; подача в (ёмкость, 2,5×ёмкость] = ({cap_ops_d:,.0f}, {2.5 * cap_ops_d:,.0f}] оп/с; ёмкость по реальным дропам), худшая потеря {worst:.2%}" if judged else "нет ступеней с подачей в (ёмкость, 2,5×ёмкость]") +
                             (f"; нарушения: {'; '.join(bad)}" if bad else "")))

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
