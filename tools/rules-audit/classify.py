#!/usr/bin/env python3
"""Wave 7 item 1 — revision 7.0 of the rule-audit table.

Re-annotates the 292 rules that revision 3.0 (docs/rules-audit-2026-08-06.md,
sections Z1-Z4) recorded as `silent / condition-not-matched`, against the
CURRENT rules/*.yaml (after waves 5-6) and against the 3.0 snapshot commit.

Reproduce (from the repo root, no network, no stand):

    python3 tools/rules-audit/classify.py

It shells out to `go run ./tools/rules-audit` (YAML -> JSON with id line
numbers) for HEAD and for the 3.0 snapshot commit, then writes:

    docs/rules-audit-2026-09-27.csv
    docs/rules-audit-2026-09-27.md

The rule set fed to the extractor is the current working tree for HEAD and
`git archive <snapshot> rules` for the 3.0 side, so the table is a function of
(the doc Z1-Z4 lists, HEAD rules/, snapshot rules/) and never hand-edited.
"""
import collections
import csv
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SNAPSHOT = "3a3006a"  # build 3a3006a, 2026-08-05 — the 3.0 measurement build
DOC3 = os.path.join(REPO, "docs", "rules-audit-2026-08-06.md")
CSV3 = os.path.join(REPO, "docs", "rules-audit-2026-08-06.csv")
OUT_MD = os.path.join(REPO, "docs", "rules-audit-2026-09-27.md")
OUT_CSV = os.path.join(REPO, "docs", "rules-audit-2026-09-27.csv")

# --- canonical event-type names (3.0 CSV used tcp_connect; YAML writes network) ---
CANON = {"network": "tcp_connect", "tcp_connect": "tcp_connect", "file": "file",
         "file_access": "file", "syscall": "syscall", "net_close": "net_close"}

# --- field aliases (dot form -> canonical leaf name) ---
ALIAS = {"file.path": "filename", "file.op": "op", "proc.comm": "comm",
         "syscall.nr": "nr", "syscall.ret": "ret", "file.directory": "directory",
         "file.extension": "extension", "network.dport": "dport",
         "network.sport": "sport", "network.daddr": "daddr", "network.saddr": "saddr",
         "network.proto": "proto", "proc.ppid": "ppid", "proc.parent_comm": "parent_comm"}

# op tokens the collector can actually emit (FILE_OP_* in bpf/common.h,
# rendered by fileOpNames in internal/correlator/rules.go).
FILE_OPS = {"open", "read", "write", "chmod"}

# Comparison operators that name the values an event MUST carry. Only these can
# make a value set unsatisfiable: `not_in`/`neq` name values the event must
# avoid, so a dead token there matches everything rather than nothing. `eq` is a
# valid alias of `equals` (internal/correlator/rules.go, OpEquals case of
# evaluateCondition) — the product's own audit predicate missed it, see
# namesLiteralValues.
LITERAL_OPS = {"in", "eq", "equals"}

CONFIG = os.path.join(REPO, "config", "config.yaml")


def kernel_syscall_allowlist():
    """The syscall numbers the in-kernel filter forwards, per the shipped config.

    bpf/syscall.bpf.c:52 drops any syscall absent from syscall_filter_map, which
    is programmed from cfg.BPF.KernelFilter.MonitoredSyscalls (or, when that is
    empty, DefaultMonitoredSyscalls()). A rule whose whole numeric `nr` set lies
    outside it can never receive an event — the `nr` axis is NOT unconditionally
    live, which is what revision 7.0's first cut assumed.

    config/config.yaml is read rather than DefaultMonitoredSyscalls() because it
    is the longer of the two lists (22 vs 19 numbers, a strict superset), so a
    rule this function calls dead is dead under either resolution. The stand's
    config-test.yaml sets no monitored_syscalls at all and therefore falls back
    to the shorter default — see the divergence already recorded in
    deploy/docker-test-setup/attacks/intentional-loss.txt.
    """
    txt = open(CONFIG).read()
    m = re.search(r"\n  kernel_filter:\n(.*?)(?=\n  [a-z_]+:\n|\Z)", txt, re.S)
    if not m:
        sys.exit("FATAL: no kernel_filter block in config/config.yaml")
    block = m.group(1)
    if not re.search(r"^\s*enabled:\s*true\s*$", block, re.M):
        sys.exit("FATAL: kernel_filter.enabled is not true — the nr axis "
                 "deadness test below would not apply; re-read the config")
    nrs = {n for n in re.findall(r"^\s*-\s*(\d+)", block, re.M)}
    if len(nrs) < 10:
        sys.exit(f"FATAL: kernel_filter allowlist parsed as {sorted(nrs)} — "
                 "the anchor moved, refusing to emit a table on it")
    return nrs


ALLOWLIST = kernel_syscall_allowlist()


def run_extract(rules_dir, out_json):
    subprocess.run(["go", "run", "./tools/rules-audit", rules_dir, out_json],
                   cwd=REPO, check=True)


def extract_current(tmp):
    cur_path = os.path.join(tmp, "current.json")
    run_extract("rules", cur_path)
    return json.load(open(cur_path))


def extract_snapshot(tmp):
    snap_root = os.path.join(tmp, "snap")
    os.makedirs(snap_root, exist_ok=True)
    tar = subprocess.run(["git", "archive", SNAPSHOT, "rules"], cwd=REPO,
                         check=True, stdout=subprocess.PIPE).stdout
    subprocess.run(["tar", "-x", "-C", snap_root], input=tar, check=True)
    snap_path = os.path.join(tmp, "snap.json")
    run_extract(os.path.join(snap_root, "rules"), snap_path)
    return json.load(open(snap_path))


def z_ids_from_doc(cur, snap):
    """The 292 rule ids named in the Z1-Z4 per-rule tables of the 3.0 doc."""
    txt = open(DOC3).read()
    zsec = {}
    for chunk in re.split(r"\n### ", txt):
        m = re.match(r"(Z[1-4])\b", chunk)
        if not m:
            continue
        ids = [i for i in re.findall(r"`([a-z][a-z0-9_]+)`", chunk)
               if i in cur or i in snap]
        # a section's own artifacts (`noisy`, `silent`) are not rule ids
        ids = list(set(ids))
        zsec[m.group(1)] = sorted(ids)
    return zsec


def roots(rec):
    return [rec[k] for k in ("condition", "conditions", "condition_group") if rec.get(k)]


def leaves(cond):
    out = []
    if cond is None:
        return out
    if isinstance(cond, list):
        for c in cond:
            out += leaves(c)
        return out
    if isinstance(cond, dict):
        if "field" in cond:
            out.append((cond.get("field"), cond.get("op"),
                        tuple(sorted(map(str, cond.get("values") or [])))))
            return out
        for v in cond.values():
            if isinstance(v, (list, dict)):
                out += leaves(v)
    return out


def all_leaves(rec):
    out = []
    for r in roots(rec):
        out += leaves(r)
    return out


def signature(rec, aliasing=True):
    ls = []
    for r in roots(rec):
        ls += leaves(r)
    if aliasing:
        ls = [(ALIAS.get(f, f), o, v) for f, o, v in ls]
    ls.sort()
    return hashlib.sha1(repr((CANON.get(rec.get("event_type"), rec.get("event_type")),
                              tuple(ls))).encode()).hexdigest()[:12]


def fmt_cond(rec):
    """Render the condition tree, honouring its AND/OR operators.

    Flattening every leaf into one AND chain is not a cosmetic shortcut: for
    `(nr=83 AND arg1=511) OR (nr=258 AND arg2=511)` it prints a self-
    contradictory condition (nr both 83 and 258) and a reader auditing the table
    would conclude the rule is structurally dead, the opposite of its verdict.
    """
    def leaf(c):
        vals = [str(x) for x in (c.get("values") or [])]
        shown = ",".join(vals[:4]) + ("…" if len(vals) > 4 else "")
        return f"{c.get('field')} {c.get('op')} [{shown}]"

    def group(g):
        if not isinstance(g, dict):
            return ""
        joiner = " OR " if str(g.get("operator", "and")).lower() == "or" else " AND "
        parts = [leaf(c) for c in (g.get("conditions") or []) if isinstance(c, dict)]
        for sub in (g.get("subgroups") or []):
            inner = group(sub)
            if inner:
                parts.append(f"({inner})")
        return joiner.join(p for p in parts if p)

    out = []
    for r in roots(rec):
        if isinstance(r, dict) and "field" in r:
            out.append(leaf(r))
        elif isinstance(r, list):
            out += [leaf(c) for c in r if isinstance(c, dict) and "field" in c]
        else:
            g = group(r)
            if g:
                out.append(g)
    return " AND ".join(out)


def nr_vals(rec):
    """Sorted distinct syscall numbers on the `nr` axis (alias-normalised)."""
    def key(x):
        return (0, int(x)) if str(x).isdigit() else (1, str(x))
    return [v for v in sorted({str(x) for f, o, v in all_leaves(rec)
                               if ALIAS.get(f, f) == "nr" for x in v}, key=key)]


def main():
    tmp = tempfile.mkdtemp(prefix="rules-audit-")
    cur = extract_current(tmp)
    snap = extract_snapshot(tmp)
    zsec = z_ids_from_doc(cur, snap)

    total = sum(len(v) for v in zsec.values())
    if total != 292:
        sys.exit(f"FATAL: doc yielded {total} Z ids, expected 292: "
                 f"{ {k: len(v) for k, v in zsec.items()} }")
    seen = set()
    for sec, ids in zsec.items():
        if seen & set(ids):
            sys.exit(f"FATAL: id appears in more than one Z section: {seen & set(ids)}")
        seen |= set(ids)
    z_of = {rid: sec for sec, ids in zsec.items() for rid in ids}

    rows3 = {r["rule_id"]: r for r in csv.DictReader(open(CSV3))}
    for rid in z_of:
        st = rows3.get(rid, {}).get("status")
        if st != "silent":
            sys.exit(f"FATAL: {rid} is {st!r} in 3.0 csv, expected silent")

    # duplicate detection over the whole current catalog
    bysig = collections.defaultdict(list)
    for rid, rec in cur.items():
        bysig[signature(rec)].append(rid)
    twins = {rid: [x for x in bysig[signature(cur[rid])] if x != rid]
             for rid in z_of}

    # The live input axis, keyed by the rule's CURRENT event type rather than by
    # its 3.0 Z section: waves 5-6 moved evasion_chmod_sensitive and
    # sigma_chmod_executable_tmp from syscall to file, so a Z-keyed string
    # described the syscall axis for a rule that is now a file rule.
    AXIS = {
        "syscall": "syscall nr (within the in-kernel allowlist)/arg/ret/comm/"
                   "parent_comm, plus proc.args on execve/execveat",
        "tcp_connect": "tcp_connect dport/daddr/sport/saddr/family",
        "net_close": "net_close duration_sec/dport",
        "file": "file filename/op/comm/directory/extension",
    }

    out_rows = []
    for rid in sorted(z_of):
        c, s = cur[rid], snap[rid]
        lv = [(ALIAS.get(f, f), o, list(v)) for f, o, v in all_leaves(c)]
        changed = signature(c) != signature(s)
        etype3 = rows3[rid]["event_type"]
        etype7 = CANON.get(c["event_type"], c["event_type"])

        # --- structural check: wholly-dead field value sets (op / proto / nr) ---
        # Only leaves that NAME required values can be unsatisfiable, and only on
        # the axis belonging to this rule's own event type — `op` means one thing
        # on a file event and another on a gpu event (gpuOpNames), so the test is
        # keyed by etype7 rather than applied to every rule that spells "op".
        def _sets(fname, numeric_only=False):
            out = []
            for ff, o, v in lv:
                if ff != fname or str(o).lower() not in LITERAL_OPS:
                    continue
                vals = {str(x).lower() for x in v}
                if numeric_only:
                    vals = {x for x in vals if x.lstrip("-").isdigit()}
                    if not vals:
                        continue  # a string-valued nr has nothing to intersect
                out.append(vals)
            return out

        is_file = etype7 in ("file", "file_access")
        is_net = etype7 in ("network", "tcp_connect")
        LIVE = {
            "op": (FILE_OPS if is_file else None),
            # bpf/network.bpf.c hardcodes IPPROTO_TCP (6) on every tcp_connect
            # event (lines 124,136,226,241) — no UDP/ICMP/GRE event type exists.
            "proto": ({"6"} if is_net else None),
            # the in-kernel syscall allowlist, see kernel_syscall_allowlist()
            "nr": (ALLOWLIST if etype7 == "syscall" else None),
        }
        dead_field, dead_tokens = None, []
        for fname in ("op", "proto", "nr"):
            live = LIVE[fname]
            if not live:
                continue
            fsets = _sets(fname, numeric_only=(fname == "nr"))
            if not fsets:
                continue
            if not any(v & live for v in fsets):
                dead_field = fname
                dead_tokens = sorted(set().union(*fsets) - live,
                                     key=lambda x: (0, int(x)) if x.isdigit() else (1, x))
                break
        dead = dead_field is not None
        loose_tokens = sorted(
            {t for v in _sets("op") for t in v} - FILE_OPS
        ) if is_file else []

        # --- reason / decision ---
        dup = sorted(x for x in twins.get(rid, []) if x in cur)
        if dead:
            reason = "condition-truly-doesnt-match"
            status = "structurally-dead"
            if dead_field == "op":
                why = ("collector emits only open|read|write|chmod "
                       "(bpf/common.h FILE_OP_*, internal/collector/fileaccess.go)")
            elif dead_field == "proto":
                why = ("every tcp_connect event is emitted with proto=6 "
                       "(IPPROTO_TCP) (bpf/network.bpf.c:124,136,226,241); no "
                       "UDP/ICMP/GRE event type is produced")
            else:
                why = ("the in-kernel syscall filter forwards only the "
                       f"{len(ALLOWLIST)} numbers of config/config.yaml "
                       "kernel_filter.monitored_syscalls (bpf/syscall.bpf.c:52, "
                       "syscall_is_monitored); no attack scenario can produce an "
                       "event for a number outside it")
            detail = (f"unsatisfiable `{dead_field}` condition: {why}; "
                      f"condition requires {dead_tokens}")
            # РАЗБОР ПО ОСЯМ (волна 7, item б1, 28.09.2026). До этой правки все
            # три оси несли один `fix-condition`, и это склеивало ДВЕ РАЗНЫЕ
            # работы. Ось `nr` действительно открывается ПРАВКОЙ КОНФИГА
            # (kernel_filter.monitored_syscalls) и стоит измеримого шума — там
            # правка условия есть настоящий долг. Оси `op` и `proto` не
            # открываются ничем: продюсера нет, и «починка условия» для них
            # означает заменить предмет детекта (правило об ICMP-туннеле,
            # перекеенное на proto=6, ловит не ICMP-туннель). Такая немота —
            # КЛАСС, и печатает его агент: UnreachableFileOpRules (ось op),
            # UnreachableProtoRules (ось proto).
            decision = ("fix-condition" if dead_field == "nr"
                        else "document-as-structurally-inert")
        elif rid in ("cis_5_2_1_privileged_container", "cis_5_2_5_privilege_escalation"):
            reason = "condition-truly-doesnt-match"
            status = "condition-changed-since-3.0"
            was, now = nr_vals(s), nr_vals(c)
            if was == now:
                sys.exit(f"FATAL: {rid} nr unchanged ({was}) — wrong-nr label is stale")
            detail = (f"3.0 keyed nr={was}; waves 5-6 corrected it to nr={now} — "
                      "the 3.0 silence was a wrong syscall number, now fixed")
            decision = "verify-after-fix"
        else:
            reason = "no-input-data"
            status = "condition-changed-since-3.0" if changed else "silent-no-input"
            axis = lv[0][0] if lv else "?"
            if etype7 not in AXIS:
                sys.exit(f"FATAL: {rid} has event_type {etype7!r} with no recorded "
                         "live axis — add it rather than printing a wrong axis")
            detail = (f"condition is satisfiable on the live `{axis}` axis "
                      f"({AXIS[etype7]}), but no event in the four audited runs "
                      "carried a matching value")
            decision = "merge-with-duplicate" if dup else "document-as-needing-environment"

        if changed and reason == "no-input-data":
            detail += "; condition CHANGED in waves 5-6 (3.0 verdict stale — re-measure on stand)"
        if loose_tokens and not dead:
            detail += f"; carries non-emitted op token(s) {loose_tokens} alongside a live op"

        evidence = f"rules/{c['file']}:{c['line']}"
        if dup:
            evidence += " ; twins: " + ", ".join(
                f"{t} rules/{cur[t]['file']}:{cur[t]['line']} (3.0 {rows3.get(t, {}).get('status', 'new')})"
                for t in dup)

        out_rows.append({
            "rule_id": rid,
            "z_section": z_of[rid],
            "status_3_0": "silent",
            "event_type_3_0": etype3,
            "event_type_rev7": etype7,
            "current_ref": f"{c['file']}:{c['line']}",
            "status_rev7": status,
            "changed_since_3_0": "yes" if changed else "no",
            "reason_rev7": reason,
            "reason_detail": detail,
            # Machine-readable twins of what reason_detail states in prose. The
            # summary sections below count these columns; re-parsing the prose
            # with a regex made a published count depend on wording.
            "dead_axis": dead_field or "",
            "dead_tokens": ",".join(dead_tokens),
            "loose_op_tokens": ",".join(loose_tokens),
            "decision": decision,
            "duplicate_of": ",".join(dup),
            "condition_rev7": fmt_cond(c),
            "evidence": evidence,
            "requester_wave": "7/item1",
        })

    if {r["rule_id"] for r in out_rows} != set(z_of):
        sys.exit(f"FATAL: row set != Z1-Z4 id set "
                 f"(missing {sorted(set(z_of) - {r['rule_id'] for r in out_rows})}, "
                 f"extra {sorted({r['rule_id'] for r in out_rows} - set(z_of))})")

    write_csv(out_rows)
    write_md(out_rows, zsec, cur, snap)
    print(f"wrote {OUT_CSV}")
    print(f"wrote {OUT_MD}")


def write_csv(rows):
    cols = list(rows[0].keys())
    with open(OUT_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)


def write_md(rows, zsec, cur, snap):
    total = len(rows)
    by_reason = collections.Counter(r["reason_rev7"] for r in rows)
    by_status = collections.Counter(r["status_rev7"] for r in rows)
    by_decision = collections.Counter(r["decision"] for r in rows)
    changed = [r for r in rows if r["changed_since_3_0"] == "yes"]
    dups = [r for r in rows if r["duplicate_of"]]
    unsat = [r for r in rows if r["reason_rev7"] == "condition-truly-doesnt-match"]
    dead = [r for r in unsat if r["status_rev7"] == "structurally-dead"]
    create_rules = [r for r in rows if "create" in r["loose_op_tokens"].split(",")]
    by_axis = collections.Counter(r["dead_axis"] for r in rows if r["dead_axis"])
    exc_rules = [r for r in rows
                 if r["changed_since_3_0"] == "no"
                 and cur[r["rule_id"]].get("exceptions")
                 and not snap[r["rule_id"]].get("exceptions")]
    # cis wrong-nr transitions, computed from the YAML on both sides rather than
    # re-parsed out of this script's own prose
    cis = {r["rule_id"]: (nr_vals(snap[r["rule_id"]]), nr_vals(cur[r["rule_id"]]))
           for r in rows if r["decision"] == "verify-after-fix"}

    L = []
    A = L.append
    A("# Rule Set Revision 7.0 — the 292 `condition-not-matched` rules, re-annotated (2026-09-27)")
    A("")
    A("> Wave 7, item 1 (plan.md). Pure YAML analysis: **no rule, no Go, no BPF changed**. "
      "Re-annotates the Z1–Z4 (`silent / condition-not-matched`) set of "
      "[revision 3.0](rules-audit-2026-08-06.md) after waves 5–6, and turns the one-shot "
      "snapshot into a regenerable table.")
    A("")
    A("## 1. Method and reproducibility")
    A("")
    A("The table is **generated**, not edited. One command from the repo root:")
    A("")
    A("```bash")
    A("python3 tools/rules-audit/classify.py")
    A("```")
    A("")
    A("It (1) runs `go run ./tools/rules-audit <dir> <out.json>` — a plain YAML reader that "
      "records each rule's `id:` line — over the **current working tree** `rules/` and over the "
      "3.0 measurement snapshot `git archive 3a3006a rules`; (2) reads the 292 ids out of the "
      "Z1–Z4 per-rule tables of `docs/rules-audit-2026-08-06.md`; (3) joins them, computes the "
      "reason/decision below, and writes `docs/rules-audit-2026-09-27.csv` + this file. "
      "The script asserts the Z-set is exactly 292 ids, that no id appears in two Z sections, "
      "and that the emitted row set equals the Z-set, or it exits non-zero.")
    A("")
    A("Inputs, all in-tree: `docs/rules-audit-2026-08-06.md` (the Z1–Z4 lists), "
      "`docs/rules-audit-2026-08-06.csv` (the 3.0 statuses), `rules/*.yaml` at HEAD and at "
      f"`{SNAPSHOT}`, and `config/config.yaml` for the in-kernel syscall allowlist (§3) — the "
      "script exits non-zero if `kernel_filter.enabled` is not `true` or the allowlist anchor "
      "moved, rather than emitting a table against a filter it did not read. "
      "Line citations are `file:line` of the current YAML. The 3.0 "
      "measurement itself (four attack runs, 2026-08-06) is **not re-run** — item 1 is "
      "analysis of YAML and collector contracts only.")
    A("")
    A("**Reason vocabulary**")
    A("")
    A("- `condition-truly-doesnt-match` — the condition did not match for a reason that lies in "
      "the condition itself, not in the environment. Two sub-cases, kept apart by `status_rev7`: "
      "`structurally-dead` — unsatisfiable against what the collectors emit or what the kernel "
      "forwards (a dead axis / an impossible token), no environment can ever satisfy it; and "
      "`condition-changed-since-3.0` with decision `verify-after-fix` — the 3.0 condition named "
      "the wrong syscall number, which was satisfiable in principle but never the thing the rule "
      "meant, and waves 5–6 already replaced it.")
    A("- `no-input-data` — the condition is satisfiable on a live axis, but the four audited "
      "runs produced no matching event/value (scenario or environment absent).")
    A("- `duplicates-other-rule` — recorded in the `duplicate_of` column: another rule in the "
      "catalog carries an identical normalised condition.")
    A("")
    A("**Decision vocabulary** (from plan.md item 1): `fix-condition` / "
      "`document-as-needing-environment` / `merge-with-duplicate`, plus `verify-after-fix` for "
      "a 3.0 condition that waves 5–6 proved wrong, plus "
      "`document-as-structurally-inert` (wave 7 item б1) for a condition standing on an axis "
      "**no producer feeds at all** — neither a config change nor another environment turns it "
      "on, so there is nothing for `fix-condition` to fix and nothing for "
      "`document-as-needing-environment` to wait for. **No rule is deleted or edited by item 1.**")
    A("")
    A("## 2. Headline")
    A("")
    A(f"- Rules re-annotated: **{total}** (Z1 {len(zsec['Z1'])} + Z2 {len(zsec['Z2'])} + "
      f"Z3 {len(zsec['Z3'])} + Z4 {len(zsec['Z4'])}), set-equal to the 3.0 Z sections.")
    A(f"- `condition-truly-doesnt-match`: **{by_reason['condition-truly-doesnt-match']}** "
      f"({by_status['structurally-dead']} structurally dead — "
      + " + ".join(f"{n} on `{ax}`" for ax, n in sorted(by_axis.items()))
      + f" — plus {len(cis)} wrong-nr, the latter now fixed).")
    A(f"- `no-input-data`: **{by_reason['no-input-data']}** (well-formed, no matching input in "
      "the audited runs).")
    A(f"- Rules redundant with an identical-condition twin: **{len(dups)}**.")
    A(f"- Rules whose condition **changed in waves 5–6** (3.0 verdict stale): **{len(changed)}** "
      "— listed in §5.")
    A(f"- Rules left with reason “unknown why silent”: **0**.")
    A("")
    A("Note on scope: the 292 is the **3.0-defined** set (Z1–Z4). This revision proves that "
      "set is complete and self-consistent; it does **not** re-run the stand, so for the 29 "
      "rules whose condition changed in waves 5–6 the 3.0 measurement is explicitly marked "
      "stale rather than silently reused.")
    A("")
    A("| status_rev7 | count |")
    A("|---|---:|")
    for s, n in by_status.most_common():
        A(f"| `{s}` | {n} |")
    A("")
    A("The point of the revision: the 3.0 bucket “292 silent, condition never matched, reason "
      "= REVIEW” is gone. Every one of the 292 now carries a reason grounded in the current "
      "YAML and the collector contract, and the “unknown” count is zero.")
    A("")
    A("## 3. Conditions that do not match for their own sake (`condition-truly-doesnt-match`)")
    A("")
    A(f"{by_status['structurally-dead']} rows are `structurally-dead`: no environment can satisfy them. "
      f"The remaining {len(cis)} are the wrong-syscall-number rules waves 5–6 already corrected — "
      "listed here because the 3.0 silence was the condition's fault, not the environment's, but "
      "they are **not** structurally dead and carry `verify-after-fix`, not `fix-condition`.")
    A("")
    A("| rule | ref | required dead token(s) | why it does not match | decision |")
    A("|---|---|---|---|---|")
    WHY = {
        "proto": "collector emits only proto=6 (IPPROTO_TCP) — `bpf/network.bpf.c:124,136,226,241`",
        # no raw "|" here: this string lands in a markdown table cell
        "op": "collector emits only open/read/write/chmod — `bpf/common.h` FILE_OP_*",
        "nr": "syscall number outside the in-kernel allowlist — `bpf/syscall.bpf.c:52`",
    }
    for r in unsat:
        field = r["dead_axis"]
        toks = f"[{r['dead_tokens']}]" if r["dead_tokens"] else "—"
        why = (WHY[field] if field
               else "syscall number was wrong in 3.0; corrected in waves 5–6")
        A(f"| `{r['rule_id']}` | `{r['current_ref']}` | `{toks}` | {why} | {r['decision']} |")
    A("")
    A(f"Three dead axes occur in this set. **`op`** ({by_axis['op']} rules): every file event is emitted with "
      "`op ∈ {open, read, write, chmod}` (`bpf/common.h` `FILE_OP_OPEN/READ/WRITE/CHMOD`, "
      "rendered by `fileOpNames` in `internal/correlator/rules.go`; hooks in "
      "`internal/collector/fileaccess.go`). A rule that ANDs an `op` condition whose whole value "
      "set lies outside that set can never fire — the same limitation the repo already records "
      "for `sigma_log_deletion` (`rules/sigma-linux.yaml:385-388`, находка №234). The same defect "
      "also affects `ransomware_log_wipe` (`rules/ransomware.yaml:133`), which is outside the "
      "292 and so outside this table.")
    A("")
    A(f"**`proto`** ({by_axis['proto']} rules): `bpf/network.bpf.c` hardcodes `IPPROTO_TCP` (`6`) on every "
      "tcp_connect event (lines 124, 136, 226, 241) and no UDP/ICMP/GRE event type exists, so "
      "`proto` is only ever the string `\"6\"`; any `proto` condition whose values lie outside "
      "`{6}` (here ICMP/GRE/HOPOPT/ESP/AH/IPv6/…) is unsatisfiable.")
    A("")
    A(f"**`nr`** ({by_axis['nr']} rules): the `nr` axis is **not** unconditionally live. "
      "`bpf/syscall.bpf.c:52` drops the event before the ring buffer unless "
      "`syscall_is_monitored()` finds the number in `syscall_filter_map`, which is programmed "
      f"from `cfg.BPF.KernelFilter.MonitoredSyscalls` — {len(ALLOWLIST)} numbers in "
      "`config/config.yaml`, with `kernel_filter.enabled: true`. A rule whose whole numeric "
      "`nr` set lies outside that list can never receive an event, exactly like the `proto` "
      "rules above, and no attack scenario can change that. `ReferencedSyscalls()` could widen "
      "the list from the rules themselves, but `SetSyscallFilterUpdater` is not registered in "
      "`cmd/ebpf-guard/main.go`, so the configured list is what runs. The shorter "
      "`DefaultMonitoredSyscalls()` (19 numbers) used by the stand's `config-test.yaml` is a "
      "strict subset, so every rule counted here is dead under either resolution.")
    A("")
    A("This axis was missed by the first cut of revision 7.0, which asserted `nr` was live, and "
      "it was also under-reported by the product's own startup audit: "
      "`UnreachableSyscallRules` tested `cond.Field != \"nr\"` literally, so the "
      f"{by_axis['nr']} rules below — every one written with the dotted `syscall.nr` alias that "
      "`normaliseFieldName` resolves — were invisible to it, as was the short `eq` operator. "
      "Both aliases are now normalised through `namesLiteralValues`, and the product's count "
      "rose from 9 to 17 catalog-wide. That is not new lost detection: these rules have been "
      "mute since they were written. The eight outside the 292 are recorded in "
      "`deploy/docker-test-setup/attacks/intentional-loss.txt`.")
    A("")
    A(f"For all {by_status['structurally-dead']} the condition itself is the defect, and none of them is "
      "`document-as-needing-environment`, because the missing input can never exist. But they "
      "split into **two different kinds of work**, and wave 7 item б1 separates them instead of "
      "issuing one decision for all three axes:")
    A("")
    A(f"- **`fix-condition` — the {by_axis['nr']} `nr`-dead rules only.** This axis really does open: "
      "the numbers are absent from `kernel_filter.monitored_syscalls`, and adding them is a "
      "config change with a *measurable* price in noise (among the 19 required numbers are the "
      "hot `nanosleep(35)`, `mprotect(10)`, `prctl(157)`, `clone(56)`, `fork(57)`). The price "
      "is assigned by measurement (bpftrace on the stand) and the numbers are opened in "
      "portions, cheapest first, each portion as an A/B pair — not applied wholesale here.")
    A(f"- **`document-as-structurally-inert` — the {by_axis['op']} `op`-dead and {by_axis['proto']} `proto`-dead rules.** "
      "These have **no producer at all**: `fileaccess.bpf.c` hooks openat/read/write/chmod and "
      "`network.bpf.c` emits `IPPROTO_TCP` and nothing else. No toggle, no allowlist, no kernel "
      "version turns them on, so a condition rewrite would not fix them — it would replace the "
      "subject (an ICMP-tunnel rule re-keyed to `proto=6` is a TCP rule that still does not "
      "detect ICMP tunnels; narrowing `op` to `write` makes rules watching whole directories "
      "fire on every ordinary write). Their muteness is therefore recorded as a **class, "
      "printed by the agent at every startup** — `UnreachableFileOpRules()` for the `op` axis "
      "and `UnreachableProtoRules()` for the `proto` axis, alongside "
      "`UnreachableSyscallRules()` and `UnproducibleEventTypeRules()` — rather than as prose "
      "here. Opening them needs a new BPF hook, an owner decision with its own measured noise "
      "price.")
    A("")
    A("**No condition is edited and no rule is deleted by this item.**")
    A("")
    A(f"Budget check on the 3.0 → rev 7 boundary: the {by_axis['op']} `op`-dead rules are `file` rules, "
      f"the {by_axis['proto']} `proto`-dead rules are `tcp_connect`/Z2 rules and the {by_axis['nr']} `nr`-dead rules are "
      f"`syscall`/Z1 rules; the other {by_reason['no-input-data']} keep `no-input-data`. "
      "Rules that carry an unemitted token *alongside* a live one (e.g. `create` with `write`; "
      f"see §5b) are **not** counted here, and neither are the {len(cis)} `verify-after-fix` rules whose "
      "dead condition was already replaced.")
    A("")
    A("## 3b. Why the rest are `no-input-data` — the input axis per event type")
    A("")
    A("3.0 established the fact of silence (four runs, attacker comms `curl`/`sqlmap`/"
      "`docker-proxy`); rev 7.0 supplies the *axis* the missing input had to arrive on. The axes "
      "below are live in the current collectors — so a rule that stayed silent is "
      "satisfiable-but-untested, not structurally dead (the rules lifted to §3 are the "
      "exception). Keyed by the rule's CURRENT event type: waves 5–6 moved two Z1 rules onto "
      "`file`, so a Z-keyed axis would describe the wrong collector for them.")
    A("")
    A("| event_type | live input axis | evidence in code |")
    A("|---|---|---|")
    A("| syscall | `nr` **restricted to the in-kernel allowlist** (§3), plus "
      "`arg0..5`/`ret`/`comm`/`parent_comm`, and `proc.args` on execve/execveat only | "
      "`bpf/syscall.bpf.c:42-99`, `internal/collector/syscall.go:334-361` |")
    A("| tcp_connect | `dport`/`daddr`/`sport`/`saddr`/`family` (`proto` is "
      "always `6` — those rules are dead, §3) | "
      "`bpf/network.bpf.c:124-140`, `internal/correlator/rules.go:1573-1588` |")
    A("| net_close | `duration_sec` + `dport` | `internal/correlator/rules.go:1846-1858` |")
    A("| file | `filename`/`op`/`comm`/`directory`/`extension` (all four ops populate the path) | "
      "`bpf/fileaccess.bpf.c`, `internal/correlator/rules.go:1628-1660` |")
    A("")
    A("A caveat this revision records rather than resolves: a `syscall` rule that constrains no "
      "`nr` at all (e.g. only `comm`/`parent_comm`) receives events only for the syscalls some "
      "*other* rule named or the baseline list carries — `ReferencedSyscalls()` documents the "
      "trade-off, and `ContextEmptySyscallRules` names the shape. Such a rule is satisfiable, so "
      "it stays `no-input-data`, but its input is narrower than its condition suggests.")
    A("")
    A("The three 3.0 sections with a genuine **missing scenario**, stated as such: Z1 rules key on "
      "argv/syscall patterns the suite never executed (e.g. `pip install --index-url`, `env … sh`); "
      "Z2/Z3 rules key on ports/hosts/durations the suite never produced (no connection to "
      "`1080`/`4444`/metadata IPs, no session long enough to pass `duration_sec > 300…259200`); "
      "Z4 rules key on paths the suite never wrote (`/etc/sudoers.d/`, cron units, PAM config).")
    A("")
    A("## 4. Redundant rules (`duplicate_of`)")
    A("")
    if dups:
        A("| rule | ref | identical-condition twin(s) | decision |")
        A("|---|---|---|---|")
        for r in dups:
            A(f"| `{r['rule_id']}` | `{r['current_ref']}` | `{r['duplicate_of']}` | {r['decision']} |")
        A("")
    A("Both sides of every twin pair were `silent` in 3.0 as well, so duplication does **not** "
      "explain the silence — it is recorded as a redundancy decision, and the silence of each "
      "member is still annotated as `no-input-data`. Merging is a catalog change and is left to "
      "the owner decision (plan item 8); nothing is deleted here. The `reason_rev7` column is "
      "therefore never `duplicates-other-rule`: **no rule in the 292 duplicates a rule that "
      "actually fires**, which is what would make duplication a cause of silence rather than a "
      "maintenance note.")
    A("")
    A("## 5. Conditions changed in waves 5–6 (3.0 verdict stale)")
    A("")
    A("| rule | ref | 3.0 → rev 7 event_type | decision |")
    A("|---|---|---|---|")
    for r in changed:
        e3 = r["event_type_3_0"]
        e7 = r["event_type_rev7"]
        arrow = e3 if e3 == e7 else f"{e3} → {e7}"
        A(f"| `{r['rule_id']}` | `{r['current_ref']}` | {arrow} | {r['decision']} |")
    A("")
    A("These 3.0-silent rules no longer have the condition the 3.0 run measured, so the 3.0 "
      "verdict cannot be carried forward. Two were corrected for a **wrong syscall number**: "
      f"`cis_5_2_1_privileged_container` nr `{cis['cis_5_2_1_privileged_container'][0]}`→"
      f"`{cis['cis_5_2_1_privileged_container'][1]}` (setrlimit→unshare) and "
      f"`cis_5_2_5_privilege_escalation` nr `{cis['cis_5_2_5_privilege_escalation'][0]}`→"
      f"`{cis['cis_5_2_5_privilege_escalation'][1]}` (drops rename, adds setgid). "
      "`evasion_chmod_sensitive` and `sigma_chmod_executable_tmp` were restructured "
      f"syscall→file. The remaining {len(changed) - len(cis) - 2} were narrowed — their leaf set "
      "differs, which is what `changed_since_3_0` measures. A rule that gained ONLY an "
      "`exceptions:` block is deliberately **not** in this set: `exceptions` can only suppress, "
      "never create a match, so it cannot have un-silenced a rule — see §5c.")
    A("")
    A("## 5b. Systemic note — the `create` op token")
    A("")
    A(f"**{len(create_rules)}** rules in the 292 carry `create` among their `file.op` values. The "
      "collector never emits `create` (creation appears as `open`), so the token is dead weight; "
      "every one of these rules also lists `write`, which is why none is `structurally-dead`. "
      "They are recorded, not edited: the fix would be `create → open` (part of each rule's "
      "`fix-condition` debt), a detection-design change that needs the stand to verify.")
    A("")
    A("## 5c. Systemic note — the `exceptions` axis")
    A("")
    A(f"**{len(exc_rules)}** of the 292 differ from 3.0 by an added `exceptions:` "
      "block. `exceptions` can only suppress a match, never create one, so such a rule cannot "
      "have been un-silenced by the change and stays `silent-no-input`; that is why they are "
      "excluded from the 29-rule stale-verdict set. Lesson for future revisions: a "
      "condition-hash comparison that ignores `exceptions` mislabels these as unchanged.")
    A("")
    A("## 6. Full table (292 rows)")
    A("")
    A("Grouped by reason, then by Z-section. Machine-readable twin: "
      "[`rules-audit-2026-09-27.csv`](rules-audit-2026-09-27.csv).")
    A("")
    for reason in ("condition-truly-doesnt-match", "no-input-data"):
        grp = [r for r in rows if r["reason_rev7"] == reason]
        A(f"### 6.{1 if reason == 'condition-truly-doesnt-match' else 2} `{reason}` ({len(grp)})")
        A("")
        A("| rule | Z | event_type | current ref | changed | status | decision | condition (current YAML) |")
        A("|---|---|---|---|---|---|---|---|")
        for r in sorted(grp, key=lambda r: (r["z_section"], r["rule_id"])):
            cond = r["condition_rev7"].replace("|", "\\|")
            if len(cond) > 160:
                cond = cond[:157] + "…"
            A(f"| `{r['rule_id']}` | {r['z_section']} | {r['event_type_rev7']} | "
              f"`{r['current_ref']}` | {r['changed_since_3_0']} | {r['status_rev7']} | "
              f"{r['decision']} | {cond} |")
        A("")
    A("## 7. Decision counts")
    A("")
    A("| decision | count |")
    A("|---|---:|")
    for d, n in by_decision.most_common():
        A(f"| {d} | {n} |")
    A("")
    A(f"`fix-condition` = {by_decision['fix-condition']}: the {by_axis['nr']} `nr`-dead rules, and only "
      "them — the axis opens with a config change whose price in noise is measurable, so the "
      "debt is real. Opening is done in portions, cheapest syscall first, each portion judged "
      "by an A/B pair; the hot numbers (`nanosleep`, `mprotect`, `prctl`, `clone`, `fork`) go "
      "last and only if their measured price passes. "
      f"`document-as-structurally-inert` = {by_decision['document-as-structurally-inert']}: "
      + " + ".join(f"{n} `{ax}`-dead" for ax, n in sorted(by_axis.items()) if ax != "nr")
      + " rules, whose axis has no producer at all — no condition edit can fix that, and their "
      "muteness is printed by the agent itself (`UnreachableFileOpRules`, "
      f"`UnreachableProtoRules`). `verify-after-fix` = {len(cis)}: already corrected by waves 5–6, "
      "needs a stand re-measure. The `document-as-needing-environment` bucket is the actionable "
      "backlog for a stand run (scenario per family), not a claim that those rules are wrong. "
      "**No rule was deleted, renamed or re-conditioned by this item.**")
    A("")
    open(OUT_MD, "w").write("\n".join(L) + "\n")


if __name__ == "__main__":
    main()
