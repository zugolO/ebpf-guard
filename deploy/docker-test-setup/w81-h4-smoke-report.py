#!/usr/bin/env python3
"""Отчёт смока w81-h4-smoke.sh (долги 8.1, 09.10.2026): M (man-db), V
(systemd-detect-virt), A (apt-daily), P (положительные контроли).

Usage: w81-h4-smoke-report.py <OUT dir fetched from the stand>

Каждая фаза: исполнилось ли событие (по свидетелю bpftrace и юниту, не по
метке фазы); цена E − C по трём слоям и по правилам; алерты дерева события по
(правило, образ, comm, объект) — образ берётся из execve свидетеля по pid;
подавления по всем исключениям окна E; инциденты дерева по вердикту.
Вердикты — по содержимому окна."""
import importlib.util
import json
import os
import re
import sys

_here = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location('w549smoke', os.path.join(_here, 'w549-smoke-report.py'))
_s = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_s)
load, per_rule, alerts, ts, LAYERS = _s.load, _s.per_rule, _s.alerts, _s.ts, _s.LAYERS
layers, rd, root_comm, incidents_in, print_incidents = _s.layers, _s.rd, _s.root_comm, _s.incidents_in, _s.print_incidents

FAIL = []
MAN_TREE = re.compile(r'^\(?(mandb|man-db|man|nroff|groff|gzip|zcat|gunzip|bzip2|xz|zsoelim|preconv|tbl|grotty|troff|sh|dash|find|cat|ls|sort|rm|cp|mv|touch|stat|dpkg|mandb\.real|systemctl|systemd)\)?$')
VIRT_TREE = re.compile(r'^\(?systemd-detect-?(virt)?\)?$')
APT_TREE = _s.APT_TREE


def exc_all(m0, m1):
    out = {}
    for (n, l), v in m1.items():
        if n != 'ebpf_guard_rule_exceptions_total':
            continue
        dl = dict(l)
        d = int(v - m0.get((n, l), 0.0))
        if d:
            out[(dl.get('exception_name'), dl.get('rule_id'))] = d
    return out


def witness(d):
    """pid → последний execve-образ; открытия (pid, comm, flags, path)."""
    exe, opens = {}, []
    for l in rd(d, 'bpf.txt').splitlines():
        if l.startswith('X '):
            p = l.split(None, 3)
            if len(p) == 4:
                exe[p[1]] = p[3]
        elif l.startswith('O '):
            p = l.split(None, 4)
            if len(p) == 5:
                opens.append((p[1], p[2], int(p[3]) if p[3].lstrip('-').isdigit() else 0, p[4]))
    return exe, opens


def norm(p):
    p = re.sub(r'\.[A-Za-z0-9]{6,}', '.XXXXXX', p)
    return re.sub(r'/\d+(/|$)', r'/N\1', p)


def common(d, label, tree_re, extra_unit=None):
    tE0, tE1 = int(rd(d, 'tE0')), int(rd(d, 'tE1'))
    if os.path.exists(os.path.join(d, 'skipped')):
        FAIL.append(f'{label}: {rd(d, "skipped")}')
        print('  ПРОПУЩЕНА: ' + rd(d, 'skipped'))
        return None
    print('  команда события: ' + rd(d, 'command'))
    print('  ' + rd(d, 'force-unit.txt').replace('\n', '\n  '))
    exe, opens = witness(d)
    rows, (c0, c1, e0, e1) = layers(d, 'mC0.txt', 'mC1.txt', 'mE0.txt', 'mE1.txt')
    tot = {layer: sum(v.get(layer, 0) for v in rows.values()) for layer, _ in LAYERS}
    print(f'  E − C по трём слоям: выпущено {tot["emitted"]} / дедуп {tot["dedup"]} / лимитер {tot["limiter"]}')
    price = {r: sum(v.values()) for r, v in rows.items()}
    for r in sorted(price, key=lambda r: -price[r])[:14]:
        if price[r] <= 0:
            continue
        v = rows[r]
        print(f'    {price[r]:+7d}  {v.get("emitted", 0):+6d}/{v.get("dedup", 0):+6d}/{v.get("limiter", 0):+6d}  {r}')
    exc = exc_all(e0, e1)
    print('  подавлено исключениями в E (имя, правило): ' + (', '.join(f'{n}/{r}={v}' for (n, r), v in sorted(exc.items())) or 'ничего'))
    al = [a for a in alerts(os.path.join(d, 'alerts-CE.json')) if tE0 <= ts(a['timestamp']) <= tE1 + 1]
    tree = []
    for a in al:
        chain = [x.get('comm', '') for x in (a.get('process_tree') or [])]
        if tree_re.match(a.get('comm') or '') or any(tree_re.match(c or '') for c in chain[:3]):
            tree.append(a)
    print(f'  алертов в сторе окна E: {len(al)}, в дереве события: {len(tree)}')
    rec = {}
    for a in tree:
        det = a.get('details') or {}
        path = det.get('file.path') or det.get('filename') or ''
        k = (a['rule_id'], exe.get(str(a.get('pid')), '?'), a.get('comm'), norm(path))
        rec[k] = rec.get(k, 0) + 1
    print('  дерево: правило | образ (execve свидетеля) | comm | объект → число')
    for (r, x, c, p), n in sorted(rec.items(), key=lambda kv: (kv[0][0], -kv[1])):
        print(f'    {n:4d}  {r:36s} {x:42s} {c:14s} {p}')
    return dict(tE0=tE0, tE1=tE1, rows=rows, exc=exc, tree=tree, exe=exe, opens=opens, al=al, e0=e0, e1=e1)


def phase_m(d):
    print('\n=== M: man-db.service форсированно ===')
    r = common(d, 'M', MAN_TREE)
    if not r:
        return
    mandb = [p for p, x in r['exe'].items() if x.endswith('/mandb')]
    unit = rd(d, 'force-unit.txt')
    executed = bool(mandb)
    print(f'  событие исполнилось: {"ДА" if executed else "НЕТ"} (execve /usr/bin/mandb у свидетеля: pid {mandb[:3]})')
    if not executed:
        FAIL.append('M: mandb не исполнился')
    # открытия образом mandb: режим и пути (свидетель)
    mset = set(mandb)
    acc = {}
    for pid, comm, fl, path in r['opens']:
        if pid not in mset:
            continue
        mode = 'W' if fl & 3 else 'R'
        k = (mode, norm(os.path.dirname(path) or path) if mode == 'R' else norm(path))
        acc[k] = acc.get(k, 0) + 1
    print('  открытия образом mandb (свидетель): режим | каталог (R) или файл (W) → число')
    for (mode, p), n in sorted(acc.items(), key=lambda kv: (kv[0][0] != 'W', -kv[1]))[:40]:
        print(f'    {n:6d}  {mode}  {p}')
    own = print_incidents(incidents_in(d, r['tE0'], r['tE1']), MAN_TREE, 'man-db')
    return r


def phase_v(d):
    print('\n=== V: systemd-detect-virt (настоящий образ, транзиентный юнит) ===')
    r = common(d, 'V', VIRT_TREE)
    if not r:
        return
    ran = [p for p, x in r['exe'].items() if x.endswith('/systemd-detect-virt')]
    print(f'  событие исполнилось: {"ДА" if ran else "НЕТ"} (execve свидетеля: pid {ran[:3]})')
    if not ran:
        FAIL.append('V: systemd-detect-virt не исполнился')
    n = sum(v for (nme, rule), v in r['exc'].items() if nme == 'virt-detect-self' and rule == 'mitre_vm_detect_dmi_read')
    dmi_tree = [a for a in r['tree'] if a['rule_id'] == 'mitre_vm_detect_dmi_read']
    print(f'  virt-detect-self подавил mitre_vm_detect_dmi_read: {n}; алертов правила в дереве: {len(dmi_tree)}')
    ok = bool(ran) and n > 0 and not dmi_tree
    if not ok:
        FAIL.append('V: virt-detect-self не подтверждён живьём')
    print(f'  ИТОГ V: {"OK" if ok else "FAIL"}')


def phase_a(d):
    print('\n=== A: apt-daily со сдвинутыми штампами ===')
    r = common(d, 'A', APT_TREE)
    if not r:
        return
    after = dict(l.split() for l in rd(d, 'stamps-after.txt').splitlines() if l.strip())
    restored = dict(l.split() for l in rd(d, 'stamps-restored.txt').splitlines() if l.strip())
    orig = dict(l.split() for l in rd(os.path.dirname(d), 'stamps-orig.txt').splitlines() if l.strip())
    upd = '/var/lib/apt/periodic/update-stamp'
    moved = int(after.get(upd, 0)) >= r['tE0']
    paths = set(r['exe'].values())
    want = {k: [p for p in paths if p.endswith(k)] for k in ('/apt-get', '/gpgv', '/apt-key', 'methods/http', 'methods/https')}
    executed = moved and all(want[k] for k in ('/apt-get', '/gpgv'))
    print(f'  штамп update сдвинут событием: {"ДА" if moved else "НЕТ"}; образы исполненных методов: ' +
          ', '.join(f'{k} → {sorted(v) or "НЕТ"}' for k, v in want.items()))
    print(f'  событие исполнилось: {"ДА" if executed else "НЕТ"}')
    if not executed:
        FAIL.append('A: apt-get update не исполнился')
    if all(restored.get(s) == orig.get(s) for s in orig):
        print('  исходные mtime штампов возвращены')
    else:
        FAIL.append('A: штампы не возвращены')
    g = sum(v for (n, rule), v in r['exc'].items() if n == 'apt-gpgv-method-tmp')
    hid = [a for a in r['tree'] if a['rule_id'] == 'evasion_hidden_elf_in_tmp']
    print(f'  apt-gpgv-method-tmp: подавлено {g}; evasion_hidden_elf_in_tmp ушло в сторе окна: {len(hid)} (по образам: ' +
          ', '.join(sorted({r["exe"].get(str(a.get("pid")), "?") + ":" + (a.get("comm") or "") for a in hid})) + ')')
    own = print_incidents(incidents_in(d, r['tE0'], r['tE1']), APT_TREE, 'apt-daily')
    # корни сетевых правил — по образам методов
    nets = ['dns_nxdomain_flood', 'mitre_dns_c2_high_frequency', 'netintr_syn_scan_pattern', 'netintr_large_upload_port', 'exfil_raw_socket_by_non_root',
            'initial_package_postinstall_network']
    print('  сетевые эвристики дерева по образу (стор окна E):')
    for rid in nets:
        c = {}
        for a in r['al']:
            if a['rule_id'] == rid:
                k = r['exe'].get(str(a.get('pid')), '?') + ' comm=' + (a.get('comm') or '')
                c[k] = c.get(k, 0) + 1
        print(f'    {rid:36s} ' + (', '.join(f'{k}×{n}' for k, n in sorted(c.items(), key=lambda kv: -kv[1])) or '—'))
    print(f'  ИТОГ A (измерение): {"OK — событие снято" if executed else "FAIL"}')


def phase_p(d):
    print('\n=== P: копии образов из /var/tmp ===')
    print('  ' + rd(d, 'reads.txt').replace('\n', '\n  '))
    t0, t1 = int(rd(d, 't0')), int(rd(d, 't1'))
    m0, m1 = load(os.path.join(d, 'm0.txt')), load(os.path.join(d, 'm1.txt'))
    exc = {k: v for k, v in exc_all(m0, m1).items() if k[0] in ('mandb-self', 'apt-method-net', 'virt-detect-self', 'apt-gpgv-method-tmp')}
    al = [a for a in alerts(os.path.join(d, 'alerts.json')) if t0 <= ts(a['timestamp']) <= t1 + 1 and a.get('comm') in ('systemd-detect-virt', 'mandb', 'http')]
    c = {}
    for a in al:
        k = (a.get('comm'), a['rule_id'])
        c[k] = c.get(k, 0) + 1
    print('  алерты копий в сторе (comm, правило) → число: ' + (', '.join(f'{k[0]}/{k[1]}×{n}' for k, n in sorted(c.items())) or 'нет'))
    print('  подавлено исключениями долгов за P (обязано быть пусто): ' + (', '.join(f'{n}/{r}={v}' for (n, r), v in sorted(exc.items())) or 'ничего'))
    if not c:
        FAIL.append('P: копии не подняли ни одного правила')
    if exc:
        FAIL.append('P: копия получила исключение')
    for need in (('systemd-detect-virt', 'mitre_vm_detect_dmi_read'), ('mandb', 'sensitive_file_read'),
                 ('mandb', 'sigma_passwd_shadow_read'), ('mandb', 'proc_inject_ld_preload_file'),
                 ('mandb', 'supply_chain_pkg_install_etc_write'), ('http', 'netintr_large_upload_port'),
                 ('http', 'netintr_syn_scan_pattern')):
        lay = sum(per_rule(m0, m1, name).get(need[1], 0) for _, name in LAYERS)
        if need not in c and lay <= 0:
            FAIL.append(f'P: {need[0]} не поднял {need[1]} (ни в сторе, ни по трём слоям)')
        elif need not in c:
            print(f'    {need[0]}/{need[1]}: в сторе нет, но по трём слоям {int(lay):+d} (дедуп/лимитер) — сработало')
    print(f'  ИТОГ P: {"OK" if c and not exc else "FAIL"}')


def main():
    d = sys.argv[1]
    ident = dict(l.strip().split('=', 1) for l in open(os.path.join(d, 'binary-identity.txt')) if '=' in l)
    print(f"бинарь: файл {ident.get('sha256', '?')[:12]} процесс {ident.get('sha256_proc', '?')[:12]}")
    if ident.get('sha256') != ident.get('sha256_proc'):
        FAIL.append('измеряется не тот бинарь')
    print('образы (readlink / dpkg -S):\n  ' + rd(d, 'readlink.txt').replace('\n', '\n  '))
    for name, fn in (('M', phase_m), ('V', phase_v), ('A', phase_a), ('P', phase_p)):
        if os.path.isdir(os.path.join(d, name)):
            fn(os.path.join(d, name))
    print('\nИТОГ: ' + ('OK' if not FAIL else 'FAIL — ' + '; '.join(FAIL)))
    return 0 if not FAIL else 1


if __name__ == '__main__':
    sys.exit(main())
