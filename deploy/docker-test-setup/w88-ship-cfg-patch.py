#!/usr/bin/env python3
"""w88-ship-cfg-patch.py <config.yaml> <SRC> — делает поставочный config/config.yaml пригодным для второго агента на стенде:
свой порт/токены/хранилище/состояние профиля, правила SRC/rules, без общих с рабочим агентом сокета и файла observer-pid.
Остальное (file_rate, sampling, cpu_pressure, adaptive_load …) остаётся как в поставке — это и меряется (п.6 владельца)."""
import os, sys, yaml
p, src = sys.argv[1], sys.argv[2]
c = yaml.safe_load(open(p))
run, port = os.environ["SA_RUN"], os.environ["SA_PORT"]
c["server"]["bind_address"] = "127.0.0.1:%s" % port
c.setdefault("rules", {})["path"] = src.rstrip("/") + "/rules/"
c["rules"]["hot_reload"] = False
c["rules"]["local_tuning_path"] = ""
c.setdefault("auth", {})["admin_token"] = "w85u1smoketoken0123456789abcdef012"
c["auth"]["viewer_token"] = "w85u1viewertoken0123456789abcdef01"
c.setdefault("profiler", {}).setdefault("state_persistence", {})["path"] = run + "/profiler-state.json"
c.setdefault("store", {})["backend"] = "memory"
c.setdefault("notifications", {}).setdefault("unix_socket", {})["enabled"] = False
c.setdefault("correlator", {}).setdefault("observer_exclude", {})["enabled"] = False
if os.environ.get("SHIP_FILE_RATE"):
    # п.6 владельца: chart/Go-умолчание file_rate = 50 (в поставочном config.yaml стоит 1)
    c.setdefault("bpf", {}).setdefault("sampling", {})["file_rate"] = int(os.environ["SHIP_FILE_RATE"])
yaml.safe_dump(c, open(p, "w"), allow_unicode=True, sort_keys=False)
