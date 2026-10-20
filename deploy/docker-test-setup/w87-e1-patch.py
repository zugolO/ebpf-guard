#!/usr/bin/env python3
"""w87-e1-patch.py <config.yaml> <SRC> — заход Е1 волны 8.7: server.pprof_stage_labels=true (метки стадий).
enable_pprof уже true в config-test.yaml; pprof_rule_labels остаётся выключенным (вклад стадии rules считается
по метке stage=rules, разрез по правилам — не цель захода)."""
import sys, yaml
cfg = sys.argv[1]
c = yaml.safe_load(open(cfg))
assert c["server"]["enable_pprof"] is True, "enable_pprof выключен — меток стадий не будет"
c["server"]["pprof_stage_labels"] = True
c["server"]["pprof_rule_labels"] = False
# Rego: каталог по умолчанию относительный (rules/rego), второй агент стартует из каталога прогона и политик не нашёл бы —
# стадия rego в профиле была бы пуста по построению (первый прогон Е1: «rego» не напечатана). Рабочий агент стартует из
# /opt/ebpf-guard и политики грузит.
import os
rego = os.path.join(sys.argv[2], "rules", "rego")
assert os.path.isdir(rego), "нет каталога политик " + rego
c.setdefault("policy", {}).setdefault("rego", {})["rules_dir"] = rego
# Волна 9: умолчание Rego — off (Д15); хост-замеры идут на full и включают слой явно (HOST_REGO=1, как ночь).
if os.environ.get("HOST_REGO") == "1":
    c["policy"]["rego"]["enabled"] = True
yaml.safe_dump(c, open(cfg, "w"), allow_unicode=True, sort_keys=False)
print("pprof_stage_labels = true; policy.rego.rules_dir =", rego)
