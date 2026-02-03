# -*- coding: utf-8 -*-
from Lib.scan_service_checks import compute_service_check

def fake_probe_service_or_sid(service, db):
    # Simule Oracle
    if service == "SRV_ACC_DB1":
        return {"service_found": True}
    if service == "DB1":
        return {"sid_found": True}
    return {}

# Monkey-patch (temporaire)
import Lib.scan_service_checks as sc
sc.probe_service_or_sid = fake_probe_service_or_sid

raw = {
    "Databases": "DB1",
    "Services": "SRV_ACC_DB1",
    "New connection string":
        "jdbc:oracle:thin:@//scan-db1:1521/SRV_ACC_DB1",
    "__ScanPath_cache__": {
        "Primary": {"Status": "OK"}
    }
}

net = {
    "New": {
        "Primaire": {"scan": "scan-db1"},
        "DR": {}
    }
}

res = compute_service_check(net, raw)

print("=== RESULT ===")
print(res["Primary"])

assert res["Primary"]["Status"] == "OK"
assert res["Primary"]["OracleCheck"]["OracleStatus"] == "OK"

print("✅ TEST OK")
