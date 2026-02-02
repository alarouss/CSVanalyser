# -*- coding: utf-8 -*-

from Lib.scan_service_checks import compute_service_check

# ------------------------------------------------------------------
# MOCK minimal de la sonde Oracle (pas de DB réelle)
# ------------------------------------------------------------------

def mock_probe_service_or_sid_ok(service_name, database):
    return {
        "service_found": True,
        "sid_found": False
    }

def mock_probe_service_or_sid_sid(service_name, database):
    return {
        "service_found": False,
        "sid_found": True
    }

def mock_probe_service_or_sid_ko(service_name, database):
    return {
        "service_found": False,
        "sid_found": False
    }

# ------------------------------------------------------------------
# Injection du mock
# ------------------------------------------------------------------

import Lib.oracle_tools
Lib.oracle_tools.probe_service_or_sid = mock_probe_service_or_sid_ok

# ------------------------------------------------------------------
# Données minimales
# ------------------------------------------------------------------

network = {
    "New": {
        "Primaire": {
            "scan": "scan-db1"
        }
    }
}

raw = {
    "Databases": "DB1",
    "Services": "SRV_ACC_DB1",
    "New connection string": "jdbc:oracle:thin:@//scan-db1/SRV_ACC_DB1",
    "__ScanPath_cache__": {
        "Primary": {"Status": "OK"}
    }
}

# ------------------------------------------------------------------
# TEST 1 : SERVICE OK
# ------------------------------------------------------------------

print("\n=== TEST S2 : SERVICE OK ===")
res = compute_service_check(network, raw)
print(res["Primary"])
assert res["Primary"]["OracleCheck"]["OracleStatus"] in ("OK", "WARN")

# ------------------------------------------------------------------
# TEST 2 : SID OK (WARN)
# ------------------------------------------------------------------

Lib.oracle_tools.probe_service_or_sid = mock_probe_service_or_sid_sid

print("\n=== TEST S2 : SID (WARN) ===")
res = compute_service_check(network, raw)
print(res["Primary"])
assert res["Primary"]["OracleCheck"]["OracleStatus"] == "WARN"

# ------------------------------------------------------------------
# TEST 3 : NI SERVICE NI SID
# ------------------------------------------------------------------

Lib.oracle_tools.probe_service_or_sid = mock_probe_service_or_sid_ko

print("\n=== TEST S2 : SERVICE KO ===")
res = compute_service_check(network, raw)
print(res["Primary"])
assert res["Primary"]["OracleCheck"]["OracleStatus"] == "KO"

print("\n=== TESTS S2 OK ===")
