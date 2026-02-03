# -*- coding: utf-8 -*-

from Lib.scan_service_checks import compute_service_check

# -------------------------------------------------------------------
# MOCKS MINIMAUX (sans Oracle réel)
# -------------------------------------------------------------------

def probe_service_or_sid(service, database):
    """
    Simule la sonde Oracle :
    - SRV_*  => service existe
    - sinon  => rien trouvé
    """
    if service and service.startswith("SRV_"):
        return {"service_found": True, "sid_found": False}
    return {"service_found": False, "sid_found": False}

# Injection du mock (monkey patch)
import Lib.scan_service_checks as ssc
ssc.probe_service_or_sid = probe_service_or_sid


# -------------------------------------------------------------------
# TEST S2 — SERVICE OK
# -------------------------------------------------------------------

print("\n=== TEST S2 : SERVICE OK ===")

network = {
    "New": {
        "Primaire": {
            "host": "accueil-clientp0db.groupe.generali.fr",
            "cname": "scan-db1.groupe.generali.fr",
            "scan": "scan-db1"
        }
    }
}

raw = {
    "Databases": "DB1",
    "Services": "SRV_ACC_DB1",
    "New connection string":
        "jdbc:oracle:thin:@//scan-db1:1521/SRV_ACC_DB1",

    # Cache ScanPath simulé (SCAN OK)
    "__ScanPath_cache__": {
        "Primary": {"Status": "OK"}
    }
}

res = compute_service_check(network, raw)

print(res["Primary"])

# -----------------------
# Assertions
# -----------------------
assert res["Primary"]["Status"] == "OK"
assert res["Primary"]["ServiceNaming"]["Status"] == "OK"
assert res["Primary"]["OracleCheck"]["OracleStatus"] == "OK"

print("✔ TEST S2 OK")
