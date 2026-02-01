#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Lib/scan_service_checks.py
# Python 2.6 compatible

import re

RULE_SCANPATH = "Host -> CNAME -> SCAN must resolve to the SCAN of the target database; SCAN bypass is forbidden."
RULE_SERVICE  = "Service extracted from New JDBC must be valid for the target database reached via SCAN."

def _u(v):
    try:
        # unicode exists in py2
        if isinstance(v, unicode):
            return v
    except:
        pass
    try:
        return unicode(v, "utf-8", "ignore")
    except:
        try:
            return unicode(str(v), "latin1", "ignore")
        except:
            return u""

def _norm(v):
    return _u(v).strip().lower()

def _is_dr_applicable(rawsource):
    return _norm(rawsource.get("DR O/N", "")) == u"o"

def _get_new_block(network, side):
    # side: "Primaire" or "DR"
    return (network.get("New", {}) or {}).get(side, {}) or {}

def _get_oem_block(network, side):
    return (network.get("OEM", {}) or {}).get(side, {}) or {}

def _extract_service_from_jdbc(jdbc_str):
    """
    Extract SERVICE_NAME from a JDBC connect descriptor.
    Returns unicode or None.
    """
    s = _u(jdbc_str)
    if not s:
        return None

    # Common pattern: (SERVICE_NAME=SRV_XXX)
    m = re.search(r"SERVICE_NAME\s*=\s*([A-Za-z0-9_\-\.]+)", s, re.I)
    if m:
        return _u(m.group(1))

    # Sometimes: /SERVICE or :PORT/SERVICE in simple forms
    # Try last "/<token>" token
    m = re.search(r"/\s*([A-Za-z0-9_\-\.]+)\s*['\"\)]?", s)
    if m:
        return _u(m.group(1))

    return None

def compute_scan_path(network, rawsource):
    """
    Authority: Network.New (current choice).
    Uses OEM scan as reference if available.
    Produces:
      Status["ScanPath"] = { Rule, Primary:{...}, DR:{Applicable,...} }
    """
    out = {"Rule": RULE_SCANPATH}

    target_db = _u(rawsource.get("Databases", ""))

    def eval_side(side, applicable):
        # side: "Primaire" or "DR"
        if not applicable:
            return {
                "Applicable": False,
                "Status": "N/A",
                "Message": "Host information is missing or not applicable.",
                "Host": None,
                "CNAME": None,
                "SCAN": None,
                "TargetDatabase": target_db
            }

        nb = _get_new_block(network, side)
        host = nb.get("host")
        cname = nb.get("cname")
        scan = nb.get("scan")

        # 1) Host missing -> N/A
        if not host:
            return {
                "Status": "N/A",
                "Message": "Host information is missing or not applicable.",
                "Host": host,
                "CNAME": cname,
                "SCAN": scan,
                "TargetDatabase": target_db
            }

        # 2) CNAME missing -> KO
        if not cname:
            return {
                "Status": "KO",
                "Message": "CNAME could not be resolved from host.",
                "Host": host,
                "CNAME": cname,
                "SCAN": scan,
                "TargetDatabase": target_db
            }

        # 3) SCAN missing -> KO
        if not scan:
            return {
                "Status": "KO",
                "Message": "SCAN could not be resolved from CNAME.",
                "Host": host,
                "CNAME": cname,
                "SCAN": scan,
                "TargetDatabase": target_db
            }

        # 4) Bypass check: host must be the SCAN (case-insensitive)
        # 4) Belongs-to-target-db check:
        # If OEM scan exists, it becomes a strong reference to validate cluster/base intent.
        ob = _get_oem_block(network, side)
        oem_scan = ob.get("scan")
        
        if oem_scan and _norm(oem_scan) != _norm(scan):
            return {
                "Status": "KO",
                "Message": "Resolved path does not lead to the SCAN of the target database.",
                "Host": host,
                "CNAME": cname,
                "SCAN": scan,
                "TargetDatabase": target_db
            }
        
        # OK
        return {
            "Status": "OK",
            "Message": "Host resolves via DNS and Oracle to the SCAN of the target database.",
            "Host": host,
            "CNAME": cname,
            "SCAN": scan,
            "TargetDatabase": target_db
        }


        # 5) Belongs-to-target-db check (current implementation):
        # If OEM scan exists, it becomes a strong reference to validate cluster/base intent.
        ob = _get_oem_block(network, side)
        oem_scan = ob.get("scan")
        if oem_scan and _norm(oem_scan) != _norm(scan):
            return {
                "Status": "KO",
                "Message": "Resolved path does not lead to the SCAN of the target database.",
                "Host": host,
                "CNAME": cname,
                "SCAN": scan,
                "TargetDatabase": target_db
            }

        # OK
        return {
            "Status": "OK",
            "Message": "Host resolves via DNS and Oracle to the SCAN of the target database.",
            "Host": host,
            "CNAME": cname,
            "SCAN": scan,
            "TargetDatabase": target_db
        }

    # Primary always applicable
    out["Primary"] = eval_side("Primaire", True)

    # DR conditional
    dr_app = _is_dr_applicable(rawsource)
    dr_block = eval_side("DR", dr_app)
    if "Applicable" not in dr_block:
        dr_block["Applicable"] = bool(dr_app)
    out["DR"] = dr_block

    return out

def compute_service_check(network, rawsource):
    """
    Authority: New JDBC (service extracted from New connection string).
    Depends on ScanPath being OK; if not OK, ServiceCheck => N/A (skipped).
    Produces:
      Status["ServiceCheck"] = { Rule, Primary:{...}, DR:{Applicable,...} }
    """
    out = {"Rule": RULE_SERVICE}

    target_db = _u(rawsource.get("Databases", ""))
    service_csv = _u(rawsource.get("Services", ""))  # optional reference
    new_jdbc = _u(rawsource.get("New connection string", ""))
    new_jdbc_dr = _u(rawsource.get("New connection string avec DR", "")) or _u(rawsource.get("New connection string  avec DR", ""))

    def scanpath_ok(side):
        sp = rawsource.get("__ScanPath_cache__", {}) or {}
        # sp["Primary"] corresponds to side Primaire; sp["DR"] corresponds to side DR
        key = "Primary" if side == "Primaire" else "DR"
        s = ((sp.get(key) or {}).get("Status") or "")
        return s == "OK"

    def eval_side(side, applicable, jdbc_str):
        # If ScanPath not OK => skip as N/A
        if not applicable:
            return {
                "Applicable": False,
                "Status": "N/A",
                "Message": "Service information is missing or cannot be evaluated.",
                "TargetDatabase": target_db,
                "TargetSCAN": (_get_new_block(network, side) or {}).get("scan"),
                "ServiceFromCSV": service_csv or None,
                "ServiceFromJDBC": None
            }

        if not scanpath_ok(side):
            return {
                "Status": "N/A",
                "Message": "Service check skipped because SCAN path is not valid.",
                "TargetDatabase": target_db,
                "TargetSCAN": (_get_new_block(network, side) or {}).get("scan"),
                "ServiceFromCSV": service_csv or None,
                "ServiceFromJDBC": None
            }

        svc_jdbc = _extract_service_from_jdbc(jdbc_str)
        if not svc_jdbc:
            return {
                "Status": "N/A",
                "Message": "Service information is missing or cannot be evaluated.",
                "TargetDatabase": target_db,
                "TargetSCAN": (_get_new_block(network, side) or {}).get("scan"),
                "ServiceFromCSV": service_csv or None,
                "ServiceFromJDBC": None
            }

        # Validation (current scope = internal consistency):
        # If CSV service present, require match (case-insensitive). Otherwise OK (service known but no reference).
        if service_csv and _norm(service_csv) != _norm(svc_jdbc):
            return {
                "Status": "KO",
                "Message": "Service extracted from New JDBC does not match expected service.",
                "TargetDatabase": target_db,
                "TargetSCAN": (_get_new_block(network, side) or {}).get("scan"),
                "ServiceFromCSV": service_csv,
                "ServiceFromJDBC": svc_jdbc
            }

        return {
            "Status": "OK",
            "Message": "Service extracted from New JDBC is valid for the target database.",
            "TargetDatabase": target_db,
            "TargetSCAN": (_get_new_block(network, side) or {}).get("scan"),
            "ServiceFromCSV": service_csv or None,
            "ServiceFromJDBC": svc_jdbc
        }

    # Primary
    out["Primary"] = eval_side("Primaire", True, new_jdbc)

    # DR
    dr_app = _is_dr_applicable(rawsource)
    dr_res = eval_side("DR", dr_app, new_jdbc_dr)
    if "Applicable" not in dr_res:
        dr_res["Applicable"] = bool(dr_app)
    out["DR"] = dr_res

    return out
