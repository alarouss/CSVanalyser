#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Lib/scan_service_checks.py
# Python 2.6 compatible

import re
from Lib.oracle_tools import probe_service_or_sid

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
      Status["ScanPath"] = { Rule, Primary:{...}, DR:{...} }
    """
    out = {"Rule": RULE_SCANPATH}

    target_db = _u(rawsource.get("Databases", ""))

    def eval_side(side, applicable):
        if not applicable:
            return {
                "Applicable": False,
                "Status": "N/A",
                "Message": "Host information is missing or not applicable.",
                "Host": None,
                "CNAME": None,
                "ResolvedSCAN": None,
                "ExpectedSCAN": None,
                "ExpectedSource": None,
                "TargetDatabase": target_db
            }

        nb = _get_new_block(network, side)
        host = nb.get("host")
        cname = nb.get("cname")
        scan = nb.get("scan")

        # 1) Host missing
        if not host:
            return {
                "Status": "N/A",
                "Message": "Host information is missing or not applicable.",
                "Host": host,
                "CNAME": cname,
                "ResolvedSCAN": scan,
                "ExpectedSCAN": None,
                "ExpectedSource": None,
                "TargetDatabase": target_db
            }

        # 2) CNAME missing
        if not cname:
            return {
                "Status": "KO",
                "Message": "CNAME could not be resolved from host.",
                "Host": host,
                "CNAME": cname,
                "ResolvedSCAN": scan,
                "ExpectedSCAN": None,
                "ExpectedSource": None,
                "TargetDatabase": target_db
            }

        # 3) SCAN missing
        if not scan:
            return {
                "Status": "KO",
                "Message": "SCAN could not be resolved from CNAME.",
                "Host": host,
                "CNAME": cname,
                "ResolvedSCAN": None,
                "ExpectedSCAN": None,
                "ExpectedSource": None,
                "TargetDatabase": target_db
            }

        # 4) Compare with expected SCAN (OEM reference)
        ob = _get_oem_block(network, side)
        expected_scan = ob.get("scan")
        expected_source = "OEM" if expected_scan else None

        if expected_scan and _norm(expected_scan) != _norm(scan):
            return {
                "Status": "KO",
                "Message": "Resolved SCAN does not match expected SCAN for target database.",
                "Host": host,
                "CNAME": cname,
                "ResolvedSCAN": scan,
                "ExpectedSCAN": expected_scan,
                "ExpectedSource": expected_source,
                "TargetDatabase": target_db
            }

        # OK
        return {
            "Status": "OK",
            "Message": "Host resolves via DNS and Oracle to the SCAN of the target database.",
            "Host": host,
            "CNAME": cname,
            "ResolvedSCAN": scan,
            "ExpectedSCAN": expected_scan,
            "ExpectedSource": expected_source,
            "TargetDatabase": target_db
        }

    # Primary
    out["Primary"] = eval_side("Primaire", True)

    # DR
    dr_app = _is_dr_applicable(rawsource)
    dr_block = eval_side("DR", dr_app)
    if "Applicable" not in dr_block:
        dr_block["Applicable"] = bool(dr_app)
    out["DR"] = dr_block

    return out

#---------------------------------
def compute_service_check(network, rawsource):
    """
    Authority: New JDBC (service extracted from New connection string).
    Depends on ScanPath being OK; if not OK, ServiceCheck => N/A (skipped).

    Option 1:
      - ServiceNaming  : cohérence métier (norme SRV_<TRIG>_<DATABASE>)
      - OracleCheck    : réalité Oracle (SERVICE / SID / NONE), non bloquant
    """
    out = {"Rule": RULE_SERVICE}

    target_db = _u(rawsource.get("Databases", ""))
    service_csv = _u(rawsource.get("Services", ""))
    new_jdbc = _u(rawsource.get("New connection string", ""))
    new_jdbc_dr = (
        _u(rawsource.get("New connection string avec DR", "")) or
        _u(rawsource.get("New connection string  avec DR", ""))
    )

    def scanpath_ok(side):
        sp = rawsource.get("__ScanPath_cache__", {}) or {}
        key = "Primary" if side == "Primaire" else "DR"
        return ((sp.get(key) or {}).get("Status") or "") == "OK"

    def expected_service_name():
        """
        Norme métier : SRV_<TRIG>_<DATABASE>
        Le TRIG est déduit du CSV si présent, sinon inconnu.
        """
        if not service_csv:
            return None
        return service_csv

    def eval_side(side, applicable, jdbc_str):
        # --------------------------------
        # Cas non applicable / non évaluable
        # --------------------------------
        if not applicable:
            return {
                "Applicable": False,
                "Status": "N/A",
                "Message": "Service information is missing or cannot be evaluated."
            }

        if not scanpath_ok(side):
            return {
                "Status": "N/A",
                "Message": "Service check skipped because SCAN path is not valid."
            }

        svc_jdbc = _extract_service_from_jdbc(jdbc_str)

        # ================================
        # ServiceNaming — cohérence métier
        # ================================
        expected = expected_service_name()
        service_naming = {
            "Rule": "SRV_<TRIG>_<DATABASE>",
            "Expected": expected,
            "Actual": svc_jdbc,
            "Status": None
        }

        if not svc_jdbc:
            service_naming["Status"] = "N/A"
        elif expected and _norm(expected) == _norm(svc_jdbc):
            service_naming["Status"] = "OK"
        else:
            service_naming["Status"] = "KO"

        # ================================
        # OracleCheck — réalité Oracle (S2)
        # ================================
        oracle_check = None
        if svc_jdbc:
            probe = probe_service_or_sid(svc_jdbc, target_db)

            if probe.get("service_found"):
                oracle_check = {
                    "OracleStatus": "OK",
                    "Probe": "SERVICE",
                    "Detail": "Service exists in database."
                }
            elif probe.get("sid_found"):
                oracle_check = {
                    "OracleStatus": "WARN",
                    "Probe": "SID",
                    "Detail": "SID found instead of service (legacy JDBC)."
                }
            else:
                oracle_check = {
                    "OracleStatus": "KO",
                    "Probe": "NONE",
                    "Detail": "Neither service nor SID found in database."
                }

        # ================================
        # Status global (inchangé en esprit)
        # ================================
        if oracle_check and oracle_check.get("OracleStatus") == "KO":
            status = "KO"
            message = "Service/SID not found in database."
        elif service_naming["Status"] == "KO":
            status = "WARN"
            message = "Service name does not comply with naming convention."
        else:
            status = "OK"
            message = "Service extracted from New JDBC is acceptable."
        return {
            "Status": status,
            "Message": message,
            "ServiceFromCSV": service_csv or None,
            "ServiceFromJDBC": svc_jdbc,
            "ServiceNaming": service_naming,
            "OracleCheck": oracle_check
        }

    # ================================
    # Primary
    # ================================
    out["Primary"] = eval_side("Primaire", True, new_jdbc)

    # ================================
    # DR
    # ================================
    dr_app = _is_dr_applicable(rawsource)
    out["DR"] = eval_side("DR", dr_app, new_jdbc_dr)

    return out


#---------------------------------
# -*- coding: utf-8 -*-

def compute_service_declaration(new_jdbc_obj):
    """
    S2 — Service Access Mode Declaration (non bloquant)

    Analyse la JDBC New et détermine le mode d'accès :
      - SERVICE_NAME
      - SID
      - UNKNOWN

    Aucun accès Oracle, aucune validation bloquante.
    Compatible Python 2.6.
    """

    out = {
        "Status": "N/A",
        "Mode": None,
        "Actual": None,
        "Message": None,
        "Rule": "Detect SERVICE_NAME or SID declared in JDBC string; SID is allowed but discouraged."
    }

    if not new_jdbc_obj:
        out["Message"] = "No JDBC object available."
        return out

    # SERVICE_NAME explicite
    svc = getattr(new_jdbc_obj, "service_name", None)
    if svc:
        out["Status"] = "OK"
        out["Mode"] = "SERVICE"
        out["Actual"] = svc
        out["Message"] = "SERVICE_NAME declared in JDBC string."
        return out

    # SID explicite
    sid = getattr(new_jdbc_obj, "sid", None)
    if sid:
        out["Status"] = "WARN"
        out["Mode"] = "SID"
        out["Actual"] = sid
        out["Message"] = (
            "SID-based JDBC detected; service resolution will be required."
        )
        return out

    # Aucun des deux
    out["Status"] = "WARN"
    out["Mode"] = "UNKNOWN"
    out["Actual"] = None
    out["Message"] = (
        "Neither SERVICE_NAME nor SID explicitly declared in JDBC string."
    )

    return out
#---------------------------------------------------------------
# -*- coding: utf-8 -*-

from Lib.io_common import ustr

def compute_service_resolution(network, rawsource, oracle_probe):
    """
    S2 — Service functional validation (with Oracle probe)

    - Non blocking
    - Uses Oracle probe to check SERVICE_NAME or SID
    - Produces Status.ServiceCheck

    oracle_probe: callable(service_name=None, sid=None) -> dict
    """

    out = {
        "Rule": "JDBC service or SID must resolve to an entity served by the target database.",
        "Authority": "Oracle probe",
        "Primary": {
            "Status": "N/A",
            "Declared": None,
            "ResolvedAs": None,
            "Message": None,
            "Database": ustr(rawsource.get("Databases"))
        }
    }

    svc = rawsource.get("Services")
    if not svc:
        out["Primary"]["Status"] = "N/A"
        out["Primary"]["Message"] = "No service declared in JDBC."
        return out

    svc = ustr(svc).strip()
    out["Primary"]["Declared"] = svc

    # --- Oracle probe call ---
    try:
        probe = oracle_probe(service_name=svc)
    except Exception as e:
        out["Primary"]["Status"] = "WARN"
        out["Primary"]["ResolvedAs"] = "UNKNOWN"
        out["Primary"]["Message"] = "Oracle probe failed: %s" % e
        return out

    # --- Decision matrix ---
    if probe.get("service_found"):
        out["Primary"]["Status"] = "OK"
        out["Primary"]["ResolvedAs"] = "SERVICE"
        out["Primary"]["Message"] = "Service name resolved and served by target database."
        return out

    if probe.get("sid_found"):
        out["Primary"]["Status"] = "WARN"
        out["Primary"]["ResolvedAs"] = "SID"
        out["Primary"]["Message"] = "SID used instead of SERVICE_NAME (legacy usage)."
        return out

    out["Primary"]["Status"] = "KO"
    out["Primary"]["ResolvedAs"] = "NONE"
    out["Primary"]["Message"] = "Declared service or SID not served by the target database."
    return out
#----------------------------------------------------------------------------------------------------
