# Lib/object_builder_v3.py
# -*- coding: utf-8 -*-

from Lib.analyse_builder_v3 import (
    build_raw_source,
    build_raw_debug,
    compute_net_side,
    fill_net_from_addresses,
    build_status
)

from Lib.jdbc_flow_v2 import interpret
from Lib.oem_flow import oem_get_host_and_port
from Lib.host_coherence import check_host_coherence
from Lib.analyse_builder_v3 import DEBUG

# ------------------------------------------------
def build_object_v3(row, obj_id, oem_conn, pos, total, force):

    raw = build_raw_source(row)
    raw_debug = build_raw_debug(row)

    cur = raw.get("Current connection string")
    new = raw.get("New connection string")

    cur_o, ecur, dcur = interpret(cur)
    new_o, enew, dnew = interpret(new)
    # === INJECTION DR (OPTION 1) ===
    if getattr(new_o, "addresses", None):
        dr_addr = new_o.addresses.get("DR")
        if dr_addr and not dr_addr.get("host"):
    
            # priorité 1 : JDBC DR explicite
            dr_jdbc = raw.get("New connection string avec DR") or raw.get("New connection string  avec DR")
            if dr_jdbc:
                dr_o, e_dr, d_dr = interpret(dr_jdbc)
                if dr_o and getattr(dr_o, "addresses", None):
                    dr_host = dr_o.addresses.get("Primaire", {}).get("host")
                    if dr_host:
                        new_o.addresses["DR"]["host"] = dr_host
    
            # priorité 2 : CNAME DR
            if not new_o.addresses["DR"].get("host"):
                cname_dr = raw.get("Cnames DR")
                if cname_dr:
                    new_o.addresses["DR"]["host"] = cname_dr
    # === FIN INJECTION DR ===
    net = {
        "Current": {
            "Primaire": {"host": None, "cname": None, "scan": None},
            "DR":       {"host": None, "cname": None, "scan": None},
        },
        "New": {
            "Primaire": {"host": None, "cname": None, "scan": None},
            "DR":       {"host": None, "cname": None, "scan": None},
        },
        "OEM": {
            "Primaire": {"host": None, "port": None, "cname": None, "scan": None},
            "DR":       {"host": None, "port": None, "cname": None, "scan": None},
        }
    }
    # =========================
    # OEM — PRIMAIRE (ETAPE 1)
    # =========================
    # =========================
    # OEM — PRIMAIRE (DEBUG)
    # =========================
    # 2) OEM — récupération host/port
    if oem_conn:
        oem_host, oem_port, e, d = oem_get_host_and_port(
            oem_conn,
            raw.get("Databases")
        )
        print("DEBUG OEM:", oem_host, oem_port, e, d)
        if not e and oem_host:
            net["OEM"]["Primaire"]["host"] = oem_host
            net["OEM"]["Primaire"]["port"] = oem_port
    
    # 3) OEM — résolution réseau (CNAME + SCAN)  👈 ICI
    if net["OEM"]["Primaire"].get("host"):
        net["OEM"]["Primaire"], e, d = compute_net_side(
            net["OEM"]["Primaire"],
            "OEM_PRIMAIRE",
            pos, total
        )



    fill_net_from_addresses(cur_o, net["Current"])
    fill_net_from_addresses(new_o, net["New"])

    fill_net_from_addresses(cur_o, net["Current"])
    fill_net_from_addresses(new_o, net["New"])
    if DEBUG:
        # ===== DEBUG TEMPORAIRE (ETAPE 1) =====
        print("DEBUG ADDRESSES NEW =", getattr(new_o, "addresses", None))
        print("DEBUG NET NEW =", net["New"])
        # =====================================

    valid = bool(cur_o.valide and new_o.valide)

    err_type = None
    err_detail = None
    if DEBUG:
        print("DEBUG VALID =", valid, "cur_o =", cur_o, "new_o =", new_o)
    if not valid:
        status = build_status(
            False, "ERROR", None,
            False, None,
            "SYNTAX_ERROR",
            "Invalid JDBC syntax",
            "FORCE_UPDATE" if force else "AUTO"
        )
        return {
            "id": obj_id,
            "Network": net,
            "OEM": net["OEM"],
            "Status": status,
            "RawSource": raw,
            "RawSource_DEBUG": raw_debug
        }

    # Résolution CURRENT
    if DEBUG:
        print("DEBUG BEFORE CURRENT LOOP", net["Current"])
    for role in ("Primaire", "DR"):
        net["Current"][role], e, d = compute_net_side(
            net["Current"][role],
            "CURRENT_%s" % role.upper(),
            pos, total
        )
        if e and not err_type:
            err_type, err_detail = e, d

    # Résolution NEW
    for role in ("Primaire", "DR"):
        net["New"][role], e, d = compute_net_side(
            net["New"][role],
            "NEW_%s" % role.upper(),
            pos, total
        )
        if e and not err_type:
            err_type, err_detail = e, d

    # =====================================================
    # Comparaison Current / New — Primaire UNIQUEMENT
    # Règle : host → cname → scan
    # =====================================================

    scan_status = "OK"
    err_type = None
    err_detail = None

    cur_p = net.get("Current", {}).get("Primaire", {})
    new_p = net.get("New", {}).get("Primaire", {})

    # 1) HOST
    if cur_p.get("host") and new_p.get("host"):
        if cur_p["host"] != new_p["host"]:

            # 2) CNAME
            if cur_p.get("cname") and new_p.get("cname"):
                if cur_p["cname"] != new_p["cname"]:

                    # 3) SCAN
                    if cur_p.get("scan") and new_p.get("scan"):
                        if cur_p["scan"] != new_p["scan"]:
                            scan_status = "DIFFERENT"
                    else:
                        scan_status = "N/A"
            else:
                scan_status = "N/A"
    else:
        scan_status = "N/A"

    # AUCUNE ERREUR ICI : situation normale
    err_type = None
    err_detail = None

    scan_dr_status = "N/A"   # DR volontairement ignoré

    status = build_status(
        True,
        scan_status,
        scan_dr_status,
        False,
        None,
        err_type,
        err_detail,
        "FORCE_UPDATE" if force else "AUTO"
    )

    return {
        "id": obj_id,
        "OEM": net["OEM"],
        "Network": net,
        "Status": status,
        "RawSource": raw,
        "RawSource_DEBUG": raw_debug
    }
