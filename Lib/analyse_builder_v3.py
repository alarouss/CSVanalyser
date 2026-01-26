#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Lib/analyse_builder_v3.py

import time
import sys
from Lib.jdbc_flow_v2 import interpret, compare, resolve_cname, resolve_scan
from Lib.io_common import ustr
from Lib.oem_flow import oem_get_host_and_port

RAW_COLUMNS = [
    "Statut Global", "Lot", "Application", "Databases", "DR O/N",
    "Current connection string",
    "New connection string",
    "New connection string avec DR",
    "Cnames", "Services", "Acces", "Cnames DR"
]
DEBUG = False

def set_debug(flag):
    global DEBUG
    DEBUG = bool(flag)
# ------------------------------------------------
def show_progress(pos, total, step):
    try:
        percent = int((float(pos) / float(total)) * 100) if total else 100
    except:
        percent = 100

    percent = max(0, min(100, percent))
    bar = "." * int(percent / 2)

    label = "Pos:%3d/%-3d | %-14s" % (pos, total, (step or "")[:14])
    label = "[%-30s]" % label

    sys.stdout.write(
        "\rProgress: %s %-50s %3d%%\033[K" % (label, bar, percent)
    )
    sys.stdout.flush()
# ------------------------------------------------
def ustr_csv(v):
    if v is None:
        return u""
    if isinstance(v, unicode):
        return v
    try:
        return unicode(v, "utf-8")
    except:
        try:
            return unicode(v, "latin1")
        except:
            try:
                return unicode(str(v), "latin1", "ignore")
            except:
                return u""

def normalize_key(k):
    return ustr_csv(k).replace(u'\ufeff', u'').strip()

def normalize_row(row):
    out = {}
    for k, v in row.items():
        out[normalize_key(k)] = ustr_csv(v)
    return out

# ------------------------------------------------
def _raw_source(row):
    raw = {}
    for c in RAW_COLUMNS:
        raw[c] = ustr_csv(row.get(c, u"")).strip()
    return raw

def _raw_debug(row):
    dbg = {}
    for k, v in row.items():
        dbg[ustr_csv(k)] = ustr_csv(v)
    return dbg

def build_raw_source(row):
    raw = {}
    for c in RAW_COLUMNS:
        v = row.get(c, u"") or u""
        raw[c] = ustr(v).strip()
    return raw

def build_raw_debug(row):
    dbg = {}
    for k, v in row.items():
        dbg[ustr(k)] = ustr(v)
    return dbg

# ------------------------------------------------
def build_status(valid, scan, scan_dr, dirty, dirty_reason,
                 err_type, err_detail, mode,
                 oem_err_type=None, oem_err_detail=None):

    st = {
        "ValidSyntax": bool(valid),
        "ScanCompare": scan,
        "ScanCompareDR": scan_dr,
        "Dirty": bool(dirty),
        "DirtyReason": dirty_reason,
        "ErrorType": err_type,
        "ErrorDetail": err_detail,
        "Mode": mode,
        "LastUpdateTime": time.strftime("%Y-%m-%d %H:%M:%S")
    }

    if oem_err_type or oem_err_detail:
        st["OEMErrorType"] = oem_err_type
        st["OEMErrorDetail"] = oem_err_detail

    return st

# ------------------------------------------------
def compute_net_side(block, step_prefix, pos, total):
    host = block.get("host")
    if not host:
        return block, None, None

    if host in ("DR", "Primaire"):
        raise Exception("INVARIANT VIOLATION: host=%r" % host)

    show_progress(pos, total, "%s_CNAME" % step_prefix)
    cname, e1, d1 = resolve_cname(host)
    if e1:
        return block, "CNAME_ERROR", "%s: cname resolution failed for %s | %s" % (
            step_prefix, host, d1
        )

    block["cname"] = cname

    show_progress(pos, total, "%s_SCAN" % step_prefix)
    scan, e2, d2 = resolve_scan(cname)
    if e2:
        return block, "SCAN_ERROR", "%s: scan resolution failed for %s | %s" % (
            step_prefix, cname, d2
        )

    block["scan"] = scan
    return block, None, None

# ------------------------------------------------
def compute_block_status(block, had_error):
    if not block.get("host"):
        return "N/A"
    if had_error:
        return "ERROR"
    return "OK"

# ------------------------------------------------
def compute_network_block(host, step, pos, total):
    net = {"host": host, "cname": None, "scan": None}
    if not host:
        return net, "HOST_NONE", "%s: host empty" % step

    show_progress(pos, total, "%s_CNAME" % step)
    cname, e1, d1 = resolve_cname(host)
    if (not e1) and cname:
        net["cname"] = cname

    scan_input = net["cname"] or host
    show_progress(pos, total, "%s_SCAN" % step)
    scan, e2, d2 = resolve_scan(scan_input)
    if e2:
        net["scan"] = scan
        return net, e2, "%s: scan resolution failed for %s | %s" % (
            step, scan_input, d2
        )

    net["scan"] = scan
    return net, None, None

# ------------------------------------------------
def fill_net_from_addresses(o, net_side):
    if not o or not getattr(o, "addresses", None):
        return

    addrs = o.addresses
    if isinstance(addrs, dict):
        if "Primaire" in addrs:
            net_side["Primaire"]["host"] = addrs["Primaire"].get("host")
        if "DR" in addrs:
            net_side["DR"]["host"] = addrs["DR"].get("host")

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

    # Comparaison référence = Current / Primaire
    if err_type:
        scan_status = "ERROR"
    else:
        eq = compare(
            net["Current"]["Primaire"]["scan"],
            net["New"]["Primaire"]["scan"]
        )
        scan_status = "VALIDE" if eq else "DIFFERENT"
        if not eq:
            err_type = "SCAN_DIFFERENT"
            err_detail = "Current and New SCAN differ"

    scan_dr_status = None
    if net["New"]["DR"]["host"]:
        eqdr = compare(
            net["Current"]["Primaire"]["scan"],
            net["New"]["DR"]["scan"]
        )
        scan_dr_status = "VALIDE" if eqdr else "DIFFERENT"
    else:
        scan_dr_status = "N/A"

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
