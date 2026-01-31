#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Lib/analyse_builder_v3.py

import time
import sys
from Lib.jdbc_flow_v2 import interpret, compare, resolve_cname, resolve_scan
from Lib.io_common import ustr
from Lib.oem_flow import oem_get_host_and_port
from Lib.compare_primary import compare_primary

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

