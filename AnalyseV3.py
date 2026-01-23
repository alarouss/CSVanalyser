#!/usr/bin/env python
# -*- coding: utf-8 -*-

import csv
import sys
import time
import os
import codecs

from Lib.common import ustr
from Lib.config import load_main_conf
from Lib.store import load_store, save_store, build_index
from Lib.jdbc_flow_v2 import interpret, compare, resolve_cname, resolve_scan
from Lib.oem_flow import oem_get_host_and_port

DEBUG = False

RAW_COLUMNS = [
    "Statut Global","Lot","Application","Databases","DR O/N",
    "Current connection string",
    "New connection string",
    "New connection string avec DR",
    "Cnames","Services","Acces","Cnames DR"
]

# ------------------------------------------------
def print_help():
    print """AnalyseV3.py

Usage:
 python AnalyseV3.py ligne=N|ALL [OPTIONS]
 python AnalyseV3.py id=N [OPTIONS]
 python AnalyseV3.py id=1,2,5 [OPTIONS]
 python AnalyseV3.py columns

Options:
 -debug
 -force / -update / -upgrade
 -h | --help | -help
"""

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
    sys.stdout.write("\rProgress: %s %-50s %3d%%\033[K" % (label, bar, percent))
    sys.stdout.flush()

# ------------------------------------------------
def normalize_key(k):
    return ustr(k).replace(u'\ufeff', u'').strip()

def normalize_row(row):
    return dict((normalize_key(k), ustr(v)) for k, v in row.items())

# ------------------------------------------------
def build_raw_source(row):
    return dict((c, ustr(row.get(c, u"")).strip()) for c in RAW_COLUMNS)

# ------------------------------------------------
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
def compute_network_block(host, step, pos, total):
    net = {"host": host, "cname": None, "scan": None}
    if not host:
        return net, "HOST_NONE", "%s: host empty" % step

    show_progress(pos, total, "%s_CNAME" % step)
    cname, e1, d1 = resolve_cname(host)
    if not e1 and cname:
        net["cname"] = cname

    scan_input = cname or host
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
def build_object_v3(row, obj_id, store_index, force, oem_conn, pos, total):

    raw = build_raw_source(row)
    raw_debug = build_raw_debug(row)

    cur = raw.get("Current connection string")
    new = raw.get("New connection string")
    dr  = raw.get("New connection string avec DR")

    cur_o, _, _ = interpret(cur)
    new_o, _, _ = interpret(new)
    dr_o,  _, _ = interpret(dr)

    net = {
        "Current": {"host": cur_o.host, "cname": None, "scan": None},
        "New":     {"host": new_o.host, "cname": None, "scan": None},
        "NewDR":   {"host": dr_o.host,  "cname": None, "scan": None},
        "OEM":     {"host": None, "port": None, "cname": None, "scan": None}
    }

    err_type = None
    err_detail = None

    net["Current"], e, d = compute_network_block(cur_o.host, "CURRENT", pos, total)
    if e:
        err_type, err_detail = e, d

    net["New"], e, d = compute_network_block(new_o.host, "NEW", pos, total)
    if e and not err_type:
        err_type, err_detail = e, d

    scan_status = "ERROR" if err_type else (
        "VALIDE" if compare(net["Current"]["scan"], net["New"]["scan"]) else "DIFFERENT"
    )

    scan_dr_status = None
    if dr_o and dr_o.valide:
        net["NewDR"], _, _ = compute_network_block(dr_o.host, "NEWDR", pos, total)
        scan_dr_status = (
            "VALIDE" if compare(net["Current"]["scan"], net["NewDR"]["scan"])
            else "DIFFERENT"
        )

    oem_err_type = None
    oem_err_detail = None

    show_progress(pos, total, "OEM_SQLPLUS")
    dbname = ustr(raw.get("Databases")).strip()
    if dbname:
        oh, op, oe, od = oem_get_host_and_port(oem_conn, dbname)
        if oe:
            oem_err_type, oem_err_detail = oe, od
        else:
            net["OEM"]["host"] = oh
            net["OEM"]["port"] = op
            net_oem, _, _ = compute_network_block(oh, "OEM", pos, total)
            net["OEM"]["cname"] = net_oem.get("cname")
            net["OEM"]["scan"]  = net_oem.get("scan")

    status = build_status(True, scan_status, scan_dr_status,
                          False, None, err_type, err_detail,
                          "FORCE_UPDATE" if force else "AUTO",
                          oem_err_type, oem_err_detail)

    return {
        "id": obj_id,
        "OEM": net["OEM"],
        "Network": net,
        "Status": status,
        "RawSource": raw,
        "RawSource_DEBUG": raw_debug
    }

# ------------------------------------------------
# MAIN
# ------------------------------------------------
if __name__ == "__main__":

    if len(sys.argv) < 2:
        print_help()
        sys.exit(0)

    option = sys.argv[1]
    args = [a.lower() for a in sys.argv[2:]]
    force = ("-force" in args) or ("-update" in args) or ("-upgrade" in args)

    conf, _, _ = load_main_conf()
    fichier = conf.get("SOURCE_CSV")
    STORE_FILE = conf.get("SOURCE_JSON")
    OEM_CONF = conf.get("OEM_CONF_FILE")

    oem_conn = None
    if OEM_CONF and os.path.isfile(OEM_CONF):
        for l in open(OEM_CONF):
            if l.strip().startswith("OEM_CONN="):
                oem_conn = l.split("=",1)[1].strip()

    rows = [normalize_row(r)
        for r in csv.DictReader(
            codecs.open(fichier, "r", "latin-1"),
            delimiter=';'
        )]

    store = load_store(STORE_FILE)
    index = build_index(store)

    targets = range(1, int(option.split("=")[1]) + 1) if "=" in option else []
    objs = []
    pos = 0
    total = len(targets)

    for oid in targets:
        pos += 1
        objs.append(build_object_v3(rows[oid-1], oid, index, force, oem_conn, pos, total))

    store["objects"] = objs
    save_store(STORE_FILE, store)

    print "\nAnalyseV3 terminé. Objets générés:", len(objs)
