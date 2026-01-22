#!/usr/bin/env python
# -*- coding: utf-8 -*-

import csv
import sys
import time
import os

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
 -force / -update / -upgrade   (force recalcul + remplace l'existant)
 -h | --help | -help
"""

# ------------------------------------------------
def show_progress(pos, total, step):
    try:
        percent = int((float(pos) / float(total)) * 100) if total else 100
    except:
        percent = 100
    if percent < 0: percent = 0
    if percent > 100: percent = 100

    bar = "." * int(percent / 2)
    label = "Pos:%3d/%-3d | %-14s" % (pos, total, (step or "")[:14])
    label = "[%-30s]" % label
    sys.stdout.write("\rProgress: %s %-50s %3d%%\033[K" % (label, bar, percent))
    sys.stdout.flush()

# ------------------------------------------------
def normalize_key(k):
    return ustr(k).replace(u'\ufeff', u'').strip()

def normalize_row(row):
    out = {}
    for k, v in row.items():
        out[normalize_key(k)] = ustr(v)
    return out

# ------------------------------------------------
def build_raw_source(row):
    raw = {}
    for c in RAW_COLUMNS:
        v = row.get(c, u"")
        if v is None:
            v = u""
        raw[c] = ustr(v).strip()
    return raw

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
def parse_target_ids(option, maxid):
    if option == "columns":
        return ("columns", None)

    if option.lower().startswith("ligne="):
        v = option.split("=", 1)[1].strip()
        if v.upper() == "ALL":
            return ("range", range(1, maxid + 1))
        return ("range", range(1, int(v) + 1))

    if option.lower().startswith("id="):
        s = option.split("=", 1)[1].strip()
        if "," in s:
            ids = []
            for part in s.split(","):
                part = part.strip()
                if part:
                    ids.append(int(part))
            return ("list", ids)
        # IMPORTANT: id=N => 1..N (incrémental)
        return ("range", range(1, int(s) + 1))

    return (None, None)

# ------------------------------------------------
def read_oem_conn(path):
    if not path or not os.path.isfile(path):
        return None
    try:
        for l in open(path, "rb").read().splitlines():
            try:
                s = l.decode("utf-8", "ignore")
            except:
                s = l
            s = s.strip()
            if not s:
                continue
            if s.startswith("#") or s.startswith(";"):
                continue
            if "=" not in s:
                continue
            k, v = s.split("=", 1)
            if k.strip() == "OEM_CONN":
                return v.strip()
    except:
        return None
    return None

# ------------------------------------------------
def compute_network_block(host, step_prefix, pos, total):
    """
    Flux V2 corrigé:
      host -> cname (nslookup)
      puis scan via resolve_scan( cname si dispo sinon host )
    """
    net = {"host": host, "cname": None, "scan": None}

    if not host:
        return net, "HOST_NONE", ("%s: host empty" % step_prefix)

    # CNAME
    show_progress(pos, total, "%s_CNAME" % step_prefix)
    cname, e1, d1 = resolve_cname(host)
    if not e1 and cname:
        net["cname"] = cname

    # SCAN (IMPORTANT: si cname absent -> utiliser host)
    scan_input = net["cname"] or host
    show_progress(pos, total, "%s_SCAN" % step_prefix)
    scan, e2, d2 = resolve_scan(scan_input)
    if e2:
        # on garde scan éventuellement renvoyé
        net["scan"] = scan
        return net, e2, ("%s: scan resolution failed for %s | %s" %
                         (step_prefix, scan_input, d2))

    net["scan"] = scan
    return net, None, None

# ------------------------------------------------
def build_object_v3(row, obj_id, store_index, force_update, oem_conn, pos, total):

    raw = build_raw_source(row)

    cached = store_index.get(obj_id)
    dirty = False
    dirty_reason = None
    if cached and cached.get("RawSource") != raw:
        dirty = True
        dirty_reason = "RAW_CHANGED"

    # PARSE
    show_progress(pos, total, "PARSE")
    cur = raw.get("Current connection string")
    new = raw.get("New connection string")
    dr  = raw.get("New connection string avec DR")

    cur_o, e1, d1 = interpret(cur)
    new_o, e2, d2 = interpret(new)
    dr_o,  e3, d3 = interpret(dr)

    net = {
        "Current": {"host": cur_o.host, "cname": None, "scan": None},
        "New":     {"host": new_o.host, "cname": None, "scan": None},
        "NewDR":   {"host": dr_o.host,  "cname": None, "scan": None},
        "OEM":     {"host": None, "port": None, "cname": None, "scan": None}
    }

    # Network CURRENT/NEW (+ erreurs)
    err_type = None
    err_detail = None

    net_cur, ecur, dcur = compute_network_block(cur_o.host, "CURRENT", pos, total)
    net["Current"] = net_cur
    if ecur:
        err_type = ecur
        err_detail = dcur

    net_new, enew, dnew = compute_network_block(new_o.host, "NEW", pos, total)
    net["New"] = net_new
    if enew and (not err_type):
        err_type = enew
        err_detail = dnew

    # Compare
    scan_status = None
    if err_type:
        scan_status = "ERROR"
    else:
        eq = compare(net["Current"].get("scan"), net["New"].get("scan"))
        if eq is None:
            scan_status = "ERROR"
            err_type = "SCAN_COMPARE_ERROR"
            err_detail = "Normalization failed"
        else:
            scan_status = "VALIDE" if eq else "DIFFERENT"
            if not eq:
                err_type = "SCAN_DIFFERENT"
                err_detail = "Current and New SCAN differ"

    # DR optionnel
    scan_dr_status = None
    if dr_o and dr_o.valide:
        net_dr, edr, ddr = compute_network_block(dr_o.host, "NEWDR", pos, total)
        net["NewDR"] = net_dr
        if edr:
            scan_dr_status = "ERROR"
        else:
            eqdr = compare(net["Current"].get("scan"), net["NewDR"].get("scan"))
            scan_dr_status = "VALIDE" if eqdr else "DIFFERENT"

    # OEM
    oem_err_type = None
    oem_err_detail = None

    show_progress(pos, total, "OEM_SQLPLUS")
    dbname = ustr(raw.get("Databases", u"")).strip()
    if not dbname:
        oem_err_type = "OEM_DBNAME_EMPTY"
        oem_err_detail = "Databases column empty"
    else:
        oh, op, oe, od = oem_get_host_and_port(oem_conn, dbname)
        if oe:
            oem_err_type = oe
            oem_err_detail = od
        else:
            net["OEM"]["host"] = oh
            net["OEM"]["port"] = op

            # OEM cname/scan comme V2
            net_oem, eo, do = compute_network_block(oh, "OEM", pos, total)
            net["OEM"]["cname"] = net_oem.get("cname")
            net["OEM"]["scan"] = net_oem.get("scan")
            if eo and (not oem_err_type):
                oem_err_type = eo
                oem_err_detail = do

    mode = "FORCE_UPDATE" if force_update else ("AUTO_DIRTY" if dirty else "AUTO")

    status = build_status(True, scan_status, scan_dr_status,
                          dirty, dirty_reason,
                          err_type, err_detail,
                          mode,
                          oem_err_type=oem_err_type,
                          oem_err_detail=oem_err_detail)

    # IMPORTANT: rendre OEM visible pour ReportV3 (racine + Network)
    obj = {
        "id": obj_id,
        "RawSource": raw,
        "Network": net,
        "Status": status,
        "OEM": net.get("OEM")  # <-- duplication au niveau racine
    }
    return obj

# ------------------------------------------------
if __name__ == "__main__":

    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "-help"):
        print_help()
        sys.exit(0)

    option = sys.argv[1].strip()
    args = [a.lower() for a in sys.argv[2:]]

    force_update = ("-force" in args) or ("-update" in args) or ("-upgrade" in args)

    main_conf, mce, mcd = load_main_conf()
    if mce:
        print "Configuration error:", mce
        print mcd
        sys.exit(1)

    fichier = main_conf.get("SOURCE_CSV")
    STORE_FILE = main_conf.get("SOURCE_JSON")
    OEM_CONF_FILE = main_conf.get("OEM_CONF_FILE")

    oem_conn = read_oem_conn(OEM_CONF_FILE)

    rows = [normalize_row(r) for r in csv.DictReader(open(fichier, "rb"), delimiter=';')]

    if option == "columns":
        if not rows:
            print "No rows in CSV."
            sys.exit(0)
        for c in rows[0].keys():
            print c
        sys.exit(0)

    kind, targets = parse_target_ids(option, len(rows))
    if not kind:
        print_help()
        sys.exit(1)

    store = load_store(STORE_FILE)
    index = build_index(store)

    existing_ids = {}
    for o in store.get("objects", []):
        try:
            existing_ids[int(o.get("id"))] = 1
        except:
            pass

    # incrémental:
    if force_update:
        ids_to_run = list(targets)
    else:
        ids_to_run = []
        for i in targets:
            if int(i) not in existing_ids:
                ids_to_run.append(int(i))

    if not ids_to_run:
        print "Nothing to do (no new ids)."
        sys.exit(0)

    # keep:
    if force_update:
        target_set = {}
        for i in targets:
            target_set[int(i)] = 1
        keep = []
        for o in store.get("objects", []):
            try:
                oid = int(o.get("id"))
            except:
                oid = None
            if oid is None or oid not in target_set:
                keep.append(o)
    else:
        keep = store.get("objects", [])[:]

    ids_to_run.sort()

    objs = []
    total = len(ids_to_run)
    pos = 0

    for obj_id in ids_to_run:
        if obj_id < 1 or obj_id > len(rows):
            continue
        pos += 1
        r = rows[obj_id - 1]
        objs.append(build_object_v3(r, obj_id, index, force_update, oem_conn, pos, total))

    sys.stdout.write("\n")

    store["objects"] = keep + objs
    save_store(STORE_FILE, store)

    print "\nAnalyseV3 terminé. Objets générés:", len(objs)
