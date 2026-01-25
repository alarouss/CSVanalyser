#!/usr/bin/env python
# -*- coding: utf-8 -*-

import csv
import sys
import time
import os

#from Lib.common import ustr
#from Lib.config import load_main_conf
from Lib.io_common import load_main_conf, ustr
from Lib.store import load_store, save_store, build_index
from Lib.jdbc_flow_v2 import interpret, compare, resolve_cname, resolve_scan
from Lib.oem_flow import oem_get_host_and_port

DEBUG = False

RAW_COLUMNS = [
    "Statut Global", "Lot", "Application", "Databases", "DR O/N",
    "Current connection string",
    "New connection string",
    "New connection string avec DR",
    "Cnames", "Services", "Acces", "Cnames DR"
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
 -force / -update / -upgrade   (recalcule et remplace les ids cibles)
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
# IMPORTANT: le CSV chez toi est souvent latin1/cp1252 => sinon "Terminé" devient "Termin"
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

# ------------------------------------------------
def _status(valid, scan, scan_dr, dirty, dirty_reason,
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
    """
    Applique la résolution CNAME / SCAN
    sur block = {"host":..., "cname":..., "scan":...}
    """
    host = block.get("host")
    if not host:
        return block, None, None

    show_progress(pos, total, "%s_CNAME" % step_prefix)
    cname, e1, d1 = resolve_cname(host)
    if not e1 and cname:
        block["cname"] = cname

    scan_input =  host
    show_progress(pos, total, "%s_SCAN" % step_prefix)
    if host in ("DR", "Primaire"):
        raise Exception("INVARIANT VIOLATION: host=%r" % host)
    scan, e2, d2 = resolve_scan(scan_input)
    if e2:
        block["scan"] = scan
        return block, e2, "%s: scan resolution failed for %s | %s" % (
            step_prefix, scan_input, d2
        )

    block["scan"] = scan
    return block, None, None
# ------------------------------------------------
def compute_block_status(block, had_error):
    """
    Déduit le statut logique d’un bloc réseau
    """
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
    if host in ("DR", "Primaire"):
        raise Exception("INVARIANT VIOLATION: host=%r" % host)
    scan, e2, d2 = resolve_scan(scan_input)
    if e2:
        net["scan"] = scan
        return net, e2, "%s: scan resolution failed for %s | %s" % (
            step, scan_input, d2
        )

    net["scan"] = scan
    return net, None, None

# ------------------------------------------------
def fill_net_from_addresses(parsed, net_side):
    """
    Remplit net_side {"Primaire":{}, "DR":{}}
    à partir de parsed (interpret).

    Règles :
      - ignore les tokens structurels ("DR", "PRIMARY", etc.)
      - addresses > host simple
    """

    if not parsed:
        return

    def is_valid_host(h):
        if not h:
            return False
        h = h.strip()
        # Rejeter mots-clés structurels
        if h.upper() in ("DR", "PRIMARY", "PRIMAIRE"):
            return False
        # Heuristique minimale host
        return ("." in h) or any(c.isdigit() for c in h)

    # 1️⃣ Cas addresses structurées
    addrs = getattr(parsed, "addresses", None)
    if addrs:
        if isinstance(addrs, basestring):
            addrs = [addrs]

        for a in addrs:
            if isinstance(a, dict):
                host = a.get("host")
                role = a.get("role") or "Primaire"
            else:
                host = a
                role = "Primaire"

            if not is_valid_host(host):
                continue

            if role not in net_side:
                role = "Primaire"

            net_side[role]["host"] = host

        return

    # 2️⃣ Fallback : host simple
    host = getattr(parsed, "host", None)
    if is_valid_host(host):
        net_side["Primaire"]["host"] = host

# ------------------------------------------------
def build_raw_source(row):
    """
    Source brute contractuelle (colonnes métier)
    → utilisée pour comparaison dirty + affichage ReportV3
    """
    raw = {}
    for c in RAW_COLUMNS:
        v = row.get(c, u"")
        if v is None:
            v = u""
        raw[c] = ustr(v).strip()
    return raw


# ------------------------------------------------
def build_raw_debug(row):
    """
    Source CSV complète (DEBUG)
    → ne sert qu’au diagnostic
    """
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

def build_object_v3(row, obj_id, oem_conn, pos, total, force):

    raw = build_raw_source(row)
    raw_debug = build_raw_debug(row)

    cur = raw.get("Current connection string")
    new = raw.get("New connection string")

    cur_o, ecur, dcur = interpret(cur)
    new_o, enew, dnew = interpret(new)

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

    fill_net_from_addresses(cur_o, net["Current"])
    fill_net_from_addresses(new_o, net["New"])

    valid = bool(cur_o.valide and new_o.valide)

    err_type = None
    err_detail = None
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

# ------------------------------------------------
def parse_target_ids(option, maxid):
    opt = (option or "").strip()

    if opt.lower() == "columns":
        return ("columns", None)

    low = opt.lower()
    if low.startswith("ligne="):
        v = opt.split("=", 1)[1].strip()
        if v.upper() == "ALL":
            return ("range", range(1, maxid + 1))
        return ("range", range(1, int(v) + 1))

    if low.startswith("id="):
        v = opt.split("=", 1)[1].strip()
        if "," in v:
            out = []
            for p in v.split(","):
                p = p.strip()
                if p:
                    out.append(int(p))
            return ("list", out)
        # IMPORTANT: id=N => UNITAIRE (contrat)
        return ("list", [int(v)])

    return (None, None)

# ------------------------------------------------
def read_oem_conn(oem_conf_file):
    if not oem_conf_file or not os.path.isfile(oem_conf_file):
        return None
    try:
        for l in open(oem_conf_file, "rb").read().splitlines():
            try:
                s = l.decode("utf-8", "ignore")
            except:
                s = l
            s = s.strip()
            if not s or s.startswith("#") or s.startswith(";"):
                continue
            if s.startswith("OEM_CONN="):
                return s.split("=", 1)[1].strip()
    except:
        return None
    return None

# ------------------------------------------------
# MAIN
# ------------------------------------------------
if __name__ == "__main__":

    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "-help"):
        print_help()
        sys.exit(0)

    option = sys.argv[1].strip()
    args = [a.lower() for a in sys.argv[2:]]
    force = ("-force" in args) or ("-update" in args) or ("-upgrade" in args)
    DEBUG = ("-debug" in args)

    conf, ce, cd = load_main_conf()
    if ce:
        print "Configuration error:", ce
        print cd
        sys.exit(1)

    fichier = conf.get("SOURCE_CSV")
    STORE_FILE = conf.get("SOURCE_JSON")
    OEM_CONF = conf.get("OEM_CONF_FILE")

    if not fichier or not os.path.isfile(fichier):
        print "CSV missing:", fichier
        sys.exit(1)

    oem_conn = read_oem_conn(OEM_CONF)

    # CSV en binaire (python2.6 csv exige bytes)
    reader = csv.DictReader(open(fichier, "rb"), delimiter=';')
    rows = [normalize_row(r) for r in reader]

    if not rows:
        print "CSV empty:", fichier
        sys.exit(0)

    kind, targets = parse_target_ids(option, len(rows))
    if not kind:
        print_help()
        sys.exit(1)

    if kind == "columns":
        for c in rows[0].keys():
            print c
        sys.exit(0)

    # Charger store
    store = load_store(STORE_FILE)
    index = build_index(store)

    # IDs existants
    existing = {}
    for o in store.get("objects", []):
        try:
            existing[int(o.get("id"))] = 1
        except:
            pass

    # Contrat :
    # - sans -update : skip tout id déjà présent (même dirty)
    # - avec -update : recalcul ids cibles et remplace uniquement ces ids
    targets = list(targets)
    targets.sort()

    ids_to_process = []
    skipped = 0
    for oid in targets:
        if oid < 1 or oid > len(rows):
            continue
        if (not force) and (oid in existing):
            skipped += 1
            continue
        ids_to_process.append(oid)

    # Log clair
    print "Targets:", len(targets), "| ToProcess:", len(ids_to_process), "| Skipped(existing):", skipped, "| Force:", ("YES" if force else "NO")

    if not ids_to_process:
        print "Nothing to do."
        sys.exit(0)

    # Keep:
    if force:
        target_set = dict((i, 1) for i in targets)
        keep = []
        for o in store.get("objects", []):
            try:
                oid = int(o.get("id"))
            except:
                oid = None
            if (oid is None) or (oid not in target_set):
                keep.append(o)
    else:
        keep = store.get("objects", [])[:]

    # Build
    objs = []
    total = len(ids_to_process)
    pos = 0

    for oid in ids_to_process:
        pos += 1
        row = rows[oid - 1]
        objs.append(build_object_v3(row, oid, oem_conn, pos, total, force))

    sys.stdout.write("\n")

    store["objects"] = keep + objs
    save_store(STORE_FILE, store)

    print "\nAnalyseV3 terminé."
    print "  objets générés :", len(objs)
    print "  skipped(existing) :", skipped
    print "  total store :", len(store.get('objects', []))
