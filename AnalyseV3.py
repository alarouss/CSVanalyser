#!/usr/bin/env python
# -*- coding: utf-8 -*-

import csv
import sys
import time
import os

from Lib.common import ustr
from Lib.config import load_main_conf
from Lib.store import load_store, save_store, build_index
from Lib.jdbc_flow_v2 import interpret, compare
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
    label = "Pos:%3d/%-3d | %-12s" % (pos, total, (step or "")[:12])
    label = "[%-26s]" % label
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
    """
    Règle demandée :
      - ligne=N   => cible 1..N
      - ligne=ALL => 1..maxid
      - id=N      => cible 1..N (incrémental)
      - id=1,2,5  => liste explicite
    """
    opt = (option or "").strip()

    if opt == "columns":
        return ("columns", None)

    if opt.lower().startswith("ligne="):
        v = opt.split("=", 1)[1].strip()
        if v.upper() == "ALL":
            return ("range", range(1, maxid + 1))
        return ("range", range(1, int(v) + 1))

    if opt.lower().startswith("id="):
        s = opt.split("=", 1)[1].strip()
        if "," in s:
            ids = []
            for part in s.split(","):
                part = part.strip()
                if part:
                    ids.append(int(part))
            return ("list", ids)
        # IMPORTANT: id=N = 1..N (comportement incrémental demandé)
        return ("range", range(1, int(s) + 1))

    return (None, None)

# ------------------------------------------------
def read_oem_conn(oem_conf_file):
    """
    Lit OEM_CONN depuis oem.conf (KEY=VALUE).
    Tolère espaces. Ne casse pas si absent.
    """
    if not oem_conf_file:
        return None

    if not os.path.isfile(oem_conf_file):
        return None

    try:
        for line in open(oem_conf_file, "rb").read().splitlines():
            try:
                s = line.decode("utf-8", "ignore")
            except:
                s = line
            s = s.strip()
            if not s:
                continue
            if s.startswith("#") or s.startswith(";"):
                continue
            if "=" not in s:
                continue
            k, v = s.split("=", 1)
            k = k.strip()
            v = v.strip()
            if k == "OEM_CONN":
                return v
    except:
        return None

    return None

# ------------------------------------------------
def build_object_v3(row, obj_id, store_index, force_update, oem_conn):
    raw = build_raw_source(row)

    cached = store_index.get(obj_id)
    dirty = False
    dirty_reason = None

    # Dirty seulement informatif (et utilisé surtout en mode force)
    if cached and cached.get("RawSource") != raw:
        dirty = True
        dirty_reason = "RAW_CHANGED"

    # JDBC + réseau (V2 flow)
    cur = raw.get("Current connection string")
    new = raw.get("New connection string")
    dr  = raw.get("New connection string avec DR")

    cur_o, e1, d1 = interpret(cur)
    new_o, e2, d2 = interpret(new)
    dr_o,  e3, d3 = interpret(dr)

    net = {
        "Current": {"host": cur_o.host, "cname": cur_o.cname, "scan": cur_o.scan},
        "New":     {"host": new_o.host, "cname": new_o.cname, "scan": new_o.scan},
        "NewDR":   {"host": dr_o.host,  "cname": dr_o.cname,  "scan": dr_o.scan},
        "OEM":     {"host": None, "port": None, "cname": None, "scan": None}
    }

    # Comparaison SCAN (Current vs New)
    err_type = None
    err_detail = None
    scan_status = None
    scan_dr_status = None

    if e1 or e2:
        scan_status = "ERROR"
        err_type = e1 or e2
        err_detail = d1 or d2
    else:
        eq = compare(cur_o.scan, new_o.scan)
        if eq is None:
            scan_status = "ERROR"
            err_type = "SCAN_COMPARE_ERROR"
            err_detail = "Normalization failed"
        else:
            scan_status = "VALIDE" if eq else "DIFFERENT"
            if not eq:
                err_type = "SCAN_DIFFERENT"
                err_detail = "Current and New SCAN differ"

    # DR compare (optionnel)
    if dr_o and dr_o.valide:
        if e3:
            scan_dr_status = "ERROR"
        else:
            eqdr = compare(cur_o.scan, dr_o.scan)
            scan_dr_status = "VALIDE" if eqdr else "DIFFERENT"

    # OEM (host/port + erreurs traçables)
    oem_err_type = None
    oem_err_detail = None

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

    mode = "FORCE_UPDATE" if force_update else ("AUTO_DIRTY" if dirty else "AUTO")

    status = build_status(True, scan_status, scan_dr_status,
                          dirty, dirty_reason,
                          err_type, err_detail,
                          mode,
                          oem_err_type=oem_err_type,
                          oem_err_detail=oem_err_detail)

    return {
        "id": obj_id,
        "RawSource": raw,
        "Network": net,
        "Status": status
    }

# ------------------------------------------------
if __name__ == "__main__":

    # Help
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "-help"):
        print_help()
        sys.exit(0)

    option = sys.argv[1].strip()
    args = [a.lower() for a in sys.argv[2:]]

    DEBUG = ("-debug" in args)

    # IMPORTANT: force synonyms (update/upgrade)
    force_update = ("-force" in args) or ("-update" in args) or ("-upgrade" in args)

    # Load config
    main_conf, mce, mcd = load_main_conf()
    if mce:
        print "Configuration error:", mce
        print mcd
        sys.exit(1)

    fichier = main_conf.get("SOURCE_CSV")
    STORE_FILE = main_conf.get("SOURCE_JSON")
    OEM_CONF_FILE = main_conf.get("OEM_CONF_FILE")

    if not fichier or not os.path.isfile(fichier):
        print "CSV missing:", fichier
        sys.exit(1)

    # OEM_CONN (peut être None : on trace l'erreur dans Status OEM)
    oem_conn = read_oem_conn(OEM_CONF_FILE)

    # Read CSV
    reader = csv.DictReader(open(fichier, "rb"),
                            delimiter=';',
                            quotechar='"',
                            skipinitialspace=True)
    rows = [normalize_row(r) for r in reader]

    if option == "columns":
        if not rows:
            print "No rows in CSV."
            sys.exit(0)
        for c in rows[0].keys():
            print c
        sys.exit(0)

    opt_kind, target_ids = parse_target_ids(option, len(rows))
    if not opt_kind:
        print_help()
        sys.exit(1)

    # Load store + index
    store = load_store(STORE_FILE)
    store_index = build_index(store)

    existing_ids = {}
    for o in store.get("objects", []):
        try:
            existing_ids[int(o.get("id"))] = 1
        except:
            pass

    # Calcul incrémental demandé :
    # - sans force : on NE TOUCHE PAS à l'existant, on ajoute seulement les ids manquants
    # - avec force : on RECALCULE et on REMPLACE les ids de la cible
    if force_update:
        ids_to_run = list(target_ids)
    else:
        ids_to_run = []
        for i in target_ids:
            if int(i) not in existing_ids:
                ids_to_run.append(int(i))

    if not ids_to_run:
        print "Nothing to do (no new ids)."
        sys.exit(0)

    # Préparer la liste des objets à conserver / remplacer
    if force_update:
        # on remplace uniquement la cible
        target_set = {}
        for i in target_ids:
            target_set[int(i)] = 1
        keep = []
        for o in store.get("objects", []):
            oid = o.get("id")
            try:
                oid = int(oid)
            except:
                oid = None
            if oid is None or oid not in target_set:
                keep.append(o)
    else:
        # sans force : on garde tout
        keep = store.get("objects", [])[:]

    # Construire les nouveaux objets (dans l'ordre des ids)
    ids_to_run.sort()
    objs = []
    total = len(ids_to_run)
    pos = 0

    # index accès CSV : rows est 0-based ; id est 1-based
    for obj_id in ids_to_run:
        if obj_id < 1 or obj_id > len(rows):
            continue
        pos += 1
        show_progress(pos, total, "ID=%d" % obj_id)
        r = rows[obj_id - 1]
        objs.append(build_object_v3(r, obj_id, store_index, force_update, oem_conn))

    sys.stdout.write("\n")

    store["objects"] = keep + objs
    save_store(STORE_FILE, store)

    print "\nAnalyseV3 terminé. Objets générés:", len(objs)
