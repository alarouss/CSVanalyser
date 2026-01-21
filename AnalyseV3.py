#!/usr/bin/env python
# -*- coding: utf-8 -*-
# AnalyseV3.py  (base = AnalyseV2 + ajout OEM, sans régression)

import csv
import re
import sys
import subprocess
import json
import time
import os
import tempfile
from Lib.store import load_store, save_store, build_index
from Lib.jdbc import (
    JdbcChaine, clean_jdbc, parse_simple_jdbc, parse_sqlnet_jdbc,
    parse_jdbc, extract_dr_hosts, build_interpreted, build_raw_source
)
from Lib.network import (
    resolve_cname, resolve_scan_address,
    normalize_scan_name, compare_scans,
    compute_network_block
)
from Lib.config import load_config

STORE_FILE = "Data/connexions_store_v3.json"   # on garde le store identique (même fichier)
DEBUG = False

# Fichier de paramètres OEM (dans le répertoire courant)
OEM_CONF_FILE = "oem.conf"               # contient OEM_CONN=...
# Exemple oem.conf :
#   OEM_CONN=user/pass@tns
# (si tu veux un connect plus sécurisé : voir notes en bas)

RAW_COLUMNS = [
    "Statut Global", "Lot", "Application", "Databases", "DR O/N",
    "Current connection string",
    "New connection string",
    "New connection string  avec DR",
    "Cnames", "Services", "Acces", "Cnames DR"
]

# ------------------------------------------------
def print_help():
    print """AnalyseV3.py - Analyse JDBC Oracle V3 (V2 + OEM)

Usage:
 python AnalyseV3.py file.csv ligne=N|ALL [OPTIONS]
 python AnalyseV3.py file.csv id=N [OPTIONS]
 python AnalyseV3.py file.csv id=1,2,5 [OPTIONS]
 python AnalyseV3.py file.csv columns

Options:
 -debug
 -force     (recalcule reseau: nslookup/srvctl + OEM sqlplus, ignore cache)
 -update    (alias de -force)
 -h | -help | --help

OEM:
 - Le script lit oem.conf (dans le répertoire courant) et attend la variable:
     N=...   (chaine pour sqlplus)
 - OEM est stocké dans JSON sous Network/OEM : host,cname,scan (+ port optionnel)
"""

# ------------------------------------------------
def debug_print(msg):
    if DEBUG:
        try:
            print msg
        except:
            pass

# ------------------------------------------------
def ustr(v):
    """Return unicode in py2 safely."""
    if v is None:
        return u""
    if isinstance(v, unicode):
        return v
    if isinstance(v, str):
        try:
            return v.decode("latin1", "ignore")
        except:
            return unicode(v, "latin1", "ignore")
    try:
        return unicode(str(v), "latin1", "ignore")
    except:
        return u""

def normalize_key(k):
    return ustr(k).replace(u'\ufeff', u'').strip()

def normalize_row(row):
    out = {}
    for k, v in row.items():
        out[normalize_key(k)] = ustr(v)
    return out

# ------------------------------------------------
# Progress (signature fixe comme demandé)
def show_progress(idval, total, step):
    """
    - total = total lignes CSV (pas le nombre d'ids sélectionnés)
    - percent = idval/total
    - label entre [] largeur fixe, step tronqué
    """
    try:
        percent = int((float(idval) / float(total)) * 100) if total else 100
    except:
        percent = 100

    if percent < 0: percent = 0
    if percent > 100: percent = 100

    dots = int(percent / 2)
    bar = "." * dots

    # label largeur fixe
    # Id:99999/99999 -> 5 digits max (ok)
    step_txt = (step or "")[:12]
    label_core = "Id:%5d/%-5d | %-12s" % (int(idval), int(total), step_txt)
    label = "[%-34s]" % label_core  # fixe

    sys.stdout.write("\rProgress: %s %-50s %3d%%\033[K" % (label, bar, percent))
    sys.stdout.flush()

# ------------------------------------------------
# DNS: CNAME via nslookup (Name/Nom)
def resolve_cname(host):
    try:
        if not host:
            return None, "CNAME_HOST_NONE", "Host is None"

        p = subprocess.Popen(["nslookup", host],
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        out, err = p.communicate()
        output = out.decode("utf-8", "ignore")

        cname = None
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("Nom") or line.startswith("Name"):
                parts = line.split(":", 1)
                if len(parts) == 2:
                    cname = parts[1].strip()
                    break

        if not cname:
            return None, "CNAME_NSLOOKUP_ERROR", "No Name/Nom in nslookup for " + host

        if "," in cname:
            cname = cname.split(",")[0].strip()

        return cname, None, None
    except Exception as e:
        return None, "CNAME_EXCEPTION", str(e)

# ------------------------------------------------
# SCAN engine (nslookup si scan, sinon ssh srvctl)
def resolve_scan_address(host):
    try:
        if not host:
            return None, "HOST_NONE", "Host is None"

        if "scan" in host.lower():
            p = subprocess.Popen(["nslookup", host],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            out, err = p.communicate()
            output = out.decode("utf-8", "ignore")
            for line in output.splitlines():
                line = line.strip()
                if line.startswith("Nom") or line.startswith("Name"):
                    return line.split(":", 1)[1].strip(), None, None
            return None, "NSLOOKUP_ERROR", "No Name in nslookup for " + host

        cmd = ["ssh",
               "-o", "StrictHostKeyChecking=no",
               "-o", "UserKnownHostsFile=/dev/null",
               "oracle@%s" % host,
               ". /home/oracle/.bash_profile ; srvctl config scan"]
        p = subprocess.Popen(cmd,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        out, err = p.communicate()
        output = out.decode("utf-8", "ignore")
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("SCAN name"):
                result = line.split(":", 1)[1].strip()
                if "," in result:
                    result = result.split(",")[0].strip()
                return result, None, None
        return None, "SRVCTL_ERROR", "No SCAN name in srvctl for " + host
    except Exception as e:
        return None, "EXCEPTION", str(e)

def normalize_scan_name(name):
    if not name:
        return None
    name = name.strip()
    if "," in name:
        name = name.split(",")[0].strip()
    if "." in name:
        name = name.split(".")[0].strip()
    return name.lower()


# ------------------------------------------------
def build_status(valid, scan, scan_dr, dirty, dirty_reason, err_type, err_detail, mode,
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
    # OEM erreurs séparées (ne casse pas l'existant)
    if oem_err_type or oem_err_detail:
        st["OEMErrorType"] = oem_err_type
        st["OEMErrorDetail"] = oem_err_detail
    return st

# ------------------------------------------------
# OEM conf
def load_oem_conf():
    """
    Cherche oem.conf dans :
      - répertoire courant
      - Data/
    """
    paths = [
        OEM_CONF_FILE,
        os.path.join("Data", OEM_CONF_FILE)
    ]

    conf_path = None
    for p in paths:
        if os.path.isfile(p):
            conf_path = p
            break

    if not conf_path:
        return None, "OEM_CONF_MISSING", "Missing %s in current directory or Data/" % OEM_CONF_FILE

    d = {}
    try:
        for line in open(conf_path, "rb").read().splitlines():
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
            if k:
                d[k] = v

        if "OEM_CONN" not in d or not d.get("OEM_CONN"):
            return None, "OEM_CONF_INVALID", "OEM_CONN is missing or empty in %s" % conf_path

        return d, None, None

    except Exception as e:
        return None, "OEM_CONF_ERROR", str(e)

# ------------------------------------------------
# OEM sqlplus query
def oem_get_host_and_port(oem_conn, target_name):
    """
    Appelle sqlplus -s OEM_CONN et retourne (host, port, err_type, err_detail)
    """
    if not oem_conn:
        return None, None, "OEM_CONN_EMPTY", "OEM_CONN is empty"
    if not target_name:
        return None, None, "OEM_TARGET_EMPTY", "Database target name is empty"

    # Script sqlplus minimal, sortie parsable
    # On sort HOST_NAME|PORT sur une seule ligne
    sql = []
    sql.append("set pages 0")
    sql.append("set head off")
    sql.append("set feed off")
    sql.append("set verify off")
    sql.append("set echo off")
    sql.append("set trimspool on")
    sql.append("set lines 400")
    sql.append("define TNAME='%s'" % target_name.replace("'", "''"))
    sql.append("""
select A.HOST_NAME||'|'||F.property_value
from SYSMAN.MGMT$DB_DBNINSTANCEINFO A, SYSMAN.MGMT$TARGET_PROPERTIES F
where A.TARGET_NAME='&&TNAME'
  and F.TARGET_GUID = A.TARGET_GUID
  and F.property_name = 'Port';
""".strip())
    sql.append("exit")
    payload = "\n".join(sql) + "\n"

    try:
        p = subprocess.Popen(["sqlplus", "-s", oem_conn],
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        out, err = p.communicate(payload)
        rc = p.returncode

        # parse
        o = out.decode("utf-8", "ignore").strip()
        e = err.decode("utf-8", "ignore").strip()

        if rc not in (0, None):
            return None, None, "OEM_SQLPLUS_ERROR", "sqlplus rc=%s | %s" % (rc, e or o)

        if not o:
            return None, None, "OEM_NO_RESULT", "No output for target %s" % target_name

        # prendre la première ligne non vide
        line = None
        for ln in o.splitlines():
            ln = ln.strip()
            if ln:
                line = ln
                break
        if not line:
            return None, None, "OEM_NO_RESULT", "No data line for target %s" % target_name

        # HOST|PORT
        if "|" in line:
            h, prt = line.split("|", 1)
            h = h.strip()
            prt = prt.strip()
        else:
            h = line.strip()
            prt = None

        if not h:
            return None, None, "OEM_BAD_OUTPUT", "Bad output line: %s" % line

        return h, prt, None, None

    except Exception as ex:
        return None, None, "OEM_EXCEPTION", str(ex)

# ------------------------------------------------
def compute_network_block(host, step_prefix, obj_id, total_csv):
    """
    Calcule host/cname/scan.
    - Affiche progress stable (basé sur obj_id / total_csv)
    """
    net = {"host": host, "cname": None, "scan": None}
    if not host:
        return net, "HOST_NONE", ("%s: host is empty" % step_prefix)

    show_progress(obj_id, total_csv, "%s_CNAME" % step_prefix)
    cname, e1, d1 = resolve_cname(host)
    if e1:
        return net, "CNAME_ERROR", ("%s: nslookup cname failed for host=%s | %s" % (step_prefix, host, d1))
    net["cname"] = cname

    show_progress(obj_id, total_csv, "%s_SCAN" % step_prefix)
    scan, e2, d2 = resolve_scan_address(cname)
    if e2:
        net["scan"] = scan
        return net, e2, ("%s: scan resolution failed for cname=%s | %s" % (step_prefix, cname, d2))
    net["scan"] = scan
    return net, None, None

def compare_scans(scan_a, scan_b):
    na = normalize_scan_name(scan_a)
    nb = normalize_scan_name(scan_b)
    if (not na) or (not nb):
        return None
    return (na == nb)

# ------------------------------------------------
def build_object_v3(row, obj_id, store_index, force_update, total_csv, oem_conn):
    raw = build_raw_source(row, RAW_COLUMNS)
    interpreted = build_interpreted(raw)

    cached = store_index.get(obj_id)
    dirty = False
    dirty_reason = None

    if cached and cached.get("RawSource") != raw:
        dirty = True
        dirty_reason = "RAW_CHANGED"

    # PARSE progress
    show_progress(obj_id, total_csv, "PARSE")

    pc = interpreted.get("ParsedCurrentJdbc", {})
    pn = interpreted.get("ParsedNewJdbc", {})
    pdr = interpreted.get("ParsedNewJdbcDR", {})

    valid_main = bool(pc.get("valide")) and bool(pn.get("valide"))

    # Cache mode: objet déjà présent + RawSource identique + pas force => on ne refait pas réseau, ni OEM
    if cached and (not dirty) and (not force_update):
        st = cached.get("Status", {})
        st["Mode"] = "AUTO_CACHE"
        return {
            "id": obj_id,
            "RawSource": raw,
            "Interpreted": interpreted,
            "Network": cached.get("Network", {}),
            "Status": st
        }

    mode = "FORCE_UPDATE" if force_update else ("AUTO_DIRTY" if dirty else "AUTO")

    # Network skeleton (inclut OEM)
    net = {
        "Current": {"host": pc.get("host"), "cname": None, "scan": None},
        "New": {"host": pn.get("host"), "cname": None, "scan": None},
        "NewDR": {"host": pdr.get("host"), "cname": None, "scan": None},
        "OEM": {"host": None, "port": None, "cname": None, "scan": None}
    }

    scan_status = None
    scan_dr_status = None
    err_type = None
    err_detail = None

    oem_err_type = None
    oem_err_detail = None

    # Si main syntax invalide: on ne fait pas réseau Current/New/DR (comme V2)
    if not valid_main:
        scan_status = "ERROR"
        err_type = "SYNTAX_ERROR"
        err_detail = "Parsing failed for CurrentJdbc or NewJdbc"
        status = build_status(False, scan_status, scan_dr_status, dirty, dirty_reason, err_type, err_detail, mode)
        return {
            "id": obj_id,
            "RawSource": raw,
            "Interpreted": interpreted,
            "Network": net,
            "Status": status
        }

    # CURRENT
    net_cur, ecur, dcur = compute_network_block(host, step, obj_id, total_csv)
    net["Current"] = net_cur
    if ecur and (not err_type):
        err_type = ecur
        err_detail = dcur

    # NEW
    net_new, enew, dnew = compute_network_block(net["New"]["host"], "NEW", obj_id, total_csv)
    net["New"] = net_new
    if enew and (not err_type):
        err_type = enew
        err_detail = dnew

    # Compare Current vs New (seule règle d'erreur principale)
    if err_type:
        scan_status = "ERROR"
    else:
        eq = compare_scans(net["Current"].get("scan"), net["New"].get("scan"))
        if eq is None:
            scan_status = "ERROR"
            err_type = "SCAN_COMPARE_ERROR"
            err_detail = "Normalization failed for SCAN compare (Current vs New)"
        else:
            scan_status = "VALIDE" if eq else "DIFFERENT"
            if not eq:
                err_type = "SCAN_DIFFERENT"
                err_detail = "SCAN differs between Current and New (current=%s, new=%s)" % (
                    ustr(net["Current"].get("scan")).encode("utf-8"),
                    ustr(net["New"].get("scan")).encode("utf-8")
                )

    # DR (info + règle A existante)
    if interpreted.get("NewJdbcDR"):
        valid_dr = bool(pc.get("valide")) and bool(pdr.get("valide"))
        if not valid_dr:
            scan_dr_status = "ERROR"
            if not err_type:
                err_type = "SYNTAX_ERROR_DR"
                err_detail = "Parsing failed for DR comparison (CurrentJdbc or NewJdbcDR)"
        else:
            net_dr, edr, ddr = compute_network_block(net["NewDR"]["host"], "NEWDR", obj_id, total_csv)
            net["NewDR"] = net_dr
            if edr:
                scan_dr_status = "ERROR"
                if not err_type:
                    err_type = edr
                    err_detail = ddr
            else:
                eqdr = compare_scans(net["Current"].get("scan"), net["NewDR"].get("scan"))
                if eqdr is None:
                    scan_dr_status = "ERROR"
                    if not err_type:
                        err_type = "SCAN_COMPARE_ERROR_DR"
                        err_detail = "Normalization failed for SCAN compare (Current vs DR)"
                else:
                    scan_dr_status = "VALIDE" if eqdr else "DIFFERENT"

                # Règle A: DR ne doit pas pointer vers le même scan que primary/new
                same_as_current = compare_scans(net["NewDR"].get("scan"), net["Current"].get("scan"))
                same_as_new = compare_scans(net["NewDR"].get("scan"), net["New"].get("scan"))
                if (same_as_current is True) or (same_as_new is True):
                    scan_dr_status = "ERROR"
                    if not err_type:
                        err_type = "DR_SAME_AS_PRIMARY"
                        err_detail = "DR points to same SCAN as primary/new (dr=%s, current=%s, new=%s)" % (
                            ustr(net["NewDR"].get("scan")).encode("utf-8"),
                            ustr(net["Current"].get("scan")).encode("utf-8"),
                            ustr(net["New"].get("scan")).encode("utf-8")
                        )
                    else:
                        # on n'écrase pas l'erreur principale, on ajoute juste une info
                        try:
                            err_detail = (ustr(err_detail) + u" | DR_SAME_AS_PRIMARY").encode("utf-8")
                        except:
                            pass

    # OEM (toujours calculé si objet nouveau/dirty/force)
    # host OEM = via sqlplus OEM, basé sur "Databases"
    dbname = ustr(raw.get("Databases", u"")).strip()
    if dbname:
        show_progress(obj_id, total_csv, "OEM_SQLPLUS")
        oem_host, oem_port, oe, od = oem_get_host_and_port(oem_conn, dbname)
        if oe:
            oem_err_type = oe
            oem_err_detail = od
        else:
            net["OEM"]["host"] = oem_host
            net["OEM"]["port"] = oem_port

            # réseau OEM : cname/scan
            net_oem, eo2, do2 = compute_network_block(oem_host, "OEM", obj_id, total_csv)
            # merge en gardant port
            net["OEM"]["cname"] = net_oem.get("cname")
            net["OEM"]["scan"] = net_oem.get("scan")
            if eo2 and (not oem_err_type):
                oem_err_type = eo2
                oem_err_detail = do2
    else:
        oem_err_type = "OEM_DBNAME_EMPTY"
        oem_err_detail = "Databases field is empty; cannot query OEM"

    status = build_status(True, scan_status, scan_dr_status, dirty, dirty_reason,
                          err_type, err_detail, mode,
                          oem_err_type=oem_err_type, oem_err_detail=oem_err_detail)

    return {
        "id": obj_id,
        "RawSource": raw,
        "Interpreted": interpreted,
        "Network": net,
        "Status": status
    }

# ------------------------------------------------
def parse_ids(option, max_id):
    """
    id=N or id=1,2,5
    ligne=N or ligne=ALL
    """
    opt = option.strip()
    if opt.lower().startswith("id="):
        s = opt.split("=", 1)[1].strip()
        if "," in s:
            out = []
            for part in s.split(","):
                part = part.strip()
                if part:
                    out.append(int(part))
            return out
        return [int(s)]
    if opt.lower().startswith("ligne="):
        v = opt.split("=", 1)[1].strip()
        if v.upper() == "ALL":
            return range(1, max_id + 1)
        return range(1, int(v) + 1)
    return None

# ------------------------------------------------
if __name__ == "__main__":
    conf = load_config("Data/app.conf")

    CSV_FILE   = conf.get("CSV_INPUT")
    STORE_FILE = conf.get("STORE_JSON")
    OEM_CONF_FILE = conf.get("OEM_CONF")

    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "-help"):
        print_help()
        sys.exit(0)

    fichier = CSV_FILE
    if len(sys.argv) < 3:
        print_help()
        sys.exit(1)
    if not os.path.isfile(fichier):
        print "CSV file not found:", fichier
        sys.exit(1)
        
    option = sys.argv[1]
    args = [a.lower() for a in sys.argv[2:]]

    DEBUG = ("-debug" in args)
    force_update = ("-force" in args) or ("-update" in args)

    # OEM conf obligatoire si on doit calculer (new/dirty/force)
    conf, ce, cd = load_oem_conf()
    if ce:
        # Si on ne veut pas casser un run "columns"
        if option != "columns":
            print "OEM configuration error:", ce
            print cd
            sys.exit(1)
        conf = None
    oem_conn = conf.get("OEM_CONN") if conf else None

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

    ids = parse_ids(option, len(rows))
    if not ids:
        print_help()
        sys.exit(1)

    # Load store / index
    store = load_store(STORE_FILE)
    store_index = build_index(store)

    # Rebuild objects list: keep existing not in ids, update ids
    existing = store.get("objects", [])
    keep = []
    for o in existing:
        oid = o.get("id")
        if oid not in ids:
            keep.append(o)

    objects = []
    total_csv = len(rows)

    idx = 1
    for r in rows:
        if idx in ids:
            obj = build_object_v3(r, idx, store_index, force_update, total_csv, oem_conn)
            objects.append(obj)
        idx += 1

    # End progress line
    sys.stdout.write("\n")

    store["objects"] = keep + objects
    save_store(STORE_FILE, store)

    print "\nAnalyseV3 terminé. Objets générés:", len(objects)
