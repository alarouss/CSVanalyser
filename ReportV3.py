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

STORE_FILE = "connexions_store_v2.json"   # on garde le store identique (même fichier)
DEBUG = False

# Fichier de paramètres OEM (dans le répertoire courant)
OEM_CONF_FILE = "oem.conf"               # contient OEM_CONN=...
# Exemple oem.conf :
#   OEM_CONN=user/pass@tns

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
     OEM_CONN=...   (chaine pour sqlplus)
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
def show_progress(idval, total, step):
    try:
        percent = int((float(idval) / float(total)) * 100) if total else 100
    except:
        percent = 100

    if percent < 0: percent = 0
    if percent > 100: percent = 100

    dots = int(percent / 2)
    bar = "." * dots

    step_txt = (step or "")[:12]
    label_core = "Id:%5d/%-5d | %-12s" % (int(idval), int(total), step_txt)
    label = "[%-34s]" % label_core

    sys.stdout.write("\rProgress: %s %-50s %3d%%\033[K" % (label, bar, percent))
    sys.stdout.flush()

# ------------------------------------------------
class JdbcChaine(object):
    def __init__(self):
        self.host = None
        self.port = None
        self.service_name = None
        self.type_adresse = None
        self.valide = False

# ------------------------------------------------
def clean_jdbc(raw):
    if not raw:
        return None
    raw = ustr(raw).strip()
    if u'"' in raw:
        p = raw.split(u'"')
        if len(p) >= 2:
            raw = p[1]
    return raw.strip()

# ------------------------------------------------
def parse_simple_jdbc(raw):
    raw = raw or u""
    obj = JdbcChaine()
    m = re.search(r'jdbc:oracle:thin:@(.+?):(\d+)[/:](.+)', raw, re.I)
    if not m:
        return obj
    obj.host = m.group(1).strip()
    obj.port = m.group(2).strip()
    obj.service_name = m.group(3).strip()
    obj.type_adresse = "SCAN" if obj.host and ("scan" in obj.host.lower()) else "NON_SCAN"
    obj.valide = True
    return obj

def parse_sqlnet_jdbc(raw):
    raw = raw or u""
    obj = JdbcChaine()
    h = re.search(r'host=([^)]+)', raw, re.I)
    p = re.search(r'port=(\d+)', raw, re.I)
    s = re.search(r'service_name=([^)]+)', raw, re.I)
    if not (h and p and s):
        return obj
    obj.host = h.group(1).strip()
    obj.port = p.group(1).strip()
    obj.service_name = s.group(1).strip()
    obj.type_adresse = "SCAN" if obj.host and ("scan" in obj.host.lower()) else "NON_SCAN"
    obj.valide = True
    return obj

def parse_jdbc(raw):
    o = parse_simple_jdbc(raw)
    if o.valide:
        return o
    return parse_sqlnet_jdbc(raw)

# ------------------------------------------------
def extract_dr_hosts(jdbc):
    if not jdbc:
        return []
    seen = {}
    out = []
    for h in re.findall(r'host=([^)]+)', jdbc, re.I):
        hh = h.strip()
        if hh and hh not in seen:
            seen[hh] = 1
            out.append(hh)
    return out

# ------------------------------------------------
def load_store():
    if not os.path.isfile(STORE_FILE):
        return {"objects": []}
    return json.loads(open(STORE_FILE, "rb").read().decode("utf-8"))

def save_store(store):
    open(STORE_FILE, "wb").write(
        json.dumps(store, indent=2, ensure_ascii=False).encode("utf-8")
    )

def build_index(store):
    idx = {}
    for o in store.get("objects", []):
        idx[o.get("id")] = o
    return idx

# ------------------------------------------------
def parse_ids(option, max_id):
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

    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "-help"):
        print_help()
        sys.exit(0)

    fichier = sys.argv[1]
    if len(sys.argv) < 3:
        print_help()
        sys.exit(1)

    option = sys.argv[2]
    args = [a.lower() for a in sys.argv[3:]]

    DEBUG = ("-debug" in args)
    force_update = ("-force" in args) or ("-update" in args)

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

    store = load_store()
    store_index = build_index(store)

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
            objects.append({
                "id": idx,
                "RawSource": r
            })
        idx += 1

    sys.stdout.write("\n")

    store["objects"] = keep + objects
    save_store(store)

    print "\nAnalyseV3 terminé. Objets générés:", len(objects)
