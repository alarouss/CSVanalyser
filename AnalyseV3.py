#!/usr/bin/env python
# -*- coding: utf-8 -*-
# AnalyseV3.py

import csv
import sys
import time
import os

from Lib.io_common import load_main_conf, ustr
from Lib.store import load_store, save_store, build_index
from Lib.oem_flow import oem_get_host_and_port

# IMPORTS APRÈS DÉCOUPAGE (OBLIGATOIRES)
from Lib.analyse_builder_v3 import build_object_v3, normalize_row

DEBUG = False

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

    # CSV en binaire (python 2.6 exige bytes)
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

    store = load_store(STORE_FILE)
    index = build_index(store)

    existing = {}
    for o in store.get("objects", []):
        try:
            existing[int(o.get("id"))] = 1
        except:
            pass

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

    print "Targets:", len(targets), \
          "| ToProcess:", len(ids_to_process), \
          "| Skipped(existing):", skipped, \
          "| Force:", ("YES" if force else "NO")

    if not ids_to_process:
        print "Nothing to do."
        sys.exit(0)

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

    objs = []
    total = len(ids_to_process)
    pos = 0

    for oid in ids_to_process:
        pos += 1
        row = rows[oid - 1]
        objs.append(
            build_object_v3(row, oid, oem_conn, pos, total, force)
        )

    sys.stdout.write("\n")

    store["objects"] = keep + objs
    print("DEBUG FINAL OBJECT =", objs[-1]["Network"]["New"]["DR"])
    save_store(STORE_FILE, store)

    print "\nAnalyseV3 terminé."
    print "  objets générés :", len(objs)
    print "  skipped(existing) :", skipped
    print "  total store :", len(store.get("objects", []))
