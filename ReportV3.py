#!/usr/bin/env python
# -*- coding: utf-8 -*-
# ReportV3.py — JDBC Analysis Report (contrat restauré)

import json
import sys
import os
import re
import textwrap

from Lib.common import (
    ustr, pad, trim_lot,
    RED, GREEN, YELLOW, RESET,
    strip_ansi, print_section, print_table
)

# ================= CONFIG =================

KEY_WIDTH   = 24
VALUE_WIDTH = 60

CONF_FILE = os.path.join("Data", "config.conf")

# ================= HELP ===================

def print_help():
    print u"""ReportV3.py — JDBC Report

Usage:
 python ReportV3.py -summary
 python ReportV3.py -summary ?
 python ReportV3.py -summary Application=?
 python ReportV3.py -summary Application=APP_1 Lot=5
 python ReportV3.py id=N [-debug]
 python ReportV3.py -help
""".encode("utf-8")

# ================= CONFIG LOAD =================

def load_main_conf():
    if not os.path.isfile(CONF_FILE):
        return None, "CONF_MISSING", CONF_FILE

    conf = {}
    for l in open(CONF_FILE, "rb").read().splitlines():
        try:
            s = l.decode("utf-8", "ignore").strip()
        except:
            s = l.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        k, v = s.split("=", 1)
        conf[k.strip()] = v.strip()

    if not conf.get("SOURCE_JSON"):
        return None, "CONF_INVALID", "SOURCE_JSON missing"

    return conf, None, None

# ================= STATUS FORMAT =================

def normalize_text(v):
    return ustr(v).strip().lower()

def format_global_status(val):
    if not val:
        return YELLOW + u"[--] N/A" + RESET

    txt = ustr(val)
    v = normalize_text(txt)

    if v in (u"termine", u"terminé"):
        return GREEN + u"[OK] " + txt + RESET

    return YELLOW + u"[--] " + txt + RESET

def color_ok():
    return GREEN + u"✓ OK" + RESET

def color_na():
    return YELLOW + u"⚠ N/A" + RESET

def color_err(msg):
    return RED + u"✗ " + ustr(msg) + RESET

def color_dirty(v):
    return RED + u"YES" + RESET if v else GREEN + u"NO" + RESET

# ================= BLOCK STATUS =================

def compute_block_status(block, applicable=True):
    """
    block peut être :
      - ancien format: {"host":..,"cname":..,"scan":..}
      - nouveau format: {"Primaire":{...},"DR":{...}}
    """

    if not applicable:
        return color_na(), "N/A"

    if not block:
        return color_na(), "N/A"

    # 🔽 NOUVEAU : descente automatique vers Primaire
    if "Primaire" in block and isinstance(block["Primaire"], dict):
        block = block.get("Primaire", {})

    host  = block.get("host")
    cname = block.get("cname")
    scan  = block.get("scan")

    if not host:
        return color_na(), "N/A"

    # erreurs explicites
    if cname is None and scan is None:
        return color_err("SYNTAX_ERROR"), "SYNTAX_ERROR"

    if cname is None:
        return color_err("CNAME_ERROR"), "CNAME_ERROR"

    if scan is None:
        return color_err("SCAN_ERROR"), "SCAN_ERROR"

    return color_ok(), "OK"

# ================= SUMMARY =================

FILTER_FIELDS = {
    "Database":    lambda o: ustr(o.get("RawSource", {}).get("Databases", "")),
    "Application": lambda o: ustr(o.get("RawSource", {}).get("Application", "")),
    "Lot":         lambda o: trim_lot(o.get("RawSource", {}).get("Lot", "")),
    "DR":          lambda o: ustr(o.get("RawSource", {}).get("DR O/N", "")),
    "Statut":      lambda o: strip_ansi(format_global_status(
                        o.get("RawSource", {}).get("Statut Global"))),
    "Dirty":       lambda o: "YES" if o.get("Status", {}).get("Dirty") else "NO",
}

def print_summary(objs):
    print_section("SUMMARY - JDBC ANALYSIS")

    headers = [
        ("ID",4),
        ("Database",10),
        ("Application",18),
        ("Lot",8),
        ("DR",3),
        ("Statut Global",22),
        ("Valid",7),
        ("OEM",12),
        ("Current STR",14),
        ("New STR",14),
        ("New DR",14),
        ("Dirty",6),
    ]

    line = u" "
    sep  = u" "
    for h,w in headers:
        line += pad(h,w) + u" | "
        sep  += u"-"*w + u"-+-"
    print line[:-3].encode("utf-8")
    print sep[:-3].encode("utf-8")

    for o in objs:
        rs = o.get("RawSource", {})
        st = o.get("Status", {})
        net = o.get("Network", {})

        cur_s, _ = compute_block_status(net.get("Current"))
        new_s, _ = compute_block_status(net.get("New"))
        dr_s, _ = compute_block_status(
            net.get("New", {}).get("DR"),
            applicable=bool(rs.get("DR O/N"))
        )
        oem_s, _ = compute_block_status(net.get("OEM"))

        row = [
            o.get("id",""),
            rs.get("Databases",""),
            rs.get("Application",""),
            trim_lot(rs.get("Lot","")),
            rs.get("DR O/N",""),
            format_global_status(rs.get("Statut Global")),
            GREEN+"YES"+RESET if st.get("ValidSyntax") else RED+"NO"+RESET,
            oem_s,
            cur_s,
            new_s,
            dr_s,
            color_dirty(st.get("Dirty")),
        ]

        out=u" "
        for (val,(h,w)) in zip(row,headers):
            out += pad(val,w) + u" | "
        print out[:-3].encode("utf-8")

# ================= DETAIL =================

def show_object(o, debug=False):
    rs  = o.get("RawSource", {})
    st  = o.get("Status", {})
    net = o.get("Network", {})

    print (u"\nID = %s — Database: %s" %
           (o.get("id",""), rs.get("Databases",""))).encode("utf-8")

    print_section("METADATA")
    print_table([
        ("Application", rs.get("Application")),
        ("Lot", rs.get("Lot")),
        ("Databases", rs.get("Databases")),
        ("DR", rs.get("DR O/N")),
        ("Statut Global", format_global_status(rs.get("Statut Global"))),
        ("Acces", rs.get("Acces")),
    ])

    for label, key, app in [
        ("CURRENT JDBC", "Current", True),
        ("NEW JDBC", "New", True),
        ("NEW JDBC DR", ("New", "DR"), bool(rs.get("DR O/N"))),
        ("OEM CONN", "OEM", True),
    ]:
        print_section(label)
        if isinstance(key, tuple):
            block = net.get(key[0], {}).get(key[1], {})
        else:
            block = net.get(key, {})
        rows = [
            ("Host", block.get("host")),
            ("CNAME", block.get("cname")),
            ("SCAN", block.get("scan")),
            ("Status", compute_block_status(block, app)[0]),
        ]
        
        block = net.get(key, {})

        # 🔽 compat nouveau modèle
        if "Primaire" in block:
            block_p = block.get("Primaire", {})
        else:
            block_p = block
        
        rows = [
            ("Host", block_p.get("host")),
            ("CNAME", block_p.get("cname")),
            ("SCAN", block_p.get("scan")),
            ("Status", compute_block_status(block, app)[0]),
        ]
        
        if key == "OEM":
            rows.insert(1, ("Port", block.get("port")))
        print_table(rows)

    print_section("STATUS")
    rows = [
        ("Valid Syntax", GREEN+"YES"+RESET if st.get("ValidSyntax") else RED+"NO"+RESET),
        ("Dirty", color_dirty(st.get("Dirty"))),
        ("Mode", st.get("Mode")),
        ("Last Update", st.get("LastUpdateTime")),
    ]
    if st.get("ErrorType") or st.get("ErrorDetail"):
        rows += [
            ("Error Type", st.get("ErrorType")),
            ("Error Detail", st.get("ErrorDetail")),
        ]
    print_table(rows)

    if debug:
        print_section("RAWSOURCE (DEBUG)")
        dbg = o.get("RawSource_DEBUG", {})
        print_table(sorted(dbg.items()))

# ================= MAIN =================

if __name__ == "__main__":

    if len(sys.argv)<2 or sys.argv[1] in ("-help","-h","--help"):
        print_help()
        sys.exit(0)

    args = sys.argv[1:]
    DEBUG = ("-debug" in args)

    conf, e, d = load_main_conf()
    if e:
        print "Configuration error:", e
        print d
        sys.exit(1)

    store_file = conf.get("SOURCE_JSON")
    store = json.loads(open(store_file,"rb").read().decode("utf-8"))
    objs = store.get("objects", [])

    if "-summary" in args:
        filters = {}
        for a in args:
            if a == "?":
                print "\nFiltres disponibles:"
                for k in sorted(FILTER_FIELDS.keys()):
                    print " ",k
                sys.exit(0)
            if "=" in a:
                k,v = a.split("=",1)
                if v == "?":
                    vals = sorted(set(FILTER_FIELDS[k](o) for o in objs))
                    print "\nValeurs possibles pour",k,":"
                    for x in vals: print " ",x
                    sys.exit(0)
                filters[k] = v

        for k,v in filters.items():
            objs = [o for o in objs if FILTER_FIELDS[k](o) == v]

        print_summary(objs)
        sys.exit(0)

    target = None
    for a in args:
        if a.startswith("id="):
            target = int(a.split("=")[1])

    if not target:
        print_summary(objs)
        sys.exit(0)

    found = None
    for o in objs:
        if o.get("id") == target:
            found = o
            break

    if not found:
        print "ID non trouvé:", target
        sys.exit(0)

    show_object(found, DEBUG)
    print "\nReportV3 terminé."
