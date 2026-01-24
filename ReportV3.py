#!/usr/bin/env python
# -*- coding: utf-8 -*-
# ReportV3.py

import json
import sys
import os
import re

from Lib.common import (
    ustr, strip_ansi,
    RED, GREEN, YELLOW, RESET,
    pad, trim_lot,
    print_section, print_table
)

KEY_WIDTH   = 24
VALUE_WIDTH = 60

CONF_FILE = os.path.join("Data", "config.conf")

# ------------------------------------------------
def load_main_conf():
    if not os.path.isfile(CONF_FILE):
        return None, "CONF_MISSING", "Missing %s" % CONF_FILE

    d = {}
    try:
        for line in open(CONF_FILE, "rb").read().splitlines():
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
            d[k.strip()] = v.strip()

        if not d.get("SOURCE_JSON"):
            return None, "CONF_INVALID", "SOURCE_JSON missing in %s" % CONF_FILE

        return d, None, None
    except Exception as e:
        return None, "CONF_ERROR", str(e)

# ------------------------------------------------
def print_help():
    print u"""ReportV3.py - JDBC Report V3

Usage:
 python ReportV3.py -summary
 python ReportV3.py -summary ?
 python ReportV3.py -summary Database=VALUE
 python ReportV3.py id=N [-debug]
 python ReportV3.py -help
""".encode("utf-8")

# ------------------------------------------------
def format_global_status(val):
    if not val:
        return YELLOW + u"[--] Non renseigne" + RESET

    txt = ustr(val)
    v = txt.lower()

    if v in (u"termine", u"terminé"):
        return GREEN + u"[OK] " + txt + RESET

    return YELLOW + u"[--] " + txt + RESET

# ------------------------------------------------
def color_value(val, rule):
    if rule == "valid":
        return GREEN + u"YES" + RESET if val else RED + u"NO" + RESET
    if rule == "dirty":
        return RED + u"YES" + RESET if val else GREEN + u"NO" + RESET
    if rule == "scan":
        if val == "VALIDE":
            return GREEN + ustr(val) + RESET
        if val in ("ERROR", "DIFFERENT"):
            return RED + ustr(val) + RESET
        if val == "NOT_APPLICABLE":
            return YELLOW + ustr(val) + RESET
    return ustr(val)

# ===================== SUMMARY FILTER SUPPORT =====================

FILTER_FIELDS = {
    "Database":    lambda o: ustr(o.get("RawSource", {}).get("Databases", "")),
    "Application": lambda o: ustr(o.get("RawSource", {}).get("Application", "")),
    "Lot":         lambda o: trim_lot(o.get("RawSource", {}).get("Lot", "")),
    "DR":          lambda o: ustr(o.get("RawSource", {}).get("DR O/N") or o.get("RawSource", {}).get("DR", "")),
    "Statut":      lambda o: strip_ansi(format_global_status(o.get("RawSource", {}).get("Statut Global"))),
    "Valid":       lambda o: "YES" if o.get("Status", {}).get("ValidSyntax") else "NO",
    "Scan":        lambda o: ustr(o.get("Status", {}).get("ScanCompare", "")),
    "ScanDR":      lambda o: ustr(o.get("Status", {}).get("ScanCompareDR", "")),
    "Dirty":       lambda o: "YES" if o.get("Status", {}).get("Dirty") else "NO",
}

# ------------------------------------------------
def print_summary(store):
    objs = store.get("objects", [])
    print_section("SUMMARY - JDBC ANALYSIS")

    headers = [
        ("ID",4),("Database",9),("Application",18),("Lot",10),
        ("DR",3),("Statut Global",28),
        ("Valid Syntax",12),("Scan Compare",15),
        ("Scan Compare DR",18),("Dirty",5)
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

        row = [
            o.get("id",""),
            rs.get("Databases",""),
            rs.get("Application",""),
            trim_lot(rs.get("Lot","")),
            rs.get("DR O/N") or rs.get("DR",""),
            format_global_status(rs.get("Statut Global")),
            color_value(st.get("ValidSyntax"),"valid"),
            color_value(st.get("ScanCompare"),"scan"),
            color_value(st.get("ScanCompareDR"),"scan"),
            color_value(st.get("Dirty"),"dirty"),
        ]

        line = u" "
        for (val,(h,w)) in zip(row, headers):
            line += pad(val,w) + u" | "
        print line[:-3].encode("utf-8")

# ------------------------------------------------
def show_network_block(title, block, include_port=False):
    print_section(title)
    rows = [
        ("Host",  block.get("host")),
        ("CNAME", block.get("cname")),
        ("SCAN",  block.get("scan")),
    ]
    if include_port:
        rows.insert(1, ("Port", block.get("port")))
    print_table(rows)

# ------------------------------------------------
def show_object(o, debug=False):
    rs  = o.get("RawSource", {})
    st  = o.get("Status", {})
    net = o.get("Network", {})

    print (u"\nID = %s — Database: %s" % (o.get("id",""), ustr(rs.get("Databases","")))).encode("utf-8")

    print_section("METADATA")
    print_table([
        ("Application", rs.get("Application")),
        ("Lot", rs.get("Lot")),
        ("Databases", rs.get("Databases")),
        ("DR", rs.get("DR O/N") or rs.get("DR")),
        ("Statut Global", format_global_status(rs.get("Statut Global"))),
        ("Acces", rs.get("Acces"))
    ])

    show_network_block("CURRENT JDBC", net.get("Current", {}))
    show_network_block("NEW JDBC", net.get("New", {}))
    show_network_block("NEW JDBC DR", net.get("NewDR", {}))
    show_network_block("OEM CONN", net.get("OEM", {}), include_port=True)

    print_section("STATUS")
    rows_status = [
        ("Valid Syntax", color_value(st.get("ValidSyntax"),"valid")),
        ("Scan Compare", color_value(st.get("ScanCompare"),"scan")),
        ("Scan Compare DR", color_value(st.get("ScanCompareDR"),"scan")),
        ("Dirty", color_value(st.get("Dirty"),"dirty")),
        ("Dirty Reason", st.get("DirtyReason")),
        ("Mode", st.get("Mode")),
        ("Last Update", st.get("LastUpdateTime")),
    ]

    if st.get("ErrorType") or st.get("ErrorDetail"):
        rows_status += [
            ("Error Type", st.get("ErrorType")),
            ("Error Detail", st.get("ErrorDetail")),
        ]

    if st.get("OEMErrorType") or st.get("OEMErrorDetail"):
        rows_status += [
            ("OEM Error Type", st.get("OEMErrorType")),
            ("OEM Error Detail", st.get("OEMErrorDetail")),
        ]

    print_table(rows_status)

    if debug:
        print_section("RAWSOURCE (DEBUG)")
        raw_rows = [(k, rs.get(k)) for k in sorted(rs.keys())]
        print_table(raw_rows)

# ===================== MAIN =====================

if __name__ == "__main__":

    if len(sys.argv) < 2 or sys.argv[1] in ("-help","-h","--help"):
        print_help()
        sys.exit(0)

    args = sys.argv[1:]
    DEBUG = ("-debug" in args)

    main_conf, mce, mcd = load_main_conf()
    if mce:
        print "Configuration error:", mce
        print mcd
        sys.exit(1)

    store_file = main_conf.get("SOURCE_JSON")
    if not os.path.isfile(store_file):
        print "Store JSON file not found:", store_file
        sys.exit(1)

    store = json.loads(open(store_file,"rb").read().decode("utf-8"))
    objs = store.get("objects", [])
#-----------------------------------------
    
#------------------------------------------
    if "-summary" in args:
    
        # 1) summary ?
        if "?" in args:
            print "\nFiltres disponibles :"
            for k in sorted(FILTER_FIELDS.keys()):
                print " ", k
            sys.exit(0)
    
        # 2) filtres progressifs
        for a in args:
            if "=" not in a:
                continue
    
            k, v = a.split("=", 1)
            if k not in FILTER_FIELDS:
                continue
    
            if v == "?":
                # valeurs possibles APRES filtres precedents
                vals = sorted(set(FILTER_FIELDS[k](o) for o in objs))
                print "\nValeurs disponibles pour", k, ":"
                for x in vals:
                    print " ", x
                sys.exit(0)
            else:
                vv = ustr(v)
                objs = [o for o in objs if ustr(FILTER_FIELDS[k](o)) == vv]
    
        # 3) affichage final
        print_summary({"objects": objs})
        sys.exit(0)

------------------------------------------
    option = None
    for a in args:
        if a.startswith("id="):
            option = a

    if not option:
        print_summary(store)
        sys.exit(0)

    target = int(option.split("=")[1])
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
