#!/usr/bin/env python
# -*- coding: utf-8 -*-
# ReportV3.py — Summary & Detail JDBC (avec OEM, erreurs détaillées, debug)

import json, sys, os, textwrap

from Lib.common import (
    ustr, strip_ansi, pad, trim_lot,
    RED, GREEN, YELLOW, RESET,
    print_section, print_table
)

CONF_FILE = os.path.join("Data", "config.conf")

KEY_WIDTH   = 24
VALUE_WIDTH = 60

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
            if not s or s.startswith("#") or s.startswith(";"):
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

# ================================================================
# VISUAL MAPPING (UNIQUEMENT AFFICHAGE)
# ================================================================

def visual_global_status(val):
    if not val:
        return u"◻ N/A"
    v = ustr(val).lower()

    if v in (u"terminé", u"termine"):
        return GREEN + u"✔ " + ustr(val) + RESET
    if v in (u"en cours",):
        return YELLOW + u"▲ " + ustr(val) + RESET
    if v in (u"ko", u"erreur"):
        return RED + u"✘ " + ustr(val) + RESET

    return YELLOW + u"▲ " + ustr(val) + RESET

def visual_status_code(code):
    if not code:
        return u"◻ N/A"

    c = ustr(code)

    if c in ("OK", "VALIDE"):
        return GREEN + u"✔ OK" + RESET

    if "ERROR" in c:
        return RED + u"✘ " + c + RESET

    if "DIFFERENT" in c or "NO_RESULT" in c:
        return YELLOW + u"▲ " + c + RESET

    if c == "NOT_APPLICABLE":
        return u"◻ N/A"

    return YELLOW + u"▲ " + c + RESET

def visual_bool(val, yes_label="YES", no_label="NO"):
    return (GREEN + u"✔ " + yes_label + RESET) if val else (RED + u"✘ " + no_label + RESET)

# ================================================================
# SUMMARY FILTER SUPPORT (CONTRAT RESTAURÉ)
# ================================================================

FILTER_FIELDS = {
    "Database":    lambda o: ustr(o.get("RawSource",{}).get("Databases","")),
    "Application": lambda o: ustr(o.get("RawSource",{}).get("Application","")),
    "Lot":         lambda o: trim_lot(o.get("RawSource",{}).get("Lot","")),
    "DR":          lambda o: ustr(o.get("RawSource",{}).get("DR O/N") or o.get("RawSource",{}).get("DR","")),
    "Statut":      lambda o: strip_ansi(visual_global_status(o.get("RawSource",{}).get("Statut Global"))),
    "Valid":       lambda o: "YES" if o.get("Status",{}).get("ValidSyntax") else "NO",
    "Scan":        lambda o: ustr(o.get("Status",{}).get("ScanCompare","")),
    "Dirty":       lambda o: "YES" if o.get("Status",{}).get("Dirty") else "NO",
}

# ================================================================
# SUMMARY
# ================================================================

def print_summary(store):

    objs = store.get("objects",[])
    print_section("SUMMARY - JDBC ANALYSIS")

    headers = [
        ("ID",4),
        ("Database",10),
        ("Application",18),
        ("Lot",8),
        ("DR",3),
        ("Statut Global",24),
        ("Valid Syntax",14),
        ("OEM Status",18),
        ("Current STR",18),
        ("New STR",18),
        ("New DR",18),
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
        rs = o.get("RawSource",{})
        st = o.get("Status",{})

        row = [
            o.get("id",""),
            rs.get("Databases",""),
            rs.get("Application",""),
            trim_lot(rs.get("Lot","")),
            rs.get("DR O/N") or rs.get("DR",""),
            visual_global_status(rs.get("Statut Global")),
            visual_bool(st.get("ValidSyntax")),
            visual_status_code(st.get("OEMErrorType") or "OK"),
            visual_status_code(st.get("ErrorType") or "OK"),
            visual_status_code(st.get("ScanCompare")),
            visual_status_code(st.get("ScanCompareDR")),
            visual_bool(st.get("Dirty")),
        ]

        line = u" "
        for (val,(h,w)) in zip(row,headers):
            line += pad(val,w) + u" | "
        print line[:-3].encode("utf-8")

# ================================================================
# DETAIL VIEW
# ================================================================

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

def show_object(o, debug=False):

    rs  = o.get("RawSource",{})
    st  = o.get("Status",{})
    net = o.get("Network",{})

    print (u"\nID = %s — Database: %s" % (o.get("id",""), rs.get("Databases",""))).encode("utf-8")

    print_section("METADATA")
    print_table([
        ("Application",rs.get("Application")),
        ("Lot",rs.get("Lot")),
        ("Databases",rs.get("Databases")),
        ("DR",rs.get("DR O/N") or rs.get("DR")),
        ("Statut Global", visual_global_status(rs.get("Statut Global"))),
        ("Acces",rs.get("Acces"))
    ])

    show_network_block("CURRENT JDBC", net.get("Current",{}))
    show_network_block("NEW JDBC", net.get("New",{}))
    show_network_block("NEW JDBC DR", net.get("NewDR",{}))
    show_network_block("OEM CONN", net.get("OEM",{}), include_port=True)

    print_section("STATUS")
    rows_status = [
        ("Valid Syntax", visual_bool(st.get("ValidSyntax"))),
        ("Scan Compare", visual_status_code(st.get("ScanCompare"))),
        ("Scan Compare DR", visual_status_code(st.get("ScanCompareDR"))),
        ("Dirty", visual_bool(st.get("Dirty"))),
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

# ================================================================
# MAIN
# ================================================================

if __name__=="__main__":

    if len(sys.argv)<2 or sys.argv[1] in ("-help","-h","--help"):
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
    store = json.loads(open(store_file,"rb").read().decode("utf-8"))
    objs  = store.get("objects",[])

    if "-summary" in args:

        for a in args:
            if a == "?":
                print "\nFiltres disponibles :"
                for k in sorted(FILTER_FIELDS.keys()):
                    print " ", k
                sys.exit(0)

            if "=" in a:
                k,v = a.split("=",1)
                if k in FILTER_FIELDS:
                    if v == "?":
                        vals = sorted(set(FILTER_FIELDS[k](o) for o in objs))
                        print "\nValeurs disponibles pour",k,":"
                        for x in vals:
                            print " ", x
                        sys.exit(0)
                    else:
                        vv = ustr(v)
                        objs = [o for o in objs if ustr(FILTER_FIELDS[k](o)) == vv]
                        break

        print_summary({"objects":objs})
        sys.exit(0)

    option = None
    for a in args:
        if a.startswith("id="):
            option = a

    if not option:
        print_summary(store)
        sys.exit(0)

    target = int(option.split("=")[1])
    found  = None
    for o in objs:
        if o.get("id") == target:
            found = o
            break

    if not found:
        print "ID non trouvé:", target
        sys.exit(0)

    show_object(found, DEBUG)
    print "\nReportV3 terminé."
