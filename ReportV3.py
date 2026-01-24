#!/usr/bin/env python
# -*- coding: utf-8 -*-
# ReportV3.py — SUMMARY enrichi (visuel) sans régression

import json, sys, textwrap, re, os

from Lib.common import (
    ustr, pad, trim_lot,
    strip_ansi,
    print_section, print_table,
    RED, GREEN, YELLOW, RESET
)

KEY_WIDTH   = 24
VALUE_WIDTH = 60

CONF_FILE = os.path.join("Data","config.conf")

# ============================================================
# CONFIG
# ============================================================

def load_main_conf():
    if not os.path.isfile(CONF_FILE):
        return None, "CONF_MISSING", "Missing %s" % CONF_FILE

    d = {}
    try:
        for line in open(CONF_FILE,"rb").read().splitlines():
            try:
                s = line.decode("utf-8","ignore")
            except:
                s = line
            s = s.strip()
            if not s or s.startswith("#") or s.startswith(";"): continue
            if "=" not in s: continue
            k,v = s.split("=",1)
            d[k.strip()] = v.strip()

        if not d.get("SOURCE_JSON"):
            return None,"CONF_INVALID","SOURCE_JSON missing"

        return d,None,None
    except Exception as e:
        return None,"CONF_ERROR",str(e)

# ============================================================
# VISUAL STATUS (NOUVEAU — AFFICHAGE SEULEMENT)
# ============================================================

def visual_status(val):
    if val in ("VALIDE", "OK", True):
        return GREEN + u"✔ OK" + RESET
    if val in ("ERROR", False):
        return RED + u"✘ ERROR" + RESET
    if val == "DIFFERENT":
        return YELLOW + u"▲ DIFF" + RESET
    if val in ("NOT_APPLICABLE", None):
        return u"◻ N/A"
    return ustr(val)

# ============================================================
# LOGIQUE DE COMPARAISON (NOUVEAU)
# ============================================================

def compare_block(ref, block):
    """
    Compare host / cname / scan par rapport à une référence
    Retourne: OK | DIFFERENT | ERROR | NOT_APPLICABLE
    """
    if not block:
        return "NOT_APPLICABLE"
    if not ref or not block:
        return "NOT_APPLICABLE"

    if not ref.get("scan") or not block.get("scan"):
        return "ERROR"

    if ref.get("scan") == block.get("scan"):
        return "OK"

    return "DIFFERENT"

# ============================================================
# SUMMARY FILTERS (CONTRAT RESTAURÉ)
# ============================================================

FILTER_FIELDS = {
    "Database":    lambda o: ustr(o.get("RawSource",{}).get("Databases","")),
    "Application": lambda o: ustr(o.get("RawSource",{}).get("Application","")),
    "Lot":         lambda o: trim_lot(o.get("RawSource",{}).get("Lot","")),
    "DR":          lambda o: ustr(o.get("RawSource",{}).get("DR O/N","")),
    "Statut":      lambda o: strip_ansi(ustr(o.get("RawSource",{}).get("Statut Global",""))),
    "Valid":       lambda o: "YES" if o.get("Status",{}).get("ValidSyntax") else "NO",
    "Dirty":       lambda o: "YES" if o.get("Status",{}).get("Dirty") else "NO",
}

# ============================================================
# SUMMARY
# ============================================================

def print_summary(store):

    objs = store.get("objects",[])
    print_section("SUMMARY - JDBC ANALYSIS")

    headers = [
        ("ID",4),
        ("Database",10),
        ("Application",18),
        ("Lot",8),
        ("DR",3),
        ("Statut Global",20),
        ("Valid",10),
        ("OEM Status",14),
        ("Current STR",14),
        ("New STR",14),
        ("New DR",14),
        ("Dirty",8)
    ]

    # Header
    line=u" "
    sep=u" "
    for h,w in headers:
        line += pad(h,w) + u" | "
        sep  += u"-"*w + u"-+-"
    print line[:-3].encode("utf-8")
    print sep[:-3].encode("utf-8")

    for o in objs:
        rs = o.get("RawSource",{})
        st = o.get("Status",{})
        net = o.get("Network",{})

        ref = net.get("Current",{})

        row = [
            o.get("id",""),
            rs.get("Databases",""),
            rs.get("Application",""),
            trim_lot(rs.get("Lot","")),
            rs.get("DR O/N",""),
            rs.get("Statut Global",""),
            visual_status(st.get("ValidSyntax")),
            visual_status(compare_block(ref, net.get("OEM"))),
            visual_status("OK" if not st.get("ErrorType") else "ERROR"),
            visual_status(compare_block(ref, net.get("New"))),
            visual_status(compare_block(ref, net.get("NewDR"))),
            visual_status(not st.get("Dirty"))
        ]

        line=u" "
        for (val,(h,w)) in zip(row,headers):
            line += pad(val,w) + u" | "
        print line[:-3].encode("utf-8")

# ============================================================
# DETAIL VIEW (INCHANGÉ)
# ============================================================

def show_object(o, debug=False):

    rs  = o.get("RawSource",{})
    st  = o.get("Status",{})
    net = o.get("Network",{})

    print (u"\nID = %s — Database: %s" % (
        o.get("id",""),
        rs.get("Databases","")
    )).encode("utf-8")

    print_section("METADATA")
    print_table([
        ("Application",rs.get("Application")),
        ("Lot",rs.get("Lot")),
        ("Databases",rs.get("Databases")),
        ("DR",rs.get("DR O/N")),
        ("Statut Global",rs.get("Statut Global")),
        ("Acces",rs.get("Acces"))
    ])

    for title,key in [
        ("CURRENT JDBC","Current"),
        ("NEW JDBC","New"),
        ("NEW JDBC DR","NewDR"),
        ("OEM CONN","OEM")
    ]:
        block = net.get(key,{})
        print_section(title)
        rows=[
            ("Host",block.get("host")),
            ("CNAME",block.get("cname")),
            ("SCAN",block.get("scan")),
        ]
        if key=="OEM":
            rows.insert(1,("Port",block.get("port")))
        print_table(rows)

    print_section("STATUS")
    rows=[
        ("Valid Syntax",st.get("ValidSyntax")),
        ("Scan Compare",st.get("ScanCompare")),
        ("Scan Compare DR",st.get("ScanCompareDR")),
        ("Dirty",st.get("Dirty")),
        ("Mode",st.get("Mode")),
        ("Last Update",st.get("LastUpdateTime")),
    ]
    if st.get("ErrorType"):
        rows += [
            ("Error Type",st.get("ErrorType")),
            ("Error Detail",st.get("ErrorDetail")),
        ]
    if st.get("OEMErrorType"):
        rows += [
            ("OEM Error Type",st.get("OEMErrorType")),
            ("OEM Error Detail",st.get("OEMErrorDetail")),
        ]
    print_table(rows)

    if debug:
        print_section("RAWSOURCE (DEBUG)")
        print_table(sorted(rs.items()))

# ============================================================
# MAIN
# ============================================================

if __name__=="__main__":

    if len(sys.argv)<2 or sys.argv[1] in ("-help","-h","--help"):
        print "Usage: ReportV3.py -summary | id=N [-debug]"
        sys.exit(0)

    args=sys.argv[1:]
    DEBUG = ("-debug" in args)

    conf,err,msg = load_main_conf()
    if err:
        print "Configuration error:",err,msg
        sys.exit(1)

    store_file = conf.get("SOURCE_JSON")
    store=json.loads(open(store_file,"rb").read().decode("utf-8"))
    objs=store.get("objects",[])

    if "-summary" in args:
        # filtres
        for a in args:
            if a=="?":
                print "\nFiltres disponibles:"
                for k in sorted(FILTER_FIELDS):
                    print " ",k
                sys.exit(0)

            if "=" in a:
                k,v=a.split("=",1)
                if k in FILTER_FIELDS:
                    if v=="?":
                        vals=sorted(set(FILTER_FIELDS[k](o) for o in objs))
                        print "\nValeurs pour",k,":"
                        for x in vals:
                            print " ",x
                        sys.exit(0)
                    else:
                        objs=[o for o in objs if FILTER_FIELDS[k](o)==v]

        print_summary({"objects":objs})
        sys.exit(0)

    # id=N
    target=None
    for a in args:
        if a.startswith("id="):
            target=int(a.split("=")[1])

    if not target:
        print_summary(store)
        sys.exit(0)

    found=None
    for o in objs:
        if o.get("id")==target:
            found=o
            break

    if not found:
        print "ID non trouvé:",target
        sys.exit(0)

    show_object(found,DEBUG)
    print "\nReportV3 terminé."
