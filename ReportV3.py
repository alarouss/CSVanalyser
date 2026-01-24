#!/usr/bin/env python
# -*- coding: utf-8 -*-
# ReportV3.py — VERSION STABLE SANS RÉGRESSION

import json, sys, os, textwrap, re

from Lib.common import (
    ustr, pad, trim_lot,
    print_section, print_table,
    strip_ansi,
    RED, GREEN, YELLOW, RESET
)

KEY_WIDTH   = 24
VALUE_WIDTH = 60

CONF_FILE = os.path.join("Data","config.conf")

# ==================================================
# CONFIG
# ==================================================

def load_main_conf():
    if not os.path.isfile(CONF_FILE):
        return None,"CONF_MISSING","Missing %s"%CONF_FILE
    d={}
    for l in open(CONF_FILE,"rb").read().splitlines():
        try: s=l.decode("utf-8","ignore")
        except: s=l
        s=s.strip()
        if not s or s.startswith("#") or "=" not in s: continue
        k,v=s.split("=",1)
        d[k.strip()]=v.strip()
    if not d.get("SOURCE_JSON"):
        return None,"CONF_INVALID","SOURCE_JSON missing"
    return d,None,None

# ==================================================
# VISUAL CONTRACT
# ==================================================

def visual_dirty(val):
    return RED+u"YES"+RESET if val else GREEN+u"NO"+RESET

def visual_error(code):
    if not code:
        return GREEN+u"✔ OK"+RESET
    c=ustr(code)
    if "DIFFERENT" in c or "NO_RESULT" in c:
        return YELLOW+u"▲ "+c+RESET
    if "ERROR" in c:
        return RED+u"✘ "+c+RESET
    return c

def visual_global_status(val):
    if not val:
        return YELLOW+u"◻ Non renseigné"+RESET
    v=ustr(val)
    vl=v.lower()
    if vl in ("termine","terminé"):
        return GREEN+u"✔ "+v+RESET
    if vl in ("en cours",):
        return YELLOW+u"▲ "+v+RESET
    if vl in ("ko","erreur"):
        return RED+u"✘ "+v+RESET
    return YELLOW+u"◻ "+v+RESET

# ==================================================
# SUMMARY FILTER SUPPORT (RESTAURÉ)
# ==================================================

FILTER_FIELDS = {
    "Database":    lambda o: ustr(o.get("RawSource",{}).get("Databases","")),
    "Application": lambda o: ustr(o.get("RawSource",{}).get("Application","")),
    "Lot":         lambda o: trim_lot(o.get("RawSource",{}).get("Lot","")),
    "DR":          lambda o: ustr(o.get("RawSource",{}).get("DR O/N","")),
    "Statut":      lambda o: strip_ansi(visual_global_status(
                            o.get("RawSource",{}).get("Statut Global"))),
    "Dirty":       lambda o: "YES" if o.get("Status",{}).get("Dirty") else "NO",
}

# ==================================================
# SUMMARY
# ==================================================

def print_summary(store):
    objs=store.get("objects",[])
    print_section("SUMMARY - JDBC ANALYSIS")

    headers=[
        ("ID",4),("Database",10),("Application",18),("Lot",8),
        ("DR",3),("Statut Global",22),
        ("Valid Syntax",14),
        ("OEM Status",18),
        ("Current STR",20),
        ("New STR",20),
        ("New DR",18),
        ("Dirty",6)
    ]

    line=u" "; sep=u" "
    for h,w in headers:
        line+=pad(h,w)+u" | "
        sep+=u"-"*w+u"-+-"
    print line[:-3].encode("utf-8")
    print sep[:-3].encode("utf-8")

    for o in objs:
        rs=o.get("RawSource",{})
        st=o.get("Status",{})

        row=[
            o.get("id"),
            rs.get("Databases"),
            rs.get("Application"),
            trim_lot(rs.get("Lot")),
            rs.get("DR O/N"),
            visual_global_status(rs.get("Statut Global")),
            visual_error(None if st.get("ValidSyntax") else "SYNTAX_ERROR"),
            visual_error(st.get("OEMErrorType")),
            visual_error(st.get("ErrorType")),
            visual_error(st.get("ErrorType")),
            visual_error(st.get("ScanCompareDR")),
            visual_dirty(st.get("Dirty")),
        ]

        l=u" "
        for (val,(h,w)) in zip(row,headers):
            l+=pad(val,w)+u" | "
        print l[:-3].encode("utf-8")

# ==================================================
# DETAIL VIEW
# ==================================================

def show_network_block(title, block, include_port=False):
    print_section(title)
    rows=[
        ("Host",block.get("host")),
        ("CNAME",block.get("cname")),
        ("SCAN",block.get("scan"))
    ]
    if include_port:
        rows.insert(1,("Port",block.get("port")))
    print_table(rows)

def show_object(o, debug=False):
    rs=o.get("RawSource",{})
    st=o.get("Status",{})
    net=o.get("Network",{})

    print (u"\nID=%s — Database=%s"%(o.get("id"),rs.get("Databases"))).encode("utf-8")

    print_section("METADATA")
    print_table([
        ("Application",rs.get("Application")),
        ("Lot",rs.get("Lot")),
        ("Databases",rs.get("Databases")),
        ("DR",rs.get("DR O/N")),
        ("Statut Global",visual_global_status(rs.get("Statut Global"))),
    ])

    show_network_block("CURRENT JDBC",net.get("Current",{}))
    show_network_block("NEW JDBC",net.get("New",{}))
    show_network_block("NEW JDBC DR",net.get("NewDR",{}))
    show_network_block("OEM CONN",net.get("OEM",{}),include_port=True)

    print_section("STATUS")
    rows=[
        ("Valid Syntax",visual_error(None if st.get("ValidSyntax") else "SYNTAX_ERROR")),
        ("Current STR",visual_error(st.get("ErrorType"))),
        ("Scan Compare",visual_error(st.get("ScanCompare"))),
        ("Scan Compare DR",visual_error(st.get("ScanCompareDR"))),
        ("Dirty",visual_dirty(st.get("Dirty"))),
        ("Mode",st.get("Mode")),
        ("Last Update",st.get("LastUpdateTime")),
    ]

    if st.get("OEMErrorType"):
        rows+= [
            ("OEM Error Type",visual_error(st.get("OEMErrorType"))),
            ("OEM Error Detail",st.get("OEMErrorDetail")),
        ]

    print_table(rows)

    if debug:
        print_section("RAWSOURCE (DEBUG)")
        print_table(sorted(rs.items()))

# ==================================================
# MAIN
# ==================================================

if __name__=="__main__":

    if len(sys.argv)<2 or sys.argv[1] in ("-h","--help","-help"):
        print "Usage: ReportV3.py [-summary [?]] | id=N [-debug]"
        sys.exit(0)

    args=sys.argv[1:]
    DEBUG="-debug" in args

    conf,err,msg=load_main_conf()
    if err:
        print err,msg
        sys.exit(1)

    store_file=conf["SOURCE_JSON"]
    store=json.loads(open(store_file,"rb").read().decode("utf-8"))
    objs=store.get("objects",[])

    if "-summary" in args:
        for a in args:
            if a=="?":
                print "\nFiltres disponibles :"
                for k in sorted(FILTER_FIELDS):
                    print " ",k
                sys.exit(0)
            if "=" in a:
                k,v=a.split("=",1)
                if k in FILTER_FIELDS:
                    if v=="?":
                        vals=sorted(set(FILTER_FIELDS[k](o) for o in objs))
                        print "\nValeurs pour",k
                        for x in vals: print " ",x
                        sys.exit(0)
                    objs=[o for o in objs if ustr(FILTER_FIELDS[k](o))==ustr(v)]
        print_summary({"objects":objs})
        sys.exit(0)

    target=None
    for a in args:
        if a.startswith("id="):
            target=int(a.split("=",1)[1])

    if not target:
        print_summary(store)
        sys.exit(0)

    for o in objs:
        if o.get("id")==target:
            show_object(o,DEBUG)
            sys.exit(0)

    print "ID non trouvé:",target
