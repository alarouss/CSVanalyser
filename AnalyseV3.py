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

Options:
 -debug
 -force / -update
"""

# ------------------------------------------------
def show_progress(idval,total,step):
    try:
        percent=int((float(idval)/float(total))*100) if total else 100
    except:
        percent=100
    bar="."*int(percent/2)
    label="Id:%3d/%-3d | %-12s"%(idval,total,(step or "")[:12])
    label="[%-26s]"%label
    sys.stdout.write("\rProgress: %s %-50s %3d%%\033[K"%(label,bar,percent))
    sys.stdout.flush()

# ------------------------------------------------
def normalize_key(k):
    return ustr(k).replace(u'\ufeff',u'').strip()

def normalize_row(row):
    return dict((normalize_key(k),ustr(v)) for k,v in row.items())

# ------------------------------------------------
def build_raw_source(row):
    return dict((c, ustr(row.get(c,u"")).strip()) for c in RAW_COLUMNS)

# ------------------------------------------------
def build_status(valid,scan,scan_dr,dirty,dirty_reason,err_type,err_detail,mode,
                 oem_err_type=None,oem_err_detail=None):

    st = {
        "ValidSyntax":valid,
        "ScanCompare":scan,
        "ScanCompareDR":scan_dr,
        "Dirty":dirty,
        "DirtyReason":dirty_reason,
        "ErrorType":err_type,
        "ErrorDetail":err_detail,
        "Mode":mode,
        "LastUpdateTime":time.strftime("%Y-%m-%d %H:%M:%S")
    }

    if oem_err_type or oem_err_detail:
        st["OEMErrorType"]=oem_err_type
        st["OEMErrorDetail"]=oem_err_detail

    return st

# ------------------------------------------------
def parse_ids(opt,maxid):
    if opt.startswith("id="):
        s=opt.split("=",1)[1]
        if "," in s: return [int(x) for x in s.split(",")]
        return [int(s)]
    if opt.startswith("ligne="):
        v=opt.split("=",1)[1]
        if v.upper()=="ALL": return range(1,maxid+1)
        return range(1,int(v)+1)
    return None

# ------------------------------------------------
def build_object_v3(row,obj_id,store_index,force_update,total_csv,oem_conn):

    raw = build_raw_source(row)

    cached = store_index.get(obj_id)
    dirty=False; dirty_reason=None
    if cached and cached.get("RawSource")!=raw:
        dirty=True; dirty_reason="RAW_CHANGED"

    cur = raw.get("Current connection string")
    new = raw.get("New connection string")
    dr  = raw.get("New connection string avec DR")

    cur_o,e1,d1 = interpret(cur)
    new_o,e2,d2 = interpret(new)
    dr_o ,e3,d3 = interpret(dr)

    net = {
        "Current":{"host":cur_o.host,"cname":cur_o.cname,"scan":cur_o.scan},
        "New":{"host":new_o.host,"cname":new_o.cname,"scan":new_o.scan},
        "NewDR":{"host":dr_o.host,"cname":dr_o.cname,"scan":dr_o.scan},
        "OEM":{"host":None,"port":None,"cname":None,"scan":None}
    }

    # OEM
    oem_err_type=None
    oem_err_detail=None

    dbname = ustr(raw.get("Databases","")).strip()
    if dbname:
        oh,op,oe,od = oem_get_host_and_port(oem_conn,dbname)
        if oe:
            oem_err_type=oe
            oem_err_detail=od
        else:
            net["OEM"]["host"]=oh
            net["OEM"]["port"]=op
    else:
        oem_err_type="OEM_DBNAME_EMPTY"
        oem_err_detail="Databases column empty"

    err_type=None; err_detail=None
    scan=None; scan_dr=None

    if e1 or e2:
        scan="ERROR"
        err_type=e1 or e2
        err_detail=d1 or d2
    else:
        eq=compare(cur_o.scan,new_o.scan)
        if eq is None:
            scan="ERROR"; err_type="SCAN_COMPARE_ERROR"; err_detail="Normalization failed"
        else:
            scan="VALIDE" if eq else "DIFFERENT"
            if not eq:
                err_type="SCAN_DIFFERENT"
                err_detail="Current and New SCAN differ"

    if dr_o.valide:
        eqdr=compare(cur_o.scan,dr_o.scan)
        scan_dr="VALIDE" if eqdr else "DIFFERENT"

    status=build_status(True,scan,scan_dr,dirty,dirty_reason,
                        err_type,err_detail,
                        "FORCE_UPDATE" if force_update else
                        ("AUTO_DIRTY" if dirty else "AUTO"),
                        oem_err_type,oem_err_detail)

    return {
        "id":obj_id,
        "RawSource":raw,
        "Network":net,
        "Status":status
    }

# ------------------------------------------------
if __name__=="__main__":

    if len(sys.argv)<2 or sys.argv[1] in ("-h","--help","-help"):
        print_help()
        sys.exit(0)

    option=sys.argv[1]
    args=[a.lower() for a in sys.argv[2:]]

    DEBUG="-debug" in args
    force_update="-force" in args or "-update" in args

    main_conf,_,_ = load_main_conf()
    fichier = main_conf.get("SOURCE_CSV")
    STORE_FILE = main_conf.get("SOURCE_JSON")
    OEM_CONF_FILE = main_conf.get("OEM_CONF_FILE")

    # OEM conn
    oem_conn=None
    if OEM_CONF_FILE and os.path.isfile(OEM_CONF_FILE):
        for l in open(OEM_CONF_FILE,"rb").read().splitlines():
            try: s=l.decode("utf-8","ignore")
            except: s=l
            s=s.strip()
            if s.startswith("OEM_CONN="):
                oem_conn=s.split("=",1)[1].strip()

    rows=[normalize_row(r) for r in csv.DictReader(open(fichier,"rb"),delimiter=';')]

    ids=parse_ids(option,len(rows))
    if not ids:
        print_help()
        sys.exit(1)

    store=load_store(STORE_FILE)
    index=build_index(store)

    keep=[o for o in store.get("objects",[]) if o["id"] not in ids]

    objs=[]
    pos=0; total=len(ids)

    for i,r in enumerate(rows,1):
        if i in ids:
            pos+=1
            show_progress(pos,total,"ID=%d"%i)
            objs.append(build_object_v3(r,i,index,force_update,len(rows),oem_conn))

    sys.stdout.write("\n")

    store["objects"]=keep+objs
    save_store(STORE_FILE,store)

    print "\nAnalyseV3 terminé. Objets générés:",len(objs)
