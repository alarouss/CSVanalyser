#!/usr/bin/env python
# -*- coding: utf-8 -*-

import csv
import sys
import time
import os

from Lib.common import ustr
from Lib.config import load_main_conf
from Lib.store import load_store, save_store, build_index
from Lib.jdbc_flow_v2 import interpret, compare, resolve_cname, resolve_scan
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
def show_progress(pos,total,step):
    try:
        percent=int((float(pos)/float(total))*100) if total else 100
    except:
        percent=100
    bar="."*int(percent/2)
    label="Pos:%3d/%-3d | %-14s"%(pos,total,(step or "")[:14])
    label="[%-30s]"%label
    sys.stdout.write("\rProgress: %s %-50s %3d%%\033[K"%(label,bar,percent))
    sys.stdout.flush()

# ------------------------------------------------
def normalize_key(k):
    return ustr(k).replace(u'\ufeff',u'').strip()

def normalize_row(row):
    return dict((normalize_key(k),ustr(v)) for k,v in row.items())

# ------------------------------------------------
def build_raw_source(row):
    return dict((c,ustr(row.get(c,u"")).strip()) for c in RAW_COLUMNS)

# ------------------------------------------------
def build_status(valid,scan,scan_dr,dirty,dirty_reason,
                 err_type,err_detail,mode,
                 oem_err_type=None,oem_err_detail=None):

    st={
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
def parse_target_ids(option,maxid):

    if option=="columns":
        return ("columns",None)

    if option.lower().startswith("ligne="):
        v=option.split("=",1)[1]
        if v.upper()=="ALL":
            return ("range",range(1,maxid+1))
        return ("range",range(1,int(v)+1))

    if option.lower().startswith("id="):
        s=option.split("=",1)[1]
        if "," in s:
            return ("list",[int(x) for x in s.split(",")])
        return ("range",range(1,int(s)+1))

    return (None,None)

# ------------------------------------------------
def read_oem_conn(path):
    if not path or not os.path.isfile(path):
        return None
    for l in open(path,"rb").read().splitlines():
        try: s=l.decode("utf-8","ignore")
        except: s=l
        s=s.strip()
        if s.startswith("OEM_CONN="):
            return s.split("=",1)[1].strip()
    return None

# ------------------------------------------------
def build_object_v3(row,obj_id,store_index,force_update,oem_conn,pos,total):

    raw=build_raw_source(row)

    cached=store_index.get(obj_id)
    dirty=False; dirty_reason=None
    if cached and cached.get("RawSource")!=raw:
        dirty=True; dirty_reason="RAW_CHANGED"

    # ---------------- PARSE ----------------
    show_progress(pos,total,"PARSE")
    cur=raw.get("Current connection string")
    new=raw.get("New connection string")
    dr =raw.get("New connection string avec DR")

    cur_o,e1,d1=interpret(cur)
    new_o,e2,d2=interpret(new)
    dr_o ,e3,d3=interpret(dr)

    net={
        "Current":{"host":cur_o.host,"cname":None,"scan":None},
        "New":{"host":new_o.host,"cname":None,"scan":None},
        "NewDR":{"host":dr_o.host,"cname":None,"scan":None},
        "OEM":{"host":None,"port":None,"cname":None,"scan":None}
    }

    err_type=None; err_detail=None
    scan_status=None; scan_dr_status=None

    # ---------------- CURRENT ----------------
    show_progress(pos,total,"CURRENT_CNAME")
    cname,e,d=resolve_cname(cur_o.host)
    if not e: net["Current"]["cname"]=cname

    show_progress(pos,total,"CURRENT_SCAN")
    scan,e,d=resolve_scan(cname)
    if not e: net["Current"]["scan"]=scan

    # ---------------- NEW ----------------
    show_progress(pos,total,"NEW_CNAME")
    cname,e,d=resolve_cname(new_o.host)
    if not e: net["New"]["cname"]=cname

    show_progress(pos,total,"NEW_SCAN")
    scan,e,d=resolve_scan(cname)
    if not e: net["New"]["scan"]=scan

    # ---------------- COMPARE ----------------
    eq=compare(net["Current"]["scan"],net["New"]["scan"])
    if eq is None:
        scan_status="ERROR"
        err_type="SCAN_COMPARE_ERROR"
        err_detail="Normalization failed"
    else:
        scan_status="VALIDE" if eq else "DIFFERENT"
        if not eq:
            err_type="SCAN_DIFFERENT"
            err_detail="Current and New SCAN differ"

    # ---------------- DR ----------------
    if dr_o and dr_o.valide:
        show_progress(pos,total,"NEWDR_CNAME")
        cname,e,d=resolve_cname(dr_o.host)
        if not e: net["NewDR"]["cname"]=cname

        show_progress(pos,total,"NEWDR_SCAN")
        scan,e,d=resolve_scan(cname)
        if not e: net["NewDR"]["scan"]=scan

        eqdr=compare(net["Current"]["scan"],net["NewDR"]["scan"])
        scan_dr_status="VALIDE" if eqdr else "DIFFERENT"

    # ---------------- OEM ----------------
    oem_err_type=None; oem_err_detail=None

    show_progress(pos,total,"OEM_SQLPLUS")
    dbname=ustr(raw.get("Databases","")).strip()
    if dbname:
        oh,op,oe,od=oem_get_host_and_port(oem_conn,dbname)
        if oe:
            oem_err_type=oe; oem_err_detail=od
        else:
            net["OEM"]["host"]=oh
            net["OEM"]["port"]=op

            show_progress(pos,total,"OEM_CNAME")
            cname,e,d=resolve_cname(oh)
            if not e: net["OEM"]["cname"]=cname

            show_progress(pos,total,"OEM_SCAN")
            scan,e,d=resolve_scan(cname)
            if not e: net["OEM"]["scan"]=scan
    else:
        oem_err_type="OEM_DBNAME_EMPTY"
        oem_err_detail="Databases column empty"

    mode="FORCE_UPDATE" if force_update else ("AUTO_DIRTY" if dirty else "AUTO")

    status=build_status(True,scan_status,scan_dr_status,
                        dirty,dirty_reason,
                        err_type,err_detail,
                        mode,
                        oem_err_type,oem_err_detail)

    return {
        "id":obj_id,
        "RawSource":raw,
        "Network":net,
        "Status":status
    }

# ------------------------------------------------
if __name__=="__main__":

    option=sys.argv[1]
    args=[a.lower() for a in sys.argv[2:]]

    force_update=("-force" in args) or ("-update" in args) or ("-upgrade" in args)

    main_conf,_,_=load_main_conf()
    fichier=main_conf.get("SOURCE_CSV")
    STORE_FILE=main_conf.get("SOURCE_JSON")
    OEM_CONF_FILE=main_conf.get("OEM_CONF_FILE")

    oem_conn=read_oem_conn(OEM_CONF_FILE)

    rows=[normalize_row(r) for r in csv.DictReader(open(fichier,"rb"),delimiter=';')]

    kind,targets=parse_target_ids(option,len(rows))

    store=load_store(STORE_FILE)
    index=build_index(store)

    existing_ids=set([int(o["id"]) for o in store.get("objects",[]) if "id" in o])

    if force_update:
        ids_to_run=list(targets)
        keep=[o for o in store.get("objects",[]) if int(o["id"]) not in targets]
    else:
        ids_to_run=[i for i in targets if i not in existing_ids]
        keep=store.get("objects",[])[:]

    ids_to_run.sort()

    objs=[]
    total=len(ids_to_run)
    pos=0

    for i in ids_to_run:
        pos+=1
        r=rows[i-1]
        objs.append(build_object_v3(r,i,index,force_update,oem_conn,pos,total))

    sys.stdout.write("\n")

    store["objects"]=keep+objs
    save_store(STORE_FILE,store)

    print "\nAnalyseV3 terminé. Objets générés:",len(objs)
