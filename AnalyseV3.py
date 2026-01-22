#!/usr/bin/env python
# -*- coding: utf-8 -*-

import csv,sys,time
from Lib.jdbc_flow_v2 import interpret,compare
from Lib.store import load_store,save_store,build_index
from Lib.common import ustr

RAW_COLUMNS=[
 "Statut Global","Lot","Application","Databases","DR O/N",
 "Current connection string","New connection string",
 "New connection string avec DR","Cnames","Services","Acces","Cnames DR"
]

# -------------------------
def build_raw(row):
    return dict((c,ustr(row.get(c,u"")).strip()) for c in RAW_COLUMNS)

# -------------------------
def build_status(valid,scan,scan_dr,dirty,dirty_reason,err_type,err_detail,mode):
    return {
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

# -------------------------
def build_object(row,i,store_index,force):

    raw=build_raw(row)
    cached=store_index.get(i)

    dirty=False; dirty_reason=None
    if cached and cached.get("RawSource")!=raw:
        dirty=True; dirty_reason="RAW_CHANGED"

    cur,new,dr = raw["Current connection string"],raw["New connection string"],raw["New connection string avec DR"]

    cur_o,e1,d1=interpret(cur)
    new_o,e2,d2=interpret(new)
    dr_o,e3,d3=interpret(dr)

    net={
      "Current":{"host":cur_o.host,"cname":cur_o.cname,"scan":cur_o.scan},
      "New":{"host":new_o.host,"cname":new_o.cname,"scan":new_o.scan},
      "NewDR":{"host":dr_o.host,"cname":dr_o.cname,"scan":dr_o.scan}
    }

    err_type=None; err_detail=None
    scan=None; scan_dr=None

    if e1 or e2:
        scan="ERROR"; err_type=e1 or e2; err_detail=d1 or d2
    else:
        eq=compare(cur_o.scan,new_o.scan)
        if eq is None:
            scan="ERROR"; err_type="SCAN_COMPARE_ERROR"; err_detail="Normalization failed"
        else:
            scan="VALIDE" if eq else "DIFFERENT"
            if not eq:
                err_type="SCAN_DIFFERENT"; err_detail="Current and New SCAN differ"

    if dr_o.valide:
        eqdr=compare(cur_o.scan,dr_o.scan)
        scan_dr="VALIDE" if eqdr else "DIFFERENT"

    status=build_status(True,scan,scan_dr,dirty,dirty_reason,err_type,err_detail,
                        "FORCE_UPDATE" if force else ("AUTO_DIRTY" if dirty else "AUTO"))

    return {"id":i,"RawSource":raw,"Network":net,"Status":status}

# -------------------------
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

# -------------------------
if __name__=="__main__":

    fichier=sys.argv[1]
    option=sys.argv[2]
    args=[a.lower() for a in sys.argv[3:]]

    force="-force" in args or "-update" in args

    rows=[dict((k,ustr(v)) for k,v in r.items())
          for r in csv.DictReader(open(fichier,"rb"),delimiter=';')]

    ids=parse_ids(option,len(rows))

    store=load_store("Data/connexions_store_v3.json")
    index=build_index(store)

    keep=[o for o in store.get("objects",[]) if o["id"] not in ids]

    objs=[]
    for i,r in enumerate(rows,1):
        if i in ids:
            objs.append(build_object(r,i,index,force))

    store["objects"]=keep+objs
    save_store("Data/connexions_store_v3.json",store)

    print "\nAnalyseV3 terminé. Objets générés:",len(objs)
