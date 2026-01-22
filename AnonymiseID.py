#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json, sys, re

# ---------- mappings globaux ----------
HOST_MAP = {}
SCAN_MAP = {}
CNAME_MAP = {}
DB_MAP = {}
SERVICE_MAP = {}

HOST_C = 1
SCAN_C = 1
CNAME_C = 1
DB_C = 1
SERVICE_C = 1

def map_value(val, prefix, store):
    global HOST_C, SCAN_C, CNAME_C, DB_C, SERVICE_C

    if not val:
        return val

    if val in store:
        return store[val]

    if prefix == "HOST":
        alias = "HOST_%d" % HOST_C
        HOST_C += 1
    elif prefix == "SCAN":
        alias = "SCAN_%d" % SCAN_C
        SCAN_C += 1
    elif prefix == "CNAME":
        alias = "CNAME_%d" % CNAME_C
        CNAME_C += 1
    elif prefix == "DB":
        alias = "DB_%d" % DB_C
        DB_C += 1
    elif prefix == "SRV":
        alias = "SRV_%d" % SERVICE_C
        SERVICE_C += 1
    else:
        alias = prefix + "_X"

    store[val] = alias
    return alias

# ---------------------------------------------------
def anonymise_text(txt):
    if not txt:
        return txt

    # Ports
    txt = re.sub(r'\b\d{4,5}\b', "XXXX", txt)

    # HOST patterns
    for h in re.findall(r'[A-Za-z0-9._-]+', txt):
        if "." in h or "scan" in h.lower() or "host" in h.lower():
            alias = map_value(h, "HOST", HOST_MAP)
            txt = txt.replace(h, "{%s}" % alias)

    return txt

# ---------------------------------------------------
def anonymise_rawsource(rs):

    for k in rs:
        v = rs[k]
        if not v:
            continue
        rs[k] = anonymise_text(v)

# ---------------------------------------------------
def anonymise_network(net):

    for sec in net:
        blk = net.get(sec)
        if not blk:
            continue

        if blk.get("host"):
            blk["host"] = map_value(blk["host"], "HOST", HOST_MAP)

        if blk.get("cname"):
            blk["cname"] = map_value(blk["cname"], "CNAME", CNAME_MAP)

        if blk.get("scan"):
            blk["scan"] = map_value(blk["scan"], "SCAN", SCAN_MAP)

        if blk.get("port"):
            blk["port"] = "XXXX"

# ---------------------------------------------------
def anonymise_status(st):

    for k in ("ErrorDetail","OEMErrorDetail"):
        if st.get(k):
            txt = st[k]

            for h, a in HOST_MAP.items():
                txt = txt.replace(h, "{%s}" % a)
            for s, a in SCAN_MAP.items():
                txt = txt.replace(s, "{%s}" % a)

            st[k] = txt

# ---------------------------------------------------
def main():

    if len(sys.argv) < 3:
        print "Usage: python AnonymiseID.py source.json id=N"
        sys.exit(1)

    src = sys.argv[1]
    opt = sys.argv[2]

    if not opt.startswith("id="):
        print "Invalid id parameter"
        sys.exit(1)

    target = int(opt.split("=")[1])

    data = json.loads(open(src,"rb").read().decode("utf-8"))

    obj = None
    for o in data.get("objects",[]):
        if o.get("id")==target:
            obj = o
            break

    if not obj:
        print "ID not found"
        sys.exit(1)

    anonymise_rawsource(obj.get("RawSource",{}))
    anonymise_network(obj.get("Network",{}))
    anonymise_status(obj.get("Status",{}))

    print json.dumps(obj, indent=2, ensure_ascii=False).encode("utf-8")

# ---------------------------------------------------
if __name__=="__main__":
    main()
