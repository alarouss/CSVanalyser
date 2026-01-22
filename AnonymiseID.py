#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json, sys, os, re

HOST_MAP = {}
DB_MAP = {}
host_counter = 1

# ------------------------------------------------
def get_host_alias(h):
    global host_counter
    if not h:
        return h
    if h not in HOST_MAP:
        HOST_MAP[h] = "HOST_%d" % host_counter
        host_counter += 1
    return HOST_MAP[h]

def anonymise_db(name):
    if not name:
        return name
    return "{DATABASENAME}"

# ------------------------------------------------
def anonymise_numbers(val):
    return re.sub(r"=([0-9]+)", "=XXXX", val)

# ------------------------------------------------
def anonymise_hosts_in_text(txt):
    if not txt:
        return txt
    for h, alias in HOST_MAP.items():
        txt = txt.replace(h, "{%s}" % alias)
    return txt

# ------------------------------------------------
def anonymise_rawsource(raw):
    for k in raw:
        v = raw[k]
        if not isinstance(v, unicode):
            try:
                v = unicode(v, "utf-8", "ignore")
            except:
                continue

        if k == "Databases":
            raw[k] = anonymise_db(v)
            continue

        v = anonymise_numbers(v)

        for d in DB_MAP:
            v = v.replace(d, "{DATABASENAME}")

        v = anonymise_hosts_in_text(v)

        raw[k] = v

# ------------------------------------------------
def anonymise_network(net):

    for section in net:
        blk = net.get(section)
        if not isinstance(blk, dict):
            continue

        for key in ("host","cname","scan"):
            val = blk.get(key)
            if val:
                blk[key] = get_host_alias(val)

        if "port" in blk and blk.get("port"):
            blk["port"] = "XXXX"

# ------------------------------------------------
def anonymise_status(st):

    for k in ("ErrorDetail","OEMErrorDetail"):
        v = st.get(k)
        if not v:
            continue

        if not isinstance(v, unicode):
            v = unicode(v,"utf-8","ignore")

        for h, alias in HOST_MAP.items():
            v = v.replace(h, "{%s}" % alias)

        for d in DB_MAP:
            v = v.replace(d, "{DATABASENAME}")

        v = anonymise_numbers(v)
        st[k] = v

# ------------------------------------------------
def parse_ids(val):
    out=[]
    for p in val.split(","):
        p=p.strip()
        if p:
            out.append(int(p))
    return out

# ------------------------------------------------
def main():

    src = None
    ids = []

    for a in sys.argv[1:]:
        if a.startswith("source="):
            src = a.split("=",1)[1]
        elif a.startswith("id="):
            ids = parse_ids(a.split("=",1)[1])

    if not src or not ids:
        print "Usage: python AnonymiseID.py source=FILE.json id=2,3,4"
        sys.exit(1)

    if not os.path.isfile(src):
        print "Source file not found:", src
        sys.exit(1)

    data = json.loads(open(src,"rb").read().decode("utf-8"))

    objects = data.get("objects",[])

    selected = [o for o in objects if o.get("id") in ids]

    if not selected:
        print "No matching IDs found"
        sys.exit(1)

    # collect DB names
    for o in selected:
        db = o.get("RawSource",{}).get("Databases")
        if db:
            DB_MAP[db] = "{DATABASENAME}"

    # anonymise all
    for o in selected:
        anonymise_network(o.get("Network",{}))
        anonymise_rawsource(o.get("RawSource",{}))
        anonymise_status(o.get("Status",{}))

        # OEM section outside Network (V3 structure)
        if "OEM" in o and isinstance(o["OEM"],dict):
            anonymise_network({"OEM":o["OEM"]})

    print json.dumps(selected, indent=2, ensure_ascii=False).encode("utf-8")

# ------------------------------------------------
if __name__=="__main__":
    main()
