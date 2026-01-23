#!/usr/bin/env python
# -*- coding: utf-8 -*-
# retour
"""
AnonymiseID.py
Anonymisation ciblée par ID du store AnalyseV3

Usage:
  python AnonymiseID.py source=store.json id=1,2
  python AnonymiseID.py source=store.json id=ALL
"""

import json
import sys
import os

# ------------------------------------------------
def parse_args(argv):
    src = None
    ids = None

    for a in argv[1:]:
        if a.startswith("source="):
            src = a.split("=", 1)[1]
        elif a.startswith("id="):
            ids = a.split("=", 1)[1]

    if not src or not ids:
        return None, None

    return src, ids

# ------------------------------------------------
def parse_ids(ids, max_id):
    if ids.upper() == "ALL":
        return range(1, max_id + 1)
    out = []
    for p in ids.split(","):
        p = p.strip()
        if p:
            out.append(int(p))
    return out

# ------------------------------------------------
def anonymize_rawsource(raw, obj_id):
    repl = {}

    # Application
    if "Application" in raw and raw["Application"]:
        repl[raw["Application"]] = "App_%d" % obj_id

    # Databases
    if "Databases" in raw and raw["Databases"]:
        repl[raw["Databases"]] = "DatabaseName_%d" % obj_id

    # Placeholder {DATABASENAME}
    repl["{DATABASENAME}"] = "DatabaseName_%d" % obj_id

    # Cnames
    if "Cnames" in raw and raw["Cnames"]:
        repl[raw["Cnames"]] = "CNames_%d" % obj_id

    # Cnames DR
    if "Cnames DR" in raw and raw["Cnames DR"]:
        repl[raw["Cnames DR"]] = "CNamesDR_%d" % obj_id

    # Ports (ex: 1521)
    repl["1521"] = "PORT_%d" % obj_id

    out = {}
    for k, v in raw.items():
        if isinstance(v, basestring):
            nv = v
            for a, b in repl.items():
                nv = nv.replace(a, b)
            out[k] = nv
        else:
            out[k] = v
    return out

# ------------------------------------------------
def anonymize_network(net, obj_id, host_map, scan_map):
    out = {}
    for zone, data in net.items():
        if not isinstance(data, dict):
            out[zone] = data
            continue

        d = {}
        for k, v in data.items():
            if k in ("host", "cname") and v:
                if v not in host_map:
                    host_map[v] = "HOST_%d" % (len(host_map) + 1)
                d[k] = host_map[v]
            elif k == "scan" and v:
                if v not in scan_map:
                    scan_map[v] = "SCAN_%d" % (len(scan_map) + 1)
                d[k] = scan_map[v]
            elif k == "port" and v:
                d[k] = "PORT_%d" % obj_id
            else:
                d[k] = v
        out[zone] = d
    return out

# ------------------------------------------------
def anonymize_oem(oem, obj_id, host_map, scan_map):
    if not isinstance(oem, dict):
        return oem

    d = {}
    for k, v in oem.items():
        if k in ("host", "cname") and v:
            if v not in host_map:
                host_map[v] = "HOST_%d" % (len(host_map) + 1)
            d[k] = host_map[v]
        elif k == "scan" and v:
            if v not in scan_map:
                scan_map[v] = "SCAN_%d" % (len(scan_map) + 1)
            d[k] = scan_map[v]
        elif k == "port" and v:
            d[k] = "PORT_%d" % obj_id
        else:
            d[k] = v
    return d

# ------------------------------------------------
def main():
    src, ids_arg = parse_args(sys.argv)
    if not src or not os.path.isfile(src):
        print "Usage: python AnonymiseID.py source=store.json id=1,2|ALL"
        sys.exit(1)

    data = json.loads(open(src, "rb").read().decode("utf-8"))
    objects = data.get("objects", [])

    ids = parse_ids(ids_arg, len(objects))

    host_map = {}
    scan_map = {}

    for obj in objects:
        try:
            oid = int(obj.get("id"))
        except:
            continue

        if oid not in ids:
            continue

        if "RawSource" in obj:
            obj["RawSource"] = anonymize_rawsource(obj["RawSource"], oid)

        if "Network" in obj:
            obj["Network"] = anonymize_network(
                obj["Network"], oid, host_map, scan_map
            )

        if "OEM" in obj:
            obj["OEM"] = anonymize_oem(
                obj["OEM"], oid, host_map, scan_map
            )

    base, ext = os.path.splitext(src)
    out = base + "_anon.json"

    open(out, "wb").write(
        json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")
    )

    print "Anonymisation terminée :", out

# ------------------------------------------------
if __name__ == "__main__":
    main()
