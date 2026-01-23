#!/usr/bin/env python
# -*- coding: utf-8 -*-
#retour 3
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
import re

# ------------------------------------------------
def parse_args(argv):
    src = None
    ids = None
    for a in argv[1:]:
        if a.startswith("source="):
            src = a.split("=", 1)[1]
        elif a.startswith("id="):
            ids = a.split("=", 1)[1]
    return src, ids

# ------------------------------------------------
def parse_ids(ids, max_id):
    if ids.upper() == "ALL":
        return range(1, max_id + 1)
    return [int(x.strip()) for x in ids.split(",") if x.strip()]

# ------------------------------------------------
def make_seq_mapper(prefix, obj_id):
    seq = [0]
    mapping = {}

    def map_value(v):
        if v not in mapping:
            seq[0] += 1
            mapping[v] = "%s_%d_%d" % (prefix, obj_id, seq[0])
        return mapping[v]

    return map_value

# ------------------------------------------------
def anonymize_string(s, repl):
    out = s
    for a, b in repl.items():
        out = out.replace(a, b)
    return out

# ------------------------------------------------
def anonymize_rawsource(raw, obj_id, host_map, cname_map):
    out = {}

    dbname = "DBNAME_%d" % obj_id
    repl = {
        "{DATABASENAME}": dbname,
        "1521": "PORT_%d" % obj_id
    }

    if "Application" in raw:
        repl[raw["Application"]] = "APP_%d" % obj_id

    if "Databases" in raw:
        repl[raw["Databases"]] = dbname

    if "Cnames" in raw:
        repl[raw["Cnames"]] = "CNames_%d" % obj_id

    if "Cnames DR" in raw:
        repl[raw["Cnames DR"]] = "CNamesDR_%d" % obj_id

    for k, v in raw.items():
        if not isinstance(v, basestring):
            out[k] = v
            continue

        nv = anonymize_string(v, repl)

        # anonymiser tout ce qui est entre '=' et ')'
        def _eq_paren(m):
            return "=" + host_map(m.group(1)) + ")"

        nv = re.sub(r"=([^)=]+)\)", _eq_paren, nv)

        # anonymiser host après '@'
        nv = re.sub(
            r'@([^:/]+)',
            lambda m: '@' + host_map(m.group(1)),
            nv
        )

        # anonymiser node -> DBNAME_ID_NODE
        nv = re.sub(
            r'/[^/"]+',
            '/' + dbname + '_NODE',
            nv
        )

        # services SRV_xxx_DBNAME
        nv = re.sub(
            r'(SRV_[A-Z0-9_]+)_.*',
            r'\1_' + dbname,
            nv
        )

        out[k] = nv

    return out, dbname

# ------------------------------------------------
def anonymize_dict_block(block, obj_id, host_map, scan_map):
    out = {}
    for k, v in block.items():
        if isinstance(v, dict):
            out[k] = anonymize_dict_block(v, obj_id, host_map, scan_map)
        elif isinstance(v, basestring):
            if k in ("host", "cname"):
                out[k] = host_map(v)
            elif k == "scan":
                out[k] = scan_map(v)
            elif k == "port":
                out[k] = "PORT_%d" % obj_id
            else:
                out[k] = v
        else:
            out[k] = v
    return out

# ------------------------------------------------
def main():
    src, ids_arg = parse_args(sys.argv)
    if not src or not ids_arg or not os.path.isfile(src):
        print "Usage: python AnonymiseID.py source=store.json id=1,2|ALL"
        sys.exit(1)

    data = json.loads(open(src, "rb").read().decode("utf-8"))
    objects = data.get("objects", [])

    ids = parse_ids(ids_arg, len(objects))

    for obj in objects:
        try:
            oid = int(obj.get("id"))
        except:
            continue

        if oid not in ids:
            continue

        host_map = make_seq_mapper("Host", oid)
        scan_map = make_seq_mapper("SCAN", oid)
        cname_map = make_seq_mapper("CNames", oid)

        if "RawSource" in obj:
            obj["RawSource"], dbname = anonymize_rawsource(
                obj["RawSource"], oid, host_map, cname_map
            )

        if "Network" in obj:
            obj["Network"] = anonymize_dict_block(
                obj["Network"], oid, host_map, scan_map
            )

        if "OEM" in obj:
            obj["OEM"] = anonymize_dict_block(
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
