#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Python 2.6 compatible

import sys
import json
import re

HOST_MAP = {}
HOST_SEQ = 1

IP_RE = re.compile(r'\b\d{1,3}(\.\d{1,3}){3}\b', re.I)
HOST_RE = re.compile(r'\b([A-Za-z0-9\-_]+\.[A-Za-z0-9\.\-_]+|\b[A-Za-z0-9\-_]+scan[A-Za-z0-9\-_]*|\b[A-Za-z0-9\-_]+)\b', re.I)

def new_alias(name):
    global HOST_SEQ
    alias = None

    low = name.lower()

    if "scan" in low:
        alias = "SCAN_%d" % HOST_SEQ
    else:
        alias = "HOST_%d" % HOST_SEQ

    HOST_SEQ += 1
    return alias

def anonymize_value(val):
    if not val:
        return val

    if not isinstance(val, basestring):
        return val

    txt = val

    # IP anonymisation
    txt = IP_RE.sub("X.X.X.X", txt)

    # Host / FQDN anonymisation
    def repl(m):
        name = m.group(0)

        if name.lower().startswith("jdbc"):
            return name

        if name not in HOST_MAP:
            HOST_MAP[name] = new_alias(name)

        return HOST_MAP[name]

    txt = HOST_RE.sub(repl, txt)

    return txt

def anonymize_obj(obj):
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            out[k] = anonymize_obj(v)
        return out

    if isinstance(obj, list):
        return [anonymize_obj(x) for x in obj]

    return anonymize_value(obj)

# ------------------------------------------------

def parse_args():
    src = None
    idv = None

    for a in sys.argv[1:]:
        if a.startswith("source="):
            src = a.split("=",1)[1]
        if a.startswith("id="):
            idv = int(a.split("=",1)[1])

    return src, idv

# ------------------------------------------------

if __name__ == "__main__":

    src, idv = parse_args()

    if not src or not idv:
        print "Usage:"
        print "  python AnonymiseID.py source=/path/file.json id=5"
        sys.exit(1)

    data = json.loads(open(src,"rb").read())

    found = None
    for o in data.get("objects",[]):
        if o.get("id") == idv:
            found = o
            break

    if not found:
        print "ID not found:", idv
        sys.exit(1)

    anon = anonymize_obj(found)

    print json.dumps(anon, indent=2, ensure_ascii=False)
