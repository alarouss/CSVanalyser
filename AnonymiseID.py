#!/usr/bin/env python
# -*- coding: utf-8 -*-
# AnonymiseID.py

import sys
import os
import json

from Lib.anonymise_engine import run
from Lib.anonymise_utils import parse_ids

def parse_args(argv):
    src = None
    ids = None

    for a in argv[1:]:
        if a.startswith("source="):
            src = a.split("=", 1)[1]
        elif a.startswith("id="):
            ids = a.split("=", 1)[1]

    return src, ids

def main():
    src, ids_arg = parse_args(sys.argv)

    if not src or not ids_arg or not os.path.isfile(src):
        print "Usage: python AnonymiseID.py source=store.json id=1,2|ALL"
        sys.exit(1)

    data = json.loads(open(src, "rb").read().decode("utf-8"))
    ids = parse_ids(ids_arg, len(data.get("objects", [])))

    objects, changed = run(src, ids)

    out = {"objects": objects}
    base, _ = os.path.splitext(src)
    out_file = base + "_anon.json"

    open(out_file, "wb").write(
        json.dumps(out, indent=2, ensure_ascii=False).encode("utf-8")
    )

    print
    print "Anonymisation terminee"
    print "  objets traites :", len(objects)
    print "  objets modifies :", changed
    print "  fichier :", out_file

if __name__ == "__main__":
    main()
