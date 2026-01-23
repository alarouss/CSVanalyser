# -*- coding: utf-8 -*-
# Lib/anonymise_engine.py
#
# Moteur d’anonymisation CLI (I/O, filtrage, orchestration)

import json
import os

from Lib.anon_pipeline import anonymize_object
from Lib.anonymise_utils import parse_ids

def run(source_file, ids):
    data = json.loads(open(source_file, "rb").read().decode("utf-8"))
    objects = data.get("objects", [])

    out_objects = []
    changed = 0

    for obj in objects:
        try:
            oid = int(obj.get("id"))
        except:
            continue

        if oid not in ids:
            continue

        before = json.dumps(obj, sort_keys=True)
        obj = anonymize_object(obj, oid)
        after = json.dumps(obj, sort_keys=True)

        if before != after:
            changed += 1

        out_objects.append(obj)

    return out_objects, changed
