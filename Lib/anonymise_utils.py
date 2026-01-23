# -*- coding: utf-8 -*-
# Lib/anonymise_utils.py

def parse_ids(ids_arg, max_id):
    if ids_arg.upper() == "ALL":
        return range(1, max_id + 1)

    out = []
    for p in ids_arg.split(","):
        p = p.strip()
        if p:
            out.append(int(p))
    return out
