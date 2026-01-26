# -*- coding: utf-8 -*-
# Lib/store.py

import os
import json

def load_store(store_file):
    
    if not os.path.isfile(store_file):
        return {"objects": []}

    data = open(store_file, "rb").read().decode("utf-8")
    return json.loads(data)

def save_store(store_file, store):
    open(store_file, "wb").write(
        json.dumps(store, indent=2, ensure_ascii=False).encode("utf-8")
    )

def build_index(store):
    idx = {}
    for o in store.get("objects", []):
        idx[o.get("id")] = o
    return idx
