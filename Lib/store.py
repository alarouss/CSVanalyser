# Lib/store.py
# -*- coding: utf-8 -*-

import os, json

def load_store(store_file):
    if not os.path.isfile(store_file):
        return {"objects": []}
    return json.loads(open(store_file, "rb").read().decode("utf-8"))

def save_store(store_file, store):
    open(store_file, "wb").write(
        json.dumps(store, indent=2, ensure_ascii=False).encode("utf-8")
    )

def build_index(store):
    idx = {}
    for o in store.get("objects", []):
        idx[o.get("id")] = o
    return idx
