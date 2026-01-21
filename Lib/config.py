# Lib/config.py
# -*- coding: utf-8 -*-

import os

def load_config(conf_file):
    cfg = {}
    for line in open(conf_file, "rb").read().splitlines():
        try:
            s = line.decode("utf-8","ignore")
        except:
            s = line
        s = s.strip()
        if not s or s.startswith("#"):
            continue
        if "=" not in s:
            continue
        k,v = s.split("=",1)
        cfg[k.strip()] = v.strip()
    return cfg
