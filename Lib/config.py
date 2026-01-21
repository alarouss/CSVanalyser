# -*- coding: utf-8 -*-
# Lib/config.py

import os

CONF_FILE = os.path.join("Data", "config.conf")

def load_main_conf():
    """
    Lit Data/config.conf et retourne (dict, err_code, err_detail)
    Format:
        KEY=VALUE
    Ignore lignes vides et commentaires (# ou ;)
    """

    if not os.path.isfile(CONF_FILE):
        return None, "CONF_MISSING", "Missing %s" % CONF_FILE

    d = {}

    try:
        for line in open(CONF_FILE, "rb").read().splitlines():
            try:
                s = line.decode("utf-8", "ignore")
            except:
                s = line

            s = s.strip()

            if not s:
                continue
            if s.startswith("#") or s.startswith(";"):
                continue
            if "=" not in s:
                continue

            k, v = s.split("=", 1)
            k = k.strip()
            v = v.strip()

            if k:
                d[k] = v

        return d, None, None

    except Exception as e:
        return None, "CONF_ERROR", str(e)
