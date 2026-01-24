# -*- coding: utf-8 -*-
# Lib/io_common.py
#
# Utilitaires I/O communs AnalyseV3 / ReportV3
# AUCUNE logique métier ici

import os
import json
import re

ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')

CONF_FILE = os.path.join("Data", "config.conf")

# -------------------------
def load_main_conf():
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
            d[k.strip()] = v.strip()

        if not d.get("SOURCE_JSON"):
            return None, "CONF_INVALID", "SOURCE_JSON missing in %s" % CONF_FILE

        return d, None, None

    except Exception as e:
        return None, "CONF_ERROR", str(e)

# -------------------------
def ustr(v):
    if v is None:
        return u""
    if isinstance(v, unicode):
        return v
    try:
        return unicode(v, "utf-8", "ignore")
    except:
        return unicode(str(v), "utf-8", "ignore")

# -------------------------
def strip_ansi(s):
    return ANSI_RE.sub('', s or "")

# -------------------------
def load_store_json(path):
    if not os.path.isfile(path):
        return None, "STORE_MISSING", "Missing %s" % path
    try:
        return json.loads(open(path, "rb").read().decode("utf-8")), None, None
    except Exception as e:
        return None, "STORE_ERROR", str(e)
