# -*- coding: utf-8 -*-
# Lib/anon_lock.py
#
# ETAPE 6 – verrouillage global (corrigé)
# - supprime toute fuite dans Status / Application
# - n'introduit AUCUNE nouvelle anonymisation

import re

HOST_RE = re.compile(r'Host_\d+_\d+')
DB_RE   = re.compile(r'DBNAME_\d+')
PORT_RE = re.compile(r'PORT_\d+')
SCAN_RE = re.compile(r'SCAN_\d+')
APP_RE  = re.compile(r'APP_\d+')

def apply(obj, oid):
    if not isinstance(obj, dict):
        return obj

    known = {
        "host": None,
        "db": None,
        "port": None,
        "app": "APP_%d" % oid
    }

    def collect(n):
        if isinstance(n, dict):
            for v in n.values():
                collect(v)
        elif isinstance(n, list):
            for x in n:
                collect(x)
        elif isinstance(n, basestring):
            if not known["host"]:
                m = HOST_RE.search(n)
                if m:
                    known["host"] = m.group(0)
            if not known["db"]:
                m = DB_RE.search(n)
                if m:
                    known["db"] = m.group(0)
            if not known["port"]:
                m = PORT_RE.search(n)
                if m:
                    known["port"] = m.group(0)

    collect(obj)

    def enforce(n):
        if isinstance(n, dict):
            out = {}
            for k, v in n.items():
                if k == "Application":
                    out[k] = known["app"]
                else:
                    out[k] = enforce(v)
            return out

        if isinstance(n, list):
            return [enforce(x) for x in n]

        if isinstance(n, basestring):
            if known["host"]:
                n = re.sub(r'\b[a-zA-Z0-9_.-]+\b', known["host"], n)
            if known["db"]:
                n = re.sub(r'DBNAME_\d+', known["db"], n)
            if known["port"]:
                n = re.sub(r'PORT_\d+', known["port"], n)
            return n

        return n

    return enforce(obj)
