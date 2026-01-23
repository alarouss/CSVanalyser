# -*- coding: utf-8 -*-
# Lib/anon_lock.py
#
# ETAPE 6 – propagation globale par cohérence
# (aucune supposition sur les valeurs)

import re

HOST_ANON_RE = re.compile(r'Host_\d+_\d+')
DB_ANON_RE   = re.compile(r'DBNAME_\d+')
PORT_ANON_RE = re.compile(r'PORT_\d+')

def apply(obj, oid):
    if not isinstance(obj, dict):
        return obj

    known = {
        "host": None,
        "db": "DBNAME_%d" % oid,
        "port": None,
        "app": "APP_%d" % oid
    }

    # 1) Collecte des anonymisations déjà présentes
    def collect(n):
        if isinstance(n, dict):
            for v in n.values():
                collect(v)
        elif isinstance(n, list):
            for x in n:
                collect(x)
        elif isinstance(n, basestring):
            if not known["host"]:
                m = HOST_ANON_RE.search(n)
                if m:
                    known["host"] = m.group(0)
            if not known["port"]:
                m = PORT_ANON_RE.search(n)
                if m:
                    known["port"] = m.group(0)

    collect(obj)

    # 2) Propagation globale
    def walk(n):
        if isinstance(n, dict):
            out = {}
            for k, v in n.items():
                if k == "Application":
                    out[k] = known["app"]
                else:
                    out[k] = walk(v)
            return out

        if isinstance(n, list):
            return [walk(x) for x in n]

        if isinstance(n, basestring):
            if known["host"]:
                n = re.sub(r'\b[A-Za-z0-9_-]+\b', known["host"], n)
            n = re.sub(DB_ANON_RE, known["db"], n)
            if known["port"]:
                n = re.sub(PORT_ANON_RE, known["port"], n)
            return n

        return n

    return walk(obj)
