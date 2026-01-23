# -*- coding: utf-8 -*-
# Lib/anon_lock.py
#
# ETAPE 6 : cohérence globale & verrouillage
# - réutilise les anonymisations existantes
# - interdit toute divergence entre sections

import re

HOST_RE = re.compile(r'\bHost_\d+_\d+\b')
DB_RE   = re.compile(r'\bDBNAME_\d+\b')
PORT_RE = re.compile(r'\bPORT_\d+\b')
SCAN_RE = re.compile(r'\bSCAN_\d+\b')

def apply(obj, oid):
    if not isinstance(obj, dict):
        return obj

    known = {
        "hosts": set(),
        "db": None,
        "ports": set(),
        "scans": set()
    }

    def collect(n):
        if isinstance(n, dict):
            for v in n.values():
                collect(v)
        elif isinstance(n, list):
            for x in n:
                collect(x)
        elif isinstance(n, basestring):
            for m in HOST_RE.findall(n):
                known["hosts"].add(m)
            for m in PORT_RE.findall(n):
                known["ports"].add(m)
            for m in SCAN_RE.findall(n):
                known["scans"].add(m)
            m = DB_RE.search(n)
            if m:
                known["db"] = m.group(0)

    collect(obj)

    def enforce(n):
        if isinstance(n, dict):
            return dict((k, enforce(v)) for k, v in n.items())
        if isinstance(n, list):
            return [enforce(x) for x in n]
        if isinstance(n, basestring):
            if known["db"]:
                n = re.sub(r'DBNAME_\d+', known["db"], n)
            for h in known["hosts"]:
                n = re.sub(r'Host_\d+_\d+', h, n, count=1)
            for p in known["ports"]:
                n = re.sub(r'PORT_\d+', p, n)
            return n
        return n

    return enforce(obj)
