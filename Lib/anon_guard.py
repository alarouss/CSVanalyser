# -*- coding: utf-8 -*-
# Lib/anon_guard.py
#
# ETAPE 7 : garde-fous finaux
# - détecte toute fuite de données brutes
# - n'effectue AUCUNE transformation

import re

FORBIDDEN_PATTERNS = [
    # ports classiques Oracle
    re.compile(r'\b15\d{2}\b'),

    # host encore lisible (heuristique volontairement large)
    re.compile(r'\b[a-zA-Z0-9_-]+\.(fr|com|net|local)\b', re.I),

    # anciens patterns DB
    re.compile(r'\b[A-Z]{3,}_[A-Z0-9]+\b')
]

ALLOWED = [
    re.compile(r'\bHost_\d+_\d+\b'),
    re.compile(r'\bDBNAME_\d+\b'),
    re.compile(r'\bPORT_\d+\b'),
    re.compile(r'\bSCAN_\d+\b'),
    re.compile(r'\bSRV_.*_DBNAME_\d+\b')
]

def apply(obj, oid):
    errors = []

    def allowed(s):
        return any(p.search(s) for p in ALLOWED)

    def walk(n, path=""):
        if isinstance(n, dict):
            for k, v in n.items():
                walk(v, path + "/" + k)
        elif isinstance(n, list):
            for i, x in enumerate(n):
                walk(x, path + "[%d]" % i)
        elif isinstance(n, basestring):
            for p in FORBIDDEN_PATTERNS:
                if p.search(n) and not allowed(n):
                    errors.append((path, n))

    walk(obj)

    if errors:
        print
        print "ERREUR ANONYMISATION (ID=%d)" % oid
        for p, v in errors:
            print " - fuite detectee:", p
            print "   valeur:", v
        raise SystemExit(2)

    return obj
