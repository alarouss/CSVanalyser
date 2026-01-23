# -*- coding: utf-8 -*-
# Lib/anon_hosts.py
#
# Étape HOSTS :
# - anonymise host / cname / scan / Cnames / Cnames DR
# - Host_<ID>_<SEQ>, séquence locale par objet
# - mapping persistant par objet (_anon_ctx)
# - propagation globale (y compris ErrorDetail)

import re

HOST_KEYS = set([
    "host", "cname", "scan", "Cnames", "Cnames DR"
])

def apply(obj, oid):
    if not isinstance(obj, dict):
        return obj

    # ------------------------------
    # CONTEXTE GLOBAL PAR OBJET
    # ------------------------------
    ctx = obj.setdefault("_anon_ctx", {})
    host_map = ctx.setdefault("hosts", {})
    ctx.setdefault("host_seq", 1)

    def anon_host(val):
        if not val:
            return val
        if val not in host_map:
            seq = ctx["host_seq"]
            host_map[val] = "Host_%d_%d" % (oid, seq)
            ctx["host_seq"] = seq + 1
        return host_map[val]

    # ------------------------------
    # 1) DÉTECTION + MAPPING
    # ------------------------------
    def collect(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if k in HOST_KEYS and isinstance(v, basestring):
                    anon_host(v)
                else:
                    collect(v)
        elif isinstance(node, list):
            for x in node:
                collect(x)
        elif isinstance(node, basestring):
            # extraction HOST=xxx, @xxx, etc.
            for m in re.findall(r'HOST=([A-Za-z0-9_.-]+)', node):
                anon_host(m)
            for m in re.findall(r'@([A-Za-z0-9_.-]+)', node):
                anon_host(m)

    # ------------------------------
    # 2) REMPLACEMENT GLOBAL
    # ------------------------------
    def replace(node):
        if isinstance(node, dict):
            return dict((k, replace(v)) for k, v in node.items())
        if isinstance(node, list):
            return [replace(x) for x in node]
        if isinstance(node, basestring):
            s = node
            for real, anon in host_map.items():
                s = s.replace(real, anon)
            return s
        return node

    # Phase 1 : collecter TOUS les hosts
    collect(obj)

    # Phase 2 : remplacer PARTOUT
    return replace(obj)
