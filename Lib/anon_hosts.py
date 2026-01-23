# -*- coding: utf-8 -*-
# Lib/anon_hosts.py
#
# Étape HOSTS :
# - anonymise host / cname / cname DR / scan
# - Host_<ID>_<SEQ>, séquence locale par objet
# - propagation globale
# - ne touche PAS à DBNAME, ports, services, nodes

import re

HOST_KEYS = set([
    "host", "cname", "scan", "Cnames", "Cnames DR"
])

def apply(obj, oid):
    if not isinstance(obj, dict):
        return obj

    host_map = {}
    seq = [1]  # compteur local mutable

    def anon_host(val):
        if not val:
            return val
        if val not in host_map:
            host_map[val] = "Host_%d_%d" % (oid, seq[0])
            seq[0] += 1
        return host_map[val]

    def replace_in_string(s):
        # remplace chaque token "host-like" déjà rencontré
        for h, a in host_map.items():
            s = s.replace(h, a)
        return s

    def walk(node):
        if isinstance(node, dict):
            out = {}
            for k, v in node.items():
                if k in ("host", "cname", "scan"):
                    out[k] = anon_host(v)
                elif k in ("Cnames", "Cnames DR"):
                    out[k] = anon_host(v)
                else:
                    out[k] = walk(v)
            return out

        if isinstance(node, list):
            return [walk(x) for x in node]

        if isinstance(node, basestring):
            return replace_in_string(node)

        return node

    return walk(obj)
