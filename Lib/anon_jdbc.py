# -*- coding: utf-8 -*-
# Lib/anon_jdbc.py
#
# ETAPE 5 – JDBC : anonymisation des HOST par POSITION
# (la valeur n'a aucune importance)

import re

# JDBC simple : @TOKEN: ou @TOKEN/
AT_HOST_RE = re.compile(r'(@)([^:/\s",]+)', re.I)

# SQLNet : HOST=TOKEN
SQLNET_HOST_RE = re.compile(r'(HOST=)([^)]+)', re.I)

def apply(obj, oid):
    if not isinstance(obj, dict):
        return obj

    host_map = {}
    seq = [1]

    def map_host(token):
        if token not in host_map:
            host_map[token] = "Host_%d_%d" % (oid, seq[0])
            seq[0] += 1
        return host_map[token]

    def anon_jdbc_string(s):
        # JDBC simple @TOKEN
        s = AT_HOST_RE.sub(
            lambda m: m.group(1) + map_host(m.group(2)),
            s
        )

        # SQLNet HOST=TOKEN
        s = SQLNET_HOST_RE.sub(
            lambda m: m.group(1) + map_host(m.group(2)),
            s
        )

        return s

    def walk(n):
        if isinstance(n, dict):
            return dict((k, walk(v)) for k, v in n.items())
        if isinstance(n, list):
            return [walk(x) for x in n]
        if isinstance(n, basestring):
            if "jdbc:oracle:thin:@" in n.lower():
                return anon_jdbc_string(n)
        return n

    return walk(obj)
