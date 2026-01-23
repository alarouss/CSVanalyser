# -*- coding: utf-8 -*-
# Lib/anon_jdbc.py
#
# ETAPE 5 – JDBC fine grain (corrigée)
# - anonymise TOUS les hosts après @
# - respecte les mappings existants (Host_<ID>_<SEQ>)
# - ne crée PAS de nouveaux hosts

import re

# JDBC simple : @host:port/xxx
SIMPLE_JDBC_RE = re.compile(r'(@)([^:/\s",]+)(:)', re.I)

# SQLNet : HOST=xxx)
SQLNET_HOST_RE = re.compile(r'(HOST=)([^)]+)(\))', re.I)

# paramètres SQLNet génériques X=VALUE)
SQLNET_PARAM_RE = re.compile(r'([A-Z_]+)=([^)]+)\)', re.I)

PROTECTED_KEYS = set(['HOST', 'PORT', 'SERVICE_NAME'])

def apply(obj, oid):
    if not isinstance(obj, dict):
        return obj

    # récupération des hosts déjà anonymisés (ETAPE 2)
    known_hosts = {}

    def collect_hosts(n):
        if isinstance(n, dict):
            for v in n.values():
                collect_hosts(v)
        elif isinstance(n, list):
            for x in n:
                collect_hosts(x)
        elif isinstance(n, basestring):
            for h in re.findall(r'Host_\d+_\d+', n):
                known_hosts[h] = h

    collect_hosts(obj)

    def anon_host(val):
        # si déjà anonymisé → on ne touche pas
        if re.match(r'Host_\d+_\d+', val):
            return val

        # sinon, on prend le premier host connu
        if known_hosts:
            return sorted(known_hosts.keys())[0]

        # fallback (ne devrait jamais arriver)
        return "Host_%d_1" % oid

    def anon_string(s):
        # JDBC simple
        s = SIMPLE_JDBC_RE.sub(
            lambda m: m.group(1) + anon_host(m.group(2)) + m.group(3),
            s
        )

        # SQLNet HOST=
        s = SQLNET_HOST_RE.sub(
            lambda m: m.group(1) + anon_host(m.group(2)) + m.group(3),
            s
        )

        # autres paramètres SQLNet
        def repl(m):
            k = m.group(1).upper()
            v = m.group(2)
            if k in PROTECTED_KEYS:
                return "%s=%s)" % (k, v)
            return "%s=VAL_%d)" % (k, oid)

        s = SQLNET_PARAM_RE.sub(repl, s)
        return s

    def walk(n):
        if isinstance(n, dict):
            return dict((k, walk(v)) for k, v in n.items())
        if isinstance(n, list):
            return [walk(x) for x in n]
        if isinstance(n, basestring):
            if "jdbc:oracle:thin:@" in n.lower():
                return anon_string(n)
        return n

    return walk(obj)
