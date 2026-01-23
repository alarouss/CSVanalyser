# -*- coding: utf-8 -*-
# Lib/anon_jdbc.py
#
# ETAPE 5 : anonymisation JDBC fine-grain
# - cible uniquement les chaînes JDBC / SQLNet
# - anonymise les paramètres =... ) non couverts par ETAPES 1-4
# - normalise le node en DBNAME_<ID>_NODE pour la forme simple

import re

# repère une JDBC simple
SIMPLE_JDBC_RE = re.compile(r'(jdbc:oracle:thin:@)([^:/\s]+):([^/\s]+)/([^\s",)]+)', re.I)

# repère paramètres SQLNet X=VALUE)
SQLNET_PARAM_RE = re.compile(r'([A-Z_]+)=([^)]+)\)', re.I)

PROTECTED_KEYS = set([
    'HOST', 'PORT', 'SERVICE_NAME'
])

def apply(obj, oid):
    if not isinstance(obj, dict):
        return obj

    dbname = "DBNAME_%d" % oid
    port = "PORT_%d" % oid

    def anon_sqlnet(s):
        def repl(m):
            key = m.group(1).upper()
            val = m.group(2)
            if key in PROTECTED_KEYS:
                return "%s=%s)" % (key, val)
            return "%s=VAL_%d)" % (key, oid)
        return SQLNET_PARAM_RE.sub(repl, s)

    def anon_simple(s):
        def repl(m):
            return "%s%s:%s/%s_NODE" % (
                m.group(1),
                m.group(2),
                port,
                dbname
            )
        return SIMPLE_JDBC_RE.sub(repl, s)

    def walk(node):
        if isinstance(node, dict):
            return dict((k, walk(v)) for k, v in node.items())

        if isinstance(node, list):
            return [walk(x) for x in node]

        if isinstance(node, basestring):
            if "jdbc:oracle:thin:@" in node.lower():
                node = anon_simple(node)
                node = anon_sqlnet(node)
            return node

        return node

    return walk(obj)
