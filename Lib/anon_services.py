# -*- coding: utf-8 -*-
# Lib/anon_services.py
#
# ETAPE 4 : anonymisation des Services
# - SRV_XXX_<Databasename> -> SRV_XXX_DBNAME_<ID>
# - utilise DBNAME_<ID> déjà présent
# - propagation globale
# - ne touche pas aux hosts, ports, scans, nodes

import re

SRV_RE = re.compile(r'\b(SRV_[A-Za-z0-9_]+)_([A-Za-z0-9_]+)\b')

def apply(obj, oid):
    if not isinstance(obj, dict):
        return obj

    dbname = "DBNAME_%d" % oid

    def repl(match):
        prefix = match.group(1)
        return "%s_%s" % (prefix, dbname)

    def walk(node):
        if isinstance(node, dict):
            return dict((k, walk(v)) for k, v in node.items())

        if isinstance(node, list):
            return [walk(x) for x in node]

        if isinstance(node, basestring):
            return SRV_RE.sub(repl, node)

        return node

    return walk(obj)
