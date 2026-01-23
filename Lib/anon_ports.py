# -*- coding: utf-8 -*-
# Lib/anon_ports.py
#
# ETAPE 3 : anonymisation des ports
# - remplace tout port numérique par PORT_<ID>
# - propagation globale
# - ne touche pas aux hosts, services, DBNAME

import re

PORT_RE = re.compile(r'\b\d{2,5}\b')

def apply(obj, oid):
    if not isinstance(obj, dict):
        return obj

    repl = "PORT_%d" % oid

    def walk(node):
        if isinstance(node, dict):
            return dict((k, walk(v)) for k, v in node.items())

        if isinstance(node, list):
            return [walk(x) for x in node]

        if isinstance(node, basestring):
            return PORT_RE.sub(repl, node)

        return node

    return walk(obj)
