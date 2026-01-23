# -*- coding: utf-8 -*-
# Lib/anon_pipeline.py
#
# Orchestration COMPLETE de l’anonymisation
# Le main() ne doit plus jamais changer

from Lib.anon_dbname   import apply as anon_dbname
from Lib.anon_hosts    import apply as anon_hosts
from Lib.anon_ports    import apply as anon_ports
from Lib.anon_services import apply as anon_services
from Lib.anon_jdbc     import apply as anon_jdbc
from Lib.anon_lock     import apply as anon_lock
from Lib.anon_guard    import apply as anon_guard

PIPELINE = [
    anon_dbname,
    anon_hosts,
    anon_ports,
    anon_services,
    anon_jdbc,
    anon_lock,
    #anon_guard
]

def anonymize_object(obj, oid):
    for step in PIPELINE:
        obj = step(obj, oid)
    return obj
