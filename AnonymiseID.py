#!/usr/bin/env python
# -*- coding: utf-8 -*-
#V5
"""
AnonymiseID.py
Anonymisation ciblée par ID du store AnalyseV3

Usage:
  python AnonymiseID.py source=store.json id=1,2
  python AnonymiseID.py source=store.json id=ALL
"""

import json
import sys
import os
import re

# ------------------------------------------------
def parse_args(argv):
    src = None
    ids = None
    for a in argv[1:]:
        if a.startswith("source="):
            src = a.split("=", 1)[1]
        elif a.startswith("id="):
            ids = a.split("=", 1)[1]
    return src, ids

# ------------------------------------------------
def parse_ids(ids, max_id):
    if ids.upper() == "ALL":
        return range(1, max_id + 1)
    out = []
    for p in ids.split(","):
        p = p.strip()
        if p:
            out.append(int(p))
    return out

# ------------------------------------------------
def make_seq_mapper(prefix, obj_id):
    """
    mapping stable intra-objet :
      même valeur -> même alias
      alias = <prefix>_<ID>_<SEQ>
    """
    seq = [0]
    mapping = {}

    def map_value(v):
        if v is None:
            return v
        vv = v.strip()
        if not vv:
            return v
        if vv not in mapping:
            seq[0] += 1
            mapping[vv] = "%s_%d_%d" % (prefix, obj_id, seq[0])
        return mapping[vv]

    return map_value

# ------------------------------------------------
def anonymize_service_name(val, dbname):
    """
    SRV_XXX_<Databasename> -> SRV_XXX_DBNAME_<ID>
    Règle : on garde le préfixe SRV_XXX et on remplace le suffixe par dbname
    """
    if not val:
        return val
    m = re.match(r'^(SRV_[A-Za-z0-9]+)_.*$', val.strip())
    if m:
        return m.group(1) + "_" + dbname
    # si pas de forme SRV_XXX_..., on force quand même dbname (option stricte)
    return dbname

# ------------------------------------------------
def anonymize_misc_value(val):
    """
    Point 1 : tout ce qui est entre '=' et ')'
    Si la clé n'est pas HOST/PORT/SERVICE_NAME, on anonymise quand même.
    """
    if val is None:
        return val
    v = val.strip()
    if not v:
        return val
    # digits -> XXXX
    if re.match(r'^\d+$', v):
        return "XXXX"
    # ON/OFF/TRUE/FALSE/Y/N -> XX
    if v.upper() in ("ON", "OFF", "TRUE", "FALSE", "YES", "NO", "Y", "N"):
        return "XX"
    # TCP/TCPS/UDP etc : on peut laisser ou anonymiser ; ici on laisse PROTOCOL-like
    if v.upper() in ("TCP", "TCPS", "UDP"):
        return v.upper()
    # défaut
    return "XXXX"

# ------------------------------------------------
def anonymize_current_jdbc_compact(s, host_map, port_token, dbnode_token):
    """
    Point 5 : Current connection string
    - host après @ => Host_<ID>_<SEQ>
    - port => PORT_<ID>
    - node => DBNAME_<ID>_NODE (dbnode_token)
    Supporte :
      jdbc:oracle:thin:@host:port/service
      jdbc:oracle:thin:@host:port:SID
      jdbc:oracle:thin:@host/service
    """
    if not s:
        return s

    out = s

    # host après @ jusqu'à ':' ou '/' ou '"' ou ',' (on reste prudent)
    def repl_host(m):
        return "@" + host_map(m.group(1))

    out = re.sub(r'@([^:/"\s,]+)', repl_host, out)

    # port après ':' si digits
    out = re.sub(r':(\d+)(?=[/:"\s,])', ":" + port_token, out)

    # node/service après '/' ou ':' (dernier segment)
    # - cas /XXX  -> /DBNAME_ID_NODE
    out = re.sub(r'/([^"\s,]+)', "/" + dbnode_token, out)

    # - cas @host:port:SID  -> @host:PORT_ID:DBNAME_ID_NODE
    out = re.sub(r'@([^:]+):' + re.escape(port_token) + r':([^"\s,]+)',
                 r'@\1:' + port_token + r':' + dbnode_token, out)

    return out

# ------------------------------------------------
def anonymize_sqlnet_kv_inside_parens(s, host_map, port_token, dbname, svc_transformer):
    """
    Point 1 : toute sous-chaîne entre '=' et ')', sur les blocs (KEY=VALUE)
    - HOST => host_map
    - PORT => PORT_<ID>
    - SERVICE_NAME => SRV_XXX_DBNAME_<ID>
    - autres => anonymize_misc_value (XXXX/XX/TCP)
    """
    if not s:
        return s

    def repl(m):
        key = m.group(1)
        val = m.group(2)
        up = key.upper()

        if up == "HOST":
            newv = host_map(val)
        elif up == "PORT":
            newv = port_token
        elif up == "SERVICE_NAME":
            newv = svc_transformer(val, dbname)
        else:
            newv = anonymize_misc_value(val)

        return key + "=" + newv + ")"

    # capture KEY=VALUE) avec KEY alpha/_ et VALUE tout sauf ')'
    return re.sub(r'([A-Za-z_]+)=([^)]+)\)', repl, s)

# ------------------------------------------------
def anonymize_any_string(s, obj_id, dbname, host_map, cnamesdr_map, port_token, dbnode_token):
    """
    Applique les règles partout (RawSource + Network + OEM + sous-sections):
    - remplace {DATABASENAME} par dbname
    - anonymise tous les (KEY=VALUE) ) via anonymize_sqlnet_kv_inside_parens
    - anonymise les hosts après @ dans les JDBC compacts (utile pour New si compact)
    - anonymise ports digits (1521 ou autres) => PORT_<ID> (au moins dans patterns courants)
    - force DBNAME_ID_NODE pour les segments /xxx dans current-like (si présent)
    """
    if s is None:
        return s
    if not isinstance(s, basestring):
        return s

    out = s

    # 3) placeholder
    out = out.replace("{DATABASENAME}", dbname)

    # 1) SQLNet blocks KEY=VALUE)
    out = anonymize_sqlnet_kv_inside_parens(out, host_map, port_token, dbname, anonymize_service_name)

    # 5) JDBC compact (si on trouve '@')
    if "@ " in out:
        out = out.replace("@ ", "@")  # mini robustesse
    if "@" in out:
        # host après @, port, node
        out = re.sub(r'@([^:/"\s,]+)',
                     lambda m: "@" + host_map(m.group(1)),
                     out)
        out = re.sub(r':(\d+)(?=[/:"\s,])', ":" + port_token, out)

    # ports explicites "1521" en brut (fallback)
    out = out.replace("1521", port_token)

    return out

# ------------------------------------------------
def anonymize_object(obj, oid):
    """
    Applique les 9 points à l'objet entier (propagation globale).
    """
    dbname = "DBNAME_%d" % oid
    port_token = "PORT_%d" % oid
    dbnode_token = dbname + "_NODE"

    host_map = make_seq_mapper("Host", oid)
    cnamesdr_map = make_seq_mapper("CNamesDR", oid)

    # --- helpers champ RawSource spécifiques (points 3,4,6,7,8) ---
    def anonymize_rawsource_block(raw):
        out = {}
        for k, v in raw.items():
            if not isinstance(v, basestring):
                out[k] = v
                continue

            # 6) Application
            if k == "Application":
                out[k] = "APP_%d" % oid
                continue

            # 3) Databases
            if k == "Databases":
                out[k] = dbname
                continue

            # 7) Cnames
            if k == "Cnames":
                out[k] = "CNames_%d" % oid
                continue

            # 4) Cnames DR -> CNamesDR_ID_SEQ (stable intra-objet)
            if k == "Cnames DR":
                out[k] = cnamesdr_map(v)
                continue

            # 8) Services
            if k == "Services":
                out[k] = anonymize_service_name(v, dbname)
                continue

            # 5) Current connection string (traitement spécifique)
            if k == "Current connection string":
                tmp = v.replace("{DATABASENAME}", dbname)
                tmp = anonymize_current_jdbc_compact(tmp, host_map, port_token, dbnode_token)
                # + règle 1 sur les éventuels (KEY=VALUE))
                tmp = anonymize_sqlnet_kv_inside_parens(tmp, host_map, port_token, dbname, anonymize_service_name)
                out[k] = tmp
                continue

            # autres champs : règle générale + règle 1 incluse
            out[k] = anonymize_any_string(v, oid, dbname, host_map, cnamesdr_map, port_token, dbnode_token)

        return out

    # --- propagation globale récursive ---
    def walk(node):
        if isinstance(node, dict):
            newd = {}
            for k, v in node.items():
                if k == "RawSource" and isinstance(v, dict):
                    newd[k] = anonymize_rawsource_block(v)
                else:
                    newd[k] = walk(v)
            return newd

        if isinstance(node, list):
            return [walk(x) for x in node]

        if isinstance(node, basestring):
            return anonymize_any_string(node, oid, dbname, host_map, cnamesdr_map, port_token, dbnode_token)

        return node

    return walk(obj)

# ------------------------------------------------
#V10
def main():
    src, ids_arg = parse_args(sys.argv)
    if not src or not os.path.isfile(src):
        print "Usage: python AnonymiseID.py source=store.json id=1,2|ALL"
        sys.exit(1)

    data = json.loads(open(src, "rb").read().decode("utf-8"))
    objects = data.get("objects", [])

    ids = parse_ids(ids_arg, len(objects))

    from Lib.anon_dbname   import apply as anon_dbname
    from Lib.anon_hosts    import apply as anon_hosts
    from Lib.anon_ports    import apply as anon_ports
    from Lib.anon_services import apply as anon_services
    from Lib.anon_jdbc     import apply as anon_jdbc
    from Lib.anon_lock import apply as anon_lock
    from Lib.anon_guard import apply as anon_guard
  
    out_objects = []
    changed = 0

    for obj in objects:
        try:
            oid = int(obj.get("id"))
        except:
            continue

        if oid not in ids:
            continue

        before = json.dumps(obj, sort_keys=True)

        obj = anon_dbname(obj, oid)   # ETAPE 1
        obj = anon_hosts(obj, oid)    # ETAPE 2
        obj = anon_ports(obj, oid)    # ETAPE 3
        obj = anon_services(obj, oid) # ETAPE 4
        obj = anon_jdbc(obj, oid)     # ETAPE 5
        obj = anon_lock(obj, oid)     # ETAPE 6
        obj = anon_guard(obj, oid)    # ETAPE 7
      
        after = json.dumps(obj, sort_keys=True)
        if before != after:
            changed += 1
            print "DEBUG id=%d: ETAPES 1 a 5 anonymised" % oid

        out_objects.append(obj)

    out = {"objects": out_objects}

    base, ext = os.path.splitext(src)
    out_file = base + "_anon.json"

    open(out_file, "wb").write(
        json.dumps(out, indent=2, ensure_ascii=False).encode("utf-8")
    )

    print
    print "Anonymisation terminee (ETAPES 1 a 5)"
    print "  objects traites :", len(out_objects)
    print "  objets modifies :", changed
    print "  fichier :", out_file

# ------------------------------------------------
if __name__ == "__main__":
    main()
