# -*- coding: utf-8 -*-
# Lib/jdbc_flow_v2.py

import re

# ------------------------------------------------
class JdbcParsed(object):
    def __init__(self):
        self.valide = False

        # compat historique : host principal (primaire)
        self.host = None

        # nouveau modèle : adresses structurées
        # {"Primaire": {"host":..}, "DR": {"host":..}}
        self.addresses = {
            "Primaire": {"host": None},
            "DR": {"host": None},
        }

        # debug
        self.mode = None   # SIMPLE / SQLNET
        self.raw = None

# ------------------------------------------------
def _clean_jdbc(raw):
    if raw is None:
        return u""
    s = raw
    # raw peut arriver déjà unicode via ustr() côté AnalyseV3
    try:
        if isinstance(s, unicode):
            pass
        else:
            # best effort
            s = s.decode("utf-8", "ignore")
    except:
        try:
            s = unicode(str(s), "utf-8", "ignore")
        except:
            s = u""

    s = s.strip()

    # extraire ce qu'il y a entre guillemets si présent
    if u'"' in s:
        parts = s.split(u'"')
        if len(parts) >= 2:
            s = parts[1].strip()

    return s.strip()

# ------------------------------------------------
def _parse_simple(s):
    """
    Supporte :
      jdbc:oracle:thin:@host
      jdbc:oracle:thin:@host:port/service
      jdbc:oracle:thin:@host:port:sid  (rare)
    """
    o = JdbcParsed()
    sl = (s or u"").lower()

    if "jdbc:oracle:thin:@" not in sl:
        return o

    # récupérer le bloc après @
    try:
        after = s.split("@", 1)[1].strip()
    except:
        return o

    # couper sur espaces / virgules finales éventuelles
    after = after.strip().strip(",").strip()

    # cas @host (sans port/service)
    # ex: @Host_3_1
    m = re.match(r'^([A-Za-z0-9_.-]+)$', after)
    if m:
        host = m.group(1)
        o.valide = True
        o.mode = "SIMPLE"
        o.host = host
        o.addresses["Primaire"]["host"] = host
        return o

    # cas @host:port/service  ou @host:port:sid
    m = re.match(r'^([A-Za-z0-9_.-]+):(\d+)[/:](.+)$', after)
    if m:
        host = m.group(1)
        o.valide = True
        o.mode = "SIMPLE"
        o.host = host
        o.addresses["Primaire"]["host"] = host
        return o

    return o

# ------------------------------------------------
def _parse_sqlnet(s):
    """
    Supporte DESCRIPTION avec une ou plusieurs occurrences de (ADDRESS=... (HOST=...) ...)
    - 1ère HOST => Primaire
    - 2ème HOST => DR
    """
    o = JdbcParsed()
    sl = (s or u"").lower()
    if "(description=" not in sl:
        return o

    # Extraire tous les HOST=... dans l'ordre
    hosts = []
    for m in re.finditer(r'host\s*=\s*([^)]+)\)', s, flags=re.I):
        h = m.group(1).strip()
        if h:
            hosts.append(h)

    if not hosts:
        return o

    o.valide = True
    o.mode = "SQLNET"
    o.host = hosts[0]
    o.addresses["Primaire"]["host"] = hosts[0]
    if len(hosts) >= 2:
        o.addresses["DR"]["host"] = hosts[1]

    return o
# ------------------------------------------------
def compare(scan1, scan2):
    """
    Comparaison normalisée des SCAN.
    Retour :
      True  : identiques
      False : différents
      None  : comparaison impossible
    """
    if not scan1 or not scan2:
        return None

    try:
        s1 = unicode(scan1).strip().lower()
        s2 = unicode(scan2).strip().lower()
    except:
        try:
            s1 = str(scan1).strip().lower()
            s2 = str(scan2).strip().lower()
        except:
            return None

    if not s1 or not s2:
        return None

    return s1 == s2

# ------------------------------------------------
def interpret(raw):
    """
    Point d'entrée utilisé par AnalyseV3.
    Doit rester rétro-compatible :
      - o.host (primaire)
      - o.valide
      - o.addresses["Primaire"]["host"], o.addresses["DR"]["host"]
    """
    o = JdbcParsed()
    s = _clean_jdbc(raw)
    o.raw = s

    if not s:
        # chaîne vide => pas une erreur de syntaxe, juste N/A
        o.valide = False
        o.mode = "EMPTY"
        return o, "EMPTY", "Empty JDBC string"

    # 1) essayer simple
    os = _parse_simple(s)
    if os.valide:
        o = os
    else:
        # 2) essayer sqlnet
        on = _parse_sqlnet(s)
        if on.valide:
            o = on
        else:
            # 3) sinon : syntaxe inconnue
            return o, "SYNTAX_ERROR", "Invalid JDBC syntax"

    # ===============================
    # 🔒 NORMALISATION CONTRAT (A2)
    # ===============================

    # Primaire : priorité à o.host (historique)
    if o.host:
        o.addresses.setdefault("Primaire", {})
        if not o.addresses["Primaire"].get("host"):
            o.addresses["Primaire"]["host"] = o.host

    # Si Primaire existe mais o.host absent → rétro-sync
    if not o.host:
        h = o.addresses.get("Primaire", {}).get("host")
        if h:
            o.host = h

    # DR : on ne force RIEN
    # (sera rempli uniquement par le parseur sqlnet si applicable)

    return o, None, None

# ============================================================
# COMPATIBILITÉ API V2 (NE PAS SUPPRIMER)
# ============================================================

def resolve_cname(host):
    """
    Stub CNAME.
    Retour : (cname, error_type, error_detail)
    """
    if not host:
        return None, "HOST_EMPTY", "Host is empty"

    # stub : on considère que le host est déjà un cname
    return host, None, None

# ------------------------------------------------
def resolve_scan(host):
    import traceback
    print(">>> resolve_scan CALLED for host =", repr(host))
    traceback.print_stack(limit=5)

    if not host:
        return None, "HOST_EMPTY", "Host is empty"

    try:
        scan = _resolve_scan_internal(host)
        if not scan:
            return None, "SCAN_NOT_FOUND", "No SCAN found for %s" % host
        return scan, None, None
    except Exception as e:
        return None, "SCAN_EXCEPTION", str(e)
#------------------------------------------------------
def _resolve_scan_internal(host):
    """
    Résolution SCAN minimale (stub).
    À remplacer plus tard par la vraie logique DNS / SQLNET.
    """
    if not host:
        return None
    return host
