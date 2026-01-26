# -*- coding: utf-8 -*-
# Lib/jdbc_flow_v2.py

import re
import subprocess
import time
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
def _to_unicode_best_effort(s):
    if s is None:
        return u""
    try:
        if isinstance(s, unicode):
            return s
    except:
        pass
    try:
        return s.decode("utf-8", "ignore")
    except:
        try:
            return unicode(str(s), "utf-8", "ignore")
        except:
            return u""

def _run_cmd(cmd, timeout_sec=8):
    """
    Exécute cmd avec timeout (Python 2.6 compatible).
    Retourne (rc, out_u, err_u).
    """
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except Exception as e:
        return 127, u"", _to_unicode_best_effort(str(e))

    start = time.time()
    while True:
        rc = p.poll()
        if rc is not None:
            out, err = p.communicate()
            return rc, _to_unicode_best_effort(out), _to_unicode_best_effort(err)
        if (time.time() - start) > timeout_sec:
            try:
                p.kill()
            except:
                pass
            try:
                out, err = p.communicate()
            except:
                out, err = "", ""
            return 124, _to_unicode_best_effort(out), _to_unicode_best_effort(err)
        time.sleep(0.1)

def _extract_name_from_nslookup(output_u):
    """
    Essaie d'extraire un nom utile depuis nslookup (FR/EN).
    Priorité :
      1) "canonical name = X"
      2) "Name:" / "Nom :" / "Nom" / "Name"
    Retourne unicode ou None.
    """
    if not output_u:
        return None

    # 1) canonical name =
    m = re.search(r'canonical name\s*=\s*([A-Za-z0-9_.-]+)\.?\s*$', output_u, flags=re.I | re.M)
    if m:
        v = m.group(1).strip()
        if v:
            return v

    # 2) lignes "Name:" / "Nom :"
    for l in output_u.splitlines():
        s = (l or u"").strip()
        # exemples: "Name: xxx", "Nom : xxx"
        if s.lower().startswith(u"name") or s.lower().startswith(u"nom"):
            if u":" in s:
                v = s.split(u":", 1)[1].strip()
                if u"," in v:
                    v = v.split(u",", 1)[0].strip()
                if v:
                    return v
    return None

def _extract_scan_from_srvctl(output_u):
    """
    Extrait "SCAN name: XXX" depuis 'srvctl config scan'
    Retourne unicode ou None.
    """
    if not output_u:
        return None
    for l in output_u.splitlines():
        s = (l or u"").strip()
        if s.lower().startswith(u"scan name"):
            if u":" in s:
                v = s.split(u":", 1)[1].strip()
                if u"," in v:
                    v = v.split(u",", 1)[0].strip()
                if v:
                    return v
    return None
#------------------------------------------------------
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
def _normalize_host(h):
    if not h:
        return None
    try:
        h = ustr(h)
    except:
        pass
    return h.strip()
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
    Doit TOUJOURS retourner (obj, err_code, err_detail)
    """
    o = JdbcParsed()

    s = _clean_jdbc(raw)
    o.raw = s

    if not s:
        o.valide = False
        o.mode = "EMPTY"
        return o, "EMPTY", "Empty JDBC string"

    # 1) simple
    os = _parse_simple(s)
    if os and os.valide:
        return os, None, None

    # 2) sqlnet
    on = _parse_sqlnet(s)
    if on and on.valide:
        return on, None, None

    # 3) syntax error
    o.valide = False
    o.mode = "INVALID"
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
    Résolution réelle CNAME via nslookup.
    Retourne (cname, None, None) si trouvé,
    sinon (None, CODE, DETAIL).
    """
    host = _normalize_host(host)
    if not host:
        return None, "HOST_EMPTY", "Host is empty"

    # nslookup host
    rc, out_u, err_u = _run_cmd(["nslookup", host], timeout_sec=8)
    if rc == 124:
        return None, "NSLOOKUP_TIMEOUT", "nslookup timeout for %s" % host
    if rc != 0 and (not out_u):
        # parfois rc!=0 mais out utile; on ne fail que si out vide
        return None, "NSLOOKUP_ERROR", (u"nslookup rc=%s err=%s" % (rc, err_u)).encode("utf-8", "ignore")

    cname = _extract_name_from_nslookup(out_u)
    if not cname:
        return None, "CNAME_NOT_FOUND", "No Name/canonical name in nslookup for %s" % host

    cname = _normalize_host(cname)
    if not cname:
        return None, "CNAME_EMPTY", "Empty cname after parse for %s" % host

    return cname, None, None


# ------------------------------------------------
def resolve_scan(host):
    """
    Résolution réelle SCAN :
      1) nslookup host -> cname
      2) ssh oracle@cname -> srvctl config scan
    Retourne (scan, None, None) si OK, sinon (None, CODE, DETAIL).
    """
    host = _normalize_host(host)
    if not host:
        return None, "HOST_EMPTY", "Host is empty"

    # 1) CNAME via nslookup
    cname, e1, d1 = resolve_cname(host)
    if e1:
        return None, e1, d1
    cname = _normalize_host(cname)
    if not cname:
        return None, "CNAME_EMPTY", "Empty cname for %s" % host

    # 2) srvctl via ssh sur cname
    cmd = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "oracle@%s" % cname,
        ". /home/oracle/.bash_profile ; srvctl config scan"
    ]

    rc, out_u, err_u = _run_cmd(cmd, timeout_sec=12)
    if rc == 124:
        return None, "SRVCTL_TIMEOUT", "srvctl timeout via ssh for %s" % cname
    if rc != 0 and (not out_u):
        return None, "SRVCTL_ERROR", (u"srvctl rc=%s err=%s" % (rc, err_u)).encode("utf-8", "ignore")

    scan = _extract_scan_from_srvctl(out_u)
    if not scan:
        return None, "SCAN_NOT_FOUND", "No SCAN name in srvctl for %s" % cname

    scan = _normalize_host(scan)
    if not scan:
        return None, "SCAN_EMPTY", "Empty scan after parse for %s" % cname

    return scan, None, None

#------------------------------------------------------
def _resolve_scan_internal(host):
    """
    Résolution SCAN minimale (stub).
    À remplacer plus tard par la vraie logique DNS / SQLNET.
    """
    if not host:
        return None
    return host
