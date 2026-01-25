# -*- coding: utf-8 -*-
# Lib/jdbc_flow_v2.py

import re
import subprocess

# ------------------------------------------------
class JdbcChaine(object):
    def __init__(self):
        self.host = None
        self.port = None
        self.service_name = None
        self.type_adresse = None
        self.valide = False

# ------------------------------------------------
def clean_jdbc(raw):
    if not raw:
        return None
    raw = raw.strip()
    if '"' in raw:
        p = raw.split('"')
        if len(p) >= 2:
            raw = p[1]
    return raw.strip()

# ------------------------------------------------
def parse_simple_jdbc(raw):
    raw = raw or ""
    o = JdbcChaine()
    m = re.search(r'jdbc:oracle:thin:@(.+?):(\d+)[/:](.+)', raw, re.I)
    if not m:
        return o
    o.host = m.group(1).strip()
    o.port = m.group(2).strip()
    o.service_name = m.group(3).strip()
    o.type_adresse = "SCAN" if o.host and o.host.lower().startswith("scan") else "NON_SCAN"
    o.valide = True
    return o

# ------------------------------------------------
def parse_sqlnet_jdbc(raw):
    raw = raw or ""
    o = JdbcChaine()
    h = re.search(r'host=([^)]+)', raw, re.I)
    p = re.search(r'port=(\d+)', raw, re.I)
    s = re.search(r'service_name=([^)]+)', raw, re.I)
    if not (h and p and s):
        return o
    o.host = h.group(1).strip()
    o.port = p.group(1).strip()
    o.service_name = s.group(1).strip()
    o.type_adresse = "SCAN" if o.host and o.host.lower().startswith("scan") else "NON_SCAN"
    o.valide = True
    return o

# ------------------------------------------------
def parse_jdbc(raw):
    o = parse_simple_jdbc(raw)
    if o.valide:
        return o
    return parse_sqlnet_jdbc(raw)

# ------------------------------------------------
# ------------------------------------------------
# EXTENSION MULTI ADDRESS_LIST – Oracle SQLNet
# Compatible Python 2.6 – sans regression
# ------------------------------------------------



class ParsedJdbc(object):
    def __init__(self):
        self.valide = False
        self.host = None
        self.port = None
        self.service = None
        self.addresses = []   # NOUVEAU (liste complète)

# ------------------------------------------------
def interpret(jdbc):
    """
    Analyse une chaine JDBC Oracle SQLNet.
    Supporte 1 ou plusieurs ADDRESS_LIST.
    Ne casse aucun contrat existant.
    """

    p = ParsedJdbc()

    if not jdbc:
        return p, "JDBC_EMPTY", "Empty JDBC string"

    s = jdbc.strip()
    s_low = s.lower()

    if "jdbc:oracle:thin:@" not in s_low:
        return p, "JDBC_INVALID", "Not an Oracle JDBC thin URL"

    try:
        # Normalisation légère
        txt = s.replace("\n", "").replace("\r", "")

        # --- Extraction SERVICE_NAME (unique, commun à toutes les adresses)
        m_srv = re.search(r"service_name\s*=\s*([^)]+)", txt, re.I)
        service = m_srv.group(1).strip() if m_srv else None

        # --- Extraction de TOUS les blocs ADDRESS
        addr_blocks = re.findall(
            r"\(\s*address\s*=\s*\((.*?)\)\s*\)",
            txt,
            re.I
        )

        addresses = []

        for blk in addr_blocks:
            mh = re.search(r"host\s*=\s*([^)]+)", blk, re.I)
            mp = re.search(r"port\s*=\s*([^)]+)", blk, re.I)

            host = mh.group(1).strip() if mh else None
            port = mp.group(1).strip() if mp else None

            if host:
                addresses.append({
                    "host": host,
                    "port": port,
                    "service": service
                })

        # --- Cas simple : jdbc:oracle:thin:@host:port/service
        if not addresses:
            m = re.search(
                r"@\s*([^:/\)]+)\s*:\s*([0-9]+)\s*/\s*([^\s\"\,\)]+)",
                txt
            )
            if m:
                addresses.append({
                    "host": m.group(1).strip(),
                    "port": m.group(2).strip(),
                    "service": m.group(3).strip()
                })

        if not addresses:
            return p, "JDBC_PARSE_ERROR", "No HOST found in JDBC string"

        # --- Alimentation objet de sortie
        p.addresses = addresses
        p.host = addresses[0]["host"]
        p.port = addresses[0]["port"]
        p.service = addresses[0]["service"]
        p.valide = True

        return p, None, None

    except Exception as e:
        return p, "JDBC_EXCEPTION", str(e)


# ------------------------------------------------
def resolve_cname(host):
    try:
        if not host:
            return None, "CNAME_HOST_NONE", "Host is None"

        p = subprocess.Popen(["nslookup", host],
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        out, err = p.communicate()
        output = out.decode("utf-8", "ignore")

        for l in output.splitlines():
            l = l.strip()
            if l.startswith("Nom") or l.startswith("Name"):
                v = l.split(":", 1)[1].strip()
                if "," in v:
                    v = v.split(",")[0].strip()
                return v, None, None

        return None, "CNAME_ERROR", "No Name in nslookup for " + host

    except Exception as e:
        return None, "CNAME_EXCEPTION", str(e)

# ------------------------------------------------
def resolve_scan(host):
    """
    LOGIQUE ORACLE CORRECTE :

    host -> nslookup -> cname
         -> srvctl sur cname -> scan réel
    """
    try:
        if not host:
            return None, "HOST_NONE", "Host is None"

        # --- 1) CNAME ---
        p = subprocess.Popen(["nslookup", host],
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        out, err = p.communicate()
        output = out.decode("utf-8", "ignore")

        cname = None
        for l in output.splitlines():
            l = l.strip()
            if l.startswith("Nom") or l.startswith("Name"):
                cname = l.split(":", 1)[1].strip()
                if "," in cname:
                    cname = cname.split(",")[0].strip()
                break

        if not cname:
            return None, "CNAME_ERROR", "No Name in nslookup for " + host

        # --- 2) SRVCTL ---
        cmd = [
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "oracle@%s" % cname,
            ". /home/oracle/.bash_profile ; srvctl config scan"
        ]

        p = subprocess.Popen(cmd,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        out, err = p.communicate()
        output = out.decode("utf-8", "ignore")

        for l in output.splitlines():
            l = l.strip()
            if l.startswith("SCAN name"):
                v = l.split(":", 1)[1].strip()
                if "," in v:
                    v = v.split(",")[0].strip()
                return v, None, None

        return None, "SRVCTL_ERROR", "No SCAN in srvctl for " + cname

    except Exception as e:
        return None, "SCAN_EXCEPTION", str(e)

# ------------------------------------------------
def normalize_scan_name(n):
    if not n:
        return None
    n = n.strip()
    if "," in n:
        n = n.split(",")[0].strip()
    if "." in n:
        n = n.split(".")[0].strip()
    return n.lower()

# ------------------------------------------------
def compare(a, b):
    na = normalize_scan_name(a)
    nb = normalize_scan_name(b)
    if not na or not nb:
        return None
    return na == nb
