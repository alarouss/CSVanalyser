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
def interpret(raw):
    """
    API compatible AnalyseV3:
    retourne (JdbcChaine, err_type, err_detail)
    """
    try:
        raw = clean_jdbc(raw)
        o = parse_jdbc(raw)
        return o, None, None
    except Exception as e:
        o = JdbcChaine()
        return o, "PARSE_EXCEPTION", str(e)

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
