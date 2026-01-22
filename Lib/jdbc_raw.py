# -*- coding: utf-8 -*-
# Lib/jdbc_raw.py
#
# Librairie d'interprétation RAW JDBC (issue AnalyseV2)

import re
import subprocess

# ------------------------------------------------
class JdbcChaine(object):
    def __init__(self):
        self.raw = None
        self.host = None
        self.port = None
        self.service_name = None
        self.type_adresse = None
        self.valide = False
        self.cname = None
        self.scan = None

# ------------------------------------------------
def clean_jdbc(raw):
    if not raw:
        return None
    raw = unicode(raw).strip()
    if u'"' in raw:
        p = raw.split(u'"')
        if len(p) >= 2:
            raw = p[1]
    return raw.strip()

# ------------------------------------------------
def parse_simple_jdbc(raw):
    o = JdbcChaine()
    o.raw = raw
    m = re.search(r'jdbc:oracle:thin:@(.+?):(\d+)[/:](.+)', raw or u"", re.I)
    if not m:
        return o
    o.host = m.group(1).strip()
    o.port = m.group(2).strip()
    o.service_name = m.group(3).strip()
    o.type_adresse = "SCAN" if "scan" in o.host.lower() else "NON_SCAN"
    o.valide = True
    return o

def parse_sqlnet_jdbc(raw):
    o = JdbcChaine()
    o.raw = raw
    h = re.search(r'host=([^)]+)', raw or u"", re.I)
    p = re.search(r'port=(\d+)', raw or u"", re.I)
    s = re.search(r'service_name=([^)]+)', raw or u"", re.I)
    if not (h and p and s):
        return o
    o.host = h.group(1).strip()
    o.port = p.group(1).strip()
    o.service_name = s.group(1).strip()
    o.type_adresse = "SCAN" if "scan" in o.host.lower() else "NON_SCAN"
    o.valide = True
    return o

def parse_jdbc(raw):
    o = parse_simple_jdbc(raw)
    if o.valide:
        return o
    return parse_sqlnet_jdbc(raw)

# ------------------------------------------------
def resolve_cname(host):
    try:
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
def resolve_scan_address(host):
    try:
        if "scan" in host.lower():
            p = subprocess.Popen(["nslookup", host],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            out, err = p.communicate()
            output = out.decode("utf-8", "ignore")
            for l in output.splitlines():
                l = l.strip()
                if l.startswith("Nom") or l.startswith("Name"):
                    return l.split(":", 1)[1].strip(), None, None
            return None, "NSLOOKUP_ERROR", "No Name in nslookup for " + host

        cmd = ["ssh",
               "-o", "StrictHostKeyChecking=no",
               "-o", "UserKnownHostsFile=/dev/null",
               "oracle@%s" % host,
               ". /home/oracle/.bash_profile ; srvctl config scan"]
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
        return None, "SRVCTL_ERROR", "No SCAN in srvctl for " + host
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

def compare_scans(a, b):
    na = normalize_scan_name(a)
    nb = normalize_scan_name(b)
    if not na or not nb:
        return None
    return na == nb

# ------------------------------------------------
def interpret_raw_jdbc(raw):
    """
    Interprétation complète V2 RAW → JDBC + réseau
    """
    raw = clean_jdbc(raw)
    obj = parse_jdbc(raw)

    if not obj.valide:
        return obj, "SYNTAX_ERROR", "Invalid JDBC syntax"

    cname, e1, d1 = resolve_cname(obj.host)
    if e1:
        return obj, e1, d1

    obj.cname = cname

    scan, e2, d2 = resolve_scan_address(cname)
    if e2:
        return obj, e2, d2

    obj.scan = scan

    return obj, None, None

