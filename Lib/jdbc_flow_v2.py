# -*- coding: utf-8 -*-
# Lib/jdbc_flow_v2.py — VERSION FINALE STABLE

import re
import subprocess
import time

# ============================================================
# MODELE
# ============================================================

class JdbcParsed(object):
    def __init__(self):
        self.valide = False
        self.host = None
        self.addresses = {
            "Primaire": {"host": None},
            "DR": {"host": None},
        }
        self.mode = None
        self.raw = None

# ============================================================
# UTILITAIRES
# ============================================================

def _to_unicode(s):
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

def _normalize_host(h):
    if not h:
        return None
    return _to_unicode(h).strip()

def _run_cmd(cmd, timeout_sec):
    """
    Exécution avec timeout — Python 2.6 compatible
    """
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except Exception as e:
        return 127, u"", _to_unicode(str(e))

    start = time.time()
    while True:
        rc = p.poll()
        if rc is not None:
            out, err = p.communicate()
            return rc, _to_unicode(out), _to_unicode(err)

        if (time.time() - start) > timeout_sec:
            try:
                p.kill()
            except:
                pass
            try:
                out, err = p.communicate()
            except:
                out, err = "", ""
            return 124, _to_unicode(out), _to_unicode(err)

        time.sleep(0.1)

# ============================================================
# JDBC PARSING
# ============================================================

def _clean_jdbc(raw):
    s = _to_unicode(raw).strip()
    if u'"' in s:
        parts = s.split(u'"')
        if len(parts) >= 2:
            s = parts[1]
    return s.strip()

def _parse_simple(s):
    o = JdbcParsed()
    if "jdbc:oracle:thin:@" not in s.lower():
        return o

    try:
        after = s.split("@", 1)[1].strip().strip(",")
    except:
        return o

    m = re.match(r'^([A-Za-z0-9_.-]+)$', after)
    if m:
        host = m.group(1)
        o.valide = True
        o.mode = "SIMPLE"
        o.host = host
        o.addresses["Primaire"]["host"] = host
        return o

    m = re.match(r'^([A-Za-z0-9_.-]+):(\d+)[/:].+$', after)
    if m:
        host = m.group(1)
        o.valide = True
        o.mode = "SIMPLE"
        o.host = host
        o.addresses["Primaire"]["host"] = host
        return o

    return o

def _parse_sqlnet(s):
    o = JdbcParsed()
    if "(description=" not in s.lower():
        return o

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

def interpret(raw):
    o = JdbcParsed()
    s = _clean_jdbc(raw)
    o.raw = s

    if not s:
        o.mode = "EMPTY"
        return o, "EMPTY", "Empty JDBC string"

    os = _parse_simple(s)
    if os.valide:
        return os, None, None

    on = _parse_sqlnet(s)
    if on.valide:
        return on, None, None

    o.mode = "INVALID"
    return o, "SYNTAX_ERROR", "Invalid JDBC syntax"

# ============================================================
# COMPARAISON SCAN
# ============================================================

def compare(scan1, scan2):
    if not scan1 or not scan2:
        return None
    return _normalize_host(scan1).lower() == _normalize_host(scan2).lower()

# ============================================================
# DNS / ORACLE — RESOLUTION REELLE
# ============================================================

def resolve_cname(host):
    host = _normalize_host(host)
    if not host:
        return None, "HOST_EMPTY", "Host is empty"

    rc, out_u, err_u = _run_cmd(["nslookup", host], timeout_sec=8)
    if rc == 124:
        return None, "NSLOOKUP_TIMEOUT", "nslookup timeout for %s" % host
    if not out_u:
        return None, "NSLOOKUP_ERROR", err_u

    for l in out_u.splitlines():
        s = l.strip().lower()

        # canonical name = xxx.
        if s.startswith("canonical name"):
            v = l.split("=", 1)[1].strip()
            if "," in v:
                v = v.split(",", 1)[0].strip()
            if v.endswith("."):
                v = v[:-1]
            return _normalize_host(v), None, None

        # Name: xxx
        if s.startswith("name") or s.startswith("nom"):
            if ":" in l:
                v = l.split(":", 1)[1].strip()
                if "," in v:
                    v = v.split(",", 1)[0].strip()
                if v.endswith("."):
                    v = v[:-1]
                return _normalize_host(v), None, None

    return None, "CNAME_NOT_FOUND", "No cname for %s" % host


def resolve_scan(host):
    host = _normalize_host(host)
    if not host:
        return None, "HOST_EMPTY", "Host is empty"

    cname, e, d = resolve_cname(host)
    if e:
        return None, e, d

    cmd = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "oracle@%s" % cname,
        ". /home/oracle/.bash_profile ; srvctl config scan"
    ]

    rc, out_u, err_u = _run_cmd(cmd, timeout_sec=12)
    if rc == 124:
        return None, "SRVCTL_TIMEOUT", "srvctl timeout for %s" % cname
    if not out_u:
        return None, "SRVCTL_ERROR", err_u

    for l in out_u.splitlines():
        if l.lower().startswith("scan name"):
            return _normalize_host(l.split(":", 1)[1]), None, None

    return None, "SCAN_NOT_FOUND", "No SCAN for %s" % cname
