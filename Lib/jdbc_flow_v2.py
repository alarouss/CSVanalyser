# -*- coding: utf-8 -*-
# Lib/jdbc_flow_v2.py

import re
import subprocess

class JdbcObj(object):
    def __init__(self):
        self.raw=None
        self.host=None
        self.port=None
        self.service=None
        self.valide=False
        self.cname=None
        self.scan=None

# -------------------------
def clean(raw):
    if not raw: return None
    raw=unicode(raw).strip()
    if u'"' in raw:
        p=raw.split(u'"')
        if len(p)>=2: raw=p[1]
    return raw.strip()

# -------------------------
def parse_simple(raw):
    o=JdbcObj(); o.raw=raw
    m=re.search(r'jdbc:oracle:thin:@(.+?):(\d+)[/:](.+)',raw or u"",re.I)
    if not m: return o
    o.host=m.group(1).strip()
    o.port=m.group(2).strip()
    o.service=m.group(3).strip()
    o.valide=True
    return o

def parse_sqlnet(raw):
    o=JdbcObj(); o.raw=raw
    h=re.search(r'host=([^)]+)',raw or u"",re.I)
    p=re.search(r'port=(\d+)',raw or u"",re.I)
    s=re.search(r'service_name=([^)]+)',raw or u"",re.I)
    if not(h and p and s): return o
    o.host=h.group(1).strip()
    o.port=p.group(1).strip()
    o.service=s.group(1).strip()
    o.valide=True
    return o

def parse(raw):
    raw=clean(raw)
    o=parse_simple(raw)
    if o.valide: return o
    return parse_sqlnet(raw)

# -------------------------
def resolve_cname(host):
    try:
        p=subprocess.Popen(["nslookup",host],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        out,err=p.communicate()
        txt=out.decode("utf-8","ignore")
        for l in txt.splitlines():
            l=l.strip()
            if l.startswith("Nom") or l.startswith("Name"):
                v=l.split(":",1)[1].strip()
                if "," in v: v=v.split(",")[0].strip()
                return v,None,None
        return None,"CNAME_ERROR","No Name in nslookup for "+host
    except Exception as e:
        return None,"CNAME_EXCEPTION",str(e)

# -------------------------
def resolve_scan(host):
    try:
        if "scan" in host.lower():
            p=subprocess.Popen(["nslookup",host],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            out,err=p.communicate()
            txt=out.decode("utf-8","ignore")
            for l in txt.splitlines():
                l=l.strip()
                if l.startswith("Nom") or l.startswith("Name"):
                    return l.split(":",1)[1].strip(),None,None
            return None,"NSLOOKUP_ERROR","No Name in nslookup for "+host

        cmd=["ssh","-o","StrictHostKeyChecking=no","-o","UserKnownHostsFile=/dev/null",
             "oracle@%s"%host,". /home/oracle/.bash_profile ; srvctl config scan"]
        p=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        out,err=p.communicate()
        txt=out.decode("utf-8","ignore")
        for l in txt.splitlines():
            l=l.strip()
            if l.startswith("SCAN name"):
                v=l.split(":",1)[1].strip()
                if "," in v: v=v.split(",")[0].strip()
                return v,None,None
        return None,"SRVCTL_ERROR","No SCAN in srvctl for "+host
    except Exception as e:
        return None,"SCAN_EXCEPTION",str(e)

# -------------------------
def normalize(scan):
    if not scan: return None
    scan=scan.strip()
    if "," in scan: scan=scan.split(",")[0].strip()
    if "." in scan: scan=scan.split(".")[0].strip()
    return scan.lower()

def compare(a,b):
    na=normalize(a)
    nb=normalize(b)
    if not na or not nb: return None
    return na==nb

# -------------------------
def interpret(raw):
    o=parse(raw)
    if not o.valide:
        return o,"SYNTAX_ERROR","Invalid JDBC syntax"

    cname,e1,d1=resolve_cname(o.host)
    if e1:
        return o,e1,d1
    o.cname=cname

    scan,e2,d2=resolve_scan(cname)
    if e2:
        return o,e2,d2
    o.scan=scan

    return o,None,None
