# Lib/jdbc.py
# -*- coding: utf-8 -*-

import re
from Lib.common import ustr

class JdbcChaine(object):
    def __init__(self):
        self.host = None
        self.port = None
        self.service_name = None
        self.type_adresse = None
        self.valide = False

def clean_jdbc(raw):
    if not raw:
        return None
    raw = ustr(raw).strip()
    if u'"' in raw:
        p = raw.split(u'"')
        if len(p) >= 2:
            raw = p[1]
    return raw.strip()

def parse_simple_jdbc(raw):
    raw = raw or u""
    obj = JdbcChaine()
    m = re.search(r'jdbc:oracle:thin:@(.+?):(\d+)[/:](.+)', raw, re.I)
    if not m:
        return obj
    obj.host = m.group(1).strip()
    obj.port = m.group(2).strip()
    obj.service_name = m.group(3).strip()
    obj.type_adresse = "SCAN" if obj.host and ("scan" in obj.host.lower()) else "NON_SCAN"
    obj.valide = True
    return obj

def parse_sqlnet_jdbc(raw):
    raw = raw or u""
    obj = JdbcChaine()
    h = re.search(r'host=([^)]+)', raw, re.I)
    p = re.search(r'port=(\d+)', raw, re.I)
    s = re.search(r'service_name=([^)]+)', raw, re.I)
    if not (h and p and s):
        return obj
    obj.host = h.group(1).strip()
    obj.port = p.group(1).strip()
    obj.service_name = s.group(1).strip()
    obj.type_adresse = "SCAN" if obj.host and ("scan" in obj.host.lower()) else "NON_SCAN"
    obj.valide = True
    return obj

def parse_jdbc(raw):
    o = parse_simple_jdbc(raw)
    if o.valide:
        return o
    return parse_sqlnet_jdbc(raw)

def extract_dr_hosts(jdbc):
    if not jdbc:
        return []
    seen = {}
    out = []
    for h in re.findall(r'host=([^)]+)', jdbc, re.I):
        hh = h.strip()
        if hh and hh not in seen:
            seen[hh] = 1
            out.append(hh)
    return out

def build_raw_source(row, RAW_COLUMNS):
    raw = {}
    for c in RAW_COLUMNS:
        v = row.get(c, u"")
        if v is None:
            v = u""
        raw[c] = ustr(v).strip()
    return raw

def build_interpreted(raw):
    cur = clean_jdbc(raw.get("Current connection string"))
    new = clean_jdbc(raw.get("New connection string"))
    newdr = clean_jdbc(raw.get("New connection string  avec DR"))

    cur_obj = parse_jdbc(cur)
    new_obj = parse_jdbc(new)
    newdr_obj = parse_jdbc(newdr)

    return {
        "CurrentJdbc": cur,
        "NewJdbc": new,
        "NewJdbcDR": newdr,

        "ParsedCurrentJdbc": {
            "host": cur_obj.host,
            "port": cur_obj.port,
            "service": cur_obj.service_name,
            "type_adresse": cur_obj.type_adresse,
            "valide": cur_obj.valide
        },

        "ParsedNewJdbc": {
            "host": new_obj.host,
            "port": new_obj.port,
            "service": new_obj.service_name,
            "type_adresse": new_obj.type_adresse,
            "valide": new_obj.valide
        },

        "ParsedNewJdbcDR": {
            "host": newdr_obj.host,
            "port": newdr_obj.port,
            "service": newdr_obj.service_name,
            "type_adresse": newdr_obj.type_adresse,
            "valide": newdr_obj.valide
        },

        "DRHosts": extract_dr_hosts(newdr)
    }
