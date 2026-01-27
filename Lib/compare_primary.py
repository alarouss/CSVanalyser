# -*- coding: utf-8 -*-
# Lib/compare_primary.py

def compare_primary(cur_p, new_p):
    """
    Compare Current vs New (Primaire)
    Règle :
      1) host
      2) cname
      3) scan

    Retour :
      (status, error_type, error_detail)
    """

    if not cur_p or not new_p:
        return "N/A", None, None

    # 1) HOST
    h1 = cur_p.get("host")
    h2 = new_p.get("host")
    if h1 != h2:
        return "DIFFERENT", "HOST_DIFFERENT", "Current and New host differ"

    # 2) CNAME
    c1 = cur_p.get("cname")
    c2 = new_p.get("cname")
    if c1 != c2:
        return "DIFFERENT", "CNAME_DIFFERENT", "Current and New cname differ"

    # 3) SCAN
    s1 = cur_p.get("scan")
    s2 = new_p.get("scan")
    if s1 != s2:
        return "DIFFERENT", "SCAN_DIFFERENT", "Current and New scan differ"

    return "OK", None, None
