# Lib/network.py
# -*- coding: utf-8 -*-

import subprocess
from Lib.common import ustr

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

        cname = None
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("Nom") or line.startswith("Name"):
                parts = line.split(":", 1)
                if len(parts) == 2:
                    cname = parts[1].strip()
                    break

        if not cname:
            return None, "CNAME_NSLOOKUP_ERROR", "No Name/Nom in nslookup for " + host

        if "," in cname:
            cname = cname.split(",")[0].strip()

        return cname, None, None
    except Exception as e:
        return None, "CNAME_EXCEPTION", str(e)

# ------------------------------------------------
def resolve_scan_address(host):
    try:
        if not host:
            return None, "HOST_NONE", "Host is None"

        if "scan" in host.lower():
            p = subprocess.Popen(["nslookup", host],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            out, err = p.communicate()
            output = out.decode("utf-8", "ignore")
            for line in output.splitlines():
                line = line.strip()
                if line.startswith("Nom") or line.startswith("Name"):
                    return line.split(":", 1)[1].strip(), None, None
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
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("SCAN name"):
                result = line.split(":", 1)[1].strip()
                if "," in result:
                    result = result.split(",")[0].strip()
                return result, None, None
        return None, "SRVCTL_ERROR", "No SCAN name in srvctl for " + host
    except Exception as e:
        return None, "EXCEPTION", str(e)

# ------------------------------------------------
def normalize_scan_name(name):
    if not name:
        return None
    name = name.strip()
    if "," in name:
        name = name.split(",")[0].strip()
    if "." in name:
        name = name.split(".")[0].strip()
    return name.lower()

# ------------------------------------------------
def compare_scans(scan_a, scan_b):
    na = normalize_scan_name(scan_a)
    nb = normalize_scan_name(scan_b)
    if (not na) or (not nb):
        return None
    return (na == nb)

# ------------------------------------------------
def compute_network_block(host, step_prefix, obj_id, total_csv, show_progress):
    net = {"host": host, "cname": None, "scan": None}
    if not host:
        return net, "HOST_NONE", ("%s: host is empty" % step_prefix)

    show_progress(obj_id, total_csv, "%s_CNAME" % step_prefix)
    cname, e1, d1 = resolve_cname(host)
    if e1:
        return net, "CNAME_ERROR", ("%s: nslookup cname failed for host=%s | %s" % (step_prefix, host, d1))
    net["cname"] = cname

    show_progress(obj_id, total_csv, "%s_SCAN" % step_prefix)
    scan, e2, d2 = resolve_scan_address(cname)
    if e2:
        net["scan"] = scan
        return net, e2, ("%s: scan resolution failed for cname=%s | %s" % (step_prefix, cname, d2))
    net["scan"] = scan

    return net, None, None
