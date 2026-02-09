#!/usr/bin/env python
# -*- coding: utf-8 -*-
# OemOnly.py — OEM extractor (standalone)

import sys
import json
import time

from Lib.io_common import load_main_conf
from Lib.oem_flow import oem_get_host_and_port
from Lib.analyse_builder_v3 import compute_net_side

# ------------------------------------------------
def usage():
    print("Usage: python OemOnly.py <DATABASE_NAME>")
    sys.exit(1)

# ------------------------------------------------
if __name__ == "__main__":

    if len(sys.argv) != 2:
        usage()

    db_name = sys.argv[1]

    conf, ce, cd = load_main_conf()
    if ce:
        print("Configuration error:", ce)
        print(cd)
        sys.exit(1)

    OEM_CONF = conf.get("OEM_CONF_FILE")
    if not OEM_CONF:
        print("OEM_CONF_FILE not defined in config")
        sys.exit(1)
    
    from AnalyseV3 import read_oem_conn
    oem_conn = read_oem_conn(OEM_CONF)
    
    if not oem_conn:
        print("OEM connection string not found in OEM_CONF_FILE")
        sys.exit(1)


    result = {
        "Database": db_name,
        "OEM": {
            "Primaire": {
                "host": None,
                "port": None,
                "cname": None,
                "scan": None
            }
        },
        "Status": {
            "Valid": False,
            "ErrorType": None,
            "ErrorDetail": None,
            "Timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
    }

    # ------------------------------------------------
    # 1) OEM host / port
    # ------------------------------------------------
    host, ora_version, e, d = oem_get_host_and_port(oem_conn, db_name)
    if e:
        result["Status"]["ErrorType"] = e
        result["Status"]["ErrorDetail"] = d
        print(json.dumps(result, indent=2))
        sys.exit(0)

    result["OEM"]["Primaire"]["host"] = host
    result["OEM"]["Primaire"]["port"] = port

    # ------------------------------------------------
    # 2) Résolution réseau (CNAME + SCAN)
    # ------------------------------------------------
    block = {
        "host": host,
        "cname": None,
        "scan": None
    }

    block, e, d = compute_net_side(block, "OEM_PRIMAIRE", 1, 1)
    if e:
        result["Status"]["ErrorType"] = e
        result["Status"]["ErrorDetail"] = d
    else:
        result["OEM"]["Primaire"]["cname"] = block.get("cname")
        result["OEM"]["Primaire"]["scan"] = block.get("scan")
        result["Status"]["Valid"] = True

    print(json.dumps(result, indent=2))
