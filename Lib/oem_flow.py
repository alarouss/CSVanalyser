# -*- coding: utf-8 -*-
# Lib/oem_flow.py
#
# OEM Oracle access (autonome, sans dépendance projet)

import subprocess

# ------------------------------------------------
def oem_get_host_and_port(oem_conn, target_name):
    """
    Retourne (host, port, err_type, err_detail)
    """

    if not oem_conn:
        return None, None, "OEM_CONN_EMPTY", "OEM_CONN is empty"

    if not target_name:
        return None, None, "OEM_TARGET_EMPTY", "Target name is empty"

    sql = []
    sql.append("set pages 0")
    sql.append("set head off")
    sql.append("set feed off")
    sql.append("set verify off")
    sql.append("set echo off")
    sql.append("set trimspool on")
    sql.append("set lines 400")
    sql.append("define TNAME='%s'" % target_name.replace("'", "''"))

    sql.append("""
select
  tp_host.property_value || '|' || tp_port.property_value
from
  sysman.mgmt$target t
  join sysman.mgmt$target_properties tp_host
       on tp_host.target_guid = t.target_guid
      and tp_host.property_name = 'Host'
  left join sysman.mgmt$target_properties tp_port
       on tp_port.target_guid = t.target_guid
      and tp_port.property_name = 'Port'
where
  t.target_name = '&&TNAME'
  and t.target_type in ('oracle_database', 'oracle_dataguard')
""".strip())


    sql.append("exit")

    payload = "\n".join(sql) + "\n"

    try:
        p = subprocess.Popen(
            ["sqlplus", "-s", oem_conn],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        out, err = p.communicate(payload)
        rc = p.returncode

        o = out.decode("utf-8", "ignore").strip()
        e = err.decode("utf-8", "ignore").strip()

        if rc not in (0, None):
            return None, None, "OEM_SQLPLUS_ERROR", "sqlplus rc=%s | %s" % (rc, e or o)

        if not o:
            return None, None, "OEM_NO_RESULT", "No output for target %s" % target_name

        line = None
        for ln in o.splitlines():
            ln = ln.strip()
            if ln:
                line = ln
                break

        if not line:
            return None, None, "OEM_NO_RESULT", "No data line for target %s" % target_name

        if "|" in line:
            h, p = line.split("|", 1)
            h = h.strip()
            p = p.strip()
        else:
            h = line.strip()
            p = None

        if not h:
            return None, None, "OEM_BAD_OUTPUT", "Bad output line: %s" % line

        return h, p, None, None

    except Exception as ex:
        return None, None, "OEM_EXCEPTION", str(ex)
