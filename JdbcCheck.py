#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# JdbcCheck.py — INPUT step only
# Python 2.6 compatible
#
# Usage:
#   python JdbcCheck.py string.ini

import sys
import os

# ---------- output helpers ----------

def out(msg):
    try:
        sys.stdout.write(msg + "\n")
    except:
        print msg

def ok(msg):
    out("[INPUT] OK – %s" % msg)

def ko(msg):
    out("[INPUT] KO – %s" % msg)
    sys.exit(1)

# ---------- minimal INI parser (Python 2.6 safe) ----------

def read_jdbc_from_ini(path):
    if not os.path.isfile(path):
        ko("file not found: %s" % path)

    section_found = False
    conn_lines = []
    in_connection = False

    try:
        f = open(path, "r")
    except Exception as e:
        ko("cannot open file %s (%s)" % (path, str(e)))

    for raw in f:
        line = raw.strip()

        if not line or line.startswith("#") or line.startswith(";"):
            continue

        if line.upper() == "[JDBC]":
            section_found = True
            in_connection = False
            continue

        if line.startswith("[") and line.endswith("]"):
            # another section
            in_connection = False
            continue

        if section_found:
            if line.lower().startswith("connection"):
                # connection = ....
                parts = line.split("=", 1)
                if len(parts) != 2:
                    ko("invalid connection definition")
                value = parts[1].strip()
                conn_lines.append(value)
                in_connection = True
                continue

            if in_connection:
                # multiline continuation
                conn_lines.append(line)

    f.close()

    if not section_found:
        ko("missing [JDBC] section")

    if not conn_lines:
        ko("missing JDBC/connection entry")

    jdbc = "".join(conn_lines).strip()

    if not jdbc:
        ko("empty JDBC connection value")

    return jdbc

# ---------- main ----------

def main():
    if len(sys.argv) < 2:
        ko("missing ini file argument (usage: python JdbcCheck.py string.ini)")

    ini_path = sys.argv[1]
    jdbc = read_jdbc_from_ini(ini_path)

    ok("JDBC string loaded from %s (length=%d)" % (ini_path, len(jdbc)))

    # For now, we STOP HERE (as agreed)
    # Next steps (SYNTAX / STRUCTURE / COHERENCE) will consume `jdbc`

    return 0

if __name__ == "__main__":
    sys.exit(main())
