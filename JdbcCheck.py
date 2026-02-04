#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# JdbcCheck.py
# Étapes implémentées :
#   INPUT  : lecture explicite d'un fichier string.ini
#   SYNTAX : validation syntaxique JDBC (bloquante)
#
# Python 2.6 compatible

import sys
import os

# ============================================================
# OUTPUT HELPERS (jamais silencieux)
# ============================================================

def out(msg):
    try:
        sys.stdout.write(msg + "\n")
    except:
        print msg

def ok(tag, msg):
    out("[%s] OK – %s" % (tag, msg))

def ko(tag, msg):
    out("[%s] KO – %s" % (tag, msg))
    sys.exit(1)

# ============================================================
# INPUT — lecture string.ini
# ============================================================

def read_jdbc_from_ini(path):
    if not os.path.isfile(path):
        ko("INPUT", "file not found: %s" % path)

    section_found = False
    in_connection = False
    conn_lines = []

    try:
        f = open(path, "r")
    except Exception as e:
        ko("INPUT", "cannot open file %s (%s)" % (path, str(e)))

    for raw in f:
        line = raw.strip()

        if not line or line.startswith("#") or line.startswith(";"):
            continue

        if line.upper() == "[JDBC]":
            section_found = True
            in_connection = False
            continue

        if line.startswith("[") and line.endswith("]"):
            in_connection = False
            continue

        if section_found:
            if line.lower().startswith("connection"):
                parts = line.split("=", 1)
                if len(parts) != 2:
                    ko("INPUT", "invalid JDBC connection definition")
                conn_lines.append(parts[1].strip())
                in_connection = True
                continue

            if in_connection:
                conn_lines.append(line)

    f.close()

    if not section_found:
        ko("INPUT", "missing [JDBC] section")

    if not conn_lines:
        ko("INPUT", "missing JDBC/connection entry")

    jdbc = "".join(conn_lines).strip()

    if not jdbc:
        ko("INPUT", "empty JDBC connection value")

    ok("INPUT", "JDBC string loaded from %s (length=%d)" % (path, len(jdbc)))
    return jdbc

# ============================================================
# SYNTAX — validation bloquante
# ============================================================

def check_syntax(jdbc):
    tag = "SYNTAX"

    # ---- Prefixe JDBC ----
    prefix = "jdbc:oracle:thin:@"
    if not jdbc.lower().startswith(prefix):
        ko(tag, "invalid JDBC prefix (expected %s)" % prefix)
    ok(tag, "prefix valid")

    # ---- Parenthèses équilibrées ----
    level = 0
    pos = 0
    for ch in jdbc:
        if ch == "(":
            level += 1
        elif ch == ")":
            level -= 1
            if level < 0:
                ko(tag, "parentheses mismatch at position %d" % pos)
        pos += 1

    if level != 0:
        ko(tag, "parentheses mismatch (unbalanced)")

    ok(tag, "parentheses balanced")

    # ---- Blocs obligatoires ----
    low = jdbc.lower()
    mandatory = [
        "(description=",
        "(address",
        "(connect_data=",
        "(service_name="
    ]

    for m in mandatory:
        if m not in low:
            ko(tag, "missing mandatory block %s" % m.upper())

    ok(tag, "mandatory blocks detected")

# ============================================================
# MAIN
# ============================================================

def usage():
    out("Usage:")
    out("  python JdbcCheck.py string.ini")
    sys.exit(1)

def main():
    if len(sys.argv) < 2:
        usage()

    ini_path = sys.argv[1]

    # ---- INPUT ----
    jdbc = read_jdbc_from_ini(ini_path)

    # ---- SYNTAX ----
    check_syntax(jdbc)

    return 0

if __name__ == "__main__":
    sys.exit(main())
