#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# JdbcCheck.py
# Étapes implémentées :
#   INPUT     : lecture explicite de string.ini
#   SYNTAX    : validation syntaxique JDBC (bloquante)
#   STRUCTURE : extraction ADDRESS / SERVICE_NAME (bloquante)
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

    prefix = "jdbc:oracle:thin:@"
    if not jdbc.lower().startswith(prefix):
        ko(tag, "invalid JDBC prefix (expected %s)" % prefix)
    ok(tag, "prefix valid")

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
# STRUCTURE — extraction ADDRESS / SERVICE
# ============================================================

def extract_between(s, start_token, end_token, start_pos):
    i = s.find(start_token, start_pos)
    if i < 0:
        return None, -1
    i += len(start_token)
    j = s.find(end_token, i)
    if j < 0:
        return None, -1
    return s[i:j], j

def extract_addresses(jdbc):
    addresses = []
    low = jdbc.lower()
    pos = 0

    while True:
        block, pos = extract_between(low, "(address=", ")", pos)
        if block is None:
            break

        host = None
        port = None
        protocol = None

        b = block

        h, _ = extract_between(b, "host=", ")", 0)
        if h:
            host = h

        p, _ = extract_between(b, "port=", ")", 0)
        if p:
            port = p

        pr, _ = extract_between(b, "protocol=", ")", 0)
        if pr:
            protocol = pr

        addresses.append({
            "host": host,
            "port": port,
            "protocol": protocol
        })

    return addresses

def extract_service(jdbc):
    low = jdbc.lower()
    val, _ = extract_between(low, "service_name=", ")", 0)
    return val

def classify_role(host):
    if not host:
        return "UNKNOWN"
    short = host.split(".")[0].upper()
    if short.endswith("DB"):
        return "PRIMARY"
    if short.endswith("DR"):
        return "DR"
    return "UNKNOWN"

def check_structure(jdbc):
    tag = "STRUCTURE"

    addresses = extract_addresses(jdbc)
    if not addresses:
        ko(tag, "no ADDRESS found")

    ok(tag, "%d address(es) detected" % len(addresses))

    for a in addresses:
        if not a["host"] or not a["port"]:
            ko(tag, "ADDRESS missing host or port")

        role = classify_role(a["host"])
        ok("STRUCTURE][%s" % role,
           "host=%s port=%s protocol=%s" %
           (a["host"], a["port"], a["protocol"] or "?"))

    service = extract_service(jdbc)
    if not service:
        ko(tag, "SERVICE_NAME not found")

    ok("STRUCTURE][SERVICE", "service_name=%s" % service)

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

    # ---- STRUCTURE ----
    check_structure(jdbc)

    return 0

if __name__ == "__main__":
    sys.exit(main())
