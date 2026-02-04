#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# JdbcCheck.py
# Pipeline :
#   INPUT      : lecture string.ini
#   SYNTAX     : validation JDBC (bloquante)
#   STRUCTURE  : extraction ADDRESS / SERVICE (bloquante)
#   COHERENCE  : règles métier (WARNING uniquement)
#
# Python 2.6 compatible

import sys
import os

# ============================================================
# OUTPUT
# ============================================================

def out(msg):
    try:
        sys.stdout.write(msg + "\n")
    except:
        print msg

def ok(tag, msg):
    out("[%s] OK – %s" % (tag, msg))

def warn(tag, msg):
    out("[%s] WARNING – %s" % (tag, msg))

def ko(tag, msg):
    out("[%s] KO – %s" % (tag, msg))
    sys.exit(1)

# ============================================================
# INPUT
# ============================================================

def read_jdbc_from_ini(path):
    if not os.path.isfile(path):
        ko("INPUT", "file not found: %s" % path)

    buf = []
    section = False
    collect = False

    f = open(path, "r")
    for raw in f:
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue

        if line.upper() == "[JDBC]":
            section = True
            continue

        if line.startswith("[") and line.endswith("]"):
            collect = False
            continue

        if section:
            if line.lower().startswith("connection"):
                buf.append(line.split("=", 1)[1].strip())
                collect = True
            elif collect:
                buf.append(line)

    f.close()

    if not buf:
        ko("INPUT", "missing JDBC/connection entry")

    jdbc = "".join(buf).strip()
    ok("INPUT", "JDBC string loaded from %s (length=%d)" % (path, len(jdbc)))
    return jdbc

# ============================================================
# SYNTAX
# ============================================================

def check_syntax(jdbc):
    tag = "SYNTAX"

    if not jdbc.lower().startswith("jdbc:oracle:thin:@"):
        ko(tag, "invalid JDBC prefix")
    ok(tag, "prefix valid")

    level = 0
    for i, ch in enumerate(jdbc):
        if ch == "(":
            level += 1
        elif ch == ")":
            level -= 1
            if level < 0:
                ko(tag, "parentheses mismatch at position %d" % i)
    if level != 0:
        ko(tag, "parentheses mismatch (unbalanced)")
    ok(tag, "parentheses balanced")

    for k in ["(description=", "(address", "(connect_data=", "(service_name="]:
        if k not in jdbc.lower():
            ko(tag, "missing mandatory block %s" % k.upper())
    ok(tag, "mandatory blocks detected")

# ============================================================
# STRUCTURE
# ============================================================

def extract_blocks(jdbc, token):
    blocks = []
    s = jdbc.lower()
    i = 0
    while True:
        i = s.find(token, i)
        if i < 0:
            break
        start = i + len(token)
        level = 1
        j = start
        while j < len(s) and level > 0:
            if s[j] == "(":
                level += 1
            elif s[j] == ")":
                level -= 1
            j += 1
        blocks.append(jdbc[start:j-1])
        i = j
    return blocks

def extract_value(block, key):
    k = key.lower() + "="
    i = block.lower().find(k)
    if i < 0:
        return None
    i += len(k)
    j = i
    while j < len(block) and block[j] not in "()":
        j += 1
    return block[i:j]

def classify_role(host):
    short = host.split(".")[0].upper()
    if short.endswith("DB"):
        return "PRIMARY"
    if short.endswith("DR"):
        return "DR"
    return "UNKNOWN"

def check_structure(jdbc):
    tag = "STRUCTURE"
    addresses = []

    blocks = extract_blocks(jdbc, "(address=")
    if not blocks:
        ko(tag, "no ADDRESS found")

    ok(tag, "%d address(es) detected" % len(blocks))

    for b in blocks:
        host = extract_value(b, "host")
        port = extract_value(b, "port")
        proto = extract_value(b, "protocol")

        if not host or not port:
            ko(tag, "ADDRESS missing host or port")

        role = classify_role(host)
        addresses.append({
            "role": role,
            "host": host,
            "port": port,
            "protocol": proto
        })

        ok("STRUCTURE][%s" % role,
           "host=%s port=%s protocol=%s" %
           (host, port, proto or "?"))

    svc = extract_blocks(jdbc, "(service_name=")
    if not svc:
        ko(tag, "SERVICE_NAME not found")

    service = svc[0]
    ok("STRUCTURE][SERVICE", "service_name=%s" % service)

    return addresses, service

# ============================================================
# COHERENCE (WARNING ONLY)
# ============================================================

def extract_env(dbname):
    if not dbname or len(dbname) < 2:
        return None
    return dbname[-2:].upper()

def extract_trig(dbname):
    if not dbname:
        return None
    d = dbname.upper()
    if d.startswith("M19"):
        d = d[3:]
    env = extract_env(dbname)
    if env and d.endswith(env):
        d = d[:-2]
    return d

def check_coherence(addresses, service, dbname):
    tag_h = "COHERENCE][HOST"
    tag_s = "COHERENCE][SERVICE"
    tag_m = "COHERENCE][HOST↔SERVICE"

    if not dbname:
        warn("COHERENCE", "Database name not provided, coherence checks limited")
        return

    env_db = extract_env(dbname)
    trig = extract_trig(dbname)

    # --- HOST coherence ---
    for a in addresses:
        short = a["host"].split(".")[0].upper()
        role = a["role"]

        if role not in ("PRIMARY", "DR"):
            warn(tag_h + "][%s" % role,
                 "cannot determine role from hostname %s" % short)
            continue

        env_host = short[-4:-2]
        if env_host != env_db:
            warn(tag_h + "][%s" % role,
                 "environment mismatch (host=%s db=%s)" % (env_host, env_db))
        else:
            ok(tag_h + "][%s" % role, "naming convention respected")

    # --- SERVICE coherence ---
    expected_service = "SRV_%s_%s" % (trig, dbname)
    if service.upper() != expected_service.upper():
        warn(tag_s,
             "expected %s, found %s" % (expected_service, service))
    else:
        ok(tag_s, "naming convention respected")

    # --- HOST ↔ SERVICE ---
    if trig and trig not in service.upper():
        warn(tag_m,
             "TRIG %s not found in service name %s" % (trig, service))
    else:
        ok(tag_m, "consistent naming")

# ============================================================
# MAIN
# ============================================================

def main():
    if len(sys.argv) < 2:
        out("Usage: python JdbcCheck.py string.ini Database=M19GAWP0")
        sys.exit(1)

    ini = sys.argv[1]
    dbname = None
    for a in sys.argv[2:]:
        if a.startswith("Database="):
            dbname = a.split("=", 1)[1]

    jdbc = read_jdbc_from_ini(ini)
    check_syntax(jdbc)
    addresses, service = check_structure(jdbc)
    check_coherence(addresses, service, dbname)

if __name__ == "__main__":
    main()
