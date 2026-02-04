#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# JdbcCheck.py
# INPUT + SYNTAX + STRUCTURE (FIX parenthèses imbriquées)
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

def ko(tag, msg):
    out("[%s] KO – %s" % (tag, msg))
    sys.exit(1)

# ============================================================
# INPUT
# ============================================================

def read_jdbc_from_ini(path):
    if not os.path.isfile(path):
        ko("INPUT", "file not found: %s" % path)

    section = False
    collect = False
    buf = []

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

    low = jdbc.lower()
    for k in ["(description=", "(address", "(connect_data=", "(service_name="]:
        if k not in low:
            ko(tag, "missing mandatory block %s" % k.upper())

    ok(tag, "mandatory blocks detected")

# ============================================================
# STRUCTURE (FIXED)
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
        ok("STRUCTURE][%s" % role,
           "host=%s port=%s protocol=%s" % (host, port, proto or "?"))

    svc_blocks = extract_blocks(jdbc, "(service_name=")
    if not svc_blocks:
        ko(tag, "SERVICE_NAME not found")

    ok("STRUCTURE][SERVICE", "service_name=%s" % svc_blocks[0])

# ============================================================
# MAIN
# ============================================================

def main():
    if len(sys.argv) < 2:
        out("Usage: python JdbcCheck.py string.ini")
        sys.exit(1)

    jdbc = read_jdbc_from_ini(sys.argv[1])
    check_syntax(jdbc)
    check_structure(jdbc)

if __name__ == "__main__":
    main()
