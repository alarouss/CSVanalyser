#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# JdbcCheck.py
# Pipeline :
#   INPUT      : lecture string.ini
#   SYNTAX     : validation JDBC (bloquante)
#   STRUCTURE  : extraction ADDRESS / SERVICE (bloquante)
#   COHERENCE  : règles métier (WARNING uniquement)
#   DNS        : résolution DNS/SCAN (bloquante)
#   TCP        : connectivité host:port (bloquante)
#
# Python 2.6 compatible

import sys
import os
import socket
import subprocess
import re


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
            "port": int(port),
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
    if not dbname:
        warn("COHERENCE", "Database name not provided, coherence checks limited")
        return

    env_db = extract_env(dbname)
    trig = extract_trig(dbname)

    for a in addresses:
        short = a["host"].split(".")[0].upper()
        role = a["role"]
        env_host = short[-4:-2]
        if env_host != env_db:
            warn("COHERENCE][HOST][%s" % role,
                 "environment mismatch (host=%s db=%s)" % (env_host, env_db))
        else:
            ok("COHERENCE][HOST][%s" % role, "naming convention respected")

    expected_service = "SRV_%s_%s" % (trig, dbname)
    if service.upper() != expected_service.upper():
        warn("COHERENCE][SERVICE",
             "expected %s, found %s" % (expected_service, service))
    else:
        ok("COHERENCE][SERVICE", "naming convention respected")

    if trig and trig not in service.upper():
        warn("COHERENCE][HOST↔SERVICE",
             "TRIG %s not found in service name %s" % (trig, service))
    else:
        ok("COHERENCE][HOST↔SERVICE", "consistent naming")

# ============================================================
# DNS
# ============================================================

def check_dns(addresses):
    for a in addresses:
        role = a["role"]
        host = a["host"]
        tag = "DNS][%s" % role
        try:
            infos = socket.getaddrinfo(host, None)
            ips = set()
            for inf in infos:
                if len(inf) >= 5:
                    ips.add(inf[4][0])
            if not ips:
                ko(tag, "no IP resolved for host %s" % host)
            ok(tag, "%s resolves to %d IP(s)" % (host, len(ips)))
        except Exception as e:
            ko(tag, "DNS resolution failed for %s (%s)" % (host, str(e)))

# ============================================================
# TCP (BLOQUANT)
# ============================================================

def check_tcp(addresses, timeout=3):
    for a in addresses:
        role = a["role"]
        host = a["host"]
        port = a["port"]
        tag = "TCP][%s" % role

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            ok(tag, "connection to %s:%d succeeded" % (host, port))
        except Exception as e:
            ko(tag, "cannot connect to %s:%d (%s)" % (host, port, str(e)))
        finally:
            try:
                s.close()
            except:
                pass
# ============================================================
# ORACLE (Option C + SCAN + PATH Oracle)
#   PRIMARY : bloquant
#   DR      : WARNING si SSH indisponible
# ============================================================

import subprocess

def check_oracle_service_ssh(addresses, service, ssh_user="oracle", timeout=10):
    for a in addresses:
        role = a["role"]
        host = a["host"]
        tag = "ORACLE][%s" % role

        remote_cmd = (
            "source ~/.bash_profile >/dev/null 2>&1 && "
            "lsnrctl services"
        )

       
        cmd = [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=%d" % timeout,
            "-o", "CheckHostIP=no",
            "%s@%s" % (ssh_user, host),
            "bash", "-lc", "lsnrctl services"
        ]
        try:
            p = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            outp, errp = p.communicate()
        except Exception as e:
            if role == "DR":
                warn(tag, "SSH execution failed (%s) – listener check skipped" % str(e))
                continue
            else:
                ko(tag, "SSH execution failed (%s)" % str(e))

        if p.returncode != 0:
            msg = (errp or "").strip() or "lsnrctl execution failed"
            if role == "DR":
                warn(tag, "SSH/lsnrctl failed (%s) – listener check skipped" % msg)
                continue
            else:
                ko(tag, "SSH/lsnrctl failed (%s)" % msg)

        txt = outp.decode("utf-8", "ignore").upper()

        if service.upper() not in txt:
            if role == "DR":
                warn(tag, "service %s not found in listener output" % service)
            else:
                ko(tag, "service %s not registered in listener" % service)
        else:
            ok(tag, "service %s known by listener" % service)

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
    check_dns(addresses)
    check_tcp(addresses)

    # ---- ORACLE (sans user/pass) ----
    #check_oracle_service(addresses, service)
    # ---- ORACLE (via SSH on DB servers) ----
    check_oracle_service_ssh(addresses, service)
if __name__ == "__main__":
    main()
