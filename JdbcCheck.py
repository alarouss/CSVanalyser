#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# JdbcCheck.py — JDBC Oracle string checker (Python 2.6)
# Steps implemented (current version):
#   0) COHERENCE (non-blocking warnings): HOST + SERVICE + HOST↔SERVICE (based on your rules)
#   1) SYNTAX (blocking): prefix + balanced parentheses + basic DESCRIPTION presence
#   2) STRUCTURE (blocking): extract ADDRESS_LIST/ADDRESS (host/port/protocol) + service_name
#
# Next evolution (not implemented yet): DNS/SCAN, TCP, Oracle auth connection.

import sys
import socket

# ---------------- Output helpers ----------------

def _out(line):
    try:
        sys.stdout.write(line + "\n")
    except:
        # last resort
        print line

def ok(tag, msg):
    _out("[%s] OK – %s" % (tag, msg))

def ko(tag, msg):
    _out("[%s] KO – %s" % (tag, msg))

def warn(tag, msg):
    _out("[%s] WARNING – %s" % (tag, msg))

# ---------------- CLI parsing (simple, Python 2.6) ----------------

def parse_kv_args(argv):
    """
    Accepts:
      - first non key=value argument as JDBC string (optional)
      - key=value args like Database=M19GAWP0
    """
    jdbc = None
    kv = {}
    for a in argv:
        if "=" in a:
            k, v = a.split("=", 1)
            kv[k.strip()] = v.strip()
        else:
            if jdbc is None:
                jdbc = a
            else:
                # ignore extra positional args
                pass
    return jdbc, kv

def read_stdin_all():
    data = sys.stdin.read()
    if data:
        return data.strip()
    return ""

# ---------------- Basic syntax validation ----------------

def normalize_jdbc(s):
    # remove surrounding spaces and collapse internal whitespace/newlines
    if s is None:
        return ""
    # keep characters, but remove whitespace characters
    out = []
    for ch in s.strip():
        if ch in (" ", "\t", "\r", "\n"):
            continue
        out.append(ch)
    return "".join(out)

def balanced_parentheses(s):
    c = 0
    for i in range(len(s)):
        ch = s[i]
        if ch == "(":
            c += 1
        elif ch == ")":
            c -= 1
            if c < 0:
                return False, i
    return (c == 0), (len(s) - 1)

# ---------------- Descriptor parser (lightweight, for Oracle net syntax) ----------------

class ParseError(Exception):
    pass

def _peek(s, i):
    if i >= len(s):
        return ""
    return s[i]

def _skip_spaces(s, i):
    # (should be none after normalize, but keep it)
    while i < len(s) and s[i] in (" ", "\t", "\r", "\n"):
        i += 1
    return i

def _read_name(s, i):
    # reads until '=', '(', ')'  (names like DESCRIPTION, ADDRESS_LIST, HOST, PORT...)
    i = _skip_spaces(s, i)
    start = i
    while i < len(s):
        ch = s[i]
        if ch in ("=", "(", ")",):
            break
        i += 1
    name = s[start:i]
    name = name.strip()
    return name, i

def _read_token_value(s, i):
    # reads a token until ')' (no nested parens)
    i = _skip_spaces(s, i)
    start = i
    while i < len(s):
        ch = s[i]
        if ch == ")":
            break
        i += 1
    val = s[start:i].strip()
    return val, i

def _add_kv(d, k, v):
    # allow repeated keys -> list
    ku = k.upper()
    if ku in d:
        cur = d[ku]
        if isinstance(cur, list):
            cur.append(v)
        else:
            d[ku] = [cur, v]
    else:
        d[ku] = v

def parse_group(s, i):
    """
    Parses one group like:
      (KEY=value)
      (KEY=(SUB=a)(SUB=b))
    Returns: (key, value, next_index)
    value is either:
      - string token
      - dict (children)
    """
    i = _skip_spaces(s, i)
    if _peek(s, i) != "(":
        raise ParseError("Expected '(' at position %d" % i)
    i += 1

    key, i = _read_name(s, i)
    if not key:
        raise ParseError("Empty key at position %d" % i)
    if _peek(s, i) != "=":
        raise ParseError("Expected '=' after key '%s' at position %d" % (key, i))
    i += 1

    # value: either token or nested groups
    i = _skip_spaces(s, i)
    if _peek(s, i) == "(":
        children = {}
        # parse one or more child groups until ')'
        while True:
            i = _skip_spaces(s, i)
            if _peek(s, i) == "(":
                ck, cv, i = parse_group(s, i)
                _add_kv(children, ck, cv)
                continue
            elif _peek(s, i) == ")":
                i += 1
                break
            else:
                # unexpected char in nested area
                raise ParseError("Unexpected char '%s' inside '%s' at position %d" % (_peek(s, i), key, i))
        return key, children, i
    else:
        # token
        val, i = _read_token_value(s, i)
        if _peek(s, i) != ")":
            raise ParseError("Expected ')' after value of '%s' at position %d" % (key, i))
        i += 1
        return key, val, i

def parse_descriptor(desc):
    """
    Parses full descriptor string which typically starts with (DESCRIPTION=...)
    We allow multiple top-level groups, but we mostly expect one DESCRIPTION group.
    Returns dict with possibly repeated keys as list.
    """
    i = 0
    root = {}
    desc = _skip_spaces(desc, 0)
    if not desc:
        raise ParseError("Empty descriptor")
    while i < len(desc):
        i = _skip_spaces(desc, i)
        if i >= len(desc):
            break
        if desc[i] != "(":
            raise ParseError("Unexpected char '%s' at top-level position %d" % (desc[i], i))
        k, v, i = parse_group(desc, i)
        _add_kv(root, k, v)
    return root

# ---------------- Tree search helpers ----------------

def _as_list(x):
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]

def find_all_nodes(node, key_upper):
    """
    Returns list of nodes matching key_upper in dict tree (value objects).
    """
    found = []
    if isinstance(node, dict):
        for k in node.keys():
            v = node[k]
            if k.upper() == key_upper:
                found.extend(_as_list(v))
            # recurse into values
            for vv in _as_list(v):
                found.extend(find_all_nodes(vv, key_upper))
    elif isinstance(node, list):
        for it in node:
            found.extend(find_all_nodes(it, key_upper))
    return found

# ---------------- Extract structure: hosts/ports/service ----------------

def extract_addresses(tree):
    """
    Returns list of address dicts: [{"ROLE":"DB/DR/UNK","HOST":..., "PORT":..., "PROTOCOL":...}, ...]
    We classify role by hostname suffix (DB/DR) on short host (before '.').
    """
    out = []
    addr_lists = find_all_nodes(tree, "ADDRESS_LIST")
    for al in addr_lists:
        # each ADDRESS_LIST contains ADDRESS groups (maybe repeated)
        addrs = []
        if isinstance(al, dict):
            addrs = _as_list(al.get("ADDRESS"))
        for a in addrs:
            if not isinstance(a, dict):
                continue
            host = a.get("HOST") or a.get("host")  # defensive
            port = a.get("PORT") or a.get("port")
            proto = a.get("PROTOCOL") or a.get("protocol")

            # normalize to strings if dicts slipped in
            if isinstance(host, dict): host = ""
            if isinstance(port, dict): port = ""
            if isinstance(proto, dict): proto = ""

            host_s = (host or "").strip()
            short = host_s.split(".")[0] if host_s else ""
            role = "UNK"
            if short.upper().endswith("DB"):
                role = "PRIMARY"
            elif short.upper().endswith("DR"):
                role = "DR"

            out.append({
                "ROLE": role,
                "HOST": host_s,
                "PORT": (port or "").strip(),
                "PROTOCOL": (proto or "").strip()
            })
    return out

def extract_service_name(tree):
    cds = find_all_nodes(tree, "CONNECT_DATA")
    for cd in cds:
        if isinstance(cd, dict):
            sn = cd.get("SERVICE_NAME")
            if sn:
                if isinstance(sn, dict):
                    continue
                return str(sn).strip()
    return ""

# ---------------- Coherence rules (WARNING only) ----------------

def compute_env_from_db(dbname):
    if not dbname or len(dbname) < 2:
        return ""
    return dbname[-2:].upper()

def compute_trig_from_db(dbname):
    """
    TRIG extracted from dbname by removing:
      - leading 'M19' if present
      - trailing ENV (last 2 chars)
    Example: M19GAWP0 -> remove M19 and P0 -> GAW
    """
    if not dbname:
        return ""
    d = dbname.upper()
    env = compute_env_from_db(d)
    core = d
    if core.startswith("M19"):
        core = core[3:]
    if env and core.endswith(env):
        core = core[:-2]
    return core

def expected_service(dbname):
    trig = compute_trig_from_db(dbname)
    if not trig or not dbname:
        return ""
    return "SRV_%s_%s" % (trig.upper(), dbname.upper())

def check_coherence_hosts(addresses, dbname):
    # hostname rule: short host = Application + ENV + (DB|DR)
    env_db = compute_env_from_db(dbname)
    for a in addresses:
        role = a.get("ROLE", "UNK")
        host = a.get("HOST", "")
        short = host.split(".")[0].upper() if host else ""
        tag = "[COHERENCE][HOST][%s]" % role

        if not short:
            warn(tag, "missing host")
            continue

        # role suffix check
        suffix = ""
        if short.endswith("DB"):
            suffix = "DB"
        elif short.endswith("DR"):
            suffix = "DR"
        else:
            warn(tag, "host '%s' does not end with DB/DR" % short)
            continue

        if len(short) < (2 + 2):  # minimal APP + ENV + suffix
            warn(tag, "host '%s' too short for convention" % short)
            continue

        env_host = short[-(2 + len(suffix)) : -len(suffix)]
        app = short[:-(2 + len(suffix))]

        # ENV check
        if env_db and env_host != env_db:
            warn(tag, "environment mismatch (host_env=%s, db_env=%s) host='%s'" % (env_host, env_db, short))
        else:
            ok(tag, "naming convention respected (app=%s env=%s role=%s)" % (app, env_host, suffix))

def check_coherence_service(service_name, dbname):
    tag = "[COHERENCE][SERVICE]"
    if not dbname:
        warn(tag, "Database name not provided (use Database=<DBNAME>), cannot validate service naming")
        return
    exp = expected_service(dbname)
    if not service_name:
        warn(tag, "missing SERVICE_NAME in JDBC (expected %s)" % exp)
        return
    # compare case-insensitive
    if service_name.upper() == exp.upper():
        ok(tag, "naming convention respected")
    else:
        warn(tag, "expected %s, found %s" % (exp, service_name))

def check_coherence_host_service(addresses, service_name, dbname):
    tag = "[COHERENCE][HOST↔SERVICE]"
    if not dbname or not service_name:
        warn(tag, "insufficient info to validate mapping (need Database and SERVICE_NAME)")
        return
    trig = compute_trig_from_db(dbname)
    if not trig:
        warn(tag, "cannot extract TRIG from database '%s'" % dbname)
        return

    # infer APP from hosts and compare with TRIG (simple heuristic: APP contains TRIG)
    apps = []
    env_db = compute_env_from_db(dbname)
    for a in addresses:
        host = a.get("HOST", "")
        short = host.split(".")[0].upper() if host else ""
        if short.endswith("DB") or short.endswith("DR"):
            suffix = short[-2:]
            env_host = short[-4:-2]
            app = short[:-4]
            if env_db and env_host == env_db and app:
                apps.append(app)

    if not apps:
        warn(tag, "cannot infer application from hosts to compare with TRIG=%s" % trig)
        return

    # if none of inferred apps contains trig -> warning
    trig_u = trig.upper()
    match = False
    for app in apps:
        if trig_u in app:
            match = True
            break

    if match:
        ok(tag, "consistent naming (TRIG=%s appears in host application)" % trig_u)
    else:
        warn(tag, "possible inconsistency: TRIG=%s not found in inferred host applications=%s" % (trig_u, ",".join(apps)))

# ---------------- Main steps 0-2 ----------------

def step1_syntax(jdbc_norm):
    tag = "SYNTAX"
    if not jdbc_norm:
        ko(tag, "empty JDBC string")
        return False

    prefix = "jdbc:oracle:thin:@"
    if not jdbc_norm.lower().startswith(prefix):
        ko(tag, "invalid prefix (expected %s)" % prefix)
        return False

    # descriptor part after '@'
    idx = jdbc_norm.find("@")
    if idx < 0 or idx == len(jdbc_norm) - 1:
        ko(tag, "missing descriptor after '@'")
        return False

    desc = jdbc_norm[idx+1:]
    ok_bal, pos = balanced_parentheses(desc)
    if not ok_bal:
        ko(tag, "parentheses mismatch near position %d" % pos)
        return False

    # quick check description present
    if "(description=" not in desc.lower():
        ko(tag, "missing DESCRIPTION group")
        return False

    ok(tag, "prefix + balanced parentheses + DESCRIPTION detected")
    return True

def step2_structure(jdbc_norm):
    tag = "STRUCTURE"
    idx = jdbc_norm.find("@")
    desc = jdbc_norm[idx+1:]

    try:
        tree = parse_descriptor(desc)
    except Exception as e:
        ko(tag, "parse error: %s" % str(e))
        return None, None, None

    addresses = extract_addresses(tree)
    service = extract_service_name(tree)

    if not addresses:
        ko(tag, "no ADDRESS_LIST/ADDRESS found")
        return None, None, None

    # Validate each address has minimal fields
    bad = 0
    for a in addresses:
        if not a.get("HOST") or not a.get("PORT"):
            bad += 1
    if bad:
        ko(tag, "found %d address(es) missing HOST/PORT" % bad)
        return None, None, None

    ok(tag, "%d address(es) extracted" % len(addresses))
    return tree, addresses, service

def print_structure_details(addresses, service):
    # Print extracted values in a deterministic way
    for a in addresses:
        role = a.get("ROLE", "UNK")
        host = a.get("HOST", "")
        port = a.get("PORT", "")
        proto = a.get("PROTOCOL", "")
        ok("STRUCTURE][%s" % role, "protocol=%s host=%s port=%s" % (proto or "?", host, port))
    if service:
        ok("STRUCTURE][SERVICE", "service_name=%s" % service)
    else:
        warn("STRUCTURE][SERVICE", "service_name missing")

# ---------------- Usage ----------------

def usage():
    _out("Usage:")
    _out("  python JdbcCheck.py \"<jdbc_string>\" Database=M19GAWP0")
    _out("  echo \"<jdbc_string>\" | python JdbcCheck.py Database=M19GAWP0")
    _out("")
    _out("Notes:")
    _out("  - Current version implements COHERENCE (warnings), SYNTAX (blocking), STRUCTURE (blocking).")
    _out("  - Network tests (DNS/TCP/Oracle) come in next evolution.")

# ---------------- Main ----------------

def main():
    jdbc_arg, kv = parse_kv_args(sys.argv[1:])
    dbname = kv.get("Database") or kv.get("DB") or kv.get("DATABASENAME") or ""

    if not jdbc_arg:
        jdbc_arg = read_stdin_all()

    if not jdbc_arg:
        usage()
        return 2

    jdbc_norm = normalize_jdbc(jdbc_arg)

    # Step 1: SYNTAX (blocking)
    if not step1_syntax(jdbc_norm):
        return 1

    # Step 2: STRUCTURE (blocking)
    tree, addresses, service = step2_structure(jdbc_norm)
    if tree is None:
        return 1

    # Structure details
    print_structure_details(addresses, service)

    # Step 0: COHERENCE (non-blocking warnings)
    # (executed after parsing because it depends on extracted fields)
    check_coherence_hosts(addresses, dbname)
    check_coherence_service(service, dbname)
    check_coherence_host_service(addresses, service, dbname)

    return 0

if __name__ == "__main__":
    sys.exit(main())
