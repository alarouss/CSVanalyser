RAW_COLUMNS = [
    "Statut Global", "Lot", "Application", "Databases", "DR O/N",
    "Current connection string",
    "New connection string",
    "New connection string avec DR",
    "Cnames", "Services", "Acces", "Cnames DR"
]
# ------------------------------------------------
# IMPORTANT: le CSV chez toi est souvent latin1/cp1252 => sinon "Terminé" devient "Termin"
def ustr_csv(v):
    if v is None:
        return u""
    if isinstance(v, unicode):
        return v
    try:
        return unicode(v, "utf-8")
    except:
        try:
            return unicode(v, "latin1")
        except:
            try:
                return unicode(str(v), "latin1", "ignore")
            except:
                return u""

def normalize_key(k):
    return ustr_csv(k).replace(u'\ufeff', u'').strip()

def normalize_row(row):
    out = {}
    for k, v in row.items():
        out[normalize_key(k)] = ustr_csv(v)
    return out
# ------------------------------------------------
def _raw_source(row):
    raw = {}
    for c in RAW_COLUMNS:
        raw[c] = ustr_csv(row.get(c, u"")).strip()
    return raw

def _raw_debug(row):
    dbg = {}
    for k, v in row.items():
        dbg[ustr_csv(k)] = ustr_csv(v)
    return dbg
def build_raw_source(row):
    """
    Source brute contractuelle (colonnes métier)
    → utilisée pour comparaison dirty + affichage ReportV3
    """
    raw = {}
    for c in RAW_COLUMNS:
        v = row.get(c, u"")
        if v is None:
            v = u""
        raw[c] = ustr(v).strip()
    return raw


# ------------------------------------------------
def build_raw_debug(row):
    """
    Source CSV complète (DEBUG)
    → ne sert qu’au diagnostic
    """
    dbg = {}
    for k, v in row.items():
        dbg[ustr(k)] = ustr(v)
    return dbg
# ------------------------------------------------
def build_status(valid, scan, scan_dr, dirty, dirty_reason,
                 err_type, err_detail, mode,
                 oem_err_type=None, oem_err_detail=None):

    st = {
        "ValidSyntax": bool(valid),
        "ScanCompare": scan,
        "ScanCompareDR": scan_dr,
        "Dirty": bool(dirty),
        "DirtyReason": dirty_reason,
        "ErrorType": err_type,
        "ErrorDetail": err_detail,
        "Mode": mode,
        "LastUpdateTime": time.strftime("%Y-%m-%d %H:%M:%S")
    }

    if oem_err_type or oem_err_detail:
        st["OEMErrorType"] = oem_err_type
        st["OEMErrorDetail"] = oem_err_detail

    return st
  def compute_net_side(block, step_prefix, pos, total):
    """
    Applique la résolution CNAME / SCAN
    sur block = {"host":..., "cname":..., "scan":...}
    """
    host = block.get("host")
    if not host:
        return block, None, None

    if host in ("DR", "Primaire"):
        raise Exception("INVARIANT VIOLATION: host=%r" % host)

    # ---------- CNAME ----------
    show_progress(pos, total, "%s_CNAME" % step_prefix)
    cname, e1, d1 = resolve_cname(host)
    if e1:
        return block, "CNAME_ERROR", "%s: cname resolution failed for %s | %s" % (
            step_prefix, host, d1
        )

    block["cname"] = cname

    # ---------- SCAN ----------
    show_progress(pos, total, "%s_SCAN" % step_prefix)
    scan, e2, d2 = resolve_scan(cname)
    if e2:
        return block, "SCAN_ERROR", "%s: scan resolution failed for %s | %s" % (
            step_prefix, cname, d2
        )

    block["scan"] = scan
    return block, None, None
# ------------------------------------------------
def compute_block_status(block, had_error):
    """
    Déduit le statut logique d’un bloc réseau
    """
    if not block.get("host"):
        return "N/A"
    if had_error:
        return "ERROR"
    return "OK"
# ------------------------------------------------
def compute_network_block(host, step, pos, total):
    net = {"host": host, "cname": None, "scan": None}
    if not host:
        return net, "HOST_NONE", "%s: host empty" % step

    show_progress(pos, total, "%s_CNAME" % step)
    cname, e1, d1 = resolve_cname(host)
    if (not e1) and cname:
        net["cname"] = cname

    scan_input = net["cname"] or host
    show_progress(pos, total, "%s_SCAN" % step)
    if host in ("DR", "Primaire"):
        raise Exception("INVARIANT VIOLATION: host=%r" % host)
    scan, e2, d2 = resolve_scan(scan_input)
    if e2:
        net["scan"] = scan
        return net, e2, "%s: scan resolution failed for %s | %s" % (
            step, scan_input, d2
        )

    net["scan"] = scan
    return net, None, None

# ------------------------------------------------
#def fill_net_from_addresses(parsed, net_side):
    """
    Remplit net_side {"Primaire":{}, "DR":{}}
    à partir de JdbcParsed.addresses (dict structuré)
    """

#    if not parsed or not isinstance(parsed.addresses, dict):
#        return
#    for role in ("Primaire", "DR"):
#        addr = parsed.addresses.get(role)
#        if not addr:
#            continue
#        host = addr.get("host")
#        if not host:
#            continue
#        if role in net_side:
#            net_side[role]["host"] = host
def fill_net_from_addresses(o, net_side):
    """
    Alimente Primaire / DR à partir de JdbcParsed.addresses
    Contrat:
      o.addresses = {
          "Primaire": {"host": ...},
          "DR": {"host": ...}
      }
    Aucune validation, aucun contrôle métier.
    """
    if not o or not getattr(o, "addresses", None):
        return

    addrs = o.addresses

    if isinstance(addrs, dict):
        if "Primaire" in addrs:
            net_side["Primaire"]["host"] = addrs["Primaire"].get("host")

        if "DR" in addrs:
            net_side["DR"]["host"] = addrs["DR"].get("host")

# ------------------------------------------------


# ------------------------------------------------

def build_object_v3(row, obj_id, oem_conn, pos, total, force):

    raw = build_raw_source(row)
    raw_debug = build_raw_debug(row)

    cur = raw.get("Current connection string")
    new = raw.get("New connection string")

    cur_o, ecur, dcur = interpret(cur)
    new_o, enew, dnew = interpret(new)

    net = {
        "Current": {
            "Primaire": {"host": None, "cname": None, "scan": None},
            "DR":       {"host": None, "cname": None, "scan": None},
        },
        "New": {
            "Primaire": {"host": None, "cname": None, "scan": None},
            "DR":       {"host": None, "cname": None, "scan": None},
        },
        "OEM": {
            "Primaire": {"host": None, "port": None, "cname": None, "scan": None},
            "DR":       {"host": None, "port": None, "cname": None, "scan": None},
        }
    }

    fill_net_from_addresses(cur_o, net["Current"])
    fill_net_from_addresses(new_o, net["New"])

    fill_net_from_addresses(cur_o, net["Current"])
    fill_net_from_addresses(new_o, net["New"])
    
    # ===== DEBUG TEMPORAIRE (ETAPE 1) =====
    print("DEBUG ADDRESSES NEW =", getattr(new_o, "addresses", None))
    print("DEBUG NET NEW =", net["New"])
    # =====================================

    valid = bool(cur_o.valide and new_o.valide)

    err_type = None
    err_detail = None
    print("DEBUG VALID =", valid, "cur_o =", cur_o, "new_o =", new_o)
    if not valid:
        status = build_status(
            False, "ERROR", None,
            False, None,
            "SYNTAX_ERROR",
            "Invalid JDBC syntax",
            "FORCE_UPDATE" if force else "AUTO"
        )
        return {
            "id": obj_id,
            "Network": net,
            "OEM": net["OEM"],
            "Status": status,
            "RawSource": raw,
            "RawSource_DEBUG": raw_debug
        }

    # Résolution CURRENT
    print("DEBUG BEFORE CURRENT LOOP", net["Current"])
    for role in ("Primaire", "DR"):
        net["Current"][role], e, d = compute_net_side(
            net["Current"][role],
            "CURRENT_%s" % role.upper(),
            pos, total
        )
        if e and not err_type:
            err_type, err_detail = e, d

    # Résolution NEW
    for role in ("Primaire", "DR"):
        net["New"][role], e, d = compute_net_side(
            net["New"][role],
            "NEW_%s" % role.upper(),
            pos, total
        )
        if e and not err_type:
            err_type, err_detail = e, d

    # Comparaison référence = Current / Primaire
    if err_type:
        scan_status = "ERROR"
    else:
        eq = compare(
            net["Current"]["Primaire"]["scan"],
            net["New"]["Primaire"]["scan"]
        )
        scan_status = "VALIDE" if eq else "DIFFERENT"
        if not eq:
            err_type = "SCAN_DIFFERENT"
            err_detail = "Current and New SCAN differ"

    scan_dr_status = None
    if net["New"]["DR"]["host"]:
        eqdr = compare(
            net["Current"]["Primaire"]["scan"],
            net["New"]["DR"]["scan"]
        )
        scan_dr_status = "VALIDE" if eqdr else "DIFFERENT"
    else:
        scan_dr_status = "N/A"

    status = build_status(
        True,
        scan_status,
        scan_dr_status,
        False,
        None,
        err_type,
        err_detail,
        "FORCE_UPDATE" if force else "AUTO"
    )

    return {
        "id": obj_id,
        "OEM": net["OEM"],
        "Network": net,
        "Status": status,
        "RawSource": raw,
        "RawSource_DEBUG": raw_debug
    }
