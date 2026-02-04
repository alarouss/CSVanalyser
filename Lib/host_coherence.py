# -*- coding: utf-8 -*-
# Lib/host_coherence.py
#
# Controle de coherence metier des hostnames (FQDN)
# Regle :
#   Primaire = Application + P0DB + suffixe DNS observe
#   DR       = Application + P0DR + suffixe DNS observe
# Comparaison insensible a la casse
#

from Lib.io_common import ustr

import re

def extract_seq_from_database(dbname):
    """
    Extrait la séquence (P0, P1, P2, ...) depuis le nom de la base.
    Exemples:
      M19ACCP0 -> P0
      M19GNRP1 -> P1
    """
    if not dbname:
        return None

    m = re.search(r'(P\d+)$', dbname.upper())
    if m:
        return m.group(1)

    return None

def _norm_host(s):
    if not s:
        return None
    try:
        return ustr(s).strip().lower()
    except:
        return None


def _extract_dns_suffix(fqdn):
    """
    Extrait le suffixe DNS a partir d'un FQDN.
    Exemple :
      accueil-clientp0db.groupe.generali.fr -> .groupe.generali.fr
    """
    if not fqdn:
        return ""
    fqdn = _norm_host(fqdn)
    if "." not in fqdn:
        return ""
    return fqdn[fqdn.find("."):]  # garde le point

# ------------------------------------------------------------
# SERVICE NAMING COHERENCE (METIER)
# Rule: SRV_<TRIG>_<DATABASE>   (case-insensitive)
# TRIG is derived from Application (first 3 alnum chars)
# ------------------------------------------------------------

def _alnum_only_upper(s):
    try:
        u = s
        if not isinstance(u, unicode):
            try:
                u = unicode(s, "utf-8", "ignore")
            except:
                try:
                    u = unicode(str(s), "latin1", "ignore")
                except:
                    u = u""
        u = u.strip().upper()
    except:
        u = u""

    out = []
    for ch in u:
        # keep A-Z 0-9 only
        o = ord(ch)
        if (o >= 48 and o <= 57) or (o >= 65 and o <= 90):
            out.append(ch)
    return u"".join(out)

def _derive_trig_from_application(app_name):
    s = _alnum_only_upper(app_name)
    if not s:
        return u""
    if len(s) >= 3:
        return s[:3]
    return s

def compute_service_naming_coherence(rawsource):
    """
    Returns a dict inserted into Status.Coherence["ServiceNaming"].
    """
    app = rawsource.get("Application") or ""
    db  = rawsource.get("Databases") or ""
    srv = rawsource.get("Services") or ""

    trig = _derive_trig_from_application(app)

    # expected: SRV_<TRIG>_<DATABASE>
    # (we keep DB as-is but normalize to upper for comparison)
    db_u = _alnum_only_upper(db)
    expected = u""
    if trig and db_u:
        expected = u"SRV_%s_%s" % (trig, db_u)

    srv_u = _alnum_only_upper(srv)  # normalize service provided

    # N/A if no service declared
    if not srv_u:
        return {
            "Rule": "Service name must follow SRV_<TRIG>_<DATABASE> naming convention.",
            "Status": "KO",
            "Expected": expected,
            "Actual": srv,
            "Message": "No service name declared in JDBC connection string."
        }

    # If we cannot compute expected (missing app/db), mark N/A
    if not expected:
        return {
            "Rule": "Service name must follow SRV_<TRIG>_<DATABASE> naming convention.",
            "Status": "N/A",
            "Expected": expected,
            "Actual": srv,
            "Message": "Service naming check not applicable (missing Application or Databases)."
        }

    if _alnum_only_upper(expected) != srv_u:
        return {
            "Rule": "Service name must follow SRV_<TRIG>_<DATABASE> naming convention.",
            "Status": "KO",
            "Expected": expected,
            "Actual": srv,
            "Message": "Service name does not comply with naming convention SRV_<TRIG>_<DATABASE>."
        }

    return {
        "Rule": "Service name must follow SRV_<TRIG>_<DATABASE> naming convention.",
        "Status": "OK",
        "Expected": expected,
        "Actual": srv,
        "Message": "Service name complies with naming convention SRV_<TRIG>_<DATABASE>."
    }

#----------------------------------------------------------

def check_host_coherence(application, new_network_block, rawsource):
    """
    Verifie la coherence FQDN des hostnames dans net['New']
    + coherence metier du nom de service (SRV_<TRIG>_<DATABASE>)
    """

    app_n = _norm_host(application)

    coh = {
        "Rule": "Application + P0DB / P0DR + DNS suffix (FQDN)",

        "PrimaryExpected": None,
        "PrimaryActual": None,
        "PrimaryOK": None,
        "PrimaryMessage": None,

        "DRExpected": None,
        "DRActual": None,
        "DROK": None,
        "DRMessage": None,

        # --- nouveau ---
        "ServiceNaming": None,

        "GlobalOK": None
    }

    # ======================
    # PRIMAIRE
    # ======================
    act_p = _norm_host(
        new_network_block.get("Primaire", {}).get("host")
    )

    dns_suffix_p = _extract_dns_suffix(act_p) if act_p else ""
    exp_p = _norm_host(app_n + "p0db" + dns_suffix_p) if app_n else None

    coh["PrimaryExpected"] = exp_p
    coh["PrimaryActual"] = act_p

    if exp_p and act_p:
        if act_p == exp_p:
            coh["PrimaryOK"] = True
            coh["PrimaryMessage"] = "OK"
        else:
            coh["PrimaryOK"] = False
            coh["PrimaryMessage"] = (
                "KO (expected %s, found %s)" % (exp_p, act_p)
            )
    else:
        coh["PrimaryOK"] = None
        coh["PrimaryMessage"] = "N/A"

    # ======================
    # DR
    # ======================
    act_d = _norm_host(
        new_network_block.get("DR", {}).get("host")
    )

    dns_suffix_d = _extract_dns_suffix(act_d) if act_d else ""
    exp_d = _norm_host(app_n + "p0dr" + dns_suffix_d) if app_n else None

    coh["DRExpected"] = exp_d
    coh["DRActual"] = act_d

    if exp_d and act_d:
        if act_d == exp_d:
            coh["DROK"] = True
            coh["DRMessage"] = "OK"
        else:
            coh["DROK"] = False
            coh["DRMessage"] = (
                "KO (expected %s, found %s)" % (exp_d, act_d)
            )
    else:
        coh["DROK"] = None
        coh["DRMessage"] = "N/A"

    # ======================
    # SERVICE NAMING (METIER)
    # ======================
    coh["ServiceNaming"] = compute_service_naming_coherence(rawsource)

    # ======================
    # GLOBAL
    # ======================
    svc_ok = coh["ServiceNaming"].get("Status") == "OK"

    if coh["PrimaryOK"] is False or coh["DROK"] is False or svc_ok is False:
        coh["GlobalOK"] = False
    elif coh["PrimaryOK"] is True and svc_ok is True:
        coh["GlobalOK"] = True
    else:
        coh["GlobalOK"] = None

    return coh
