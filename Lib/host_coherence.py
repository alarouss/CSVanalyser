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


def check_host_coherence(application, new_network_block):
    """
    Verifie la coherence FQDN des hostnames dans net['New']
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
                "KO (attendu %s, trouve %s)" % (exp_p, act_p)
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
                "KO (attendu %s, trouve %s)" % (exp_d, act_d)
            )
    else:
        coh["DROK"] = None
        coh["DRMessage"] = "N/A"

    # ======================
    # GLOBAL
    # ======================
    if coh["PrimaryOK"] is False or coh["DROK"] is False:
        coh["GlobalOK"] = False
    elif coh["PrimaryOK"] is True:
        coh["GlobalOK"] = True
    else:
        coh["GlobalOK"] = None

    return coh
