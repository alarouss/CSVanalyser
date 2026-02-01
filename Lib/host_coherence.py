# -*- coding: utf-8 -*-
# Lib/host_coherence.py
#
# Controle de coherence metier des hostnames
# Regle STRICTE :
#   Primaire = Application + P0DB
#   DR       = Application + P0DR
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


def check_host_coherence(application, new_network_block):
    """
    Verifie la coherence des hostnames dans net['New']
    """

    app_n = _norm_host(application)

    coh = {
        "Rule": "Application + P0DB / P0DR (case-insensitive)",

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
    exp_p = _norm_host(app_n + "p0db") if app_n else None
    act_p = _norm_host(
        new_network_block.get("Primaire", {}).get("host")
    )

    coh["PrimaryExpected"] = exp_p
    coh["PrimaryActual"] = act_p

    if exp_p is not None and act_p is not None:
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
    exp_d = _norm_host(app_n + "p0dr") if app_n else None
    act_d = _norm_host(
        new_network_block.get("DR", {}).get("host")
    )

    coh["DRExpected"] = exp_d
    coh["DRActual"] = act_d

    if exp_d is not None and act_d is not None:
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
