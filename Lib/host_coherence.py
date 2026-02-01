# -*- coding: utf-8 -*-
# Lib/host_coherence.py
#
# Controle de coherence metier des hostnames
# Regles :
#   - Primaire : Application + "P0DB"
#   - DR       : Application + "P0DR"
# Comparaison insensible a la casse
#

from Lib.io_common import ustr


def _norm_host(s):
    """
    Normalise un hostname pour comparaison :
    - unicode
    - strip
    - lower
    """
    if not s:
        return None
    try:
        return ustr(s).strip().lower()
    except:
        return None


def check_host_coherence(application, new_network_block):
    """
    Verifie la coherence des hostnames dans net['New']

    :param application: valeur CSV 'Application'
    :param new_network_block: net['New']
    :return: dictionnaire de statut de coherence
    """

    app_n = _norm_host(application)

    coh = {
        "Rule": "Application + P0DB / P0DR (case-insensitive)",
        "PrimaryExpected": None,
        "PrimaryActual": None,
        "PrimaryOK": None,
        "DRExpected": None,
        "DRActual": None,
        "DROK": None,
        "GlobalOK": None
    }

    # --------------------
    # Primaire
    # --------------------
    exp_p = _norm_host(app_n + "p0db") if app_n else None
    act_p = _norm_host(
        new_network_block.get("Primaire", {}).get("host")
    )

    coh["PrimaryExpected"] = exp_p
    coh["PrimaryActual"] = act_p
    if exp_p is not None and act_p is not None:
        coh["PrimaryOK"] = (act_p == exp_p)
    else:
        coh["PrimaryOK"] = None

    # --------------------
    # DR
    # --------------------
    act_dr_raw = new_network_block.get("DR", {}).get("host")
    if act_dr_raw:
        exp_d = _norm_host(app_n + "p0dr") if app_n else None
        act_d = _norm_host(act_dr_raw)

        coh["DRExpected"] = exp_d
        coh["DRActual"] = act_d
        coh["DROK"] = (exp_d is not None and act_d == exp_d)
    else:
        coh["DROK"] = "N/A"

    # --------------------
    # Global
    # --------------------
    if coh["PrimaryOK"] is False:
        coh["GlobalOK"] = False
    elif coh["DROK"] is False:
        coh["GlobalOK"] = False
    else:
        coh["GlobalOK"] = True

    return coh
