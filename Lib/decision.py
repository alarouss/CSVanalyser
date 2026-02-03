# -*- coding: utf-8 -*-
#Lib/decision.py
def compute_decision(status):
    """
    Decision engine (NON BLOQUANT).

    À ce stade :
      - aucune action automatique
      - aucune validation bloquante
      - uniquement une synthèse informative

    La décision finale (création DNS, service, JDBC)
    sera branchée plus tard.
    """

    decision = {
        "Final": "UNDECIDED",
        "Reason": [],
    }

    # Lecture des validations existantes
    coh = status.get("Coherence", {}).get("GlobalOK")
    scan = status.get("ScanPath", {}).get("Primary", {}).get("Status")
    svc  = status.get("ServiceCheck", {}).get("Primary", {}).get("Status")

    if coh is False:
        decision["Reason"].append("Host coherence failed")

    if scan == "KO":
        decision["Reason"].append("SCAN path invalid")

    if svc == "KO":
        decision["Reason"].append("Service validation failed")

    if not decision["Reason"]:
        decision["Reason"].append("All validations passed")

    return decision
