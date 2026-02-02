# -*- coding: utf-8 -*-

def probe_service_or_sid(service_name, database=None):
    """
    Oracle runtime probe (READ ONLY).

    À terme :
      - srvctl status service
      - ou sqlplus -> v$services / v$instance

    Retourne un DIAGNOSTIC, jamais une décision.
    """

    if not service_name:
        return {
            "service_found": False,
            "sid_found": False,
            "error": "No service provided"
        }

    name = service_name.strip().upper()

    # ===== STUB TEMPORAIRE =====
    # (sera remplacé par vrai Oracle)
    if name.startswith("SRV_"):
        return {
            "service_found": True,
            "sid_found": False,
            "error": None
        }

    # Legacy SID
    return {
        "service_found": False,
        "sid_found": True,
        "error": None
    }
