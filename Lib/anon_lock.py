# -*- coding: utf-8 -*-
# Lib/anon_lock.py
#
# ETAPE 6 – Propagation STRICTE via dictionnaire detecte
# - Detecte des valeurs sensibles (par position / champs)
# - Construit mapping {original -> anonymise}
# - Propagation par .replace UNIQUEMENT (aucune heuristique large)
#
# Python 2.6 compatible

import re

# Detecteurs "par position"
RE_HOST_EQ = re.compile(r'HOST=([^)]+)', re.I)          # HOST=xxxx)
RE_AT_HOST = re.compile(r'@([^:/\s",]+)', re.I)         # @host:  ou @host/
RE_SCAN_EQ = re.compile(r'\bSCAN=([^)]+)', re.I)        # optionnel, si present

def _safe_ustr(x):
    try:
        if x is None:
            return u""
        if isinstance(x, unicode):
            return x
        return unicode(str(x), "utf-8", "ignore")
    except:
        try:
            return unicode(str(x), "latin1", "ignore")
        except:
            return u""

def _collect_strings(node, out_list):
    """
    Collecte toutes les chaines de caracteres dans l'objet (recursif)
    """
    if isinstance(node, dict):
        for v in node.values():
            _collect_strings(v, out_list)
    elif isinstance(node, list):
        for x in node:
            _collect_strings(x, out_list)
    else:
        if isinstance(node, basestring):
            out_list.append(node)

def _detect_hosts_in_text(text):
    """
    Retourne une liste de tokens detectes comme "host logique" par position
    (HOST=..., @...:)
    """
    res = []
    if not isinstance(text, basestring):
        return res

    for m in RE_HOST_EQ.finditer(text):
        tok = m.group(1).strip()
        if tok:
            res.append(tok)

    for m in RE_AT_HOST.finditer(text):
        tok = m.group(1).strip()
        if tok:
            res.append(tok)

    # Optionnel : si tu as des chaines type SCAN=...
    for m in RE_SCAN_EQ.finditer(text):
        tok = m.group(1).strip()
        if tok:
            res.append(tok)

    return res

def _detect_from_object(obj):
    """
    Detection basee sur :
    - champs RawSource (Application, Cnames, Cnames DR, Databases, Services)
    - textes (HOST= / @host)
    - Network/OEM champs host/cname/scan si non anonymises
    """
    detected = {
        "hosts": [],        # tokens host/cname/scan reels (ou manuels) vus
        "apps": [],         # application brute
    }

    # 1) Detection champs RawSource
    raw = obj.get("RawSource")
    if isinstance(raw, dict):
        # Application brute
        app = raw.get("Application")
        if isinstance(app, basestring) and app:
            detected["apps"].append(app)

        # Cnames / Cnames DR (tu veux les inclure comme noms a propager aussi)
        cn = raw.get("Cnames")
        if isinstance(cn, basestring) and cn:
            detected["hosts"].append(cn)

        cndr = raw.get("Cnames DR")
        if isinstance(cndr, basestring) and cndr:
            detected["hosts"].append(cndr)

        # Dans les strings JDBC presentes dans RawSource
        for k, v in raw.items():
            if isinstance(v, basestring):
                detected["hosts"].extend(_detect_hosts_in_text(v))

    # 2) Detection dans Network (host/cname/scan) si present
    net = obj.get("Network")
    if isinstance(net, dict):
        for zone, data in net.items():
            if isinstance(data, dict):
                for kk in ("host", "cname", "scan"):
                    vv = data.get(kk)
                    if isinstance(vv, basestring) and vv:
                        detected["hosts"].append(vv)

    # 3) Detection OEM (si present)
    oem = obj.get("OEM")
    if isinstance(oem, dict):
        for kk in ("host", "cname", "scan"):
            vv = oem.get(kk)
            if isinstance(vv, basestring) and vv:
                detected["hosts"].append(vv)

    # 4) Detection dans Status.ErrorDetail (et autres champs texte)
    st = obj.get("Status")
    if isinstance(st, dict):
        for kk in ("ErrorDetail", "OEMErrorDetail"):
            vv = st.get(kk)
            if isinstance(vv, basestring) and vv:
                detected["hosts"].extend(_detect_hosts_in_text(vv))
                # on garde aussi le texte brut pour d'autres tokens (optionnel)

    # nettoyage doublons en conservant l'ordre
    def uniq(seq):
        seen = {}
        out = []
        for x in seq:
            if not x:
                continue
            if x not in seen:
                seen[x] = 1
                out.append(x)
        return out

    detected["hosts"] = uniq(detected["hosts"])
    detected["apps"] = uniq(detected["apps"])
    return detected

def _build_mapping(detected, oid):
    """
    Construit mapping strict :
    - host tokens -> Host_<ID>_<SEQ>
    - applications brutes -> APP_<ID>
    """
    mapping = {}

    # Application : force APP_ID (meme si plusieurs valeurs detectees)
    for a in detected.get("apps", []):
        mapping[a] = "APP_%d" % oid

    # Hosts : sequence locale a l'objet
    seq = 1
    for h in detected.get("hosts", []):
        # si deja anonymise Host_ID_SEQ, on le garde tel quel (et on ne remappe pas)
        if re.match(r'^Host_%d_\d+$' % oid, h):
            continue
        if h not in mapping:
            mapping[h] = "Host_%d_%d" % (oid, seq)
            seq += 1

    return mapping

def _apply_mapping_text(text, mapping):
    """
    Propagation STRICTE par mapping (replace exact).
    Aucun pattern large.
    """
    if not isinstance(text, basestring):
        return text

    # IMPORTANT: remplacer d'abord les plus longs pour eviter collisions partielles
    items = mapping.items()
    items.sort(key=lambda x: len(_safe_ustr(x[0])), reverse=True)

    out = text
    for src, dst in items:
        if src:
            out = out.replace(src, dst)
    return out

def _apply_mapping_node(node, mapping):
    """
    Applique mapping partout (recursif) sur toutes les chaines.
    """
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            out[k] = _apply_mapping_node(v, mapping)
        return out
    if isinstance(node, list):
        return [_apply_mapping_node(x, mapping) for x in node]
    if isinstance(node, basestring):
        return _apply_mapping_text(node, mapping)
    return node

def apply(obj, oid):
    """
    Point d'entree ETAPE 6.
    Retourne l'objet avec propagation stricte.
    """
    if not isinstance(obj, dict):
        return obj

    detected = _detect_from_object(obj)
    mapping = _build_mapping(detected, oid)

    # Application doit etre forcee meme si champ vide : on ecrase directement si present
    raw = obj.get("RawSource")
    if isinstance(raw, dict):
        raw["Application"] = "APP_%d" % oid

    # Propagation globale par mapping (strict)
    obj2 = _apply_mapping_node(obj, mapping)
    return obj2
