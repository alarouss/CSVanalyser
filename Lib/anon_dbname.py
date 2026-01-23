# -*- coding: utf-8 -*-
# Lib/anon_dbname.py
#
# Étape DBNAME :
# - remplace RawSource["Databases"] par DBNAME_<ID>
# - propage la valeur partout dans l'objet
# - aucune autre anonymisation

def apply(obj, oid):
    """
    obj : dict (objet JSON AnalyseV3)
    oid : int (id de l'objet)

    Retourne l'objet modifié (ou inchangé si Databases absent)
    """

    if not isinstance(obj, dict):
        return obj

    raw = obj.get("RawSource")
    if not isinstance(raw, dict):
        return obj

    if "Databases" not in raw:
        return obj

    old_db = raw.get("Databases")
    if not old_db:
        return obj

    new_db = "DBNAME_%d" % oid

    # 1) mise à jour du champ principal
    raw["Databases"] = new_db

    # 2) propagation globale
    def replace_everywhere(node):
        if isinstance(node, dict):
            return dict((k, replace_everywhere(v)) for k, v in node.items())
        if isinstance(node, list):
            return [replace_everywhere(x) for x in node]
        if isinstance(node, basestring):
            return node.replace(old_db, new_db)
        return node

    return replace_everywhere(obj)
