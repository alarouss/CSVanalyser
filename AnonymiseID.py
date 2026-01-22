#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys, json, re

def usage():
    print "Usage:"
    print " python AnonymiseID.py source=fic.json id=5"
    sys.exit(1)

def parse_args():
    src=None; oid=None
    for a in sys.argv[1:]:
        if a.startswith("source="):
            src=a.split("=",1)[1]
        elif a.startswith("id="):
            oid=int(a.split("=",1)[1])
    if not src or oid is None:
        usage()
    return src, oid

# --------------------------
IP_RE = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')

# hostname "raisonnable" : au moins un '.' ou '-' et au moins une lettre
HOST_TOKEN_RE = re.compile(r'\b([A-Za-z0-9][A-Za-z0-9\.-]*[A-Za-z][A-Za-z0-9\.-]*)\b')

# JDBC formats
JDBC_AT_RE   = re.compile(r'jdbc:oracle:thin:@([^:/\s]+)', re.I)
HOST_EQ_RE   = re.compile(r'host=([^)]+)', re.I)

def is_probable_host(s):
    if not s:
        return False
    ss = s.strip()
    if len(ss) < 2:
        return False
    # exclude pure numbers
    if re.match(r'^\d+$', ss):
        return False
    # must contain a letter
    if not re.search(r'[A-Za-z]', ss):
        return False
    # host usually contains dot or hyphen (your infra does)
    if ('.' not in ss) and ('-' not in ss):
        return False
    # avoid capturing emails
    if '@' in ss:
        return False
    return True

def safe_decode(b):
    if b is None:
        return u""
    if isinstance(b, unicode):
        return b
    if isinstance(b, str):
        try:
            return b.decode("utf-8","ignore")
        except:
            return b.decode("latin1","ignore")
    try:
        return unicode(b)
    except:
        try:
            return unicode(str(b),"utf-8","ignore")
        except:
            return u""

# --------------------------
class Anonymizer(object):
    def __init__(self):
        self.map = {}      # key(lower) -> replacement
        self.count = {"HOST":0,"IP":0,"SCAN":0,"CNAME":0}

    def _new(self, kind):
        self.count[kind] += 1
        return "%s_%d" % (kind, self.count[kind])

    def classify(self, token):
        t = token.lower()
        if IP_RE.match(token):
            return "IP"
        if "scan" in t:
            return "SCAN"
        if "cname" in t:
            return "CNAME"
        return "HOST"

    def remember(self, token):
        if not token:
            return None
        k = token.strip().lower()
        if not k:
            return None
        if k in self.map:
            return self.map[k]
        kind = self.classify(token)
        rep = self._new(kind)
        self.map[k] = rep
        return rep

    def replace_in_text(self, text):
        if not text:
            return text
        s = safe_decode(text)

        # 1) replace IPs
        def _rip(m):
            ip = m.group(1)
            rep = self.remember(ip)
            return rep or ip
        s = IP_RE.sub(_rip, s)

        # 2) replace known hosts (exact tokens) — on fait 2 passes :
        #    a) extraire tokens probables et les enregistrer si besoin
        #    b) remplacer en respectant les frontières
        tokens = []
        for m in HOST_TOKEN_RE.finditer(s):
            tok = m.group(1)
            if is_probable_host(tok):
                tokens.append(tok)

        for tok in tokens:
            self.remember(tok)

        # remplacer en priorité les tokens plus longs d'abord (évite sous-remplacements)
        keys = sorted(self.map.keys(), key=lambda x: len(x), reverse=True)

        for k in keys:
            rep = self.map[k]
            # remplacement case-insensitive "token exact" avec bornes
            # on reconstitue un regex propre à la clé
            pat = re.compile(r'(?i)\b' + re.escape(k) + r'\b')
            s = pat.sub(rep, s)

        return s

# --------------------------
def extract_candidates_from_string(u, anon):
    """Enregistre dans anon les hosts/IP présents dans une string."""
    s = safe_decode(u)

    # IPs
    for m in IP_RE.finditer(s):
        anon.remember(m.group(1))

    # JDBC: @HOST
    for m in JDBC_AT_RE.finditer(s):
        h = m.group(1).strip()
        if is_probable_host(h):
            anon.remember(h)

    # sqlnet: host=XYZ
    for m in HOST_EQ_RE.finditer(s):
        h = m.group(1).strip()
        if is_probable_host(h):
            anon.remember(h)

    # tokens généraux probables
    for m in HOST_TOKEN_RE.finditer(s):
        tok = m.group(1)
        if is_probable_host(tok):
            anon.remember(tok)

# --------------------------
def walk_collect(obj, anon):
    """Parcourt récursivement et collecte candidats (hosts/IP) dans toutes les strings."""
    if obj is None:
        return
    if isinstance(obj, dict):
        for k,v in obj.items():
            walk_collect(k, anon)
            walk_collect(v, anon)
    elif isinstance(obj, list):
        for x in obj:
            walk_collect(x, anon)
    else:
        # string/unicode -> collect
        if isinstance(obj, (str, unicode)):
            extract_candidates_from_string(obj, anon)

def walk_replace(obj, anon):
    """Parcourt récursivement et remplace dans toutes les strings."""
    if obj is None:
        return obj
    if isinstance(obj, dict):
        out = {}
        for k,v in obj.items():
            nk = walk_replace(k, anon)
            nv = walk_replace(v, anon)
            out[nk] = nv
        return out
    if isinstance(obj, list):
        return [walk_replace(x, anon) for x in obj]
    if isinstance(obj, (str, unicode)):
        return anon.replace_in_text(obj)
    return obj

# --------------------------
def main():
    src, oid = parse_args()

    raw = open(src,"rb").read()
    try:
        data = json.loads(raw.decode("utf-8"))
    except:
        data = json.loads(raw.decode("latin1","ignore"))

    objs = data.get("objects", [])
    target = None
    for o in objs:
        if o.get("id") == oid:
            target = o
            break

    if not target:
        print "ID not found:", oid
        sys.exit(1)

    anon = Anonymizer()

    # 1) collect all candidates in the target object (RawSource + everything)
    walk_collect(target, anon)

    # 2) replace everywhere in the target object
    anon_target = walk_replace(target, anon)

    out_file = "anonymized_id_%s.json" % oid
    json.dump(anon_target, open(out_file,"wb"), indent=2, ensure_ascii=False)

    print "Anonymized JSON written to:", out_file
    print "Replacements:", len(anon.map)

if __name__ == "__main__":
    main()
