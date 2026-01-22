#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys, json, re, hashlib

def usage():
    print "Usage:"
    print " python AnonymiseID.py source=file.json id=5"
    sys.exit(1)

def parse_args():
    src=None; oid=None
    for a in sys.argv[1:]:
        if a.startswith("source="):
            src=a.split("=",1)[1]
        if a.startswith("id="):
            oid=int(a.split("=",1)[1])
    if not src or oid is None:
        usage()
    return src, oid

# ------------------------------------------------
def is_ip(val):
    return bool(re.match(r'^\d+\.\d+\.\d+\.\d+$', val))

# ------------------------------------------------
class Anonymizer(object):
    def __init__(self):
        self.map={}
        self.counters={
            "HOST":0,"CNAME":0,"SCAN":0,"IP":0
        }

    def _new(self, kind):
        self.counters[kind]+=1
        return "%s_%d" % (kind, self.counters[kind])

    def anonymize_value(self,val):
        if not val: return val

        key = val.lower()

        if key in self.map:
            return self.map[key]

        kind=None

        if is_ip(val):
            kind="IP"
        elif "scan" in key:
            kind="SCAN"
        elif "cname" in key:
            kind="CNAME"
        else:
            kind="HOST"

        new=self._new(kind)
        self.map[key]=new
        return new

# ------------------------------------------------
def anonymize_block(block, anon):
    if not block: return block

    for k in ("host","cname","scan"):
        if k in block and block[k]:
            block[k]=anon.anonymize_value(block[k])
    return block

# ------------------------------------------------
def main():

    src, oid = parse_args()

    data=json.loads(open(src,"rb").read().decode("utf-8"))

    objs=data.get("objects",[])
    target=None

    for o in objs:
        if o.get("id")==oid:
            target=o
            break

    if not target:
        print "ID not found:",oid
        sys.exit(1)

    anon=Anonymizer()

    net=target.get("Network",{})

    for sec in ("Current","New","NewDR","OEM"):
        if sec in net:
            net[sec]=anonymize_block(net[sec],anon)

    target["Network"]=net

    out_file="anonymized_id_%s.json" % oid

    json.dump(
        target,
        open(out_file,"wb"),
        indent=2,
        ensure_ascii=False
    )

    print "Anonymized JSON written to:",out_file

# ------------------------------------------------
if __name__=="__main__":
    main()
