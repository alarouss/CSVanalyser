# tests/test_store.py
# Python 2.6 compatible

import sys, os
sys.path.append("..")

from Lib.store import load_store, save_store, build_index

TMP="test_store.json"

def test_store_cycle():
    data={"objects":[{"id":1},{"id":2}]}
    save_store(TMP,data)

    d=load_store(TMP)
    assert len(d["objects"])==2

    idx=build_index(d)
    assert idx[1]["id"]==1

    os.remove(TMP)

if __name__=="__main__":
    test_store_cycle()
    print "OK store.py"
