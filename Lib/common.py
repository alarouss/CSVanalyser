# lib/common.py
# -*- coding: utf-8 -*-

import re

ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')

def strip_ansi(s):
    return ANSI_RE.sub('', s or "")

def ustr(v):
    if v is None:
        return u""
    if isinstance(v, unicode):
        return v
    try:
        return unicode(v, "utf-8")
    except:
        return unicode(str(v), "utf-8", "ignore")

def pad(val, width):
    txt = ustr(val)
    visible = strip_ansi(txt)
    return txt + u" " * max(0, width - len(visible))

def trim_lot(val):
    txt = ustr(val)
    return txt[:-7] if len(txt) > 7 else txt
