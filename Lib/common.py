# -*- coding: utf-8 -*-
# Lib/common.py

import re
import textwrap

# ================= ANSI =================

RED    = u"\033[31m"
GREEN  = u"\033[32m"
YELLOW = u"\033[33m"
RESET  = u"\033[0m"

ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')

# ================= STRING =================

def strip_ansi(s):
    return ANSI_RE.sub('', s or "")


def ustr(v):
    if v is None:
        return u""
    if isinstance(v, unicode):
        return v
    for enc in ("utf-8", "latin1", "cp1252"):
        try:
            return unicode(v, enc)
        except:
            pass
    try:
        return unicode(str(v), "utf-8", "ignore")
    except:
        return u""

def pad(val, width):
    txt = ustr(val)
    visible = strip_ansi(txt)
    return txt + u" " * max(0, width - len(visible))

def trim_lot(val):
    txt = ustr(val)
    return txt[:-7] if len(txt) > 7 else txt

# ================= PRINT HELPERS =================

def print_section(title):
    print (u"\n" + ustr(title)).encode("utf-8")

def print_table(rows, key_width=24, value_width=60):
    header = u" %-*s | %s" % (key_width, u"Key", u"Value")
    print header.encode("utf-8")
    print (u" " + u"-"*key_width + u"-+-" + u"-"*value_width).encode("utf-8")

    for k,v in rows:
        txt = ustr(v)
        wrapped = textwrap.wrap(txt, value_width) or [u""]
        print (u" %-*s | %s" % (key_width, ustr(k), wrapped[0])).encode("utf-8")
        for l in wrapped[1:]:
            print (u" %-*s | %s" % (key_width, u"", l)).encode("utf-8")
