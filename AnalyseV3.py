#!/usr/bin/env python
# -*- coding: utf-8 -*-
# AnalyseV3.py (base = AnalyseV2 + ajout OEM, sans régression)

import csv
import re
import sys
import subprocess
import json
import time
import os
import tempfile

STORE_FILE = "connexions_store_v2.json"
DEBUG = False

OEM_CONF_FILE = "oem.conf"

RAW_COLUMNS = [
    "Statut Global", "Lot", "Application", "Databases", "DR O/N",
    "Current connection string",
    "New connection string",
    "New connection string avec DR",
    "Cnames", "Services", "Acces", "Cnames DR"
]

# ------------------------------------------------
def print_help():
    print """AnalyseV3.py - Analyse JDBC Oracle V3 (V2 + OEM)

Usage:
 python AnalyseV3.py file.csv ligne=N|ALL [OPTIONS]
 python AnalyseV3.py file.csv id=N [OPTIONS]
 python AnalyseV3.py file.csv id=1,2,5 [OPTIONS]
 python AnalyseV3.py file.csv columns

Options:
 -debug
 -force
 -update
 -h | -help | --help

OEM:
 - Le script lit oem.conf et attend OEM_CONN=...
"""

# ------------------------------------------------
def debug_print(msg):
    if DEBUG:
        try:
            print msg
        except:
            pass

# ------------------------------------------------
def ustr(v):
    if v is None:
        return u""
    if isinstance(v, unicode):
        return v
    if isinstance(v, str):
        try:
            return v.decode("latin1", "ignore")
        except:
            return unicode(v, "latin1", "ignore")
    try:
        return unicode(str(v), "latin1", "ignore")
    except:
        return u""

def normalize_key(k):
    return ustr(k).replace(u'\ufeff', u'').strip()

def normalize_row(row):
    out = {}
    for k, v in row.items():
        out[normalize_key(k)] = ustr(v)
    return out

# ------------------------------------------------
def show_progress(idval, total, step):
    try:
        percent = int((float(idval) / float(total)) * 100) if total else 100
    except:
        percent = 100

    if percent < 0:
        percent = 0
    if percent > 100:
        percent = 100

    dots = int(percent / 2)
    bar = "." * dots

    step_txt = (step or "")[:12]
    label_core = "Id:%5d/%-5d | %-12s" % (int(idval), int(total), step_txt)
    label = "[%-34s]" % label_core

    sys.stdout.write("\rProgress: %s %-50s %3d%%\033[K" % (label, bar, percent))
    sys.stdout.flush()

# ------------------------------------------------
class JdbcChaine(object):
    def __init__(self):
        self.host = None
        self.por
