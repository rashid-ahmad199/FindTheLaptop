# -*- coding: utf-8 -*-
"""Shared state + helpers for the cleaner. The ITEMS table is the ONLY source of what may be changed:
the web page can only send item ids, never paths or commands."""
import os, sys, re, json, time, shutil, datetime, threading, tempfile, subprocess

BASE = os.path.dirname(os.path.abspath(__file__))
IS_WIN = os.name == "nt"
DRY = (os.environ.get("FTL_DRY") == "1") or (not IS_WIN and os.environ.get("FTL_FORCE_REAL") != "1")   # dry run = nothing is changed
OUT = os.path.join(BASE, "Cleanup")
QUAR = os.path.join(OUT, "Quarantine")
BKP = os.path.join(OUT, "Backups")
STAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

ITEMS, EXPOSURE, ORIGINS = [], [], {}
HOGS = {"system": {}, "top_cpu": [], "top_ram": [], "top_disk": [], "why": []}
LOG, LOG_LOCK = [], threading.Lock()
SCAN_NOTES = []


def clog(msg):
    with LOG_LOCK:
        LOG.append("[%s] %s" % (datetime.datetime.now().strftime("%H:%M:%S"), msg))
    try:
        print("  " + msg)
    except Exception:
        pass


def human(n):
    n = float(n or 0)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or u == "TB":
            return ("%d %s" % (n, u)) if u == "B" else ("%.1f %s" % (n, u))
        n /= 1024


def psq(s):
    """Quote a value for PowerShell single-quoted strings."""
    return "'" + str(s).replace("'", "''") + "'"


def item(group, title, detail, action, params=None, risk="low", checked=False, why="", size=0, origin=""):
    it = {"id": "i%d" % (len(ITEMS) + 1), "group": group, "title": title, "detail": detail, "action": action, "params": params or {},
          "risk": risk, "checked": checked, "why": why, "size": int(size or 0), "origin": origin, "state": "pending", "result": ""}
    ITEMS.append(it)
    return it


def by_id(i):
    for it in ITEMS:
        if it["id"] == i:
            return it
    return None


def FT():
    import findthelaptop as f
    return f


def ps(cmd, timeout=120):
    if not IS_WIN:
        return ""
    return FT().ps(cmd, timeout)


def psj(cmd, timeout=120):
    if not IS_WIN:
        return []
    return FT().psj(cmd, timeout)


def users_dirs():
    out = []
    root = os.path.join(os.environ.get("SystemDrive", "C:") + os.sep, "Users")
    try:
        for n in os.listdir(root):
            p = os.path.join(root, n)
            if os.path.isdir(p) and n.lower() not in ("public", "default", "default user", "all users", "defaultuser0"):
                out.append(p)
    except OSError:
        pass
    return out


def dir_size(path, budget_s=20):
    """Size of a folder in bytes, without following links, with a time budget."""
    t0, total = time.time(), 0
    stack = [path]
    while stack:
        if time.time() - t0 > budget_s:
            break
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                for e in it:
                    try:
                        if e.is_symlink():
                            continue
                        if e.is_dir(follow_symlinks=False):
                            stack.append(e.path)
                        else:
                            total += e.stat(follow_symlinks=False).st_size
                    except OSError:
                        pass
        except OSError:
            pass
    return total


def sha256_file(path, limit=64 * 1024 * 1024):
    import hashlib
    h, n = hashlib.sha256(), 0
    try:
        with open(path, "rb") as f:
            while n < limit:
                b = f.read(1 << 20)
                if not b:
                    break
                h.update(b); n += len(b)
        return h.hexdigest()
    except OSError:
        return ""
