# -*- coding: utf-8 -*-
"""Scanners: junk, space hogs, malware files, persistence, Task Manager hogs, exposure paths. Nothing is changed here."""
import os, re, sys, glob, time, json, socket, datetime, subprocess, tempfile, shutil
import ftl_clean_core as C
from ftl_clean_core import item, clog, human, psq, ps, psj, ITEMS, EXPOSURE, HOGS, IS_WIN

PROTECTED_KILL = {"system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "explorer.exe", "dwm.exe", "registry", "memory compression", "system idle process"}


# ================================================================ 1. junk + space hogs
def junk_targets():
    env = os.environ.get
    win = env("SystemRoot", r"C:\Windows"); local = env("LOCALAPPDATA", ""); pd = env("ProgramData", r"C:\ProgramData")
    T = [("Your temporary files", env("TEMP", ""), "low", True, "Left-over files from installers and programs. Programs recreate what they need."),
         ("Windows temporary files", os.path.join(win, "Temp"), "low", True, "Windows' own scratch folder."),
         ("Windows Update download cache", os.path.join(win, "SoftwareDistribution", "Download"), "low", True, "Already-installed update files. Windows downloads again if needed."),
         ("Delivery Optimization cache", os.path.join(win, "ServiceProfiles", "NetworkService", "AppData", "Local", "Microsoft", "Windows", "DeliveryOptimization", "Cache"), "low", True, "Cached update pieces for sharing with other PCs."),
         ("Crash dump files", os.path.join(win, "Minidump"), "low", True, "Blue-screen memory dumps (useful only for debugging)."),
         ("Windows error-report files", os.path.join(pd, "Microsoft", "Windows", "WER"), "low", True, "Crash reports queued for Microsoft."),
         ("Chrome cache", os.path.join(local, "Google", "Chrome", "User Data", "Default", "Cache"), "low", True, "Web page copies; Chrome rebuilds them. Passwords/cookies are NOT touched."),
         ("Chrome code cache", os.path.join(local, "Google", "Chrome", "User Data", "Default", "Code Cache"), "low", True, "Compiled web code cache."),
         ("Edge cache", os.path.join(local, "Microsoft", "Edge", "User Data", "Default", "Cache"), "low", True, "Web page copies; Edge rebuilds them. Passwords/cookies are NOT touched."),
         ("Edge code cache", os.path.join(local, "Microsoft", "Edge", "User Data", "Default", "Code Cache"), "low", True, "Compiled web code cache."),
         ("Old Windows installation (Windows.old)", os.path.join(os.environ.get("SystemDrive", "C:") + os.sep, "Windows.old"), "medium", False, "Lets you roll back to the previous Windows. Remove only if you will not go back."),
         ("Windows upgrade leftovers ($WINDOWS.~BT)", os.path.join(os.environ.get("SystemDrive", "C:") + os.sep, "$WINDOWS.~BT"), "medium", False, "Leftover files of a Windows upgrade.")]
    for ff in glob.glob(os.path.join(local, "Mozilla", "Firefox", "Profiles", "*", "cache2")):
        T.append(("Firefox cache", ff, "low", True, "Web page copies; Firefox rebuilds them."))
    return T


def scan_junk(targets=None):
    n = 0
    for title, path, risk, checked, why in (targets if targets is not None else junk_targets()):
        if not path or not os.path.isdir(path):
            continue
        size = C.dir_size(path, 25)
        if size < 1024 * 1024:
            continue
        item("Junk files you can remove", title, "%s  (%s)" % (path, human(size)), "delete_path", {"path": path}, risk, checked, why, size)
        n += 1
    rb = os.path.join(os.environ.get("SystemDrive", "C:") + os.sep, "$Recycle.Bin")
    if IS_WIN and os.path.isdir(rb):
        size = C.dir_size(rb, 15)
        if size > 1024 * 1024:
            item("Junk files you can remove", "Recycle Bin", "All drives (%s)" % human(size), "empty_recycle", {}, "low", True, "Files you already deleted. Emptying is permanent.", size); n += 1
    return n


def scan_big_folders(limit=18):
    """Largest folders that are NOT system folders: for the user to review. Never pre-selected."""
    roots = []
    for u in C.users_dirs():
        roots += [os.path.join(u, x) for x in ("Downloads", "Desktop", "Videos", "Documents", "Pictures", "Music")]
        roots += [os.path.join(u, "AppData", "Local"), os.path.join(u, "AppData", "Roaming")]
    roots.append(os.environ.get("ProgramData", r"C:\ProgramData"))
    seen, found, t0 = set(), [], time.time()
    for r in roots:
        if not os.path.isdir(r) or time.time() - t0 > 150:
            continue
        try:
            for name in os.listdir(r):
                p = os.path.join(r, name)
                if os.path.isdir(p) and not os.path.islink(p) and p.lower() not in seen and name.lower() not in ("microsoft", "packages", "temp", "windowsapps"):
                    seen.add(p.lower()); sz = C.dir_size(p, 8)
                    if sz > 300 * 1024 * 1024:
                        found.append((sz, p))
        except OSError:
            pass
    found.sort(reverse=True)
    for sz, p in found[:limit]:
        try:
            age = (time.time() - os.path.getmtime(p)) / 86400
        except OSError:
            age = 0
        item("Big folders to review", os.path.basename(p), "%s  (%s, last changed %d days ago)" % (p, human(sz), age), "recycle_path", {"path": p}, "medium", False,
             "Not selected for you: only tick it if you know you no longer need this folder. It goes to the Recycle Bin first.", sz)
    # large old installers / archives in Downloads
    for u in C.users_dirs():
        d = os.path.join(u, "Downloads")
        try:
            for name in os.listdir(d):
                p = os.path.join(d, name)
                if os.path.isfile(p) and name.lower().endswith((".iso", ".msi", ".exe", ".zip", ".rar", ".7z")) and os.path.getsize(p) > 100 * 1024 * 1024 and (time.time() - os.path.getmtime(p)) > 90 * 86400:
                    item("Big folders to review", "Old download: " + name, "%s  (%s, older than 3 months)" % (p, human(os.path.getsize(p))), "recycle_path", {"path": p}, "medium", False, "An old installer or archive. Sent to the Recycle Bin.", os.path.getsize(p))
        except OSError:
            pass


# ================================================================ 2. malware files
PATTERNS = [(re.compile(rb"Invoke-Mimikatz|sekurlsa::logonpasswords", re.I), "password-stealing tool (Mimikatz)", "high"),
            (re.compile(rb"stratum\+tcp://|--donate-level|cryptonight|xmrig|minerd", re.I), "cryptocurrency miner", "high"),
            (re.compile(rb"powershell[^\r\n]{0,80}-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{60,}", re.I), "hidden encoded PowerShell command", "high"),
            (re.compile(rb"(IEX|Invoke-Expression)\s*\(?\s*\(?New-Object\s+Net\.WebClient", re.I), "downloads and runs code from the internet", "high"),
            (re.compile(rb"FromBase64String\([^)]{0,200}\)[^\r\n]{0,80}(iex|Invoke-Expression)", re.I), "decodes and runs hidden code", "high"),
            (re.compile(rb"mshta(\.exe)?\s+https?://", re.I), "runs a remote script via mshta", "high"),
            (re.compile(rb"vssadmin(\.exe)?\s+delete\s+shadows|wbadmin\s+delete\s+catalog", re.I), "ransomware behaviour (deletes backups)", "high"),
            (re.compile(rb"bcdedit[^\r\n]{0,40}recoveryenabled\s+no", re.I), "ransomware behaviour (disables recovery)", "high"),
            (re.compile(rb"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"), "antivirus test file (EICAR)", "high"),
            (re.compile(rb"powershell[^\r\n]{0,40}-w(indowstyle)?\s+hidden", re.I), "runs PowerShell hidden", "medium"),
            (re.compile(rb"net\s+user\s+\S+\s+\S+\s+/add", re.I), "creates a user account", "medium"),
            (re.compile(rb"schtasks[^\r\n]{0,20}/create", re.I), "creates a scheduled task", "medium"),
            (re.compile(rb"\.onion\b", re.I), "dark-web (.onion) address", "medium")]


def sig_scan(path, limit=4 * 1024 * 1024):
    hits = []
    try:
        with open(path, "rb") as f:
            data = f.read(limit)
    except OSError:
        return hits
    for rx, label, sev in PATTERNS:
        if rx.search(data):
            hits.append((label, sev))
    return hits


def origin_of(path):
    """Where did this file come from? Uses the Zone.Identifier tag Windows puts on downloads."""
    parts = []
    try:
        st = os.stat(path)
        parts.append("created %s" % datetime.datetime.fromtimestamp(st.st_ctime).strftime("%Y-%m-%d %H:%M"))
    except OSError:
        pass
    if IS_WIN:
        try:
            with open(path + ":Zone.Identifier", "r", errors="ignore") as f:
                z = dict(l.strip().split("=", 1) for l in f if "=" in l)
            zid = z.get("ZoneId")
            if z.get("HostUrl"): parts.append("DOWNLOADED FROM " + z["HostUrl"])
            if z.get("ReferrerUrl"): parts.append("via page " + z["ReferrerUrl"])
            if zid == "3" and not z.get("HostUrl"): parts.append("downloaded from the internet")
        except OSError:
            pass
    low = path.lower()
    if "\\downloads\\" in low: parts.append("sits in Downloads (came from a browser, chat app or e-mail)")
    elif "\\temp\\" in low: parts.append("sits in Temp (dropped by an installer, archive or another program)")
    elif "\\startup\\" in low: parts.append("sits in a Startup folder (runs at every login)")
    elif "$recycle.bin" in low: parts.append("hidden in the Recycle Bin")
    elif "\\appdata\\roaming" in low: parts.append("sits in AppData\\Roaming (typical malware hiding place)")
    elif "\\users\\public" in low: parts.append("sits in Public (shared by all users)")
    return "; ".join(parts)


def _native_scan(roots, maxlines=1500):
    import ftl_engines as eng
    cc = eng._find_cc("cpp")
    if not cc:
        return None
    tmp = tempfile.mkdtemp(prefix="ftl_fs_")
    exe = os.path.join(tmp, "filescan" + (".exe" if IS_WIN else ""))
    eng.sh(cc + ["-O2", "-std=c++17", os.path.join(C.BASE, "native", "filescan.cpp"), "-o", exe], 240, "C++ compiler")
    if not os.path.exists(exe):
        return None
    out = eng.sh([exe, str(maxlines)] + roots, 900, "C++ (native)")
    shutil.rmtree(tmp, ignore_errors=True)
    rows = []
    for line in out.splitlines():
        p = line.split("|")
        if p[0] == "F" and len(p) >= 9:
            rows.append({"path": p[1], "size": int(p[2] or 0), "entropy": float(p[5] or 0), "mz": p[6] == "1", "flags": p[7].split(","), "sha": p[8]})
    return rows


def _python_scan(roots, maxfiles=60000):
    """Fallback when no C++ compiler exists: same idea, slower."""
    EX = (".exe", ".dll", ".scr", ".com", ".pif", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".ps1", ".jar")
    DOCS = {"jpg", "jpeg", "png", "gif", "bmp", "pdf", "txt", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "mp3", "mp4", "avi", "mkv", "rtf", "ico", "dat", "tmp", "log", "csv"}
    rows, n = [], 0
    for r in roots:
        for dp, dn, fn in os.walk(r):
            dn[:] = [d for d in dn if d.lower() not in ("node_modules", ".git", "cache", "code cache", "gpucache", "winsxs")]
            for f in fn:
                n += 1
                if n > maxfiles: return rows
                low = f.lower(); p = os.path.join(dp, f); flags = []
                stem, ext = os.path.splitext(low)
                if low.endswith(EX) and os.path.splitext(stem)[1][1:] in DOCS: flags.append("dblext")
                if ext[1:] in DOCS:
                    try:
                        with open(p, "rb") as fh:
                            if fh.read(2) == b"MZ": flags.append("disguised")
                    except OSError: pass
                if low.endswith((".ps1", ".vbs", ".bat", ".cmd", ".js", ".hta")) and re.search(r"\\(temp|downloads|public)\\", p.lower()): flags.append("hot")
                if flags:
                    try: sz = os.path.getsize(p)
                    except OSError: sz = 0
                    rows.append({"path": p, "size": sz, "entropy": 0, "mz": "disguised" in flags, "flags": flags, "sha": C.sha256_file(p)})
    return rows


def scan_malware_files(extra_roots=None):
    roots = []
    for u in C.users_dirs():
        roots += [os.path.join(u, x) for x in ("Downloads", "Desktop", "AppData\\Local\\Temp", "AppData\\Roaming", "AppData\\Local\\Programs", "Documents")]
        roots.append(os.path.join(u, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup"))
    roots += [r"C:\Users\Public", os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Temp"), os.environ.get("ProgramData", r"C:\ProgramData"), r"C:\$Recycle.Bin"]
    roots += list(extra_roots or [])
    roots = [r for r in dict.fromkeys(roots) if os.path.isdir(r)]
    clog("Scanning %d folders with the C++ file scanner..." % len(roots))
    rows = _native_scan(roots)
    if rows is None:
        clog("No C++ compiler: using the slower Python scanner.")
        rows = _python_scan(roots)
    # signature status of candidates (batch, one PowerShell call)
    cand = [r for r in rows if any(f in r["flags"] for f in ("hot", "packed", "hidden")) and r["path"].lower().endswith((".exe", ".dll", ".scr", ".com"))][:250]
    sigs = {}
    if IS_WIN and cand:
        paths = ",".join(psq(r["path"]) for r in cand)
        for s in psj("@(%s) | foreach { $s=Get-AuthenticodeSignature -LiteralPath $_ -ErrorAction SilentlyContinue; [pscustomobject]@{Path=$_;Status=[string]$s.Status} }" % paths, 240):
            sigs[str(s.get("Path")).lower()] = s.get("Status")
    flagged = []
    for r in rows:
        low, fl = r["path"].lower(), r["flags"]
        hits = sig_scan(r["path"]) if r["size"] < 4 * 1024 * 1024 else []
        status = sigs.get(low)
        why, risk = [], "low"
        if "disguised" in fl: why.append("it is really a PROGRAM disguised as a document/picture"); risk = "high"
        if "dblext" in fl: why.append("double extension trick (looks like a document, runs as a program)"); risk = "high"
        if "hidden" in fl: why.append("hidden program file"); risk = "high" if risk != "high" else risk
        for lab, sev in hits:
            why.append("contains: " + lab)
            if sev == "high": risk = "high"
            elif risk == "low": risk = "medium"
        if "packed" in fl and status in (None, "NotSigned", "UnknownError", "HashMismatch", "NotTrusted"):
            why.append("encrypted/packed program (entropy %.1f), %s" % (r["entropy"], "unsigned" if status in (None, "NotSigned") else status))
            if risk == "low": risk = "medium"
        if status == "HashMismatch": why.append("changed after it was signed"); risk = "high"
        if status == "Valid" and risk != "high": continue
        if not why:
            if "hot" in fl and status in ("NotSigned", "UnknownError", None):
                why.append("unsigned program in a risky folder"); risk = "low"
            else:
                continue
        r["risk"], r["why"] = risk, "; ".join(why); flagged.append(r)
    order = {"high": 0, "medium": 1, "low": 2}
    flagged.sort(key=lambda r: (order[r["risk"]], -r["size"]))
    # let Windows Defender judge the worst ones
    confirmed = defender_confirm([r["path"] for r in flagged if r["risk"] == "high"][:15])
    n = 0
    for r in flagged[:120]:
        conf = r["path"].lower() in confirmed
        origin = origin_of(r["path"])
        title = os.path.basename(r["path"])
        item("Malware / suspicious files", title + ("   ☣ CONFIRMED BY DEFENDER" if conf else ""),
             "%s  (%s)  SHA-256 %s" % (r["path"], human(r["size"]), r["sha"][:16] + "…"), "quarantine_file", {"path": r["path"], "sha": r["sha"], "name": title}, "high" if conf else r["risk"],
             conf or r["risk"] == "high", "Why flagged: %s%s" % (r["why"], "; Windows Defender also detected it" if conf else ""), r["size"], origin)
        C.ORIGINS[r["path"]] = origin; n += 1
    clog("Suspicious files: %d (Defender confirmed %d)" % (n, len(confirmed)))
    return n


def defender_confirm(paths):
    """Ask Windows Defender to scan specific files; return the set of paths it flagged."""
    if not IS_WIN or not paths:
        return set()
    t0 = datetime.datetime.now() - datetime.timedelta(seconds=5)
    for p in paths:
        ps("Start-MpScan -ScanType CustomScan -ScanPath %s" % psq(p), 90)
    got = psj("Get-MpThreatDetection | where { $_.InitialDetectionTime -ge (Get-Date).AddMinutes(-30) } | select ThreatID,Resources,ProcessName,@{n='T';e={\"{0:yyyy-MM-dd HH:mm}\" -f $_.InitialDetectionTime}}", 60)
    out = set()
    for g in got:
        res = g.get("Resources") or []
        res = res if isinstance(res, list) else [res]
        for x in res:
            m = re.search(r"file:_(.+)$", str(x))
            if m: out.add(m.group(1).lower())
    return out


def scan_defender_threats():
    thr = psj("Get-MpThreat | select ThreatID,ThreatName,SeverityID,IsActive,@{n='Res';e={($_.Resources | select -First 3) -join ' ; '}}", 60)
    for t in thr:
        item("Malware / suspicious files", "Defender threat: %s" % t.get("ThreatName"), "Known threat on record. Resources: %s" % t.get("Res"), "defender_remove", {"threat": str(t.get("ThreatID"))}, "high", True,
             "Windows Defender identified this as malware%s." % (" and it is still ACTIVE" if t.get("IsActive") else ""), 0, "Detected by Windows Defender")
    return len(thr)


# ================================================================ 3. persistence / hijacks
def scan_persistence(reg):
    n = 0
    for r in reg or []:
        if r["area"].startswith("_") or r["level"] not in ("fail", "warn", "info"): continue
        if r["level"] == "info" and not (r["area"] == "Auto-start"): continue
        act = r.get("act")
        if r["level"] == "info":      # normal start-up programs: optional, never pre-selected
            item("Programs that start with Windows (slows boot)", r["name"], "%s: %s" % (r["key"], r.get("full") or r["data"]), "reg_delete", {"hive": r["hive"], "path": r["path"], "name": r["name"]}, "low", False,
                 "Stops it starting automatically. The program itself is not removed.")
            n += 1; continue
        if act == "reg_delete":
            item("Hidden hijacks & dangerous start-ups", "%s: %s" % (r["area"], r["name"]), "%s\\%s = %s" % (r["key"], r["name"], r["data"]), "reg_delete", {"hive": r["hive"], "path": r["path"], "name": r["name"]}, "high" if r["level"] == "fail" else "medium",
                 r["level"] == "fail", r["why"] + " (value is backed up first; Undo restores it)")
        elif act == "reg_set":
            item("Hidden hijacks & dangerous start-ups", "%s: %s" % (r["area"], r["name"]), "%s\\%s = %s" % (r["key"], r["name"], r["data"]), "reg_set", {"hive": r["hive"], "path": r["path"], "name": r["name"], "value": r.get("default", "")}, "high", True,
                 r["why"] + " It will be set back to the Windows default.")
        elif act == "service":
            item("Hidden hijacks & dangerous start-ups", "Service: %s" % r["key"], r["data"], "service_disable", {"svc": r["svc"], "start": r.get("start", 2)}, "high" if r["level"] == "fail" else "medium", r["level"] == "fail", r["why"] + " It will be stopped and disabled (not deleted).")
        else:
            continue
        n += 1
    # scheduled tasks
    import ftl_engines2 as e2
    for t in psj("Get-ScheduledTask | where {$_.TaskPath -notlike '\\Microsoft\\*'} | foreach { $a=$_.Actions | select -First 1; [pscustomobject]@{Name=$_.TaskName;Path=$_.TaskPath;State=[string]$_.State;Exe=[string]$a.Execute;Args=[string]$a.Arguments} }", 120):
        cmd = ("%s %s" % (t.get("Exe") or "", t.get("Args") or "")).strip()
        if t.get("State") != "Disabled" and (e2.SUSP.search(cmd) or e2.ODD_PATH.search(cmd) or re.search(r"(?i)kms|autopico|miner", t.get("Name") or "")):
            item("Hidden hijacks & dangerous start-ups", "Scheduled task: %s" % t.get("Name"), cmd[:200], "task_remove", {"name": t.get("Name"), "path": t.get("Path")}, "high", True,
                 "A task that runs a hidden/script command or a program from a risky folder. Exported to a backup, then removed."); n += 1
    for w in psj("Get-CimInstance -Namespace root\\subscription -ClassName __EventConsumer | where { $_.Name -ne 'SCM Event Log Consumer' } | select Name,@{n='Class';e={$_.CimClass.CimClassName}}", 60):
        item("Hidden hijacks & dangerous start-ups", "Hidden WMI auto-run: %s" % w.get("Name"), "Type %s" % w.get("Class"), "wmi_remove", {"name": w.get("Name"), "cls": w.get("Class")}, "high", True,
             "Fileless malware hides code in the WMI database. Its definition is saved, then removed."); n += 1
    mp = ps("(Get-MpPreference | select -ExpandProperty ExclusionPath) -join '|'", 30)
    for ex in [x for x in mp.split("|") if x.strip()]:
        item("Hidden hijacks & dangerous start-ups", "Defender exclusion: %s" % ex, "Windows Defender never scans this place.", "exclusion_remove", {"path": ex}, "medium", False,
             "Malware adds itself here to stay invisible. Remove it unless you know why it is there."); n += 1
    # hosts file
    try:
        hp = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "drivers", "etc", "hosts")
        bad = [l.strip() for l in open(hp, errors="ignore") if l.strip() and not l.strip().startswith("#") and re.search(r"(?i)activation|validation\.sls|windowsupdate|update\.microsoft|virustotal|malwarebytes|kaspersky|avast|bitdefender|defender|eset|norton|mcafee|sophos|paypal|google|facebook|bank", l)]
        for l in bad:
            item("Hidden hijacks & dangerous start-ups", "Hosts file line", l, "hosts_line", {"line": l}, "high", True, "Blocks or redirects a website (security / update / bank sites). Hosts file is backed up first."); n += 1
    except OSError:
        pass
    clog("Hijacks / start-up entries: %d" % n)
    return n


# ================================================================ 4. Task Manager hogs
KNOWN = {"msmpeng.exe": ("Windows Defender is scanning files", "Normal during a scan; very high all the time means a big scan or a stuck scan.", True),
         "tiworker.exe": ("Windows Update is installing", "Normal after updates; it ends by itself.", True),
         "trustedinstaller.exe": ("Windows Update service", "Normal during updates.", True),
         "searchindexer.exe": ("Windows Search is indexing files", "High after new files or a reset; usually stops after a while.", True),
         "searchhost.exe": ("Windows Search UI", "Normal.", True), "sysmain": ("SysMain (Superfetch)", "Often makes disks 100% busy on hard drives. Safe to disable on HDDs.", True),
         "compattelrunner.exe": ("Windows telemetry check", "Runs now and then; safe to wait.", True), "wmiprvse.exe": ("WMI service (system monitoring)", "A program is querying hardware info heavily.", True),
         "system": ("Windows kernel", "High usage here usually means a driver or disk problem, or a very busy disk.", False), "onedrive.exe": ("OneDrive syncing", "Syncing many files.", True),
         "chrome.exe": ("Google Chrome tabs/extensions", "Each tab/extension is a process. Close tabs, remove extensions.", True), "msedge.exe": ("Microsoft Edge tabs/extensions", "Each tab is a process.", True), "firefox.exe": ("Firefox tabs", "Each tab is a process.", True),
         "teams.exe": ("Microsoft Teams", "Heavy app.", True), "discord.exe": ("Discord", "Heavy app.", True), "spotify.exe": ("Spotify", "Heavy app.", True)}
MINER = re.compile(r"(?i)xmrig|minerd|nicehash|cpuminer|nbminer|t-rex|phoenixminer|stratum\+tcp|--donate-level|--coin|cryptonight|ethminer|lolminer|\bkawpow\b")


def scan_hogs(seconds=6):
    try:
        import psutil
    except ImportError:
        clog("psutil missing: Task Manager analysis skipped."); return
    procs = {}
    for p in psutil.process_iter(["pid", "name"]):
        try: p.cpu_percent(None); procs[p.pid] = (p, p.io_counters() if hasattr(p, "io_counters") else None)
        except Exception: pass
    psutil.cpu_percent(None); time.sleep(seconds)
    ncpu = psutil.cpu_count() or 1
    rows = []
    svc = {}
    if IS_WIN:
        for s in psj("Get-CimInstance Win32_Service | where { $_.ProcessId -gt 0 } | select Name,DisplayName,ProcessId", 60):
            svc.setdefault(int(s.get("ProcessId") or 0), []).append(s.get("DisplayName") or s.get("Name"))
    for pid, (p, io0) in procs.items():
        try:
            cpu = p.cpu_percent(None) / ncpu; mem = p.memory_info().rss
            io1 = p.io_counters() if io0 else None
            disk = ((io1.read_bytes + io1.write_bytes) - (io0.read_bytes + io0.write_bytes)) / seconds if io1 else 0
            exe = ""
            try: exe = p.exe()
            except Exception: pass
            try: cmd = " ".join(p.cmdline())[:300]
            except Exception: cmd = ""
            rows.append({"pid": pid, "name": p.name(), "cpu": cpu, "mem": mem, "disk": disk, "exe": exe, "cmd": cmd})
        except Exception:
            continue
    cpu_total = psutil.cpu_percent(None) if False else sum(r["cpu"] for r in rows)
    vm = psutil.virtual_memory(); dio = psutil.disk_io_counters()
    HOGS["system"] = {"cpu": round(min(100, cpu_total)), "ram": vm.percent, "ram_total": vm.total, "cores": ncpu}
    # group processes by name (Chrome has dozens)
    grp = {}
    for r in rows:
        g = grp.setdefault(r["name"].lower(), {"name": r["name"], "cpu": 0, "mem": 0, "disk": 0, "n": 0, "exe": r["exe"], "cmd": r["cmd"], "pids": [], "svc": []})
        g["cpu"] += r["cpu"]; g["mem"] += r["mem"]; g["disk"] += r["disk"]; g["n"] += 1; g["pids"].append(r["pid"])
        for s in svc.get(r["pid"], []): g["svc"].append(s)
    def explain(g):
        key = g["name"].lower()
        if MINER.search(g["name"] + " " + g["cmd"]): return ("CRYPTOCURRENCY MINER: using your CPU/GPU to make money for someone else", "high")
        if key in KNOWN: return (KNOWN[key][0] + ". " + KNOWN[key][1], "ok")
        if key == "svchost.exe" and g["svc"]: return ("Windows services inside: " + ", ".join(sorted(set(g["svc"]))[:5]), "ok")
        low = g["exe"].lower()
        if g["exe"] and re.search(r"\\temp\\|\\appdata\\local\\temp|\\users\\public|\\downloads\\|\\\$recycle", low): return ("Runs from a risky folder (%s). Suspicious." % g["exe"], "high")
        if low.startswith(("c:\\windows\\", "c:\\program files")): return ("Installed program / Windows component", "ok")
        return ("Program from %s" % (g["exe"] or "unknown location"), "unknown")
    allg = list(grp.values())
    for g in allg: g["explain"], g["flag"] = explain(g)
    HOGS["top_cpu"] = sorted(allg, key=lambda g: -g["cpu"])[:10]
    HOGS["top_ram"] = sorted(allg, key=lambda g: -g["mem"])[:10]
    HOGS["top_disk"] = sorted(allg, key=lambda g: -g["disk"])[:10]
    why = []
    s = HOGS["system"]
    if s["cpu"] >= 80:
        t = HOGS["top_cpu"][0]; why.append("CPU is %d%% busy. Biggest user: %s (%.0f%%): %s" % (s["cpu"], t["name"], t["cpu"], t["explain"]))
    if s["ram"] >= 85:
        t = HOGS["top_ram"][0]; why.append("RAM is %d%% full. Biggest user: %s (%s in %d process(es)): %s" % (s["ram"], t["name"], human(t["mem"]), t["n"], t["explain"]))
    if HOGS["top_disk"] and HOGS["top_disk"][0]["disk"] > 20 * 1024 * 1024:
        t = HOGS["top_disk"][0]; why.append("Disk is very busy. Biggest user: %s (%s/s): %s" % (t["name"], human(t["disk"]), t["explain"]))
    if not why: why.append("Right now nothing is maxing the PC out (CPU %d%%, RAM %d%%). If Task Manager hits 100%% at other times, run this scan again then." % (s["cpu"], s["ram"]))
    HOGS["why"] = why
    # actions
    for g in allg:
        if g["flag"] == "high":
            safe = g["name"].lower() not in PROTECTED_KILL
            if safe and g["exe"]:
                item("Task Manager: programs eating your PC", "STOP " + g["name"], "%s  (CPU %.0f%%, RAM %s, %d process(es))  %s" % (g["exe"], g["cpu"], human(g["mem"]), g["n"], g["explain"]),
                     "kill_process", {"pids": g["pids"], "exe": g["exe"], "name": g["name"]}, "high", True, "Ends the program now. If it is malware, quarantine its file (see above) so it cannot start again.", g["mem"], g["explain"])
    for g in HOGS["top_cpu"][:4] + HOGS["top_ram"][:4]:
        if g["flag"] in ("ok", "unknown") and (g["cpu"] >= 8 or g["mem"] >= 400 * 1024 * 1024) and g["name"].lower() not in PROTECTED_KILL and g["exe"] and not any(i["params"].get("exe") == g["exe"] for i in ITEMS if i["action"] == "kill_process"):
            if g["name"].lower() in ("msmpeng.exe", "tiworker.exe", "trustedinstaller.exe", "svchost.exe", "searchindexer.exe", "wmiprvse.exe", "msmpeng"): continue
            item("Task Manager: programs eating your PC", "End task: " + g["name"], "CPU %.0f%%, RAM %s, %d process(es). %s" % (g["cpu"], human(g["mem"]), g["n"], g["explain"]), "kill_process",
                 {"pids": g["pids"], "exe": g["exe"], "name": g["name"]}, "low", False, "Closes it now (unsaved work in it is lost). Not selected for you.", g["mem"])
    if IS_WIN and psutil:
        hdd = any(str(d.get("MediaType")).upper() == "HDD" for d in psj("Get-PhysicalDisk | select MediaType", 30))
        if hdd and sum(1 for g in allg if "sysmain" in " ".join(g["svc"]).lower()):
            item("Task Manager: programs eating your PC", "Disable SysMain (Superfetch)", "Makes hard drives 100% busy after boot.", "service_disable", {"svc": "SysMain", "start": 2}, "low", False, "Safe on hard drives. Can be re-enabled by Undo.")
    clog("Task Manager analysis done: CPU %d%%, RAM %d%%" % (s["cpu"], s["ram"]))
