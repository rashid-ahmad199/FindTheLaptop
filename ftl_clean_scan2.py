# -*- coding: utf-8 -*-
"""Exposure scan: every route by which someone can get IN, and every route by which data goes OUT. Plus the fixes (hardening items)."""
import os, re, json, socket, tempfile, shutil, threading, time, glob
import ftl_clean_core as C
from ftl_clean_core import item, clog, human, psq, ps, psj, EXPOSURE, IS_WIN

REMOTE_RE = re.compile(r"(?i)anydesk|teamviewer|ultraviewer|rustdesk|logmein|screenconnect|connectwise|splashtop|ammyy|supremo|radmin|dwservice|meshagent|remotepc|tightvnc|ultravnc|realvnc|winvnc|vncserver")
KNOWN_PORTS = {135: "Windows RPC", 139: "NetBIOS file sharing", 445: "Windows file sharing (SMB)", 3389: "Remote Desktop", 5040: "Windows connected devices", 5357: "Windows device discovery", 5985: "Windows remote management (WinRM)", 7680: "Windows Update sharing",
               22: "SSH remote login", 21: "FTP", 23: "Telnet", 5900: "VNC remote screen", 80: "Web server", 443: "Web server (HTTPS)", 8080: "Web server", 5432: "PostgreSQL", 3306: "MySQL", 1433: "SQL Server", 27017: "MongoDB"}
RISKY_PERMS = {"cookies", "webrequest", "webrequestblocking", "history", "tabs", "clipboardread", "nativemessaging", "debugger", "management", "proxy", "privacy", "downloads"}


def exposure(direction, route, what, evidence, risk, fix="", fix_item=None):
    EXPOSURE.append({"dir": direction, "route": route, "what": what, "evidence": evidence, "risk": risk, "fix": fix, "fix_item": fix_item})


def compile_run(src, lang, libs=(), args=()):
    import ftl_engines as eng
    cc = eng._find_cc(lang)
    if not cc:
        return None
    tmp = tempfile.mkdtemp(prefix="ftl_x_")
    exe = os.path.join(tmp, "x" + (".exe" if IS_WIN else ""))
    cmd = cc + ["-O2", os.path.join(C.BASE, "native", src), "-o", exe] + (["-std=c++17"] if lang == "cpp" else []) + (list(libs) if IS_WIN else [])
    eng.sh(cmd, 240, "C compiler" if lang == "c" else "C++ compiler")
    out = eng.sh([exe] + list(args), 120, "C (native)" if lang == "c" else "C++ (native)") if os.path.exists(exe) else None
    shutil.rmtree(tmp, ignore_errors=True)
    return out


def _rdns(ip, timeout=2.0):
    res = []
    t = threading.Thread(target=lambda: res.append(socket.gethostbyaddr(ip)[0]) if True else None, daemon=True)
    def work():
        try: res.append(socket.gethostbyaddr(ip)[0])
        except Exception: pass
    t = threading.Thread(target=work, daemon=True); t.start(); t.join(timeout)
    return res[0] if res else ""


def chrome_extensions():
    out = []
    bases = []
    for u in C.users_dirs():
        for b in (("AppData", "Local", "Google", "Chrome", "User Data"), ("AppData", "Local", "Microsoft", "Edge", "User Data"), ("AppData", "Local", "BraveSoftware", "Brave-Browser", "User Data")):
            bases.append(os.path.join(u, *b))
    for base in bases:
        for mf in glob.glob(os.path.join(base, "*", "Extensions", "*", "*", "manifest.json")):
            try:
                m = json.load(open(mf, encoding="utf-8", errors="ignore"))
            except Exception:
                continue
            name = str(m.get("name", "?"))
            if name.startswith("__MSG_"):
                key = name[6:-2]
                try:
                    msg = json.load(open(os.path.join(os.path.dirname(mf), "_locales", "en", "messages.json"), encoding="utf-8", errors="ignore"))
                    name = next((v["message"] for k, v in msg.items() if k.lower() == key.lower()), name)
                except Exception:
                    pass
            perms = {str(p).lower() for p in m.get("permissions", []) if isinstance(p, str)}
            hosts = [str(h) for h in (m.get("host_permissions", []) or []) + [p for p in m.get("permissions", []) if isinstance(p, str) and ("://" in p or p == "<all_urls>")]]
            allurls = any(h in ("<all_urls>", "*://*/*", "http://*/*", "https://*/*") for h in hosts)
            risky = sorted(perms & RISKY_PERMS)
            out.append({"name": name[:60], "ver": m.get("version"), "browser": "Edge" if "Edge" in base else "Brave" if "Brave" in base else "Chrome", "all_urls": allurls, "risky": risky})
    seen, uniq = set(), []
    for e in out:
        k = (e["browser"], e["name"])
        if k not in seen: seen.add(k); uniq.append(e)
    return uniq


def scan_exposure():
    try:
        import psutil
    except ImportError:
        psutil = None
    # ---------------- IN: listening ports
    listeners = []
    if psutil:
        try:
            seen = set()
            for c in psutil.net_connections(kind="inet"):
                if c.status != "LISTEN" or not c.laddr: continue
                k = (c.pid, c.laddr.port, c.laddr.ip)
                if k in seen: continue
                seen.add(k)
                try: p = psutil.Process(c.pid); name, exe = p.name(), p.exe()
                except Exception: name, exe = "pid %s" % c.pid, ""
                listeners.append({"port": c.laddr.port, "ip": c.laddr.ip, "name": name, "exe": exe, "pid": c.pid, "open": c.laddr.ip in ("0.0.0.0", "::")})
        except Exception as e:
            C.SCAN_NOTES.append("Listening ports could not be read: %s" % e)
    sigs = {}
    exes = sorted({l["exe"] for l in listeners if l["exe"] and l["open"]})[:60]
    if IS_WIN and exes:
        for s in psj("@(%s) | foreach { $s=Get-AuthenticodeSignature -LiteralPath $_ -ErrorAction SilentlyContinue; [pscustomobject]@{Path=$_;Status=[string]$s.Status} }" % ",".join(psq(e) for e in exes), 180):
            sigs[str(s.get("Path")).lower()] = s.get("Status")
    for l in listeners:
        if not l["open"]: continue
        low = l["exe"].lower(); st = sigs.get(low)
        odd = bool(re.search(r"\\temp\\|\\appdata\\|\\users\\public|\\downloads\\", low))
        known = KNOWN_PORTS.get(l["port"], "")
        risk = "high" if odd or (st in ("NotSigned", "HashMismatch") and not low.startswith("c:\\windows")) else "medium" if l["port"] in (3389, 5900, 23, 21, 445, 139, 5985, 22) else "low"
        exposure("IN", "Open door on port %d" % l["port"], "%s is listening to the whole network%s" % (l["name"], (" (" + known + ")") if known else ""),
                 "%s, signature: %s%s" % (l["exe"] or "unknown program", st or "not checked", "; runs from a risky folder" if odd else ""), risk,
                 "Close the program, or block it in the firewall." if risk != "low" else "Normal for many programs; the firewall decides who may connect.")
    # ---------------- IN: remote-control features
    if IS_WIN:
        import winreg
        def rv(h, p, n):
            try:
                with winreg.OpenKey(h, p, 0, winreg.KEY_READ) as k: return winreg.QueryValueEx(k, n)[0]
            except OSError: return None
        HL, HC = winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER
        if rv(HL, r"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections") == 0:
            it = item("Block the ways in (hardening)", "Turn OFF Remote Desktop", "Anyone who learns a password can log in over the network.", "harden", {"op": "rdp_off"}, "medium", True, "Remote Desktop is a favourite way in for hackers. Undo turns it back on.")
            exposure("IN", "Remote Desktop (port 3389)", "Remote Desktop is switched ON", "Registry: fDenyTSConnections = 0", "high", "Turn it off unless you use it.", it["id"])
        if rv(HL, r"SYSTEM\CurrentControlSet\Control\Terminal Server", "fAllowToGetHelp") == 1:
            exposure("IN", "Remote Assistance", "Remote Assistance invitations are allowed", "Registry: fAllowToGetHelp = 1", "low", "Disable in System Properties > Remote.")
        if rv(HL, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "AutoAdminLogon") in ("1", 1):
            pw = rv(HL, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "DefaultPassword")
            it = item("Block the ways in (hardening)", "Turn off automatic Windows login", "Windows logs in by itself%s." % (" and the PASSWORD IS STORED IN PLAIN TEXT in the registry" if pw else ""), "harden", {"op": "autologon_off"}, "high" if pw else "medium", bool(pw),
                      "Anyone who opens the lid is in. The stored password is removed (you will need to type it at login).")
            exposure("IN", "Automatic login", "Anyone can open the laptop", "AutoAdminLogon = 1%s" % ("; password stored in plain text" if pw else ""), "high" if pw else "medium", "Turn off auto-login.", it["id"])
        p = rv(HC, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings", "ProxyServer")
        if rv(HC, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings", "ProxyEnable") == 1 and p:
            it = item("Block the ways in (hardening)", "Remove the web proxy", "All web traffic goes through %s." % p, "harden", {"op": "proxy_off"}, "high", False, "A proxy you did not set up can read or change everything you browse. Not pre-selected because offices use proxies.")
            exposure("OUT", "Web proxy", "Your browsing is sent through a proxy", p, "high", "Remove it unless your workplace set it.", it["id"])
    fw = psj("Get-NetFirewallProfile | select Name,Enabled,@{n='In';e={[string]$_.DefaultInboundAction}}", 30)
    off = [f.get("Name") for f in fw if f.get("Enabled") in (False, 0, "False")]
    if off:
        it = item("Block the ways in (hardening)", "Turn the firewall ON", "Firewall is OFF for: %s" % ", ".join(map(str, off)), "harden", {"op": "fw_on"}, "high", True, "Without a firewall every open door is reachable.")
        exposure("IN", "Firewall", "Firewall is switched off (%s)" % ", ".join(map(str, off)), "Get-NetFirewallProfile", "high", "Turn it on.", it["id"])
    allow = [f.get("Name") for f in fw if "allow" in str(f.get("In")).lower()]
    if allow:
        it = item("Block the ways in (hardening)", "Block unknown incoming connections", "Default for incoming is ALLOW on: %s" % ", ".join(map(str, allow)), "harden", {"op": "fw_inbound_block"}, "medium", True, "Windows then only lets in programs that have a rule.")
        exposure("IN", "Firewall default", "Incoming connections are allowed by default", ", ".join(map(str, allow)), "medium", "Set default to Block.", it["id"])
    for r in psj("Get-NetFirewallApplicationFilter | where { $_.Program -match 'AppData|\\\\Temp\\\\|Users\\\\Public|Downloads' } | foreach { $r = $_ | Get-NetFirewallRule; if ($r.Enabled -eq 'True' -and $r.Direction -eq 'Inbound' -and $r.Action -eq 'Allow') { [pscustomobject]@{Name=$r.Name;Display=$r.DisplayName;Program=$_.Program} } }", 180):
        if re.match(r"^[\w\-{}. ]+$", str(r.get("Name"))):
            it = item("Block the ways in (hardening)", "Close firewall hole: %s" % r.get("Display"), "Allows incoming connections to %s" % r.get("Program"), "fw_rule_disable", {"name": r.get("Name")}, "high", True, "A rule that lets a program in a user folder accept connections from the network.")
            exposure("IN", "Firewall hole", "%s may accept connections" % os.path.basename(str(r.get("Program"))), str(r.get("Program")), "high", "Disable the rule.", it["id"])
    if str(ps("(Get-SmbServerConfiguration).EnableSMB1Protocol", 20)).strip().lower() == "true":
        it = item("Block the ways in (hardening)", "Turn off old SMBv1 file sharing", "SMBv1 is the hole used by WannaCry-type worms.", "harden", {"op": "smb1_off"}, "high", True, "Nothing modern needs it. Undo re-enables it.")
        exposure("IN", "SMBv1", "The old, wormable file-sharing protocol is on", "EnableSMB1Protocol = True", "high", "Turn it off.", it["id"])
    for s in psj("Get-SmbShare | where { -not $_.Special } | select Name,Path", 20):
        exposure("IN", "Shared folder", "Folder '%s' is shared on the network" % s.get("Name"), str(s.get("Path")), "medium", "Stop sharing in Computer Management if not needed.")
    for svc, op, lab in (("WinRM", "winrm_off", "Windows Remote Management"), ("RemoteRegistry", "remote_registry_off", "Remote Registry")):
        st = ps("(Get-Service %s -ErrorAction SilentlyContinue).Status" % svc, 15).strip()
        if st.lower() == "running":
            it = item("Block the ways in (hardening)", "Turn off %s" % lab, "The %s service is running." % lab, "harden", {"op": op}, "medium", True, "Lets other computers manage/read this PC remotely. Undo sets it to Manual.")
            exposure("IN", lab, "%s service is running" % lab, "Get-Service %s" % svc, "medium", "Turn it off.", it["id"])
    for u in psj("Get-LocalUser | select Name,Enabled,PasswordRequired,@{n='SID';e={[string]$_.SID}}", 20):
        if u.get("Enabled") and str(u.get("SID", "")).endswith("-501"):
            it = item("Block the ways in (hardening)", "Disable the Guest account", "The built-in Guest account is on.", "harden", {"op": "guest_off"}, "medium", True, "A login with no password.")
            exposure("IN", "Guest account", "Guest login is enabled", "Get-LocalUser", "medium", "Disable it.", it["id"])
        elif u.get("Enabled") and u.get("PasswordRequired") is False:
            exposure("IN", "Account without password", "User '%s' needs no password" % u.get("Name"), "PasswordRequired = False", "high", "Set a password: Settings > Accounts > Sign-in options.")
    # remote tools
    names = {l["name"] for l in listeners if REMOTE_RE.search(l["name"] + l["exe"])}
    if psutil:
        for p in psutil.process_iter(["name", "exe"]):
            try:
                if REMOTE_RE.search((p.info["name"] or "") + (p.info["exe"] or "")): names.add(p.info["name"])
            except Exception: pass
    for n in sorted(names):
        exposure("IN", "Remote-control program", "%s is running" % n, "Someone with its access code can see and control this laptop.", "high", "Uninstall it unless you installed it.")
    # BitLocker / theft
    for b in psj("Get-BitLockerVolume -ErrorAction SilentlyContinue | select MountPoint,@{n='P';e={[string]$_.ProtectionStatus}}", 20):
        if str(b.get("P")).lower() in ("off", "0"):
            exposure("OUT", "Stolen laptop", "Drive %s is NOT encrypted" % b.get("MountPoint"), "BitLocker protection off", "medium", "Turn on BitLocker / Device encryption so a thief cannot read your files.")
    cred = ps("cmdkey /list", 20).count("Target:")
    if cred: exposure("OUT", "Saved passwords", "%d saved Windows credentials" % cred, "cmdkey /list", "low", "Review in Control Panel > Credential Manager.")
    # ---------------- OUT: open Wi-Fi + DNS + extensions + live connections
    wl = ps("netsh wlan show profiles", 20)
    names = re.findall(r":\s*(.+)$", "\n".join(l for l in wl.splitlines() if "All User Profile" in l or "Profil" in l), re.M)
    opens = []
    for n in names[:25]:
        n = n.strip()
        if not re.match(r"^[\w .\-]+$", n): continue
        if re.search(r"Authentication\s*:\s*Open", ps('netsh wlan show profile name="%s"' % n, 15)): opens.append(n)
    for n in opens[:6]:
        exposure("OUT", "Open Wi-Fi network", "Saved Wi-Fi '%s' has no password" % n, "Authentication: Open", "medium", "Forget it: anyone nearby can read unprotected traffic and the laptop auto-joins it.")
    for d in psj("Get-DnsClientServerAddress -AddressFamily IPv4 | where { $_.ServerAddresses } | select InterfaceAlias,ServerAddresses", 20):
        for ip in (d.get("ServerAddresses") if isinstance(d.get("ServerAddresses"), list) else [d.get("ServerAddresses")]):
            if ip and ip not in ("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "208.67.222.222", "208.67.220.220") and not re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|fe80)", str(ip)):
                it = item("Block the ways in (hardening)", "Reset DNS servers to automatic", "DNS server %s on %s is unusual." % (ip, d.get("InterfaceAlias")), "harden", {"op": "dns_auto"}, "medium", False, "Malware changes DNS to send you to fake websites. Automatic = your router/provider.")
                exposure("OUT", "DNS server", "Your website lookups go to %s" % ip, str(d.get("InterfaceAlias")), "medium", "Reset to automatic unless you chose it.", it["id"])
    for e in chrome_extensions():
        if e["all_urls"] and e["risky"]:
            exposure("OUT", "Browser extension", "%s (%s %s) can read every site and use %s" % (e["name"], e["browser"], e["ver"], ", ".join(e["risky"][:4])), "Extension permissions", "medium", "Remove it in the browser's Extensions page if you do not need it.")
    if psutil:
        try:
            outs = {}
            for c in psutil.net_connections(kind="inet"):
                if c.status == "ESTABLISHED" and c.raddr and not re.match(r"^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|::1|fe80)", c.raddr.ip):
                    try: p = psutil.Process(c.pid); nm, exe = p.name(), p.exe()
                    except Exception: nm, exe = "pid %s" % c.pid, ""
                    outs.setdefault((nm, exe), []).append((c.raddr.ip, c.raddr.port))
            for (nm, exe), lst in sorted(outs.items(), key=lambda kv: -len(kv[1]))[:25]:
                ip, port = lst[0]
                host = _rdns(ip) if len(outs) < 40 else ""
                odd = bool(re.search(r"\\temp\\|\\appdata\\local\\temp|\\users\\public|\\downloads\\", exe.lower()))
                exposure("OUT", "Live connection", "%s is talking to %d server(s)" % (nm, len(lst)), "e.g. %s:%s%s%s" % (ip, port, (" (" + host + ")") if host else "", "; program runs from a risky folder" if odd else ""), "high" if odd else "low",
                         "Investigate: stop this program." if odd else "")
        except Exception as e:
            C.SCAN_NOTES.append("Connections could not be read: %s" % e)
    # C program cross-check (hidden connections)
    if IS_WIN and psutil:
        raw = compile_run("ports.c", "c", ("-liphlpapi", "-lws2_32"))
        if raw:
            cset = {(int(l.split("|")[3]) if False else l.split("|")[3], l.split("|")[4], l.split("|")[6]) for l in raw.splitlines() if l.startswith("T|") and len(l.split("|")) >= 7 and l.split("|")[5] == "5"}
            pset = set()
            try:
                for c in psutil.net_connections(kind="tcp"):
                    if c.status == "ESTABLISHED" and c.raddr: pset.add((c.raddr.ip, str(c.raddr.port), str(c.pid)))
            except Exception: pass
            hidden = [x for x in cset if x not in pset and x[2] != "0"]
            if len(hidden) > 5:
                exposure("OUT", "Hidden connections", "%d connections seen by the Windows network driver (C program) but not by psutil" % len(hidden), "Can be timing; re-run to confirm. Persistent mismatch can mean a rootkit.", "medium", "Run the Defender offline scan.")
    clog("Exposure paths: %d (in: %d, out: %d)" % (len(EXPOSURE), sum(1 for e in EXPOSURE if e["dir"] == "IN"), sum(1 for e in EXPOSURE if e["dir"] == "OUT")))


def maintenance_items():
    item("Maintenance & reset (optional)", "Update virus definitions", "Download the newest Windows Defender signatures.", "harden", {"op": "defender_update"}, "low", True, "Needed for the scan to know recent malware.")
    item("Maintenance & reset (optional)", "Turn ON all Windows Defender protections", "Real-time, behaviour monitoring, downloaded-file scanning and potentially-unwanted-app blocking.", "harden", {"op": "defender_on"}, "low", False, "Safe. Skip if you use another antivirus.")
    item("Maintenance & reset (optional)", "Windows Defender FULL scan of the whole laptop", "Scans every file. Can take 30 minutes to several hours; you can keep using the PC.", "harden", {"op": "defender_full"}, "low", False, "Finds and removes known malware anywhere on the drive.")
    item("Maintenance & reset (optional)", "Repair Windows system files (sfc /scannow)", "Replaces damaged or modified Windows files from the Windows store. 10-20 minutes.", "harden", {"op": "sfc"}, "low", False, "Safe repair.")
    item("Maintenance & reset (optional)", "Clean the Windows component store", "Removes superseded Windows update files (DISM StartComponentCleanup).", "harden", {"op": "dism_cleanup"}, "low", False, "Safe; frees space.")
    item("Maintenance & reset (optional)", "RESET the network (Winsock + TCP/IP + DNS cache)", "Fixes redirects, odd network drivers and hijacked network settings. A restart is needed afterwards.", "harden", {"op": "network_reset"}, "medium", False, "Wi-Fi passwords are kept; custom static IP settings are reset.")
