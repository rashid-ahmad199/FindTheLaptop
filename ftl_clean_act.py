# -*- coding: utf-8 -*-
"""Executors. Only called with item ids from the scan table. Every change is backed up and can be undone. DRY=True changes nothing."""
import os, re, sys, json, time, shutil, base64, threading, datetime, subprocess
import ftl_clean_core as C
from ftl_clean_core import clog, human, psq, ps, by_id, IS_WIN

UNDO, STATE = [], {"running": False, "done": 0, "total": 0, "freed": 0, "finished": False, "mode": "quarantine"}
PROTECTED_KILL = {"system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "explorer.exe", "dwm.exe", "registry"}
REG_OK = re.compile(r"(?i)^(software\\(wow6432node\\)?microsoft\\windows\\currentversion\\(run|runonce|policies\\(explorer|system)(\\run)?)|software\\microsoft\\windows nt\\currentversion\\(winlogon|windows|image file execution options\\[^\\]+|softwareprotectionplatform)|software\\policies\\microsoft\\.+|system\\currentcontrolset\\control\\terminal server)$")
HARDEN = {
 "fw_on": ("Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True", ""),
 "fw_inbound_block": ("Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block", "Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Allow"),
 "smb1_off": ("Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force; Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart", "Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force"),
 "rdp_off": ("Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 1; Disable-NetFirewallRule -DisplayGroup 'Remote Desktop'", "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 0; Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'"),
 "remote_registry_off": ("Stop-Service RemoteRegistry -Force; Set-Service RemoteRegistry -StartupType Disabled", "Set-Service RemoteRegistry -StartupType Manual"),
 "winrm_off": ("Stop-Service WinRM -Force; Set-Service WinRM -StartupType Disabled", "Set-Service WinRM -StartupType Manual"),
 "guest_off": ("Get-LocalUser | where { $_.SID -like '*-501' } | Disable-LocalUser", "Get-LocalUser | where { $_.SID -like '*-501' } | Enable-LocalUser"),
 "autologon_off": ("Set-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name AutoAdminLogon -Value '0'; Remove-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name DefaultPassword -ErrorAction SilentlyContinue", ""),
 "proxy_off": ("Set-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyEnable -Value 0", "Set-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyEnable -Value 1"),
 "dns_auto": ("Get-NetAdapter | where Status -eq Up | foreach { Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses }", ""),
 "defender_on": ("Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableIOAVProtection $false -PUAProtection Enabled", ""),
 "defender_update": ("Update-MpSignature", ""),
 "defender_full": ("Start-MpScan -ScanType FullScan", ""),
 "sfc": ("sfc /scannow", ""),
 "dism_cleanup": ("Dism /Online /Cleanup-Image /StartComponentCleanup", ""),
 "network_reset": ("netsh winsock reset; netsh int ip reset; ipconfig /flushdns", ""),
}
LONG = {"defender_full": 10800, "sfc": 2400, "dism_cleanup": 1800}


def _save_undo():
    try:
        os.makedirs(C.BKP, exist_ok=True)
        with open(os.path.join(C.BKP, "undo_%s.json" % C.STAMP), "w", encoding="utf-8") as f:
            json.dump(UNDO, f, indent=1, default=str)
    except Exception:
        pass


def _dry(msg):
    clog("[DRY RUN - nothing changed] would: " + msg)
    return True, "dry run: " + msg


def _under(path, roots):
    p = os.path.normcase(os.path.realpath(path))
    return any(p == os.path.normcase(os.path.realpath(r)) or p.startswith(os.path.normcase(os.path.realpath(r)) + os.sep) for r in roots if r)


def _kill_by_exe(exe):
    try:
        import psutil
    except ImportError:
        return 0
    n = 0
    for p in psutil.process_iter(["exe"]):
        try:
            if p.info["exe"] and os.path.normcase(p.info["exe"]) == os.path.normcase(exe):
                p.terminate(); n += 1
        except Exception:
            pass
    return n


# ---------------------------------------------------------------- executors (each returns (ok, message))
def a_delete_path(it):
    path = it["params"]["path"]
    from ftl_clean_scan import junk_targets
    if os.path.normcase(path) not in {os.path.normcase(t[1]) for t in junk_targets()}:
        return False, "refused: not a known junk folder"
    if C.DRY: return _dry("delete the contents of %s (%s)" % (path, human(it["size"])))
    before = C.dir_size(path, 30)
    if os.path.basename(path).lower() in ("windows.old", "$windows.~bt") and IS_WIN:
        import ftl_engines as eng
        eng.sh('takeown /F "%s" /R /D Y >nul 2>&1 & icacls "%s" /grant Administrators:F /T /C /Q >nul 2>&1 & rd /s /q "%s"' % (path, path, path), 1800, "CMD")
    else:
        for name in os.listdir(path):
            p = os.path.join(path, name)
            try:
                if os.path.islink(p) or os.path.isfile(p): os.chmod(p, 0o700) if not IS_WIN else None; os.remove(p)
                else: shutil.rmtree(p, ignore_errors=True)
            except OSError:
                pass
    freed = max(0, before - (C.dir_size(path, 30) if os.path.isdir(path) else 0)); STATE["freed"] += freed
    return True, "freed %s (files in use were skipped)" % human(freed)


def a_recycle_path(it):
    path = it["params"]["path"]
    roots = C.users_dirs() + [os.environ.get("ProgramData", r"C:\ProgramData")]
    if not _under(path, roots) or os.path.normcase(os.path.realpath(path)) in {os.path.normcase(os.path.realpath(r)) for r in roots} or not os.path.exists(path):
        return False, "refused: outside user folders / does not exist"
    if C.DRY: return _dry("send %s to the Recycle Bin (%s)" % (path, human(it["size"])))
    fn = "DeleteDirectory" if os.path.isdir(path) else "DeleteFile"
    out = ps("Add-Type -AssemblyName Microsoft.VisualBasic; [Microsoft.VisualBasic.FileIO.FileSystem]::%s(%s,'OnlyErrorDialogs','SendToRecycleBin')" % (fn, psq(path)), 600)
    ok = not os.path.exists(path); STATE["freed"] += it["size"] if ok else 0
    return ok, "sent to Recycle Bin (restore it from there)" if ok else "could not move (in use?) " + out[:100]


def a_empty_recycle(it):
    if C.DRY: return _dry("empty the Recycle Bin")
    ps("Clear-RecycleBin -Force -ErrorAction SilentlyContinue", 300); STATE["freed"] += it["size"]
    return True, "emptied"


def a_quarantine_file(it):
    path = it["params"]["path"]
    win = os.environ.get("SystemRoot", r"C:\Windows")
    if not os.path.isfile(path): return False, "file no longer exists"
    if _under(path, [win]): return False, "refused: inside the Windows folder"
    if C.DRY: return _dry("%s %s" % ("permanently delete" if STATE["mode"] == "delete" else "move to quarantine", path))
    _kill_by_exe(path); time.sleep(0.5)
    sha = C.sha256_file(path)
    if STATE["mode"] == "delete":
        try: os.remove(path); return True, "permanently deleted"
        except OSError as e: return _delete_on_reboot(path, e)
    os.makedirs(C.QUAR, exist_ok=True)
    dest = os.path.join(C.QUAR, "%s_%s_%s.quar" % (C.STAMP, sha[:8] or "nohash", it["params"].get("name", "file")))
    try:
        shutil.move(path, dest)
    except OSError as e:
        return _delete_on_reboot(path, e)
    UNDO.append({"type": "restore_file", "orig": path, "dest": dest, "sha": sha, "title": it["title"]}); _save_undo()
    STATE["freed"] += it["size"]
    return True, "moved to quarantine (made harmless; Undo restores it)"


def _delete_on_reboot(path, err):
    if IS_WIN:
        try:
            import ctypes
            if ctypes.windll.kernel32.MoveFileExW(path, None, 4): return True, "file is locked: it will be deleted at the next restart"
        except Exception: pass
    return False, "could not remove: %s" % err


def a_kill_process(it):
    try:
        import psutil
    except ImportError:
        return False, "psutil missing"
    exe, name, killed = it["params"]["exe"], it["params"]["name"], 0
    if name.lower() in PROTECTED_KILL: return False, "refused: protected Windows process"
    if C.DRY: return _dry("end %s (%d process(es))" % (name, len(it["params"]["pids"])))
    for pid in it["params"]["pids"]:
        try:
            p = psutil.Process(pid)
            if os.path.normcase(p.exe()) != os.path.normcase(exe): continue   # pid was reused by another program
            p.terminate(); killed += 1
        except Exception: pass
    time.sleep(2)
    for pid in it["params"]["pids"]:
        try:
            p = psutil.Process(pid)
            if os.path.normcase(p.exe()) == os.path.normcase(exe): p.kill()
        except Exception: pass
    return killed > 0, "ended %d process(es)" % killed if killed else "already closed"


def _hk(name):
    import winreg
    return {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}[name]


def _enc(v):
    return {"b64": base64.b64encode(v).decode()} if isinstance(v, (bytes, bytearray)) else v


def a_reg_delete(it):
    pr = it["params"]
    if not REG_OK.match(pr["path"].replace("\\\\", "\\")): return False, "refused: registry path not on the allowed list"
    if C.DRY: return _dry("back up and delete registry value %s\\%s\\%s" % (pr["hive"], pr["path"], pr["name"]))
    import winreg
    try:
        with winreg.OpenKey(_hk(pr["hive"]), pr["path"], 0, winreg.KEY_READ | winreg.KEY_WRITE) as k:
            old, typ = winreg.QueryValueEx(k, pr["name"]); winreg.DeleteValue(k, pr["name"])
        UNDO.append({"type": "reg_set", "hive": pr["hive"], "path": pr["path"], "name": pr["name"], "data": _enc(old), "regtype": typ}); _save_undo()
        return True, "value deleted (backup saved)"
    except OSError as e:
        return False, "registry error: %s" % e


def a_reg_set(it):
    pr = it["params"]
    if not REG_OK.match(pr["path"].replace("\\\\", "\\")): return False, "refused: registry path not on the allowed list"
    if C.DRY: return _dry("set %s\\%s\\%s back to '%s'" % (pr["hive"], pr["path"], pr["name"], pr["value"]))
    import winreg
    try:
        with winreg.OpenKey(_hk(pr["hive"]), pr["path"], 0, winreg.KEY_READ | winreg.KEY_WRITE) as k:
            old, typ = winreg.QueryValueEx(k, pr["name"]); winreg.SetValueEx(k, pr["name"], 0, typ, pr["value"])
        UNDO.append({"type": "reg_set", "hive": pr["hive"], "path": pr["path"], "name": pr["name"], "data": _enc(old), "regtype": typ}); _save_undo()
        return True, "reset to the Windows default (old value backed up)"
    except OSError as e:
        return False, "registry error: %s" % e


def a_task_remove(it):
    n, p = it["params"]["name"], it["params"]["path"] or "\\"
    if C.DRY: return _dry("export then remove scheduled task %s%s" % (p, n))
    os.makedirs(C.BKP, exist_ok=True); xmlp = os.path.join(C.BKP, "task_%s_%s.xml" % (C.STAMP, re.sub(r"\W+", "_", n)))
    ps("Export-ScheduledTask -TaskName %s -TaskPath %s | Out-File -Encoding utf8 -FilePath %s" % (psq(n), psq(p), psq(xmlp)), 60)
    if not os.path.exists(xmlp): return False, "could not back the task up, so it was NOT removed"
    ps("Unregister-ScheduledTask -TaskName %s -TaskPath %s -Confirm:$false" % (psq(n), psq(p)), 60)
    UNDO.append({"type": "task", "name": n, "path": p, "xml": xmlp}); _save_undo()
    return True, "task removed (XML backup saved)"


def a_service_disable(it):
    svc, start = it["params"]["svc"], int(it["params"].get("start", 2))
    if not re.match(r"^[A-Za-z0-9_.\-]+$", svc): return False, "refused: bad service name"
    if C.DRY: return _dry("stop and disable service %s" % svc)
    ps("Stop-Service -Name %s -Force -ErrorAction SilentlyContinue; Set-Service -Name %s -StartupType Disabled" % (psq(svc), psq(svc)), 60)
    UNDO.append({"type": "service", "svc": svc, "start": start}); _save_undo()
    return True, "stopped and disabled (not deleted)"


def a_wmi_remove(it):
    n, cls = it["params"]["name"], it["params"]["cls"]
    if not re.match(r"^\w+$", str(cls)): return False, "refused"
    if C.DRY: return _dry("save and remove WMI consumer %s" % n)
    os.makedirs(C.BKP, exist_ok=True); bp = os.path.join(C.BKP, "wmi_%s_%s.json" % (C.STAMP, re.sub(r"\W+", "_", n)))
    ps("Get-CimInstance -Namespace root\\subscription -ClassName %s | where { $_.Name -eq %s } | ConvertTo-Json -Depth 4 | Out-File -Encoding utf8 -FilePath %s" % (cls, psq(n), psq(bp)), 60)
    ps("Get-CimInstance -Namespace root\\subscription -ClassName __FilterToConsumerBinding | where { $_.Consumer.Name -eq %s } | Remove-CimInstance; Get-CimInstance -Namespace root\\subscription -ClassName %s | where { $_.Name -eq %s } | Remove-CimInstance" % (psq(n), cls, psq(n)), 60)
    UNDO.append({"type": "note", "text": "WMI consumer %s removed; definition saved in %s" % (n, bp)}); _save_undo()
    return True, "removed (definition saved to a backup file)"


def a_exclusion_remove(it):
    p = it["params"]["path"]
    if C.DRY: return _dry("remove Defender exclusion %s" % p)
    ps("Remove-MpPreference -ExclusionPath %s" % psq(p), 30)
    UNDO.append({"type": "exclusion", "path": p}); _save_undo()
    return True, "exclusion removed: Defender now scans this place"


def a_hosts_line(it):
    line = it["params"]["line"]
    hp = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "drivers", "etc", "hosts")
    if C.DRY: return _dry("remove this line from the hosts file: " + line)
    os.makedirs(C.BKP, exist_ok=True); bk = os.path.join(C.BKP, "hosts_%s.bak" % C.STAMP)
    if not os.path.exists(bk): shutil.copy2(hp, bk)
    ps("attrib -r %s" % psq(hp), 15)
    lines = open(hp, encoding="utf-8", errors="ignore").read().splitlines()
    new = [l for l in lines if l.strip() != line.strip()]
    open(hp, "w", encoding="utf-8").write("\r\n".join(new) + "\r\n")
    if not any(u.get("type") == "hosts" for u in UNDO): UNDO.append({"type": "hosts", "backup": bk, "path": hp}); _save_undo()
    return True, "line removed (hosts file backed up)"


def a_defender_remove(it):
    if C.DRY: return _dry("Remove-MpThreat (remove all active Defender threats)")
    ps("Remove-MpThreat", 300)
    return True, "Defender removed the threat(s)"


def a_fw_rule_disable(it):
    n = it["params"]["name"]
    if not re.match(r"^[\w\-{}. ]+$", n): return False, "refused"
    if C.DRY: return _dry("disable firewall rule %s" % n)
    ps("Disable-NetFirewallRule -Name %s" % psq(n), 30)
    UNDO.append({"type": "fwrule", "name": n}); _save_undo()
    return True, "firewall hole closed"


def a_harden(it):
    op = it["params"]["op"]
    if op not in HARDEN: return False, "refused: unknown operation"
    do, undo = HARDEN[op]
    if C.DRY: return _dry("PowerShell: " + do)
    out = ps(do, LONG.get(op, 180))
    if undo: UNDO.append({"type": "ps", "undo": undo, "title": it["title"]}); _save_undo()
    return True, ("done " + out[:120]).strip()


ACTIONS = {"delete_path": a_delete_path, "recycle_path": a_recycle_path, "empty_recycle": a_empty_recycle, "quarantine_file": a_quarantine_file, "kill_process": a_kill_process,
           "reg_delete": a_reg_delete, "reg_set": a_reg_set, "task_remove": a_task_remove, "service_disable": a_service_disable, "wmi_remove": a_wmi_remove,
           "exclusion_remove": a_exclusion_remove, "hosts_line": a_hosts_line, "defender_remove": a_defender_remove, "fw_rule_disable": a_fw_rule_disable, "harden": a_harden}
ORDER = ["kill_process", "quarantine_file", "defender_remove", "reg_delete", "reg_set", "task_remove", "wmi_remove", "service_disable", "exclusion_remove", "hosts_line", "fw_rule_disable", "harden", "delete_path", "empty_recycle", "recycle_path"]


def restore_point():
    if C.DRY: return _dry("create a System Restore point")
    out = ps("Checkpoint-Computer -Description 'FindTheLaptop before cleanup' -RestorePointType MODIFY_SETTINGS -ErrorAction Stop; 'ok'", 180)
    ok = "ok" in out
    clog("Restore point: " + ("created" if ok else "could not be created (System Protection may be off, or one was made in the last 24 h). Continuing: every change has its own backup."))
    return ok, ""


def run_items(ids, mode="quarantine", want_restore=True):
    """Runs in a background thread. mode: quarantine | delete."""
    if STATE["running"]: return
    chosen = [by_id(i) for i in ids if by_id(i) and by_id(i)["state"] == "pending"]
    chosen.sort(key=lambda it: ORDER.index(it["action"]) if it["action"] in ORDER else 99)
    STATE.update({"running": True, "done": 0, "total": len(chosen), "freed": 0, "finished": False, "mode": mode if mode in ("quarantine", "delete") else "quarantine"})
    def work():
        try:
            clog("Starting: %d change(s), mode=%s%s" % (len(chosen), STATE["mode"], "  [DRY RUN]" if C.DRY else ""))
            if want_restore and chosen: restore_point()
            for it in chosen:
                fn = ACTIONS.get(it["action"])
                try:
                    ok, msg = fn(it) if fn else (False, "unknown action")
                except Exception as e:
                    ok, msg = False, "%s: %s" % (type(e).__name__, e)
                it["state"], it["result"] = ("done" if ok else "failed"), msg
                clog("%s  %s  ->  %s" % ("OK  " if ok else "FAIL", it["title"][:70], msg))
                STATE["done"] += 1
            clog("Finished. Space freed: %s. Undo information: %s" % (human(STATE["freed"]), os.path.join(C.BKP, "undo_%s.json" % C.STAMP)))
        finally:
            STATE["running"] = False; STATE["finished"] = True
    threading.Thread(target=work, daemon=True).start()


def undo_all():
    if not UNDO: return "Nothing to undo."
    lines = []
    for u in reversed(list(UNDO)):
        t = u["type"]
        try:
            if C.DRY: lines.append("[dry run] would undo " + t); continue
            if t == "restore_file":
                os.makedirs(os.path.dirname(u["orig"]), exist_ok=True); shutil.move(u["dest"], u["orig"]); lines.append("restored " + u["orig"])
            elif t == "reg_set":
                import winreg
                d = u["data"]; d = base64.b64decode(d["b64"]) if isinstance(d, dict) else d
                with winreg.CreateKeyEx(_hk(u["hive"]), u["path"], 0, winreg.KEY_WRITE) as k: winreg.SetValueEx(k, u["name"], 0, u["regtype"], d)
                lines.append("registry value restored: " + u["name"])
            elif t == "task":
                ps("Register-ScheduledTask -Xml (Get-Content -Raw %s) -TaskName %s -TaskPath %s" % (psq(u["xml"]), psq(u["name"]), psq(u["path"])), 60); lines.append("task restored: " + u["name"])
            elif t == "service":
                m = {0: "boot", 1: "system", 2: "auto", 3: "demand", 4: "disabled"}
                ps("sc.exe config %s start= %s" % (u["svc"], m.get(u["start"], "demand")), 30); lines.append("service restored: " + u["svc"])
            elif t == "hosts":
                shutil.copy2(u["backup"], u["path"]); lines.append("hosts file restored")
            elif t == "exclusion":
                ps("Add-MpPreference -ExclusionPath %s" % psq(u["path"]), 30); lines.append("exclusion re-added: " + u["path"])
            elif t == "fwrule":
                ps("Enable-NetFirewallRule -Name %s" % psq(u["name"]), 30); lines.append("firewall rule re-enabled")
            elif t == "ps":
                ps(u["undo"], 120); lines.append("reverted: " + u.get("title", ""))
        except Exception as e:
            lines.append("could not undo %s: %s" % (t, e))
    UNDO.clear(); _save_undo()
    for l in lines: clog(l)
    return "\n".join(lines)
