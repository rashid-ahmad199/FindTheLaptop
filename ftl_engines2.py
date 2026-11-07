# -*- coding: utf-8 -*-
"""
Find the Laptop - engines v3: authenticity / fake-data detection, registry scan, camera, clock, VBScript.
All read-only (the only change is a temporary speaker un-mute for the sound test, restored afterwards).
"""
import os, re, sys, time, datetime, struct
import ftl_engines as eng

IS_WIN = os.name == "nt"


# ================================================================ raw SMBIOS (firmware table, bypasses WMI and the registry)
def parse_smbios(raw):
    """raw = SMBIOS structure table bytes. Returns dict of what the firmware itself says."""
    out = {"bios": {}, "system": {}, "board": {}, "chassis": {}, "cpu": [], "mem": [], "battery": []}
    n, i = len(raw), 0

    def strings(start, length):
        j, strs = start + length, []
        if j + 1 < n and raw[j] == 0 and raw[j + 1] == 0:
            return strs, j + 2
        while j < n and raw[j] != 0:
            k = raw.find(b"\x00", j)
            k = n if k < 0 else k
            strs.append(raw[j:k].decode("latin-1", "replace").strip()); j = k + 1
        return strs, j + 1

    guard = 0
    while i + 4 <= n and guard < 5000:
        guard += 1
        t, l = raw[i], raw[i + 1]
        if l < 4 or i + l > n:
            break
        strs, nxt = strings(i, l)
        data = raw[i:i + l]
        S = lambda idx: strs[idx - 1] if 1 <= idx <= len(strs) else ""
        B = lambda off: data[off] if off < l else 0
        W = lambda off: int.from_bytes(data[off:off + 2], "little") if off + 2 <= l else 0
        D = lambda off: int.from_bytes(data[off:off + 4], "little") if off + 4 <= l else 0
        if t == 0:
            out["bios"] = {"vendor": S(B(4)), "version": S(B(5)), "date": S(B(8))}
        elif t == 1:
            u = data[8:24] if l >= 24 else b""
            out["system"] = {"manufacturer": S(B(4)), "product": S(B(5)), "version": S(B(6)), "serial": S(B(7)), "uuid": u.hex()}
        elif t == 2 and not out["board"]:
            out["board"] = {"manufacturer": S(B(4)), "product": S(B(5)), "version": S(B(6)), "serial": S(B(7))}
        elif t == 3 and not out["chassis"]:
            out["chassis"] = {"type": B(5) & 0x7F, "serial": S(B(7))}
        elif t == 4:
            out["cpu"].append({"socket": S(B(4)), "version": S(B(0x10)), "max_mhz": W(0x14), "cur_mhz": W(0x16), "cores": B(0x23), "threads": B(0x25)})
        elif t == 17:
            w = W(0x0C)
            if w not in (0, 0xFFFF):
                size = D(0x1C) if w == 0x7FFF else ((w & 0x7FFF) / 1024 if w & 0x8000 else w)
                out["mem"].append({"slot": S(B(0x10)), "mb": int(size), "mhz": W(0x15), "cfg_mhz": W(0x20), "maker": S(B(0x17)), "part": S(B(0x1A)), "serial": S(B(0x18))})
        elif t == 22:
            mult = B(0x15) or 1
            sb = W(0x12)
            sbds = "%04d-%02d-%02d" % (1980 + (sb >> 9), (sb >> 5) & 15, sb & 31) if sb else ""
            out["battery"].append({"maker": S(B(5)), "name": S(B(8)), "date": S(B(6)) or sbds, "serial": S(B(7)), "design_mwh": W(0x0A) * mult, "volt_mv": W(0x0C)})
        if t == 127:
            break
        i = nxt
    return out


def read_smbios():
    if not IS_WIN:
        return {}
    import ctypes
    t = time.time()
    try:
        k = ctypes.windll.kernel32
        sig = 0x52534D42  # 'RSMB'
        size = k.GetSystemFirmwareTable(sig, 0, None, 0)
        if not size:
            eng.log("Python/ctypes", "GetSystemFirmwareTable(RSMB)", time.time() - t, False, "no data")
            return {}
        buf = ctypes.create_string_buffer(size)
        k.GetSystemFirmwareTable(sig, 0, buf, size)
        d = buf.raw
        length = int.from_bytes(d[4:8], "little")
        res = parse_smbios(d[8:8 + length]); res["version"] = "%d.%d" % (d[1], d[2])
        eng.log("Python/ctypes", "GetSystemFirmwareTable(RSMB) raw SMBIOS", time.time() - t, True)
        return res
    except Exception as e:
        eng.log("Python/ctypes", "GetSystemFirmwareTable(RSMB)", time.time() - t, False, type(e).__name__)
        return {}


# ================================================================ registry scan (stdlib winreg)
SUSP = re.compile(r"(?i)\\temp\\|appdata\\local\\temp|\\downloads\\|\\users\\public\\|powershell.+(-enc|-w\s*hidden|-windowstyle\s+hidden)|mshta|wscript|cscript|\.vbs\b|\.js\b|\.hta\b|rundll32.+(javascript|http)|cmd(\.exe)?\s+/c\s+start|regsvr32.+(http|scrobj)|bitsadmin")
PUBLIC_DNS = ("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220")


def eng_registry():
    """Returns list of {area, key, name, data, level (ok|info|warn|fail), why}."""
    if not IS_WIN:
        return []
    import winreg
    t = time.time(); R = []

    def add(area, key, name, data, level, why="", **kw):
        d = {"area": area, "key": key, "name": str(name), "data": str(data)[:200], "level": level, "why": why}
        d.update(kw); R.append(d)

    def get(hive, path, name, view=0):
        try:
            with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | view) as k:
                return winreg.QueryValueEx(k, name)[0]
        except OSError:
            return None

    def values(hive, path, view=0):
        try:
            with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | view) as k:
                i = 0
                while True:
                    try:
                        n, v, _ = winreg.EnumValue(k, i); i += 1; yield n, v
                    except OSError:
                        break
        except OSError:
            return

    def subkeys(hive, path, view=0):
        try:
            with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | view) as k:
                i = 0
                while True:
                    try:
                        yield winreg.EnumKey(k, i); i += 1
                    except OSError:
                        break
        except OSError:
            return

    HL, HC = winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER
    # 1. auto-start keys
    runs = [(HL, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"), (HL, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
            (HC, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"), (HC, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
            (HL, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM Run (32-bit)"), (HL, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "HKLM Policies Run"),
            (HC, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "HKCU Policies Run")]
    for h, p, lab in runs:
        for n, v in values(h, p):
            bad = bool(SUSP.search(str(v)))
            add("Auto-start", lab, n, v, "fail" if bad else "info", "Starts from a risky place or with a hidden script/command." if bad else "",
                hive="HKLM" if h == HL else "HKCU", path=p, act="reg_delete", full=str(v))
    # 2. Windows logon hijack
    wl = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    sh = get(HL, wl, "Shell"); ui = get(HL, wl, "Userinit")
    if sh is not None and str(sh).strip().lower() != "explorer.exe": add("Logon hijack", "Winlogon", "Shell", sh, "fail", "Should be exactly 'explorer.exe'. Anything else can run malware at every login.", hive="HKLM", path=wl, act="reg_set", default="explorer.exe")
    if ui is not None and str(ui).strip().lower().rstrip(",") not in (r"c:\windows\system32\userinit.exe", r"c:\windows\system32\userinit.exe"):
        add("Logon hijack", "Winlogon", "Userinit", ui, "fail", "Should be only C:\\Windows\\system32\\userinit.exe,", hive="HKLM", path=wl, act="reg_set", default="C:\\Windows\\system32\\userinit.exe,")
    # 3. Image File Execution Options debugger hijack
    ifeo = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    for sk in subkeys(HL, ifeo):
        dbg = get(HL, ifeo + "\\" + sk, "Debugger")
        if dbg: add("Program hijack", "IFEO\\" + sk, "Debugger", dbg, "fail", "When %s starts, Windows runs this instead. Classic malware trick." % sk, hive="HKLM", path=ifeo + "\\" + sk, act="reg_delete")
    # 4. AppInit DLLs
    ai = get(HL, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs")
    if ai and str(ai).strip(): add("DLL injection", "Windows", "AppInit_DLLs", ai, "fail", "A DLL is loaded into every program. Normally empty.", hive="HKLM", path=r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", act="reg_set", default="")
    # 5. boot execute
    be = get(HL, r"SYSTEM\CurrentControlSet\Control\Session Manager", "BootExecute")
    if be and any("autochk" not in str(x).lower() for x in (be if isinstance(be, list) else [be])): add("Boot", "Session Manager", "BootExecute", be, "fail", "Should only be 'autocheck autochk *'.")
    # 6. security switches turned off
    chk = [(HC, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "DisableTaskMgr", "Task Manager disabled", "fail"),
           (HC, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "DisableRegistryTools", "Registry Editor disabled", "fail"),
           (HC, r"SOFTWARE\Policies\Microsoft\Windows\System", "DisableCMD", "Command Prompt disabled", "warn"),
           (HL, r"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware", "Defender switched off by policy", "fail"),
           (HL, r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring", "Defender real-time switched off by policy", "fail"),
           (HL, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", "User Account Control is OFF", "fail", 0),
           (HL, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin", "Admin actions run with no prompt", "warn", 0),
           (HL, r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate", "Windows Update switched off by policy", "warn"),
           (HL, r"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen", "SmartScreen switched off", "warn", 0),
           (HL, r"SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile", "EnableFirewall", "Firewall switched off by policy", "warn", 0)]
    for c in chk:
        h, p, nme, why, lvl = c[:5]; bad_val = c[5] if len(c) > 5 else 1
        v = get(h, p, nme)
        if v is not None and int(v) == bad_val: add("Security switch", p.split("\\")[-1], nme, v, lvl, why, hive="HKCU" if h == HC else "HKLM", path=p, act="reg_delete")
    # 7. Windows activation (KMS)
    spp = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform"
    kms = get(HL, spp, "KeyManagementServiceName")
    if kms: add("Activation", "SoftwareProtectionPlatform", "KeyManagementServiceName", kms, "warn", "Windows is told to activate against this server. At home this is almost always an illegal 'KMS activator'.", hive="HKLM", path=spp, act="reg_delete")
    # 8. services / drivers started from strange places
    for sk in subkeys(HL, r"SYSTEM\CurrentControlSet\Services"):
        p = r"SYSTEM\CurrentControlSet\Services\\" + sk
        ip, st, ty = get(HL, p, "ImagePath"), get(HL, p, "Start"), get(HL, p, "Type")
        if ip and st is not None and int(st) <= 2:
            s = str(ip).lower()
            if re.search(r"\\temp\\|\\appdata\\|\\users\\public\\|\\downloads\\", s): add("Service", sk, "ImagePath", ip, "fail", "A service that starts automatically from Temp/AppData.", act="service", svc=sk, start=int(st))
            elif ty is not None and int(ty) in (1, 2) and "\\drivers\\" not in s and "system32" not in s and "\\windows\\" not in s and "\\program files" not in s:
                add("Driver", sk, "ImagePath", ip, "warn", "A kernel driver loading from an unusual place.", act="service", svc=sk, start=int(st))
    # 9. DNS servers
    for sk in subkeys(HL, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"):
        ns = get(HL, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\\" + sk, "NameServer")
        for ip in re.split(r"[ ,]+", str(ns or "")):
            if ip and ip not in PUBLIC_DNS and not re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)", ip):
                add("Internet", "DNS server", sk[:12], ip, "warn", "A DNS server nobody normally uses. Malware changes DNS to redirect websites.")
    # 10. identity values the BIOS wrote at boot (editable by spoofing tools) - used for cross-checking
    ident = {}
    for n in ("SystemManufacturer", "SystemProductName", "BIOSVendor", "BIOSVersion", "BIOSReleaseDate", "BaseBoardManufacturer", "BaseBoardProduct", "SystemSKU"):
        v = get(HL, r"HARDWARE\DESCRIPTION\System\BIOS", n)
        if v is not None: ident[n] = str(v)
    R.append({"area": "_identity", "key": "BIOS", "name": "", "data": ident, "level": "ok", "why": ""})
    # 11. install date
    idt = get(HL, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "InstallDate")
    if idt: R.append({"area": "_installdate", "key": "", "name": "", "data": int(idt), "level": "ok", "why": ""})
    eng.log("Python/winreg", "Run keys, Winlogon, IFEO, AppInit, policies, KMS, services, DNS", time.time() - t, True)
    return R


# ================================================================ clock tampering
def eng_clock():
    import urllib.request, email.utils
    t = time.time()
    for url in ("https://www.google.com", "https://www.microsoft.com", "https://www.cloudflare.com"):
        try:
            r = urllib.request.urlopen(urllib.request.Request(url, method="HEAD"), timeout=6)
            d = email.utils.parsedate_to_datetime(r.headers["Date"])
            drift = (datetime.datetime.now(datetime.timezone.utc) - d).total_seconds()
            eng.log("Python", "clock check against %s" % url.split("//")[1], time.time() - t, True)
            return {"drift_s": round(drift, 1), "source": url.split("//")[1]}
        except Exception:
            continue
    eng.log("Python", "clock check (offline)", time.time() - t, False, "offline")
    return {"offline": True}


# ================================================================ camera (OpenCV)
def eng_camera(mods):
    cv2 = mods.get("cv2")
    if not cv2:
        return {"skipped": "opencv not installed"}
    t = time.time()
    try:
        for idx in range(3):
            cap = cv2.VideoCapture(idx, cv2.CAP_DSHOW) if IS_WIN else cv2.VideoCapture(idx)
            if not cap.isOpened():
                cap.release(); continue
            frame = None
            for _ in range(15):          # let auto-exposure settle
                ok, f = cap.read()
                if ok: frame = f
            w, h = int(cap.get(3)), int(cap.get(4)); cap.release()
            if frame is None:
                return {"result": "no_frame", "index": idx}
            g = frame.mean(); sd = float(frame.std())
            eng.log("Python/opencv", "open camera %d, grab frames" % idx, time.time() - t, True)
            return {"result": "dark" if g < 8 else "flat" if sd < 3 else "pass", "index": idx, "w": w, "h": h, "mean": round(float(g), 1), "std": round(sd, 1)}
        eng.log("Python/opencv", "open camera", time.time() - t, False, "no camera opened")
        return {"result": "none"}
    except Exception as e:
        eng.log("Python/opencv", "camera test", time.time() - t, False, type(e).__name__)
        return {"result": "error", "error": str(e)[:80]}


# ================================================================ VBScript: Windows licence details (slmgr)
def eng_vbs():
    if not IS_WIN:
        return {}
    sysroot = os.environ.get("SystemRoot", r"C:\Windows")
    txt = eng.sh('cscript //nologo "%s\\System32\\slmgr.vbs" /dlv' % sysroot, 60, "VBScript")
    out = {}
    for line in txt.splitlines():
        if ":" in line:
            k, v = line.split(":", 1); out[k.strip()] = v.strip()
    return out


# ================================================================ force-unmute speakers for the sound test (restored afterwards)
class Speakers:
    """Context manager: un-mute + set 50% volume with pycaw, restore on exit. Silently does nothing if pycaw is missing."""
    def __init__(self, mods):
        self.mods = mods; self.vol = None; self.old = None; self.was_muted = None; self.old_level = None

    def __enter__(self):
        try:
            from ctypes import cast, POINTER
            from comtypes import CLSCTX_ALL
            from pycaw.pycaw import AudioUtilities, IAudioEndpointVolume
            dev = AudioUtilities.GetSpeakers()
            ev = getattr(dev, "EndpointVolume", None)
            if ev is None:
                iface = dev.Activate(IAudioEndpointVolume._iid_, CLSCTX_ALL, None); ev = cast(iface, POINTER(IAudioEndpointVolume))
            self.vol = ev
            self.was_muted = bool(ev.GetMute()); self.old_level = ev.GetMasterVolumeLevelScalar()
            ev.SetMute(0, None); ev.SetMasterVolumeLevelScalar(max(self.old_level, 0.5), None)
            eng.log("Python/pycaw", "un-mute speakers + volume 50%% (was %s, %d%%)" % ("muted" if self.was_muted else "on", round(self.old_level * 100)), 0, True)
        except Exception as e:
            self.vol = None
            eng.log("Python/pycaw", "speaker volume control", 0, False, type(e).__name__)
        return self

    def __exit__(self, *a):
        try:
            if self.vol is not None:
                self.vol.SetMasterVolumeLevelScalar(self.old_level, None); self.vol.SetMute(1 if self.was_muted else 0, None)
        except Exception:
            pass
        return False
