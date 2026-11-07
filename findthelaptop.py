#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Find the Laptop - full laptop health, security and condition scanner (Windows)
Developed by Rashid Ahmad
v2.1 - uses several Python libraries (psutil, py-cpuinfo, wmi, sounddevice, numpy, pyserial,
NVML) + CMD + PowerShell + C + C++. Works offline; the libraries are installed by the .bat.
"""
import os, sys, re, json, time, socket, subprocess, datetime, html, threading, webbrowser, shutil
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler

APP = "Find the Laptop"
AUTHOR = "Rashid Ahmad"
VERSION = "2.1"
BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)
import ftl_engines as eng
import ftl_charts as ch
IS_WIN = os.name == "nt"
DEMO = os.environ.get("FTL_DEMO") == "1"

# ----------------------------------------------------------------- helpers
PWSH7 = shutil.which("pwsh")          # PowerShell 7 (the "new" PowerShell), if installed
PS_PRE = "$ErrorActionPreference='SilentlyContinue'; $ProgressPreference='SilentlyContinue'; "

def run(cmd, timeout=120, shell_name="CMD"):
    t = time.time()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           encoding="utf-8", errors="replace", shell=isinstance(cmd, str))
        eng.log(shell_name, cmd if isinstance(cmd, str) else " ".join(cmd), time.time() - t, r.returncode == 0)
        return (r.stdout or "").strip()
    except Exception as e:
        eng.log(shell_name, cmd if isinstance(cmd, str) else " ".join(cmd), time.time() - t, False, type(e).__name__)
        return ""

def ps(cmd, timeout=120, new=False):
    """Windows PowerShell 5.1 by default (widest compatibility). new=True tries PowerShell 7 first."""
    if new and PWSH7:
        out = run([PWSH7, "-NoProfile", "-Command", PS_PRE + cmd], timeout, "PowerShell 7")
        if out:
            return out
    out = run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", PS_PRE + cmd], timeout, "PowerShell 5.1")
    if not out and PWSH7 and not new:          # alternative: try the new PowerShell when the old one gave nothing
        out = run([PWSH7, "-NoProfile", "-Command", PS_PRE + cmd], timeout, "PowerShell 7 (retry)")
    return out

def psj(cmd, timeout=120, new=False):
    out = ps("& { " + cmd + " } | ConvertTo-Json -Depth 4 -Compress", timeout, new)
    if not out:
        return []
    try:
        data = json.loads(out)
    except Exception:
        return []
    if data is None:
        return []
    return data if isinstance(data, list) else [data]

def gb(n, digits=1):
    try: return round(float(n) / 1024 ** 3, digits)
    except Exception: return 0

def num(v, default=0):
    try: return float(v)
    except Exception: return default

def pdate(s, fmt="%Y-%m-%d"):
    try: return datetime.datetime.strptime(str(s)[:len(datetime.datetime.now().strftime(fmt))], fmt)
    except Exception: return None

D = {}
def L(k): return [x for x in (D.get(k) or [])]
def F(k):
    v = D.get(k) or []
    return v[0] if v and isinstance(v[0], dict) else {}
def S(k):
    v = D.get(k) or []
    return v[0] if v and not isinstance(v[0], dict) else None

FINDINGS = []
def add(cat, name, status, detail, fix=""):
    FINDINGS.append({"cat": cat, "name": name, "status": status, "detail": str(detail), "fix": fix})

# ------------------------------------------------------------- data queries
UN = r"HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*,HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
DT = lambda p: "@{n='%s';e={\"{0:yyyy-MM-dd}\" -f $_.%s}}" % (p, p)
Q = {
 "cs": "Get-CimInstance Win32_ComputerSystem | select Manufacturer,Model,SystemType,TotalPhysicalMemory,UserName,Domain,PartOfDomain",
 "bios": "Get-CimInstance Win32_BIOS | select Manufacturer,SMBIOSBIOSVersion,SerialNumber,%s" % DT("ReleaseDate"),
 "board": "Get-CimInstance Win32_BaseBoard | select Manufacturer,Product,SerialNumber,Version",
 "cpu": "Get-CimInstance Win32_Processor | select Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed,LoadPercentage,VirtualizationFirmwareEnabled",
 "ram": "Get-CimInstance Win32_PhysicalMemory | select Manufacturer,PartNumber,Capacity,Speed,BankLabel",
 "os": "Get-CimInstance Win32_OperatingSystem | select Caption,Version,BuildNumber,OSArchitecture,FreePhysicalMemory,TotalVisibleMemorySize,%s,@{n='LastBoot';e={\"{0:yyyy-MM-dd HH:mm}\" -f $_.LastBootUpTime}}" % DT("InstallDate"),
 "disks": "Get-PhysicalDisk | select FriendlyName,MediaType,BusType,HealthStatus,OperationalStatus,Size",
 "reli": "Get-PhysicalDisk | Get-StorageReliabilityCounter | select DeviceId,PowerOnHours,Wear,Temperature,ReadErrorsTotal,WriteErrorsTotal",
 "vols": "Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | select DeviceID,VolumeName,FileSystem,Size,FreeSpace",
 "gpu": "Get-CimInstance Win32_VideoController | select Name,DriverVersion,CurrentHorizontalResolution,CurrentVerticalResolution,CurrentRefreshRate,ConfigManagerErrorCode",
 "monitors": "Get-CimInstance -Namespace root\\wmi -ClassName WmiMonitorID | select @{n='Name';e={-join ([char[]]($_.UserFriendlyName | where {$_ -ne 0}))}},@{n='Maker';e={-join ([char[]]($_.ManufacturerName | where {$_ -ne 0}))}},WeekOfManufacture,YearOfManufacture",
 "battery": "Get-CimInstance Win32_Battery | select Name,EstimatedChargeRemaining,BatteryStatus",
 "bat_design": "Get-CimInstance -Namespace root\\wmi -ClassName BatteryStaticData | select DesignedCapacity,ManufactureName",
 "bat_full": "Get-CimInstance -Namespace root\\wmi -ClassName BatteryFullChargedCapacity | select FullChargedCapacity",
 "bat_cycle": "Get-CimInstance -Namespace root\\wmi -ClassName BatteryCycleCount | select CycleCount",
 "thermal": "Get-CimInstance -Namespace root\\wmi -ClassName MSAcpi_ThermalZoneTemperature | select InstanceName,CurrentTemperature",
 "badpnp": "Get-CimInstance Win32_PnPEntity | where {$_.ConfigManagerErrorCode -ne 0} | select Name,PNPClass,ConfigManagerErrorCode",
 "audio": "Get-CimInstance Win32_SoundDevice | select Name,Status",
 "cam": "Get-PnpDevice -Class Camera,Image -PresentOnly | select FriendlyName,Status",
 "bt": "Get-PnpDevice -Class Bluetooth -PresentOnly | select FriendlyName,Status",
 "kbd": "Get-CimInstance Win32_Keyboard | select Name,Status",
 "mouse": "Get-CimInstance Win32_PointingDevice | select Name,Status",
 "usbctl": "Get-CimInstance Win32_USBController | select Name,Status",
 "usbdev": "Get-PnpDevice -Class USB -PresentOnly | select FriendlyName,Status",
 "nics": "Get-NetAdapter | select Name,InterfaceDescription,Status,LinkSpeed,MacAddress,PhysicalMediaType",
 "av": "Get-CimInstance -Namespace root\\SecurityCenter2 -ClassName AntiVirusProduct | select displayName,productState",
 "mp": "Get-MpComputerStatus | select AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureAge,QuickScanAge,IsTamperProtected",
 "threats": "Get-MpThreatDetection | select -First 20 ThreatID,ProcessName,@{n='When';e={\"{0:yyyy-MM-dd}\" -f $_.InitialDetectionTime}}",
 "fw": "Get-NetFirewallProfile | select Name,Enabled",
 "bitlocker": "Get-BitLockerVolume | select MountPoint,ProtectionStatus",
 "tpm": "Get-Tpm | select TpmPresent,TpmReady",
 "secboot": "try { Confirm-SecureBootUEFI } catch { 'unsupported' }",
 "smb1": "Get-SmbServerConfiguration | select EnableSMB1Protocol",
 "rdp": "Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' | select fDenyTSConnections",
 "uac": "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' | select EnableLUA",
 "users": "Get-LocalUser | select Name,Enabled,PasswordRequired",
 "hotfix": "Get-HotFix | sort InstalledOn -desc | select -First 10 HotFixID,@{n='InstalledOn';e={\"{0:yyyy-MM-dd}\" -f $_.InstalledOn}}",
 "sw": "Get-ItemProperty %s | where {$_.DisplayName} | select DisplayName,DisplayVersion,Publisher | sort DisplayName -Unique" % UN,
 "startup": "Get-CimInstance Win32_StartupCommand | select Name,Command,Location,User",
 "svc": "Get-CimInstance Win32_Service | where {$_.StartMode -eq 'Auto' -and $_.State -ne 'Running' -and $_.ExitCode -ne 0} | select Name,DisplayName,ExitCode",
 "topproc": "Get-Process | sort WS -desc | select -First 8 Name,@{n='MB';e={[int]($_.WS/1MB)}}",
 "proccount": "(Get-Process).Count",
 "events": "Get-WinEvent -FilterHashtable @{LogName='System';Level=1,2;StartTime=(Get-Date).AddDays(-7)} -MaxEvents 400 | group ProviderName | sort Count -desc | select -First 6 Count,Name",
 "kpower": "(Get-WinEvent -FilterHashtable @{LogName='System';Id=41;StartTime=(Get-Date).AddDays(-30)} -MaxEvents 100 | measure).Count",
 "bugcheck": "(Get-WinEvent -FilterHashtable @{LogName='System';Id=1001;StartTime=(Get-Date).AddDays(-90)} -MaxEvents 100 | measure).Count",
 "oldest_event": "Get-WinEvent -LogName System -Oldest -MaxEvents 1 | select @{n='T';e={\"{0:yyyy-MM-dd}\" -f $_.TimeCreated}}",
 "profiles": "Get-CimInstance Win32_UserProfile | where {-not $_.Special} | select LocalPath",
 "usbstor": "(Get-ChildItem 'HKLM:\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR' | Get-ChildItem | measure).Count",
 "winold": "Test-Path 'C:\\Windows.old'",
 "activation": "Get-CimInstance SoftwareLicensingProduct | where {$_.PartialProductKey -and $_.Name -like 'Windows*'} | select Name,LicenseStatus,PartialProductKey",
 "key": "(Get-CimInstance SoftwareLicensingService).OA3xOriginalProductKey",
 "ports": "Get-NetTCPConnection -State Listen | where {$_.LocalAddress -in '0.0.0.0','::'} | select LocalPort,@{n='Proc';e={(Get-Process -Id $_.OwningProcess).Name}}",
 "proxy": "Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' | select ProxyEnable,ProxyServer",
 "profile_dates": "Get-ChildItem C:\\Users -Directory -Force | where {$_.Name -notin 'Public','Default','Default User','All Users'} | select Name,@{n='Created';e={\"{0:yyyy-MM-dd}\" -f $_.CreationTime}}",
 "dev_first": "Get-PnpDevice -PresentOnly -Class Camera,Image,Keyboard,Mouse,HIDClass,Monitor,Display,Bluetooth,MEDIA,Biometric,Net,Battery,DiskDrive,Processor,Sensor,Firmware | select -First 120 | foreach { $d=$_; $p=(Get-PnpDeviceProperty -InstanceId $d.InstanceId -KeyName 'DEVPKEY_Device_FirstInstallDate').Data; [pscustomobject]@{Name=$d.FriendlyName;Class=$d.Class;First=$(if($p){\"{0:yyyy-MM-dd}\" -f $p}else{$null})} }",
 "drivers": "Get-CimInstance Win32_PnPSignedDriver | where {$_.DeviceName -and $_.Manufacturer -notmatch 'Microsoft' -and $_.DeviceClass -in 'DISPLAY','NET','BLUETOOTH','MEDIA','CAMERA','IMAGE','BIOMETRIC','HIDCLASS','SYSTEM','USB','SENSOR'} | select DeviceName,DeviceClass,DriverVersion,Manufacturer,@{n='DriverDate';e={\"{0:yyyy-MM-dd}\" -f $_.DriverDate}},IsSigned",
 "defexcl": "Get-MpPreference | select ExclusionPath,ExclusionExtension,ExclusionProcess,DisableRealtimeMonitoring,DisableBehaviorMonitoring",
 "tasks": "Get-ScheduledTask | where {$_.State -ne 'Disabled' -and $_.TaskPath -notlike '\\Microsoft\\*'} | select -First 40 TaskName,TaskPath,@{n='Action';e={(($_.Actions | select -First 1).Execute + ' ' + ($_.Actions | select -First 1).Arguments).Trim()}}",
 "oddsvc": "Get-CimInstance Win32_Service | where {$_.PathName -match '\\\\Temp\\\\|AppData|Users\\\\Public|ProgramData'} | select Name,PathName,StartMode,State",
 "pendreboot": "Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending'",
 "boottimes": "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Diagnostics-Performance/Operational';Id=100} -MaxEvents 5 | foreach { $x=[xml]$_.ToXml(); [int](($x.Event.EventData.Data | where {$_.Name -eq 'BootTime'}).'#text') }",
 "psver": "$PSVersionTable.PSVersion.ToString()",
 "smart": "Get-CimInstance -Namespace root\\wmi -ClassName MSStorageDriver_FailurePredictStatus | select PredictFailure",
 "thermal2": "Get-CimInstance Win32_PerfFormattedData_Counters_ThermalZoneInformation | select Name,Temperature",
 "mic_priv": "(Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\microphone').Value",
 "cfa": "(Get-MpPreference).EnableControlledFolderAccess",
 "docs": "((Get-ChildItem \"$env:USERPROFILE\\Documents\",\"$env:USERPROFILE\\Downloads\",\"$env:USERPROFILE\\Desktop\",\"$env:USERPROFILE\\Pictures\" -Recurse -File -ErrorAction SilentlyContinue | select -First 300) | measure).Count",
}

NEW_PS_KEYS = {"cs", "bios", "board", "cpu", "os", "psver"}   # tried with PowerShell 7 first when installed
import ftl_queries, ftl_engines2 as eng2
Q.update(ftl_queries.NEW_Q)
X = {}                                                        # results from the Python / C / C++ / CMD engines

def collect(deep=True):
    tasks = dict(Q)
    total = len(tasks) + 8
    done = [0]
    lock = threading.Lock()
    def tick():
        with lock:
            done[0] += 1
            print("\r  Scanning... %3d%%" % min(99, int(done[0] * 100 / total)), end="", flush=True)
    def job(k):
        r = psj(tasks[k], 150, new=(k in NEW_PS_KEYS)); tick(); return k, r
    with ThreadPoolExecutor(max_workers=8) as ex:
        futs = [ex.submit(job, k) for k in tasks]
        # CMD tools + battery report run in parallel with the PowerShell queries
        side = {"cmd": ex.submit(eng.eng_cmd, deep), "batrep": ex.submit(eng.eng_battery_report)}
        for f in as_completed(futs):
            k, v = f.result(); D[k] = v
        for k, f in side.items():
            X[k] = f.result(); tick()
    if not D.get("thermal") and D.get("thermal2"):       # alternative temperature source
        D["thermal"] = [{"InstanceName": t.get("Name"), "CurrentTemperature": num(t.get("Temperature")) * 10} for t in D["thermal2"] if t.get("Temperature")]
    D["wifi_txt"] = [run("netsh wlan show interfaces")]; tick()
    D["wifi_profiles"] = [run("netsh wlan show profiles")]; tick()
    D["dism"] = [run("dism /Online /Cleanup-Image /CheckHealth", 240)]; tick()
    D["dirty"] = [run("fsutil dirty query C:")]; tick()
    try:
        with open(os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "drivers", "etc", "hosts"), errors="ignore") as fh:
            D["hosts"] = [[l.strip() for l in fh if l.strip() and not l.strip().startswith("#")]]
    except Exception:
        D["hosts"] = [[]]
    tick()
    # ---- Python libraries + C + C++ engines (run one after another so benchmarks are not disturbed)
    mods = eng.load_libs(); tick()
    X["psutil"] = eng.eng_psutil(mods); X["cpuinfo"] = eng.eng_cpuinfo(mods); X["wmi"] = eng.eng_wmi(mods)
    X["gpu"] = eng.eng_gpu(mods); X["serial"] = eng.eng_serial(mods); X["input"] = eng.eng_input()
    print("\r  Scanning... testing speaker + microphone (you will hear a short tone)   ")
    X["smbios"] = eng2.read_smbios(); X["registry"] = eng2.eng_registry(); X["vbs"] = eng2.eng_vbs()
    X["bcd"] = eng.sh("bcdedit /enum {current}", 30, "CMD")
    X["clock"] = eng2.eng_clock()
    print("\r  Scanning... testing camera (the camera light may blink)                ")
    X["camera"] = eng2.eng_camera(mods)
    print("\r  Scanning... testing speaker + microphone (you will hear a short tone)   ")
    X["audio"] = eng.eng_audio(mods)
    X["ram"] = eng.eng_ramtest(mods); X["pybench"] = eng.eng_pybench()
    roots = []
    for v in D.get("vols") or []:
        if v.get("DeviceID") and num(v.get("FreeSpace")) > 1.5e9: roots.append(str(v["DeviceID"]).rstrip("\\") + "\\")
    X["native"] = eng.eng_native(roots or ["C:\\"])
    print("\r  Scanning... 100%                                              ")

# --------------------------------------------------------- network tests
def network_tests():
    res = {}
    out = run("ping -n 4 8.8.8.8", 30)
    m = re.search(r"Average = (\d+)ms", out); lost = re.search(r"Lost = (\d+)", out)
    res["ping"] = int(m.group(1)) if m else None
    res["lost"] = int(lost.group(1)) if lost else None
    try:
        t = time.time(); socket.gethostbyname("www.google.com"); res["dns"] = int((time.time() - t) * 1000)
    except Exception: res["dns"] = None
    try:
        t = time.time(); urllib.request.urlopen("https://www.google.com", timeout=10).read(1000); res["https"] = int((time.time() - t) * 1000)
    except Exception: res["https"] = None
    try:
        t = time.time(); n = 0
        with urllib.request.urlopen("https://speed.cloudflare.com/__down?bytes=10000000", timeout=30) as r:
            while True:
                b = r.read(65536)
                if not b: break
                n += len(b)
        sec = max(time.time() - t, 0.01); res["mbps"] = round(n * 8 / sec / 1e6, 1)
    except Exception: res["mbps"] = None
    return res

# ------------------------------------------------------------- evaluation
def evaluate():
    now = datetime.datetime.now()
    # ---------- System
    try:
        cs, bios, board, osd, cpu = F("cs"), F("bios"), F("board"), F("os"), F("cpu")
        C = "System & OS"
        add(C, "Computer", "INFO", "%s %s (%s)" % (cs.get("Manufacturer", "?"), cs.get("Model", "?"), cs.get("SystemType", "")))
        add(C, "Operating system", "INFO", "%s, build %s, %s" % (osd.get("Caption", "?"), osd.get("BuildNumber", "?"), osd.get("OSArchitecture", "")))
        if "Windows 10" in str(osd.get("Caption", "")):
            add(C, "Windows support", "WARN", "Windows 10 support ended on 14 Oct 2025 (no free security updates).", "Upgrade to Windows 11 if the hardware supports it (needs TPM 2.0 + Secure Boot).")
        elif osd:
            add(C, "Windows support", "PASS", "Windows version is still supported.")
        add(C, "Installed on", "INFO", osd.get("InstallDate", "unknown"))
        add(C, "Last boot", "INFO", osd.get("LastBoot", "unknown"))
        add(C, "Signed-in user / domain", "INFO", "%s  /  %s" % (cs.get("UserName", "?"), cs.get("Domain", "?")))
        if cs.get("PartOfDomain"):
            add(C, "Managed by an organisation", "WARN", "This laptop is joined to a domain (%s). It may be company/school property with restrictions." % cs.get("Domain"), "Ask the seller to remove it from the domain / MDM before buying.")
    except Exception as _e:
        add("Scan notes", "Check skipped: System", "INFO", "%s: %s" % (type(_e).__name__, _e))
    # ---------- BIOS
    try:
        C = "BIOS / Firmware"
        add(C, "BIOS", "INFO", "%s  v%s" % (bios.get("Manufacturer", "?"), bios.get("SMBIOSBIOSVersion", "?")))
        bd = pdate(bios.get("ReleaseDate"))
        if bd:
            yrs = (now - bd).days / 365.25
            add(C, "BIOS date", "WARN" if yrs > 5 else "PASS", "%s (%.1f years old)" % (bios.get("ReleaseDate"), yrs), "Check the manufacturer website for a BIOS update." if yrs > 5 else "")
        sn = str(bios.get("SerialNumber", "")).strip()
        if not sn or re.search(r"(?i)o\.?e\.?m|default|none|system serial|0000", sn):
            add(C, "Serial number", "WARN", "Serial number looks empty/placeholder: '%s'." % sn, "Possible board replacement or refurbished unit. Ask the seller.")
        else:
            add(C, "Serial number", "INFO", sn)
        sb = S("secboot")
        if sb is True: add(C, "Secure Boot", "PASS", "Enabled")
        elif sb == "unsupported": add(C, "Secure Boot", "WARN", "Not supported / legacy BIOS mode.", "Windows 11 requires UEFI + Secure Boot.")
        else: add(C, "Secure Boot", "WARN", "Disabled", "Enable Secure Boot in BIOS settings.")
        tpm = F("tpm")
        if tpm.get("TpmPresent"): add(C, "TPM chip", "PASS" if tpm.get("TpmReady") else "WARN", "Present, ready=%s" % tpm.get("TpmReady"))
        else: add(C, "TPM chip", "WARN", "No TPM detected (or disabled in BIOS).", "Enable fTPM/PTT in BIOS. Windows 11 needs TPM 2.0.")
        add(C, "CPU virtualization", "INFO", "Enabled" if cpu.get("VirtualizationFirmwareEnabled") else "Disabled in BIOS")
    except Exception as _e:
        add("Scan notes", "Check skipped: BIOS", "INFO", "%s: %s" % (type(_e).__name__, _e))
    # ---------- Motherboard
    try:
        C = "Motherboard"
        add(C, "Board", "INFO", "%s %s (v%s)" % (board.get("Manufacturer", "?"), board.get("Product", "?"), board.get("Version", "")))
        add(C, "Board serial", "INFO", board.get("SerialNumber", "unknown"))
        bad = L("badpnp")
        if bad:
            for b in bad:
                add(C, "Device error: " + str(b.get("Name") or "Unknown device"), "FAIL", "Windows error code %s (class: %s)" % (b.get("ConfigManagerErrorCode"), b.get("PNPClass")), "Reinstall/update the driver from the manufacturer website, or the device may be faulty.")
        else:
            add(C, "Device Manager errors", "PASS", "No devices report errors.")
    except Exception as _e:
        add("Scan notes", "Check skipped: Motherboard", "INFO", "%s: %s" % (type(_e).__name__, _e))
    # ---------- CPU
    try:
        C = "CPU"
        add(C, "Processor", "INFO", "%s - %s cores / %s threads, %s MHz" % (str(cpu.get("Name", "?")).strip(), cpu.get("NumberOfCores"), cpu.get("NumberOfLogicalProcessors"), cpu.get("MaxClockSpeed")))
        load = num(cpu.get("LoadPercentage"))
        add(C, "CPU load right now", "WARN" if load > 85 else "PASS", "%d%%" % load, "Something is using the CPU heavily; check Task Manager for malware or miners." if load > 85 else "")
        temps = [num(t.get("CurrentTemperature")) / 10 - 273.15 for t in L("thermal") if t.get("CurrentTemperature")]
        if temps:
            t = max(temps)
            add(C, "Temperature (ACPI zone)", "FAIL" if t > 90 else "WARN" if t > 75 else "PASS", "%.0f °C" % t, "Clean fans/vents, replace thermal paste." if t > 75 else "")
        else:
            add(C, "Temperature", "INFO", "Not exposed by this laptop's firmware.")
    except Exception as _e:
        add("Scan notes", "Check skipped: CPU", "INFO", "%s: %s" % (type(_e).__name__, _e))
    # ---------- RAM
    try:
        C = "Memory (RAM)"
        mods = L("ram")
        total = num(osd.get("TotalVisibleMemorySize")) * 1024
        add(C, "Installed", "INFO", "%s GB in %d module(s): %s" % (gb(total or cs.get("TotalPhysicalMemory")), len(mods), ", ".join("%s GB @ %s MHz" % (gb(m.get("Capacity"), 0), m.get("Speed")) for m in mods) or "n/a"))
        if total:
            used = 100 - num(osd.get("FreePhysicalMemory")) * 1024 * 100 / total
            add(C, "In use right now", "WARN" if used > 85 else "PASS", "%d%% used" % used, "Close apps / check for memory hogs." if used > 85 else "")
            if gb(total) < 7.5: add(C, "Capacity", "WARN", "Less than 8 GB RAM is slow for modern Windows.", "Upgrade RAM if possible.")
        tp = L("topproc")
        if tp: add(C, "Biggest memory users", "INFO", ", ".join("%s (%s MB)" % (p.get("Name"), p.get("MB")) for p in tp[:6]))
        add(C, "Running processes", "INFO", S("proccount"))
    except Exception as _e:
        add("Scan notes", "Check skipped: RAM", "INFO", "%s: %s" % (type(_e).__name__, _e))
    # ---------- Storage
    try:
        C = "Storage"
        reli = {str(r.get("DeviceId")): r for r in L("reli")}
        for i, dsk in enumerate(L("disks")):
            health = str(dsk.get("HealthStatus"))
            ok = health.lower() in ("healthy", "0")
            add(C, "Disk: " + str(dsk.get("FriendlyName")), "PASS" if ok else "FAIL", "%s %s, %s GB, health=%s, status=%s" % (dsk.get("MediaType"), dsk.get("BusType"), gb(dsk.get("Size"), 0), health, dsk.get("OperationalStatus")), "" if ok else "BACK UP DATA NOW. The drive reports problems; replace it.")
        for r in L("reli"):
            wear, poh = r.get("Wear"), r.get("PowerOnHours")
            errs = num(r.get("ReadErrorsTotal")) + num(r.get("WriteErrorsTotal"))
            st = "FAIL" if errs > 0 or (wear is not None and num(wear) > 90) else "WARN" if (wear is not None and num(wear) > 70) else "PASS"
            add(C, "Disk wear/usage (disk %s)" % r.get("DeviceId"), st, "Power-on hours: %s, wear: %s%%, temp: %s °C, read/write errors: %d" % (poh, wear, r.get("Temperature"), errs), "Drive is near end of life or has errors." if st != "PASS" else "")
        for v in L("vols"):
            size, free = num(v.get("Size")), num(v.get("FreeSpace"))
            pct = free * 100 / size if size else 0
            add(C, "Drive %s" % v.get("DeviceID"), "FAIL" if pct < 5 else "WARN" if pct < 10 else "PASS", "%s GB total, %s GB free (%d%%), %s" % (gb(size, 0), gb(free), pct, v.get("FileSystem")), "Free up space." if pct < 10 else "")
        dirty = D["dirty"][0].lower() if D.get("dirty") else ""
        if "is dirty" in dirty and "not dirty" not in dirty:
            add(C, "File system", "FAIL", "C: drive is flagged dirty (corruption suspected).", "Run 'chkdsk C: /f' and reboot.")
    except Exception as _e:
        add("Scan notes", "Check skipped: Storage", "INFO", "%s: %s" % (type(_e).__name__, _e))
    # ---------- GPU & display
    try:
        C = "Graphics & Display"
        for g in L("gpu"):
            add(C, "GPU: " + str(g.get("Name")), "FAIL" if g.get("ConfigManagerErrorCode") else "PASS", "Driver %s, %sx%s @ %s Hz" % (g.get("DriverVersion"), g.get("CurrentHorizontalResolution"), g.get("CurrentVerticalResolution"), g.get("CurrentRefreshRate")))
        for m in L("monitors"):
            add(C, "Screen", "INFO", "%s %s (made %s)" % (m.get("Maker"), m.get("Name"), m.get("YearOfManufacture")))
        add(C, "Dead pixels / backlight", "INFO", "Cannot be detected by software. Use the colour test in 'Manual tests' below.")
    except Exception as _e:
        add("Scan notes", "Check skipped: GPU & display", "INFO", "%s: %s" % (type(_e).__name__, _e))
    # ---------- Battery
    try:
        C = "Battery"
        bat = F("battery")
        if not bat:
            add(C, "Battery", "INFO", "No battery detected (desktop PC, or battery missing/dead).")
        else:
            add(C, "Charge now", "INFO", "%s%%" % bat.get("EstimatedChargeRemaining"))
            design, full, cyc = num(F("bat_design").get("DesignedCapacity")), num(F("bat_full").get("FullChargedCapacity")), F("bat_cycle").get("CycleCount")
            if design and full:
                h = full * 100 / design
                add(C, "Battery health", "FAIL" if h < 50 else "WARN" if h < 70 else "PASS", "%d%% of original capacity (%d / %d mWh)" % (h, full, design), "Battery needs replacement." if h < 70 else "")
            else:
                add(C, "Battery health", "INFO", "Capacity data not provided by this battery.")
            if cyc is not None:
                add(C, "Charge cycles", "WARN" if num(cyc) > 500 else "PASS", str(cyc), "Heavily cycled battery." if num(cyc) > 500 else "")
    except Exception as _e:
        add("Scan notes", "Check skipped: Battery", "INFO", "%s: %s" % (type(_e).__name__, _e))
    # ---------- Ports & peripherals
    try:
        C = "Ports & Peripherals"
        for name, key, need in (("Audio / speakers", "audio", True), ("Camera", "cam", True), ("Bluetooth", "bt", True), ("Keyboard", "kbd", True), ("Touchpad / mouse", "mouse", True)):
            items = L(key)
            names = ", ".join(str(i.get("Name") or i.get("FriendlyName")) for i in items)
            if not items: add(C, name, "WARN" if need else "INFO", "Not detected.", "Check Device Manager; the part may be missing, disabled or faulty.")
            else:
                badx = [i for i in items if str(i.get("Status", "OK")).upper() not in ("OK", "")]
                add(C, name, "FAIL" if badx else "PASS", names)
        ctl = L("usbctl")
        add(C, "USB controllers", "PASS" if ctl else "WARN", "%d found (%s)" % (len(ctl), ", ".join(str(c.get("Name")) for c in ctl[:4])))
        add(C, "USB devices connected now", "INFO", ", ".join(str(u.get("FriendlyName")) for u in L("usbdev")[:10]) or "none")
        add(C, "Physical ports", "INFO", "Each USB / HDMI / charging / headphone / SD port must be tested by plugging something in. Use the checklist in 'Manual tests'.")
    except Exception as _e:
        add("Scan notes", "Check skipped: Ports & peripherals", "INFO", "%s: %s" % (type(_e).__name__, _e))
    # ---------- Network
    try:
        C = "Network & Internet"
        for n in L("nics"):
            add(C, "Adapter: " + str(n.get("Name")), "INFO", "%s | %s | %s | %s" % (n.get("InterfaceDescription"), n.get("Status"), n.get("LinkSpeed"), n.get("MacAddress")))
        if not any("wi-fi" in str(n.get("Name", "")).lower() or "wireless" in str(n.get("InterfaceDescription", "")).lower() for n in L("nics")):
            add(C, "Wi-Fi card", "WARN", "No Wi-Fi adapter detected.", "Wi-Fi card may be missing, disabled in BIOS or broken.")
        net = D.get("net", {})
        add(C, "Ping (8.8.8.8)", "PASS" if net.get("ping") is not None and not net.get("lost") else "FAIL" if net.get("ping") is None else "WARN", "No reply" if net.get("ping") is None else "%s ms, %s lost" % (net["ping"], net.get("lost")), "No internet or blocked." if net.get("ping") is None else "")
        add(C, "DNS lookup", "PASS" if net.get("dns") is not None else "FAIL", "%s ms" % net["dns"] if net.get("dns") is not None else "Failed")
        add(C, "HTTPS connection", "PASS" if net.get("https") is not None else "FAIL", "%s ms" % net["https"] if net.get("https") is not None else "Failed")
        if net.get("mbps") is not None:
            add(C, "Download speed", "WARN" if net["mbps"] < 5 else "PASS", "%s Mbps" % net["mbps"], "Very slow connection or weak Wi-Fi." if net["mbps"] < 5 else "")
        else:
            add(C, "Download speed", "INFO", "Test could not complete.")
        wt = D["wifi_txt"][0] if D.get("wifi_txt") else ""
        ssid, sig = re.search(r"^\s*SSID\s*:\s*(.+)$", wt, re.M), re.search(r"Signal\s*:\s*(\d+)%", wt)
        if ssid:
            s = int(sig.group(1)) if sig else None
            add(C, "Wi-Fi connection", "WARN" if s is not None and s < 40 else "PASS", "%s, signal %s%%" % (ssid.group(1).strip(), s))
        px = F("proxy")
        if px.get("ProxyEnable") == 1:
            add(C, "Proxy", "WARN", "A proxy is enabled: %s" % px.get("ProxyServer"), "Unexpected proxies can intercept traffic. Disable if you did not set it.")
    except Exception as _e:
        add("Scan notes", "Check skipped: Network", "INFO", "%s: %s" % (type(_e).__name__, _e))
    # ---------- Security
    try:
        C = "Security & Malware"
        mp, avs = F("mp"), L("av")
        others = [a for a in avs if "defender" not in str(a.get("displayName", "")).lower()]
        if mp:
            rt = mp.get("RealTimeProtectionEnabled")
            add(C, "Microsoft Defender real-time protection", "PASS" if rt else ("WARN" if others else "FAIL"), "On" if rt else "OFF", "" if rt else "Turn on Windows Security real-time protection (or install a trusted antivirus).")
            age = num(mp.get("AntivirusSignatureAge"))
            add(C, "Virus definitions", "WARN" if age > 7 else "PASS", "%d day(s) old" % age, "Run Windows Update." if age > 7 else "")
            qs = num(mp.get("QuickScanAge"), 9999)
            add(C, "Last quick scan", "WARN" if qs > 30 else "PASS", "%s day(s) ago" % (int(qs) if qs < 9999 else "never"), "Run a full scan in Windows Security." if qs > 30 else "")
        add(C, "Installed antivirus", "PASS" if avs else "FAIL", ", ".join(str(a.get("displayName")) for a in avs) or "None detected")
        th = L("threats")
        add(C, "Detected threats (history)", "FAIL" if th else "PASS", "%d detection(s) on record" % len(th) if th else "None on record", "Open Windows Security > Protection history, and run a full scan." if th else "")
        for f in L("fw"):
            add(C, "Firewall - %s" % f.get("Name"), "PASS" if f.get("Enabled") in (True, 1) else "WARN", "On" if f.get("Enabled") in (True, 1) else "OFF", "Enable Windows Firewall." if f.get("Enabled") not in (True, 1) else "")
        uac = F("uac")
        if uac: add(C, "User Account Control", "PASS" if uac.get("EnableLUA") == 1 else "FAIL", "On" if uac.get("EnableLUA") == 1 else "OFF", "Turn UAC back on.")
        s1 = F("smb1")
        if s1: add(C, "SMBv1 (WannaCry-era protocol)", "FAIL" if s1.get("EnableSMB1Protocol") else "PASS", "Enabled" if s1.get("EnableSMB1Protocol") else "Disabled", "Disable SMBv1: Turn Windows features on/off.")
        rdp = F("rdp")
        if rdp: add(C, "Remote Desktop", "WARN" if rdp.get("fDenyTSConnections") == 0 else "PASS", "Enabled (others can try to connect)" if rdp.get("fDenyTSConnections") == 0 else "Disabled", "Disable unless you need it.")
        gu = [u for u in L("users") if str(u.get("Name")).lower() == "guest" and u.get("Enabled")]
        add(C, "Guest account", "WARN" if gu else "PASS", "Enabled" if gu else "Disabled")
        nopw = [u.get("Name") for u in L("users") if u.get("Enabled") and u.get("PasswordRequired") is False]
        if nopw: add(C, "Accounts without password", "WARN", ", ".join(map(str, nopw)), "Set a password on every account.")
        bl = L("bitlocker")
        if bl: add(C, "Disk encryption (BitLocker)", "INFO", ", ".join("%s: %s" % (b.get("MountPoint"), "On" if b.get("ProtectionStatus") in (1, "On") else "Off") for b in bl))
        risky = {21: "FTP", 23: "Telnet", 3389: "Remote Desktop", 5900: "VNC", 5985: "WinRM"}
        open_risky = sorted({"%s (%s, %s)" % (risky[int(p["LocalPort"])], p["LocalPort"], p.get("Proc")) for p in L("ports") if int(num(p.get("LocalPort"))) in risky})
        add(C, "Risky open ports", "WARN" if open_risky else "PASS", ", ".join(open_risky) or "None of the common risky ports are listening", "Close services you don't use." if open_risky else "")
        add(C, "Ports listening to the network", "INFO", "%d" % len({p.get("LocalPort") for p in L("ports")}))
        hosts = D["hosts"][0] if D.get("hosts") else []
        extra = [h for h in hosts if not re.match(r"^(127\.0\.0\.1|::1)\s+localhost", h)]
        add(C, "Hosts file", "WARN" if len(extra) > 3 else "PASS", "%d custom entries" % len(extra), "Malware sometimes hijacks websites here. Inspect C:\\Windows\\System32\\drivers\\etc\\hosts" if len(extra) > 3 else "")
        sus = [s for s in L("startup") if re.search(r"(?i)\\temp\\|appdata\\local\\temp|\\downloads\\|\.vbs|\.js\b|powershell.+-enc", str(s.get("Command")))]
        add(C, "Suspicious startup entries", "FAIL" if sus else "PASS", "; ".join("%s -> %s" % (s.get("Name"), s.get("Command")) for s in sus) or "None found", "Remove unknown startup items." if sus else "")
        hf = [pdate(h.get("InstalledOn")) for h in L("hotfix")]
        hf = [h for h in hf if h]
        if hf:
            days = (now - max(hf)).days
            add(C, "Last Windows security patch", "FAIL" if days > 180 else "WARN" if days > 90 else "PASS", "%d days ago" % days, "Run Windows Update." if days > 90 else "")
        else:
            add(C, "Last Windows security patch", "WARN", "No update history found - likely never updated.", "Run Windows Update.")
    except Exception as _e:
        add("Scan notes", "Check skipped: Security", "INFO", "%s: %s" % (type(_e).__name__, _e))
    # ---------- Licence
    try:
        C = "Windows License"
        act = L("activation")
        if act:
            a = act[0]; ok = a.get("LicenseStatus") == 1
            add(C, "Activation", "PASS" if ok else "FAIL", "%s - %s (key ends %s)" % (a.get("Name"), "Activated / genuine" if ok else "NOT activated (status %s)" % a.get("LicenseStatus"), a.get("PartialProductKey")), "" if ok else "Windows is not activated or is counterfeit. Ask the seller for a genuine licence.")
        else:
            add(C, "Activation", "WARN", "Could not read activation state.")
        key = S("key")
        add(C, "Product key stored in BIOS", "INFO", key if key else "None stored (digital licence, volume licence, or key was removed).")
    except Exception as _e:
        add("Scan notes", "Check skipped: Licence", "INFO", "%s: %s" % (type(_e).__name__, _e))
    # ---------- Software
    try:
        C = "Software"
        sw = L("sw")
        add(C, "Installed programs", "INFO", "%d programs (full list below)" % len(sw))
        pup = re.compile(r"(?i)driver ?(updater|booster|easy)|pc ?(cleaner|optimi|speed)|reimage|mackeeper|wildtangent|segurazo|opencandy|babylon|ask toolbar|mypcbackup|systweak|advanced systemcare|iobit|crack|keygen|kms|activator")
        sus_sw = [s.get("DisplayName") for s in sw if pup.search(str(s.get("DisplayName")))]
        add(C, "Unwanted / risky programs", "WARN" if sus_sw else "PASS", ", ".join(sus_sw[:12]) or "None recognised", "Uninstall these. 'Activator/KMS/crack' tools are a common malware source." if sus_sw else "")
        su = L("startup")
        add(C, "Startup programs", "WARN" if len(su) > 15 else "INFO", "%d items" % len(su), "Too many startup items slow the boot." if len(su) > 15 else "")
    except Exception as _e:
        add("Scan notes", "Check skipped: Software", "INFO", "%s: %s" % (type(_e).__name__, _e))
    # ---------- System health
    try:
        C = "System Health"
        dism = (D["dism"][0] if D.get("dism") else "").lower()
        if dism:
            bad_img = "repairable" in dism and "no component store corruption" not in dism
            add(C, "Windows system files (DISM)", "FAIL" if bad_img else "PASS", "Corruption detected" if bad_img else "No corruption detected", "Run 'DISM /Online /Cleanup-Image /RestoreHealth' then 'sfc /scannow'." if bad_img else "")
        sv = L("svc")
        add(C, "Failed Windows services", "WARN" if sv else "PASS", ", ".join(str(s.get("DisplayName")) for s in sv[:8]) or "None")
        ev = L("events")
        cnt = sum(int(num(e.get("Count"))) for e in ev)
        add(C, "Critical/Error events (7 days)", "WARN" if cnt > 100 else "PASS", "%d - top sources: %s" % (cnt, ", ".join("%s (%s)" % (e.get("Name"), e.get("Count")) for e in ev[:4])) if ev else "None")
        kp = int(num(S("kpower")))
        add(C, "Unexpected shutdowns (30 days)", "WARN" if kp > 3 else "PASS", str(kp), "Possible power, battery or overheating problem." if kp > 3 else "")
        bc = int(num(S("bugcheck")))
        add(C, "Blue-screen crashes (90 days)", "FAIL" if bc > 2 else "WARN" if bc else "PASS", str(bc), "Repeated crashes = faulty RAM, drive or driver." if bc else "")
    except Exception as _e:
        add("Scan notes", "Check skipped: System health", "INFO", "%s: %s" % (type(_e).__name__, _e))
    return

def assess_condition():
    now = datetime.datetime.now()
    pts, notes = 0, []
    def tier(v, steps):
        for limit, p in steps:
            if v < limit: return p
        return steps[-1][1] + 1
    poh = [num(r.get("PowerOnHours")) for r in L("reli") if r.get("PowerOnHours") is not None]
    poh = max(poh) if poh else None
    if poh is not None:
        p = tier(poh, [(10, 0), (100, 1), (500, 2), (2000, 3)]); pts += p
        notes.append(("Disk has been powered on for %d hours" % poh, p))
    cyc = F("bat_cycle").get("CycleCount")
    if cyc is not None:
        p = tier(num(cyc), [(3, 0), (20, 1), (100, 2), (300, 3)]); pts += p
        notes.append(("Battery has %s charge cycles" % cyc, p))
    wp = len(re.findall(r"All User Profile", D["wifi_profiles"][0])) if D.get("wifi_profiles") else 0
    p = tier(wp, [(1, 0), (3, 1), (7, 2)]); pts += p
    notes.append(("%d saved Wi-Fi networks (someone connected it to places)" % wp, p))
    us = int(num(S("usbstor")))
    p = tier(us, [(1, 0), (4, 1), (11, 2)]); pts += p
    notes.append(("%d different USB storage devices were plugged in before" % us, p))
    sw = len(L("sw"))
    p = tier(sw, [(40, 0), (80, 1), (150, 2)]); pts += p
    notes.append(("%d programs installed" % sw, p))
    prof = len(L("profiles"))
    if prof > 2: pts += 1; notes.append(("%d user profiles exist on this PC" % prof, 1))
    docs = int(num(S("docs")))
    if docs > 50: pts += 2; notes.append(("%d personal files found in Documents/Downloads/Desktop/Pictures" % docs, 2))
    if S("winold") is True: pts += 2; notes.append(("A 'Windows.old' folder exists (upgraded or reset before)", 2))
    oe = pdate((F("oldest_event") or {}).get("T"))
    if oe:
        d = (now - oe).days
        p = tier(d, [(14, 0), (90, 1), (365, 2)]); pts += p
        notes.append(("Oldest system log is %d days old" % d, p))
    inst = pdate(F("os").get("InstallDate"))
    flags = []
    if inst:
        age = (now - inst).days
        if age < 30 and ((poh or 0) > 200 or num(cyc) > 30):
            flags.append("Windows was installed only %d days ago, but the hardware shows much older use: the laptop was probably reset/reinstalled before being sold. Ask the seller why." % age)
    if pts <= 3: verdict, cls = "Looks NEW / unused", "ok"
    elif pts <= 8: verdict, cls = "Like new / lightly used", "ok"
    elif pts <= 14: verdict, cls = "Used (normal wear)", "warn"
    else: verdict, cls = "Heavily used / old", "fail"
    if flags and cls == "ok": verdict, cls = "Used - but wiped/reinstalled", "warn"
    return {"verdict": verdict, "cls": cls, "points": pts, "notes": notes, "flags": flags}

# ------------------------------------------------------------- extra evaluation (v2)
def _sev(n_fail, n_warn): return "FAIL" if n_fail else "WARN" if n_warn else "PASS"

def evaluate_extras():
    now = datetime.datetime.now()
    pu, nat, cpp = X.get("psutil", {}), (X.get("native") or {}), ((X.get("native") or {}).get("cpp") or {}).get("data", {})
    cn = ((X.get("native") or {}).get("c") or {}).get("data", {})
    # ---- CPU: per-core + benchmark + throttling
    C = "CPU"
    pc = pu.get("percore")
    if pc: add(C, "Per-core load (Python psutil)", "INFO", ", ".join("%d%%" % v for v in pc))
    ci = X.get("cpuinfo") or {}
    if ci: add(C, "CPU details (py-cpuinfo)", "INFO", "%s | L2 %s | L3 %s | AVX2 %s | virtualization flag %s" % (ci.get("brand"), ci.get("l2"), ci.get("l3"), ci.get("avx2"), ci.get("vmx")))
    runs = [num(cpp.get("int_ms_run%d" % i)) for i in (1, 2, 3)] if cpp else []
    if runs and runs[0] > 0:
        drop = (runs[2] / runs[0] - 1) * 100
        add(C, "Speed test + overheating check (C++)", "WARN" if drop > 25 else "PASS",
            "3 identical runs: %d / %d / %d ms. %s. Multi-core scaling x%s on %s threads." % (runs[0], runs[1], runs[2], ("Last run %d%% slower: CPU is slowing itself down (heat or weak power)" % drop) if drop > 25 else "Stable, no slow-down", cpp.get("multi_core_scaling"), cpp.get("threads")),
            "Clean the fans/vents, replace thermal paste, use the original charger." if drop > 25 else "")
    elif X.get("pybench"):
        r = X["pybench"]["runs_ms"]; drop = (r[-1] / r[0] - 1) * 100 if r[0] else 0
        add(C, "Speed test (Python)", "WARN" if drop > 30 else "PASS", "4 runs: %s ms" % " / ".join(map(str, r)), "CPU slows down when hot." if drop > 30 else "")
    for g in X.get("gpu") or []:
        add("Graphics & Display", "NVIDIA GPU sensors (NVML)", "WARN" if g["temp"] > 85 else "PASS", "%s: %s °C, load %s%%, %s GB VRAM" % (g["name"], g["temp"], g["load"], g["vram_gb"]))
    # ---- RAM test
    C = "Memory (RAM)"
    rt = X.get("ram") or {}
    if rt.get("errors") is None and rt: add(C, "RAM pattern test", "INFO", "Not enough free memory to run the test.")
    elif rt: add(C, "RAM pattern test (%d MB, Python/numpy)" % rt["mb"], "PASS" if rt["errors"] == 0 else "FAIL",
                 "%d error(s) in %ss" % (rt["errors"], rt["secs"]) if rt["errors"] else "No errors in %s s (quick test, not a full MemTest86)" % rt["secs"],
                 "RAM is faulty. Replace the module." if rt["errors"] else "")
    if cpp.get("mem_copy_mb_s"): add(C, "Memory speed (C++ copy test)", "INFO", "%s MB/s" % cpp["mem_copy_mb_s"])
    # ---- Audio loopback
    C = "Ports & Peripherals"
    au = X.get("audio") or {}
    res = au.get("result")
    if res == "pass": add(C, "Speaker + microphone self-test", "PASS", "The 1 kHz test tone was played and heard by the microphone (clarity %.0f%%). Both work." % (au["tone_ratio"] * 100))
    elif res == "weak": add(C, "Speaker + microphone self-test", "WARN", "Tone heard only weakly (clarity %.0f%%). Volume low, noisy room, or a weak speaker/mic." % (au["tone_ratio"] * 100), "Raise the volume, repeat in a quiet room.")
    elif res == "silent": add(C, "Speaker + microphone self-test", "WARN", "The tone was not heard. Speaker muted/at 0, microphone muted/blocked, or one of them is faulty.", "Unmute, raise volume, repeat. If still silent, test with the manual speaker + microphone buttons in the report.")
    elif res == "no_output": add(C, "Speaker", "FAIL", "No audio output device exists.", "Reinstall the audio driver.")
    elif res == "no_input": add(C, "Microphone", "FAIL", "No microphone device exists.", "Check privacy settings and the audio driver.")
    else: add(C, "Speaker + microphone self-test", "INFO", au.get("skipped") or au.get("error") or "Not run.")
    inp = X.get("input") or {}
    if inp:
        add(C, "Keyboard hardware check (Windows API)", "PASS", "Type %s, %s function keys. %d monitor(s), screen %s, mouse buttons %s, touch screen %s." % (inp["kbd_type"], inp["kbd_fkeys"], inp["monitors"], inp["screen"], inp["buttons"], "yes" if inp["touch"] else "no"))
        st = inp.get("stuck") or []
        add(C, "Stuck keys", "FAIL" if st else "PASS", ("Key code(s) held down: %s" % st) if st else "No key is stuck down.", "A key is physically jammed or shorted." if st else "")
    sp = X.get("serial") or []
    add(C, "Serial / COM ports (pyserial)", "INFO", ", ".join("%s %s" % (p["port"], p["desc"]) for p in sp) or "none")
    if cn: add(C, "Cross-check by C program", "INFO", "RAM %s MB, %s CPUs, %s monitor(s), %s, uptime %s h, AC=%s" % (cn.get("ram_total_mb"), cn.get("logical_cpus"), cn.get("monitors"), cn.get("screen"), cn.get("uptime_hours"), cn.get("ac_line")))
    nv = X.get("native") or {}
    for lang, nm in (("c", "C"), ("cpp", "C++")):
        r = nv.get(lang)
        if r and not r["ran"]: add("System Health", "%s program" % nm, "INFO", "Skipped: " + r["why"])
    # ---- Security extras
    C = "Security & Malware"
    ex = F("defexcl")
    exl = []
    for k in ("ExclusionPath", "ExclusionExtension", "ExclusionProcess"):
        v = ex.get(k)
        if v: exl += v if isinstance(v, list) else [v]
    if ex:
        add(C, "Defender exclusions (hidden setting)", "WARN" if exl else "PASS", ("%d item(s) are hidden from the virus scanner: %s" % (len(exl), "; ".join(map(str, exl[:6])))) if exl else "None. Defender scans everything.",
            "Malware often adds itself here. Remove any you did not add." if exl else "")
        if ex.get("DisableBehaviorMonitoring") is True: add(C, "Defender behaviour monitoring", "FAIL", "Disabled", "Turn it on in Windows Security.")
    tk = [t for t in L("tasks") if re.search(r"(?i)\\temp\\|appdata|\\users\\public|\.vbs|\.js\b|powershell.+(-enc|hidden)|mshta|wscript|cscript", str(t.get("Action")))]
    add(C, "Scheduled tasks (hidden auto-start)", "FAIL" if tk else "PASS", ("; ".join("%s -> %s" % (t.get("TaskName"), t.get("Action")) for t in tk[:5])) if tk else "%d non-Microsoft task(s), none suspicious" % len(L("tasks")), "Remove tasks you do not recognise." if tk else "")
    osv = L("oddsvc")
    add(C, "Services running from odd folders", "FAIL" if osv else "PASS", "; ".join("%s (%s)" % (v.get("Name"), v.get("PathName")) for v in osv[:5]) if osv else "None", "Check these services." if osv else "")
    odd = pu.get("odd_procs") or []
    if pu: add(C, "Programs running from Temp/Downloads", "WARN" if odd else "PASS", "; ".join("%s" % o["name"] for o in odd[:8]) if odd else "None", "Programs running from Temp or Downloads are a common malware sign." if odd else "")
    cn_ = pu.get("conns") or []
    if pu:
        who = sorted({c["proc"] for c in cn_})
        add(C, "Programs talking to the internet right now", "INFO", "%d connection(s) by: %s" % (len(cn_), ", ".join(who[:12]) or "none"))
    uns = eng.unsigned_drivers((X.get("cmd") or {}).get("driverquery", ""))
    if (X.get("cmd") or {}).get("driverquery"): add(C, "Unsigned drivers (CMD driverquery)", "WARN" if uns else "PASS", ", ".join(uns[:8]) if uns else "All drivers are signed", "Unsigned drivers can hide rootkits. Replace with manufacturer drivers." if uns else "")
    sfc = ((X.get("cmd") or {}).get("sfc") or "").lower()
    if sfc:
        if "did not find any integrity violations" in sfc: add("System Health", "System File Checker (sfc /verifyonly)", "PASS", "No integrity violations")
        elif "integrity violations" in sfc: add("System Health", "System File Checker (sfc /verifyonly)", "FAIL", "Windows system files are damaged or modified.", "Run 'sfc /scannow' as Administrator.")
        else: add("System Health", "System File Checker", "INFO", "Finished, result could not be read automatically.")
    if S("pendreboot") is True: add("System Health", "Restart pending", "WARN", "Windows is waiting for a restart to finish updates.", "Restart the laptop.")
    bt = [num(x) for x in L("boottimes") if not isinstance(x, dict) and num(x) > 0]
    if bt: add("System Health", "Start-up time", "WARN" if sum(bt) / len(bt) > 120000 else "PASS", "%.0f seconds (average of last %d boots)" % (sum(bt) / len(bt) / 1000, len(bt)), "Too many start-up programs or a slow drive." if sum(bt) / len(bt) > 120000 else "")
    # ---- Drivers
    C = "Drivers"
    drv = L("drivers"); old = []
    for d in drv:
        dd = pdate(d.get("DriverDate"))
        if dd and (now - dd).days > 4 * 365: old.append((d, round((now - dd).days / 365.25, 1)))
    if drv:
        add(C, "Hardware drivers (non-Microsoft)", "WARN" if len(old) > max(2, len(drv) * 0.4) else "PASS",
            "%d drivers checked, %d older than 4 years%s" % (len(drv), len(old), (": " + ", ".join("%s (%sy)" % (d.get("DeviceName"), y) for d, y in sorted(old, key=lambda t: -t[1])[:6])) if old else ""),
            "Update drivers from the laptop maker's website (not driver-booster tools)." if old else "")
        X["driver_pct"] = round(100 * (len(drv) - len(old)) / len(drv))
    # ---- battery history
    br = X.get("batrep") or {}
    if br.get("history"): add("Battery", "Battery history (powercfg report)", "INFO", "%d records, from %s to %s" % (len(br["history"]), br["history"][0]["date"], br["history"][-1]["date"]))

# ============================================================= v3: authenticity, registry, events, life
import difflib
AUTH = []
PLACEHOLDER = re.compile(r"(?i)^(to be filled.*|default string|system serial number|not specified|none|n/?a|0+|1+|123456789|1234567890|x+|o\.?e\.?m\.?|unknown|serial ?number|0123456789|.{0,2})$")
VM_RE = re.compile(r"(?i)vmware|virtualbox|innotek|qemu|kvm|xen|hyper-?v|parallels|bochs|virtual machine|bhyve")
REMOTE_RE = re.compile(r"(?i)anydesk|teamviewer|ultraviewer|rustdesk|logmein|screenconnect|connectwise|splashtop|ammyy|supremo|radmin|dwservice|meshagent|remotepc|chrome remote|tightvnc|ultravnc|realvnc|\bvnc\b")
SPY_RE = re.compile(r"(?i)keylog|spyrix|refog|actual spy|ardamax|revealer|flexispy|mspy|spyera|hoverwatch|kidlogger|webwatcher|net ?nanny|employee monitor|stealth ?recorder|invisible")
CRACK_RE = re.compile(r"(?i)\bcrack(ed)?\b|keygen|patcher|\bloader\b|activator|kmspico|kmsauto|autopico|re-?loader|hwidgen|ratiborus|microsoft toolkit|daz loader|chew-?wga|windows loader|repack")
CRITICAL = {"svchost": r"c:\windows\system32\svchost.exe", "lsass": r"c:\windows\system32\lsass.exe", "csrss": r"c:\windows\system32\csrss.exe", "winlogon": r"c:\windows\system32\winlogon.exe",
            "services": r"c:\windows\system32\services.exe", "smss": r"c:\windows\system32\smss.exe", "wininit": r"c:\windows\system32\wininit.exe", "explorer": r"c:\windows\explorer.exe",
            "taskhostw": r"c:\windows\system32\taskhostw.exe", "dwm": r"c:\windows\system32\dwm.exe", "spoolsv": r"c:\windows\system32\spoolsv.exe", "lsm": r"c:\windows\system32\lsm.exe"}

def _n(x): return re.sub(r"[^a-z0-9]", "", str(x or "").lower())
def _same(*vals):
    v = [_n(x) for x in vals if x not in (None, "")]
    v = [x for x in v if x]
    if len(v) < 2: return None
    return all(a in b or b in a for a in v for b in v)
def auth(check, a, b, ok, note=""):
    AUTH.append({"check": check, "a": str(a if a not in (None, "") else "-")[:80], "b": str(b if b not in (None, "") else "-")[:80], "ok": ok, "note": note})
    if ok is False: add("Authenticity (fake data check)", check, "FAIL", "%s  vs  %s%s" % (a, b, (" - " + note) if note else ""), "These sources must agree. A mismatch means the ID was edited, the board/CPU was swapped, or the laptop is not what it claims.")
def _tok(s):
    stop = {"intel", "r", "tm", "cpu", "core", "processor", "amd", "with", "radeon", "graphics", "ghz", "apu"}
    return {t for t in re.findall(r"[a-z0-9\-]+", str(s).lower()) if t not in stop and not re.match(r"^\d\.\d+ghz$", t) and not re.match(r"^\d\.\d+$", t)}

def model_name():
    cs = F("cs"); m, mf = str(cs.get("Model") or ""), str(cs.get("Manufacturer") or "")
    return m if mf and m.lower().startswith(mf.lower()) else ("%s %s" % (mf, m)).strip()

def evaluate_v3():
    now = datetime.datetime.now(); AUTH.clear()
    sm = X.get("smbios") or {}; reg = X.get("registry") or []
    ident = next((r["data"] for r in reg if r.get("area") == "_identity"), {})
    cs, bios, osd = F("cs"), F("bios"), F("os"); cpuw = F("cpu")
    cA = "Authenticity (fake data check)"
    # ---- identity: raw firmware vs WMI vs registry
    if sm.get("system"):
        s = sm["system"]
        for label, a, b, c in (("Model name", s.get("product"), cs.get("Model"), ident.get("SystemProductName")), ("Manufacturer", s.get("manufacturer"), cs.get("Manufacturer"), ident.get("SystemManufacturer")),
                               ("BIOS version", sm["bios"].get("version"), bios.get("SMBIOSBIOSVersion"), ident.get("BIOSVersion"))):
            r = _same(a, b, c)
            auth(label + " (firmware / WMI / registry)", a, "%s | %s" % (b or "-", c or "-"), r, "")
        r = _same(s.get("serial"), bios.get("SerialNumber"))
        auth("Serial number (firmware / WMI)", s.get("serial"), bios.get("SerialNumber"), r, "")
        for nm, val in (("System serial", s.get("serial")), ("Board serial", (sm.get("board") or {}).get("serial"))):
            if val is not None and PLACEHOLDER.match(str(val).strip()):
                add(cA, nm + " is a placeholder", "WARN", "'%s' - the maker never set a real serial number." % val, "Typical of replaced motherboards, clones or tampered firmware. Check the sticker under the laptop.")
        if VM_RE.search("%s %s" % (s.get("manufacturer"), s.get("product"))):
            auth("Is this a real laptop?", s.get("product"), "virtual machine", False, "The firmware says this is a virtual machine, not hardware.")
        else:
            auth("Is this a real laptop?", s.get("product"), "physical hardware", True)
    else:
        add(cA, "Raw firmware table", "INFO", "Could not read the SMBIOS firmware table (needs Windows + Administrator). Identity cross-checks were skipped.")
    # ---- RAM
    sm_mb = sum(m["mb"] for m in sm.get("mem") or [])
    wmi_mb = sum(num(r.get("Capacity")) for r in L("ram")) / 1048576
    os_mb = num(osd.get("TotalVisibleMemorySize")) / 1024
    cprobe = num(((X.get("native") or {}).get("c") or {}).get("data", {}).get("ram_total_mb"))
    if sm_mb and os_mb:
        auth("RAM installed (firmware) vs usable (Windows)", "%d MB" % sm_mb, "%d MB" % os_mb, os_mb <= sm_mb * 1.02 and os_mb >= sm_mb * 0.55, "Windows cannot see more memory than is installed" if os_mb > sm_mb * 1.02 else "")
    if sm_mb and wmi_mb: auth("RAM modules (firmware vs WMI)", "%d MB" % sm_mb, "%d MB" % wmi_mb, abs(sm_mb - wmi_mb) <= max(64, sm_mb * 0.02))
    if cprobe and os_mb: auth("RAM seen by C program vs Windows", "%d MB" % cprobe, "%d MB" % os_mb, abs(cprobe - os_mb) <= max(256, os_mb * 0.1))
    # ---- CPU
    cp = (X.get("native") or {}).get("cpuid", {}).get("data", {})
    if cp.get("cpu_brand"):
        a, b = _tok(cp["cpu_brand"]), _tok(cpuw.get("Name"))
        if a and b: auth("CPU name (chip itself vs Windows)", cp["cpu_brand"], cpuw.get("Name"), len(a & b) >= max(1, min(len(a), len(b)) * 0.5), "")
        tsc, mx = num(cp.get("tsc_ghz")), num(cpuw.get("MaxClockSpeed")) / 1000
        if tsc and mx: auth("CPU clock speed (measured vs claimed)", "%.2f GHz measured" % tsc, "%.2f GHz claimed" % mx, 0.7 <= tsc / mx <= 1.4, "" if 0.7 <= tsc / mx <= 1.4 else "Measured speed differs a lot from the claimed speed.")
        if cp.get("hypervisor_bit") == "1" and not VM_RE.search("%s %s" % (cs.get("Manufacturer"), cs.get("Model"))):
            add(cA, "Virtualization layer", "INFO", "Windows runs on top of a hypervisor (%s). Normal when Hyper-V / Memory Integrity / WSL is on." % (cp.get("hypervisor_vendor") or "unknown"))
    if sm.get("cpu") and cpuw:
        sc = sm["cpu"][0]
        if sc.get("cores") and cpuw.get("NumberOfCores"): auth("CPU cores (firmware vs WMI)", sc["cores"], cpuw.get("NumberOfCores"), int(sc["cores"]) == int(num(cpuw.get("NumberOfCores"))))
    pl = (X.get("psutil") or {}).get("percore")
    if pl and cpuw.get("NumberOfLogicalProcessors"): auth("CPU threads (psutil vs WMI)", len(pl), cpuw.get("NumberOfLogicalProcessors"), len(pl) == int(num(cpuw.get("NumberOfLogicalProcessors"))))
    # ---- battery
    bt = (sm.get("battery") or [None])[0]
    wd = num(F("bat_design").get("DesignedCapacity")) or num(((X.get("batrep") or {}).get("batteries") or [{}])[0].get("DesignCapacity"))
    wf = num(F("bat_full").get("FullChargedCapacity")) or num(((X.get("batrep") or {}).get("batteries") or [{}])[0].get("FullChargeCapacity"))
    if bt and bt.get("design_mwh") and wd: auth("Battery design capacity (firmware vs Windows)", "%d mWh" % bt["design_mwh"], "%d mWh" % wd, abs(bt["design_mwh"] - wd) <= wd * 0.25)
    if wd and wf: auth("Battery full charge is not above brand-new", "%d mWh" % wf, "design %d mWh" % wd, wf <= wd * 1.15, "A used battery cannot hold more than new: the numbers are fake or reset." if wf > wd * 1.15 else "")
    cyc = F("bat_cycle").get("CycleCount")
    if bt and bt.get("date"): add("Battery", "Battery made on", "INFO", "%s (%s %s)" % (bt["date"], bt.get("maker"), bt.get("name")))
    # ---- disks
    runs = ((X.get("native") or {}).get("disktest") or {}).get("runs") or []
    for r in runs:
        bad = num(r.get("disk_mismatches")) > 0 or r.get("disk_write_ok") == "0"
        add("Storage", "Disk read/write integrity %s (C++)" % r.get("root"), "FAIL" if bad else "PASS", ("%s wrong blocks after write+read" % r.get("disk_mismatches")) if bad else "%s MB written and read back identical. Write %s MB/s, read %s MB/s." % (r.get("disk_tested_mb"), r.get("disk_write_mb_s"), r.get("disk_read_mb_s")), "The drive returns wrong data: back up now and replace it." if bad else "")
    vt = sum(num(v.get("Size")) for v in L("vols")); dsz = sum(num(d.get("Size")) for d in L("disks"))
    if vt and dsz: auth("Drive size vs partitions", "%s GB drive" % gb(dsz, 0), "%s GB in partitions" % gb(vt, 0), vt <= dsz * 1.02, "Partitions cannot be bigger than the drive: fake capacity?" if vt > dsz * 1.02 else "")
    # ---- clock
    ck = X.get("clock") or {}
    if ck.get("offline"): add(cA, "Clock check", "INFO", "Offline: could not compare the clock with the internet.")
    elif "drift_s" in ck:
        d = abs(ck["drift_s"])
        add(cA, "System clock", "FAIL" if d > 86400 else "WARN" if d > 300 else "PASS", "%s vs internet time (%s)" % ("off by %.0f seconds" % ck["drift_s"] if d > 5 else "correct within %.0fs" % d, ck.get("source")), "A wrong clock is used to cheat trial software and licences. Set time automatically." if d > 300 else "")
    ne = pdate((F("newest_evt") or {}).get("T"), "%Y-%m-%d %H:%M") or pdate((F("newest_evt") or {}).get("T"))
    if ne and ne > now + datetime.timedelta(minutes=30): add(cA, "System log is dated in the future", "FAIL", "Newest log entry: %s" % ne, "The clock was moved back after these entries were written.")
    rid = next((r["data"] for r in reg if r.get("area") == "_installdate"), None)
    wi = pdate(osd.get("InstallDate"))
    if rid and wi:
        rd = datetime.datetime.fromtimestamp(rid)
        auth("Windows install date (registry vs WMI)", rd.strftime("%Y-%m-%d"), wi.strftime("%Y-%m-%d"), abs((rd - wi).days) <= 2, "")
        if wi > now + datetime.timedelta(days=1): add(cA, "Windows install date is in the future", "FAIL", wi.strftime("%Y-%m-%d"), "Clock was tampered with.")
    # ---- activation / pirated tools
    C = "Security & Malware"
    vb = X.get("vbs") or {}
    if vb:
        st = vb.get("License Status", ""); km = vb.get("Registered KMS machine name") or vb.get("KMS machine name") or ""
        add(C, "Windows licence (VBScript slmgr)", "PASS" if re.search(r"(?i)licensed", st) and "not" not in st.lower() else "WARN", "%s; %s" % (st or "status unreadable", vb.get("Name", "")), "Windows is not properly activated." if not re.search(r"(?i)licensed", st) else "")
        if km and not re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)", km.split(":")[0]) and "." in km:
            add(C, "Windows activated by a KMS server", "FAIL", "KMS host: %s" % km, "Home laptops should not use a KMS server. This is the signature of an illegal activator: it may carry malware and gets blocked by updates.")
    kf, kt = [x for x in L("kmsfiles") if isinstance(x, str)], [x for x in L("kmstasks") if isinstance(x, str)]
    add(C, "Fake-activation tools (KMSpico etc.)", "FAIL" if kf or kt else "PASS", ("Found: " + "; ".join(kf + kt)) if kf or kt else "No activator files or tasks found", "Remove them and use a real licence. These tools often contain trojans." if kf or kt else "")
    hosts = (D.get("hosts") or [[]])[0] or []
    hbad = [h for h in hosts if re.search(r"(?i)activation|validation\.sls|windowsupdate|update\.microsoft|virustotal|malwarebytes|kaspersky|avast|bitdefender|defender|eset|norton|mcafee|sophos", h)]
    hred = [h for h in hosts if re.match(r"^(?!127\.|0\.0\.0\.0|::1)\S+\s+\S+(google|facebook|paypal|bank|microsoft|apple|amazon|youtube)\S*", h, re.I)]
    add(C, "Hosts file (website redirects)", "FAIL" if hbad else "WARN" if hred else "PASS", ("; ".join((hbad + hred)[:4])) if hbad or hred else "%d custom entries, none touching security/update sites" % len(hosts), "These lines block antivirus/updates or redirect big websites. Delete them." if hbad or hred else "")
    # ---- fake / tampered programs
    names = [x.get("DisplayName", "") for x in L("sw")] + [x.get("Name", "") for x in L("startup")] + [str(n) for n in L("procnames")]
    cr = sorted({n for n in names if CRACK_RE.search(str(n))})
    add(C, "Cracked / pirated software", "FAIL" if cr else "PASS", ", ".join(cr[:8]) if cr else "None found by name", "Cracks and loaders are the #1 way malware is installed. Remove them." if cr else "")
    rm = sorted({n for n in names if REMOTE_RE.search(str(n))})
    add(C, "Remote-control software", "WARN" if rm else "PASS", ("Installed or running: " + ", ".join(rm[:8])) if rm else "None found", "Someone with the access code could see and control this laptop. Remove it unless you installed it." if rm else "")
    sp = sorted({n for n in names if SPY_RE.search(str(n))})
    add(C, "Spy / keylogger software", "FAIL" if sp else "PASS", ", ".join(sp[:8]) if sp else "None found by name", "Remove it. It records what you type." if sp else "")
    mism = []
    for p in L("procpaths"):
        nm = str(p.get("Name", "")).lower(); path = str(p.get("Path") or "").lower()
        if nm in CRITICAL and path and path != CRITICAL[nm]: mism.append("%s runs from %s" % (nm, p.get("Path")))
    allp = {str(n).lower().replace(".exe", "") for n in L("procnames")}
    fake = [n for n in allp if n not in CRITICAL and n not in ("taskhost", "taskhostex", "service", "sihost") and any(difflib.SequenceMatcher(None, n, c).ratio() >= 0.86 for c in CRITICAL)]
    add(C, "Fake system programs (name tricks)", "FAIL" if mism or fake else "PASS", ("; ".join(mism + ["look-alike name: " + f for f in fake])[:300]) if mism or fake else "Core Windows processes run from the correct folders", "Malware copies the names svchost, lsass, explorer... Remove it." if mism or fake else "")
    sg = L("sigs")
    if sg:
        hm = [x for x in sg if x.get("Status") == "HashMismatch"]
        bad = [x for x in sg if x.get("Status") in ("NotTrusted", "UnknownError", "Incompatible")]
        un = [x for x in sg if x.get("Status") == "NotSigned"]
        risky = [x for x in un if re.search(r"(?i)\\temp\\|\\appdata\\|\\users\\public\\|\\downloads\\", str(x.get("Path")))]
        add(C, "Program signatures (fake / changed programs)", "FAIL" if hm else "WARN" if bad or risky else "PASS",
            "%d running programs checked: %d valid, %d changed after signing, %d untrusted, %d unsigned (%d of them in Temp/AppData/Downloads)%s" % (len(sg), sum(1 for x in sg if x.get("Status") == "Valid"), len(hm), len(bad), len(un), len(risky), (": " + ", ".join(os.path.basename(str(x.get("Path"))) for x in (hm + bad + risky)[:6])) if hm or bad or risky else ""),
            "A 'changed after signing' program was modified by someone (virus or tampering)." if hm else "Unsigned programs in user folders deserve a check." if risky else "")
    for av in L("av2"):
        nm = str(av.get("Name") or "")
        if re.search(r"(?i)defender", nm) or not av.get("Path") or str(av.get("Path")).lower().startswith("windowsdefender"): continue
        okv = av.get("Exists") and av.get("Status") == "Valid"
        add(C, "Antivirus is genuine: " + nm, "PASS" if okv else "FAIL", "Program file %s, signature %s (%s)" % ("exists" if av.get("Exists") else "MISSING", av.get("Status") or "none", str(av.get("Signer"))[:60]), "Windows lists an antivirus whose file is missing or unsigned: a FAKE antivirus." if not okv else "")
    wp = L("wmipersist")
    add(C, "Hidden WMI auto-run (fileless malware)", "FAIL" if wp else "PASS", ", ".join("%s (%s)" % (w.get("Name"), w.get("Class")) for w in wp[:5]) if wp else "None", "Hidden code runs from the WMI database. Remove with a malware cleaner." if wp else "")
    bj = [b for b in L("bits") if b.get("Url")]
    if bj: add(C, "Background downloads (BITS)", "WARN", "; ".join("%s -> %s" % (b.get("DisplayName"), b.get("Url")) for b in bj[:4]), "Check these downloads are yours.")
    la = [a for a in L("localadmins") if not re.search(r"(?i)administrator$|domain admins", str(a.get("Name")))]
    users = [u.get("Name") for u in L("users")]
    add(C, "Administrator accounts", "INFO" if len(la) <= 2 else "WARN", ", ".join(str(a.get("Name")) for a in la) or "only the built-in Administrator", "More than two admin accounts: confirm you know each one." if len(la) > 2 else "")
    bc = (X.get("bcd") or "").lower()
    if bc:
        flag = [k for k in ("testsigning", "nointegritychecks", "debug") if re.search(k + r"\s+yes", bc)]
        add(C, "Boot security (bcdedit)", "FAIL" if flag else "PASS", ("Switched ON: " + ", ".join(flag)) if flag else "Driver signing is enforced", "These modes allow unsigned or fake drivers (rootkits, cheats, cracks). Turn off: bcdedit /set testsigning off" if flag else "")
    # ---- registry
    byarea = {}
    for r in reg:
        if r["area"].startswith("_") or r["level"] in ("ok", "info"): continue
        byarea.setdefault((r["area"], r["level"]), []).append(r)
    for (area, lvl), items in byarea.items():
        add("Registry scan", area, "FAIL" if lvl == "fail" else "WARN", "; ".join("%s\\%s = %s" % (i["key"], i["name"], i["data"]) for i in items[:4]) + (" (+%d more)" % (len(items) - 4) if len(items) > 4 else ""), items[0]["why"])
    nrun = sum(1 for r in reg if r["area"] == "Auto-start")
    if reg: add("Registry scan", "Auto-start entries", "INFO", "%d entries in Run / RunOnce keys; %d flagged" % (nrun, sum(1 for r in reg if r["area"] == "Auto-start" and r["level"] == "fail")))
    if reg and not byarea: add("Registry scan", "Hijack / policy keys", "PASS", "Winlogon, IFEO, AppInit, BootExecute, security policies, services and DNS are all normal.")
    # ---- event logs
    C = "System Health"
    wh, de, th, mdump = num(S("whea")), num(S("diskerr")), num(S("throttle")), num(S("minidumps"))
    if L("whea") and L("diskerr"):
        add(C, "Hardware error reports (WHEA, 30 days)", "FAIL" if wh > 10 else "WARN" if wh > 0 else "PASS", "%d event(s)" % wh, "The CPU/RAM/PCIe reported corrected or fatal hardware errors. Test RAM, update BIOS." if wh else "")
        add(C, "Disk / file-system errors (30 days)", "FAIL" if de > 20 else "WARN" if de > 0 else "PASS", "%d event(s)" % de, "Back up your data and check the drive." if de else "")
        add(C, "CPU forced to slow down (30 days)", "WARN" if th > 0 else "PASS", "%d event(s) of the firmware limiting CPU speed" % th, "Overheating or a weak charger. Clean fans, check the power adapter." if th else "")
        add(C, "Blue-screen crash dumps", "FAIL" if mdump > 5 else "WARN" if mdump > 0 else "PASS", "%d crash dump file(s)" % mdump, "Repeated blue screens: drivers, RAM or disk." if mdump else "")
    cr = L("crashes")
    if cr: add(C, "Programs that crashed most (30 days)", "INFO", ", ".join("%s x%s" % (c.get("Name"), c.get("Count")) for c in cr))
    md = L("memdiag")
    if md: add(C, "Windows Memory Diagnostic", "INFO", "; ".join("%s: %s" % (m.get("T"), str(m.get("Message"))[:90]) for m in md))
    # ---- camera
    cm = X.get("camera") or {}
    r = cm.get("result")
    if r == "pass": add("Ports & Peripherals", "Camera self-test (OpenCV)", "PASS", "Opened camera %s, got a live picture %sx%s (brightness %s)." % (cm.get("index"), cm.get("w"), cm.get("h"), cm.get("mean")))
    elif r == "dark": add("Ports & Peripherals", "Camera self-test (OpenCV)", "WARN", "Camera works but the picture is black (brightness %s)." % cm.get("mean"), "Privacy shutter closed, lens covered, or a dark room.")
    elif r == "flat": add("Ports & Peripherals", "Camera self-test (OpenCV)", "WARN", "Picture has no detail (flat). Lens covered or sensor fault.")
    elif r in ("none", "no_frame"): add("Ports & Peripherals", "Camera self-test (OpenCV)", "WARN", "No camera could deliver a picture.", "Camera privacy switch/key, Settings > Privacy > Camera, or another app is using it.")
    elif cm.get("skipped") or r == "error": add("Ports & Peripherals", "Camera self-test (OpenCV)", "INFO", cm.get("skipped") or cm.get("error"))
    # ---- the single ACPI temperature must be backed up by other evidence
    cp2 = ((X.get("native") or {}).get("cpp") or {}).get("data", {})
    runs3 = [num(cp2.get("int_ms_run%d" % i)) for i in (1, 2, 3)]
    slow = runs3[0] > 0 and (runs3[2] / runs3[0] - 1) > 0.25
    for f in FINDINGS:
        if f["name"].startswith("Temperature (ACPI") and f["status"] in ("FAIL", "WARN") and not slow and th == 0:
            f["status"] = "WARN"; f["detail"] += " (single ACPI sensor; the CPU speed test stayed steady and Windows logged no slow-downs, so this reading may be a hot idle zone or an inaccurate sensor)"

def life():
    out = []
    bat = F("battery"); design, full = num(F("bat_design").get("DesignedCapacity")), num(F("bat_full").get("FullChargedCapacity"))
    bb = ((X.get("batrep") or {}).get("batteries") or [{}])[0]
    if not (design and full) and bb: design, full = num(bb.get("DesignCapacity")), num(bb.get("FullChargeCapacity"))
    if design and full:
        h = full * 100 / design; left = max(0, min(100, (h - 50) * 2))
        note = "Battery holds %.0f%% of new. Treated as worn out at 50%%." % h
        hist = [x for x in (X.get("batrep") or {}).get("history") or [] if x.get("design")]
        if len(hist) >= 4:
            pts = [(i, x["full"] * 100 / x["design"]) for i, x in enumerate(hist)]
            n = len(pts); mx = sum(p[0] for p in pts) / n; my = sum(p[1] for p in pts) / n
            den = sum((p[0] - mx) ** 2 for p in pts)
            if den:
                slope = sum((p[0] - mx) * (p[1] - my) for p in pts) / den
                d0, d1 = pdate(hist[0]["date"]), pdate(hist[-1]["date"])
                span = max(1, (d1 - d0).days / 30.44) if d0 and d1 else n
                per_month = slope * n / span if span else 0
                if per_month < -0.05 and h > 50: note += " Falling about %.1f%% per month: roughly %d months until 50%%." % (-per_month, (h - 50) / -per_month)
        cyc = F("bat_cycle").get("CycleCount")
        if cyc: note += " %s charge cycles used (typical laptop batteries are rated ~300-500 cycles to 80%%)." % cyc
        out.append({"name": "Battery life left", "pct": round(left), "note": note})
    for r in L("reli"):
        if r.get("Wear") is not None:
            out.append({"name": "SSD life left", "pct": round(max(0, 100 - num(r["Wear"]))), "note": "Drive reports %s%% of its write life used." % r["Wear"]}); break
    else:
        hdd = [d for d in L("disks") if str(d.get("MediaType")).upper() == "HDD"]; poh = [num(r.get("PowerOnHours")) for r in L("reli") if r.get("PowerOnHours")]
        if hdd and poh: out.append({"name": "Hard drive life left", "pct": round(max(0, 100 - max(poh) / 350)), "note": "%d powered-on hours; mechanical drives are usually good for ~35,000 hours." % max(poh)})
    am = (D.get("age") or {}).get("months_best")
    if am is not None: out.append({"name": "Whole laptop (age)", "pct": round(max(0, min(100, 100 - am / 96 * 100))), "note": "%.0f months old; a typical laptop is useful for 6-8 years (rule of thumb)." % am})
    return out

DEVICE_GROUPS = [("Screen", ["monitor"]), ("Graphics", ["display"]), ("Camera", ["camera", "image"]), ("Keyboard", ["keyboard"]), ("Touchpad / mouse", ["mouse"]),
                 ("Bluetooth", ["bluetooth"]), ("Wi-Fi / network", ["net"]), ("Audio", ["media"]), ("Battery", ["battery"]), ("Storage", ["diskdrive"]),
                 ("Processor", ["processor"]), ("Sensors / fingerprint", ["sensor", "biometric"])]

def months_in_service():
    now = datetime.datetime.now(); res = {}
    first = L("dev_first")
    for name, classes in DEVICE_GROUPS:
        ds = [pdate(d.get("First")) for d in first if str(d.get("Class", "")).lower() in classes]
        ds = [d for d in ds if d]
        if ds: res[name] = eng.months_between(min(ds), now)
    # screen: panel manufacture date is a hardware fact (survives Windows reinstall)
    for m in L("monitors"):
        y, w = int(num(m.get("YearOfManufacture"))), int(num(m.get("WeekOfManufacture")))
        if 1990 < y <= now.year:
            try: dt = datetime.datetime.strptime("%d-%d-1" % (y, max(1, min(w, 53)) if w else 1), "%Y-%W-%w")
            except Exception: dt = datetime.datetime(y, 6, 1)
            res["Screen panel (made)"] = eng.months_between(dt, now)
    return res

def estimate_age():
    now = datetime.datetime.now(); ev = []
    inst = pdate(F("os").get("InstallDate"))
    if inst: ev.append(("Windows installed", inst, "software"))
    pr = [pdate(p.get("Created")) for p in L("profile_dates")]
    pr = [p for p in pr if p]
    if pr: ev.append(("Oldest user account folder created", min(pr), "software"))
    fd = [pdate(d.get("First")) for d in L("dev_first")]; fd = [d for d in fd if d]
    if fd: ev.append(("Windows first saw its hardware", min(fd), "software"))
    oe = pdate((F("oldest_event") or {}).get("T"))
    if oe: ev.append(("Oldest system log entry", oe, "software"))
    h = (X.get("batrep") or {}).get("history") or []
    hd = [pdate(x["date"]) for x in h]; hd = [d for d in hd if d]
    if hd: ev.append(("Battery usage tracking began", min(hd), "software"))
    hw = []
    for m in L("monitors"):
        y = int(num(m.get("YearOfManufacture")))
        if 1990 < y <= now.year: hw.append(datetime.datetime(y, 1, 1))
    if hw: ev.append(("Screen panel manufactured (year)", min(hw), "hardware"))
    bd = pdate(F("bios").get("ReleaseDate"))
    if bd: ev.append(("BIOS release date (laptop built on or after)", bd, "hardware"))
    poh = [num(r.get("PowerOnHours")) for r in L("reli") if r.get("PowerOnHours") is not None]
    poh = max(poh) if poh else None
    cyc = F("bat_cycle").get("CycleCount")
    soft = [d for _, d, k in ev if k == "software"]
    first_soft = min(soft) if soft else None
    out = {"evidence": [(n, d.strftime("%Y-%m-%d"), k, eng.months_between(d, now)) for n, d, k in sorted(ev, key=lambda t: t[1])],
           "months_software": eng.months_between(first_soft, now) if first_soft else None,
           "powered_days": round(poh / 24, 1) if poh is not None else None, "cycles": cyc, "flags": []}
    hw_months = [eng.months_between(d, now) for n, d, k in ev if k == "hardware" and "Screen" in n]
    out["months_hardware"] = max(hw_months) if hw_months else None
    best = [m for m in (out["months_software"], out["months_hardware"]) if m is not None]
    out["months_best"] = max(best) if best else None
    if out["powered_days"] is not None and first_soft and out["powered_days"] > (now - first_soft).days + 3:
        out["flags"].append("The drive has been powered on for %.0f days, but Windows is only %d days old: Windows was reinstalled/reset after the laptop was first used." % (out["powered_days"], (now - first_soft).days))
    if hw_months and out["months_software"] is not None and out["months_hardware"] - out["months_software"] > 12:
        out["flags"].append("The screen panel is %.0f months old but Windows shows only %.0f months of use: Windows was reinstalled, or the laptop sat unused / was refurbished." % (out["months_hardware"], out["months_software"]))
    return out

def _cat(cat):
    f = [x for x in FINDINGS if x["cat"] == cat and x["status"] != "INFO"]
    if not f: return None
    return max(0, 100 - 25 * sum(x["status"] == "FAIL" for x in f) - 8 * sum(x["status"] == "WARN" for x in f))

def _dev(key, need=True):
    items = L(key)
    if not items: return 0 if need else None
    badx = [i for i in items if str(i.get("Status", "OK")).upper() not in ("OK", "")]
    return 0 if badx else 100

def components():
    """[(name, percent or None, basis, note)]  basis: measured | software | none"""
    mo = months_in_service(); R = []
    def add_c(name, p, basis, note=""): R.append({"name": name, "pct": None if p is None else max(0, min(100, round(p))), "basis": basis, "note": note, "months": mo.get(name)})
    bat = F("battery"); design, full = num(F("bat_design").get("DesignedCapacity")), num(F("bat_full").get("FullChargedCapacity"))
    bb = ((X.get("batrep") or {}).get("batteries") or [{}])[0]
    if not (design and full) and bb:   # fallback: powercfg battery report
        design, full = num(bb.get("DesignCapacity")), num(bb.get("FullChargeCapacity")); bat = bat or bb
    if bat and design and full: add_c("Battery", full * 100 / design, "measured", "capacity vs. new")
    elif bat: add_c("Battery", None, "none", "capacity not reported")
    else: add_c("Battery", None, "none", "no battery found")
    dk = L("disks"); rl = L("reli")
    if dk:
        p = 100
        for d in dk:
            if str(d.get("HealthStatus")).lower() not in ("healthy", "0"): p = min(p, 20)
        for r in rl:
            if r.get("Wear") is not None: p = min(p, 100 - num(r["Wear"]))
            if num(r.get("ReadErrorsTotal")) + num(r.get("WriteErrorsTotal")) > 0: p = min(p, 30)
        add_c("Storage", p, "measured", "drive health + wear")
    else: add_c("Storage", None, "none", "not reported")
    rt = X.get("ram") or {}
    if rt.get("errors") is not None and rt: add_c("Memory (RAM)", 100 if rt["errors"] == 0 else 0, "measured", "pattern test")
    else: add_c("Memory (RAM)", None, "none", "not tested")
    cpu_p = 100; cp = ((X.get("native") or {}).get("cpp") or {}).get("data", {})
    runs = [num(cp.get("int_ms_run%d" % i)) for i in (1, 2, 3)]
    if runs[0] > 0: cpu_p -= min(40, max(0, (runs[2] / runs[0] - 1) * 100))
    temps = [num(t.get("CurrentTemperature")) / 10 - 273.15 for t in L("thermal") if t.get("CurrentTemperature")]
    if temps and max(temps) > 75: cpu_p -= min(40, (max(temps) - 75) * 3)
    add_c("Processor", cpu_p if (runs[0] > 0 or temps or L("cpu")) else None, "measured" if (runs[0] > 0 or temps) else "software", "speed stability + heat")
    g = L("gpu")
    add_c("Graphics", None if not g else (0 if any(x.get("ConfigManagerErrorCode") for x in g) else 100), "software", "driver status")
    add_c("Screen", 100 if L("monitors") and g and not any(x.get("ConfigManagerErrorCode") for x in g) else None, "software", "detected; dead pixels need the manual test")
    add_c("Camera", _dev("cam"), "software", "detected + driver OK")
    kb = _dev("kbd"); st = (X.get("input") or {}).get("stuck")
    add_c("Keyboard", (50 if st else kb) if kb is not None else None, "software", "detected, no stuck keys; each key needs the manual test")
    add_c("Touchpad / mouse", _dev("mouse"), "software", "detected + driver OK")
    au = (X.get("audio") or {}).get("result")
    if au in ("pass", "weak", "silent", "no_output", "no_input"): add_c("Audio", {"pass": 100, "weak": 70, "silent": 35, "no_output": 0, "no_input": 40}[au], "measured", "tone played and recorded")
    else: add_c("Audio", _dev("audio"), "software", "detected + driver OK")
    add_c("Bluetooth", _dev("bt"), "software", "detected + driver OK")
    wifi = [n for n in L("nics") if "wi-fi" in str(n.get("Name", "")).lower() or "wireless" in str(n.get("InterfaceDescription", "")).lower()]
    add_c("Wi-Fi / network", 100 if wifi else 0, "software", "adapter present")
    usb = L("usbctl"); badu = [b for b in L("badpnp") if "usb" in str(b.get("PNPClass", "")).lower()]
    add_c("USB ports", None if not usb else (40 if badu else 100), "software", "controllers OK; each port needs a plug-in test")
    add_c("Sensors / fingerprint", 100 if temps else None, "software", "thermal sensor present" if temps else "not exposed")
    cm = (X.get("camera") or {}).get("result")
    if cm in ("pass", "dark", "flat", "none", "no_frame"):
        R[[c["name"] for c in R].index("Camera")].update({"pct": {"pass": 100, "dark": 70, "flat": 40, "none": 20, "no_frame": 20}[cm], "basis": "measured", "note": "real picture taken by OpenCV"})
    ok_n = sum(1 for a in AUTH if a["ok"] is True); bad_n = sum(1 for a in AUTH if a["ok"] is False)
    add_c("Authenticity", (100 * ok_n / (ok_n + bad_n) - 10 * bad_n) if (ok_n + bad_n) else None, "measured", "firmware vs Windows vs registry vs chip")
    if L("whea"):
        add_c("Hardware errors", 100 - min(40, 8 * num(S("whea"))) - min(30, 3 * num(S("diskerr"))) - min(20, 4 * num(S("throttle"))) - min(30, 10 * num(S("minidumps"))), "measured", "WHEA / disk / throttling / crash dumps")
    add_c("Drivers", X.get("driver_pct"), "measured", "share younger than 4 years")
    add_c("Security", _cat("Security & Malware"), "measured", "malware / settings")
    add_c("Windows system", _cat("System Health"), "measured", "crashes, files, updates")
    if (D.get("net") or {}).get("ping") is None: add_c("Internet", None, "none", "offline: not tested")
    else: add_c("Internet", _cat("Network & Internet"), "measured", "ping, DNS, speed")
    return R

WEIGHTS = {"Battery": 14, "Storage": 18, "Memory (RAM)": 12, "Processor": 12, "Graphics": 5, "Screen": 6, "Camera": 2, "Keyboard": 5, "Touchpad / mouse": 3,
           "Audio": 3, "Bluetooth": 1, "Wi-Fi / network": 3, "USB ports": 3, "Sensors / fingerprint": 1, "Drivers": 3, "Security": 14, "Windows system": 10, "Internet": 2, "Authenticity": 8, "Hardware errors": 8}

def overall(comps):
    num_, den = 0, 0
    for c in comps:
        if c["pct"] is not None: w = WEIGHTS.get(c["name"], 2); num_ += c["pct"] * w; den += w
    return round(num_ / den) if den else 0

def verdict(score, comps):
    if sum(1 for c in comps if c["pct"] is not None) < 6 and not DEMO:
        return "INCOMPLETE - the scan was blocked", "warn", "Too little could be read to judge this laptop. Follow the 'Settings to change' list, then run again."
    fails = [f for f in FINDINGS if f["status"] == "FAIL"]
    crit = [c for c in comps if c["pct"] is not None and c["pct"] < 40 and c["name"] in ("Storage", "Memory (RAM)", "Battery", "Security", "Windows system", "Processor")]
    if score >= 85 and not fails: return "GOOD laptop - recommended", "ok", "Nothing serious was found. The remaining risks are things software cannot see: do the manual tests."
    if score >= 65 and not crit and len(fails) <= 2: return "AVERAGE - buy / keep only after the fixes below", "warn", "It works, but there are problems that should be fixed or priced in."
    return "BAD laptop - not recommended", "fail", "Serious problems were found" + (": " + ", ".join(c["name"] for c in crit) if crit else ".")

def problems():
    imp = {"Security & Malware": "can steal data or slow everything", "Storage": "data loss / slow", "Battery": "short runtime, swelling risk when very old", "CPU": "slow + hot", "Memory (RAM)": "crashes / freezes", "System Health": "crashes / corruption", "Drivers": "instability / security holes", "Ports & Peripherals": "a part may not work", "Authenticity (fake data check)": "the laptop may not be what it claims", "Registry scan": "hidden start-up or hijack", "Storage": "data loss / slow"}
    out = []
    for st in ("FAIL", "WARN"):
        for f in FINDINGS:
            if f["status"] == st: out.append({"sev": st, "name": f["name"], "detail": f["detail"], "fix": f["fix"], "why": imp.get(f["cat"], "")})
    return out

# ------------------------------------------------------------------ HTML
CSS = """
:root{--bg:#f4f6fb;--card:#fff;--text:#1b2233;--muted:#667085;--line:#e4e7ee;--ok:#14a44d;--warn:#e69a00;--fail:#d92d20;--info:#3b6fd4;--brand:#2b50c8}
@media(prefers-color-scheme:dark){:root{--bg:#0f1420;--card:#171e2e;--text:#e8ecf5;--muted:#9aa5bd;--line:#263049;--brand:#7aa2ff}}
*{box-sizing:border-box}body{margin:0;font:15px/1.5 system-ui,Segoe UI,Arial,sans-serif;background:var(--bg);color:var(--text)}
header{background:linear-gradient(135deg,#1d3a99,#2b50c8);color:#fff;padding:28px 5vw}
header h1{margin:0;font-size:30px}header p{margin:4px 0 0;opacity:.85}
main{max-width:1150px;margin:auto;padding:20px 4vw 60px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:14px;margin:-34px 0 24px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px 18px;box-shadow:0 2px 8px rgba(0,0,0,.06)}
.card .k{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.05em}.card .v{font-size:26px;font-weight:700;margin-top:4px}
.ok{color:var(--ok)}.warn{color:var(--warn)}.fail{color:var(--fail)}.info{color:var(--info)}
h2{margin:30px 0 10px;font-size:20px;border-left:5px solid var(--brand);padding-left:10px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:12px;overflow:hidden}
th,td{padding:9px 12px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top;font-size:14px}th{background:rgba(120,140,200,.12)}
tr:last-child td{border-bottom:0}.b{display:inline-block;min-width:52px;text-align:center;font-weight:700;font-size:11px;padding:3px 8px;border-radius:99px;color:#fff}
.b.PASS{background:var(--ok)}.b.WARN{background:var(--warn)}.b.FAIL{background:var(--fail)}.b.INFO{background:var(--info)}
.fix{color:var(--muted);font-size:13px}.btns{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0}
button,.btn{background:var(--brand);color:#fff;border:0;border-radius:10px;padding:10px 16px;font:600 14px inherit;cursor:pointer;text-decoration:none;display:inline-block}
button.alt{background:transparent;color:var(--brand);border:1px solid var(--brand)}
.tests{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:14px}
.kb{display:flex;flex-direction:column;gap:4px;margin:10px 0}.kr{display:flex;gap:4px}.key{flex:1;min-width:0;text-align:center;font-size:10px;padding:7px 0;border:1px solid var(--line);border-radius:5px;background:rgba(120,140,200,.08)}
.key.hit{background:var(--ok);color:#fff}.key.sp{flex:6}.key.w{flex:1.8}
#fs{position:fixed;inset:0;display:none;z-index:99;cursor:pointer}#fs span{position:absolute;bottom:10px;left:10px;font-size:12px;background:#000a;color:#fff;padding:4px 8px;border-radius:6px}
.bar{height:14px;background:var(--line);border-radius:8px;overflow:hidden}.bar i{display:block;height:100%;width:0;background:var(--ok)}
.pad{height:110px;border:2px dashed var(--line);border-radius:10px;display:flex;align-items:center;justify-content:center;text-align:center;color:var(--muted);user-select:none}
video{width:100%;border-radius:10px;background:#000;max-height:220px}label.ck{display:block;padding:3px 0}
footer{text-align:center;color:var(--muted);padding:30px 10px;font-size:13px}
.note{background:rgba(230,154,0,.12);border:1px solid var(--warn);border-radius:10px;padding:10px 14px;margin:10px 0;font-size:14px}
@media print{header{background:#2b50c8!important;-webkit-print-color-adjust:exact}.btns,#manual{display:none}}
"""
E = lambda s: html.escape(str(s if s is not None else ""))

def page(title, body, script=""):
    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>%s</title><style>%s</style></head><body>%s%s</body></html>"
            % (E(title), CSS, body, ("<script>%s</script>" % script) if script else ""))

def footer():
    return "<footer>%s v%s &middot; developed by <b>%s</b></footer>" % (APP, VERSION, AUTHOR)

def cat_tables(finds, show_fix=True):
    out, cats = [], []
    for f in finds:
        if f["cat"] not in cats: cats.append(f["cat"])
    for c in cats:
        rows = "".join("<tr><td><span class='b %s'>%s</span></td><td>%s</td><td>%s%s</td></tr>" % (
            f["status"], f["status"], E(f["name"]), E(f["detail"]),
            ("<div class='fix'>➜ %s</div>" % E(f["fix"])) if f["fix"] and show_fix else "") for f in finds if f["cat"] == c)
        out.append("<h2>%s</h2><table><tr><th style='width:80px'>Status</th><th style='width:30%%'>Check</th><th>Result</th></tr>%s</table>" % (E(c), rows))
    return "".join(out)

MANUAL = r"""
<h2 id="manual">🧪 Manual tests (things software cannot see)</h2>
<div class="tests" id="manual">
<div class="card"><b>⌨ Keyboard test</b><div class="kb" id="kb"></div><div class="btns"><button id="kbstart">Start</button><span id="kbinfo" class="fix"></span></div><div class="fix">Press every key. Keys turn green. Keys that stay grey do not work.</div></div>
<div class="card"><b>🖥 Screen test (dead pixels / backlight)</b><p class="fix">Full-screen colours. Click to change colour, Esc to exit. Look for dots, lines, yellow patches.</p><button id="scr">Start screen test</button></div>
<div class="card"><b>🔊 Speaker test</b><p class="fix">You should hear a tone only from the side named.</p><div class="btns"><button id="sl">Left</button><button id="sr">Right</button><button id="sb">Both</button></div></div>
<div class="card"><b>🎤 Microphone test</b><p class="fix">Speak: the bar should move.</p><div class="bar"><i id="mbar"></i></div><div class="btns"><button id="mic">Start microphone</button></div></div>
<div class="card"><b>📷 Camera test</b><video id="vid" autoplay muted playsinline></video><div class="btns"><button id="cam">Start camera</button></div></div>
<div class="card"><b>🖱 Touchpad / mouse test</b><div class="pad" id="pad">Click, right-click, scroll or use 2-3 fingers here</div></div>
<div class="card"><b>🔌 Physical checklist</b><div id="chk"></div><p id="chkinfo" class="fix"></p></div>
</div><div id="fs"><span>Click = next colour &middot; Esc = exit</span></div>
"""

MANUAL_JS = r"""
(function(){
var $=function(i){return document.getElementById(i)};
var rows=[["Escape","F1","F2","F3","F4","F5","F6","F7","F8","F9","F10","F11","F12","Delete"],
["Backquote","Digit1","Digit2","Digit3","Digit4","Digit5","Digit6","Digit7","Digit8","Digit9","Digit0","Minus","Equal","Backspace"],
["Tab","KeyQ","KeyW","KeyE","KeyR","KeyT","KeyY","KeyU","KeyI","KeyO","KeyP","BracketLeft","BracketRight","Backslash"],
["CapsLock","KeyA","KeyS","KeyD","KeyF","KeyG","KeyH","KeyJ","KeyK","KeyL","Semicolon","Quote","Enter"],
["ShiftLeft","KeyZ","KeyX","KeyC","KeyV","KeyB","KeyN","KeyM","Comma","Period","Slash","ShiftRight"],
["ControlLeft","MetaLeft","AltLeft","Space","AltRight","ControlRight","ArrowLeft","ArrowUp","ArrowDown","ArrowRight"]];
var total=0,hit={},active=false,kb=$("kb");
rows.forEach(function(r){var d=document.createElement("div");d.className="kr";r.forEach(function(c){total++;var k=document.createElement("div");k.className="key"+(c=="Space"?" sp":(c.length>6&&!/^(Key|Digit)/.test(c)?" w":""));k.id="k_"+c;k.textContent=c.replace(/^Key|^Digit|Left$|Right$/,function(m){return m=="Left"?" L":m=="Right"?" R":""});d.appendChild(k)});kb.appendChild(d)});
function upd(){$("kbinfo").textContent=Object.keys(hit).length+" / "+total+" keys pressed"}
$("kbstart").onclick=function(){active=!active;this.textContent=active?"Stop":"Start";upd()};
document.addEventListener("keydown",function(e){if(!active)return;e.preventDefault();var k=$("k_"+e.code);if(k){k.classList.add("hit");hit[e.code]=1}upd()});
var cols=["#000","#fff","#f00","#0f0","#00f","#808080","#ff0"],ci=0,fs=$("fs");
$("scr").onclick=function(){ci=0;fs.style.background=cols[0];fs.style.display="block";if(fs.requestFullscreen)fs.requestFullscreen()};
fs.onclick=function(){ci++;if(ci>=cols.length){fs.style.display="none";if(document.fullscreenElement)document.exitFullscreen();return}fs.style.background=cols[ci]};
document.addEventListener("fullscreenchange",function(){if(!document.fullscreenElement)fs.style.display="none"});
function tone(p){var A=new(window.AudioContext||window.webkitAudioContext)(),o=A.createOscillator(),g=A.createGain(),s=A.createStereoPanner?A.createStereoPanner():null;o.frequency.value=440;g.gain.value=.25;if(s){s.pan.value=p;o.connect(s);s.connect(g)}else o.connect(g);g.connect(A.destination);o.start();setTimeout(function(){o.stop();A.close()},1200)}
$("sl").onclick=function(){tone(-1)};$("sr").onclick=function(){tone(1)};$("sb").onclick=function(){tone(0)};
$("mic").onclick=function(){navigator.mediaDevices.getUserMedia({audio:true}).then(function(st){var A=new AudioContext(),s=A.createMediaStreamSource(st),an=A.createAnalyser();s.connect(an);var d=new Uint8Array(an.fftSize);(function f(){an.getByteTimeDomainData(d);var m=0;for(var i=0;i<d.length;i++)m=Math.max(m,Math.abs(d[i]-128));$("mbar").style.width=Math.min(100,m*2.2)+"%";requestAnimationFrame(f)})()}).catch(function(e){alert("Microphone not available: "+e.message)})};
$("cam").onclick=function(){navigator.mediaDevices.getUserMedia({video:true}).then(function(st){$("vid").srcObject=st}).catch(function(e){alert("Camera not available: "+e.message)})};
var pad=$("pad");pad.oncontextmenu=function(e){e.preventDefault()};
pad.onmousedown=function(e){pad.textContent=["Left","Middle","Right"][e.button]+" button works ✔"};
pad.onwheel=function(e){e.preventDefault();pad.textContent="Scroll works ✔ ("+(e.deltaY>0?"down":"up")+")"};
pad.ontouchstart=function(e){pad.textContent=e.touches.length+" finger(s) detected ✔"};
var items=["Every USB port (plug in a pen drive)","HDMI / display port","Charger port charges the battery","Headphone jack","SD card slot","Screen hinges open/close smoothly","No cracks, dents or loose parts","Fan spins and is quiet","Wi-Fi connects","Fingerprint / face login (if any)"];
var ch=$("chk");items.forEach(function(t,i){var l=document.createElement("label");l.className="ck";l.innerHTML="<input type='checkbox' data-i='"+i+"'> "+t;ch.appendChild(l)});
ch.onchange=function(){var n=ch.querySelectorAll("input:checked").length;$("chkinfo").textContent=n+" of "+items.length+" confirmed working"};
})();
"""

DL_JS = r"""
function dl(name,mime,txt){var a=document.createElement('a');a.href=URL.createObjectURL(new Blob([txt],{type:mime}));a.download=name;a.click()}
function dlHtml(){dl(document.title.replace(/[^\w.-]+/g,'_')+'.html','text/html','<!doctype html>'+document.documentElement.outerHTML)}
function dlJson(){dl('FindTheLaptop.json','application/json',document.getElementById('data').textContent)}
"""

CSS += """
.who{background:#0d1b4d;color:#fff;padding:8px 5vw;font-size:14px;display:flex;flex-wrap:wrap;gap:6px 22px;align-items:center}.who a{color:#9db8ff}
.who b{font-size:16px}.demo{background:#d92d20;color:#fff;text-align:center;padding:8px;font-weight:700}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:14px}.panel{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px 18px}
.panel h3{margin:0 0 8px;font-size:16px}.hero{display:flex;flex-wrap:wrap;gap:22px;align-items:center}.big{font-size:26px;font-weight:800}
.tag{font-size:11px;padding:2px 8px;border-radius:99px;border:1px solid var(--line);color:var(--muted)}details{margin:8px 0}summary{cursor:pointer;font-weight:600}
.prob{border-left:5px solid var(--warn);background:var(--card);border-radius:10px;padding:8px 12px;margin:8px 0;border-top:1px solid var(--line);border-right:1px solid var(--line);border-bottom:1px solid var(--line)}.prob.FAIL{border-left-color:var(--fail)}
"""

def header(sub):
    return ("<div class='who'><span>👤 <b>%s</b></span><span style='opacity:.7'>%s v%s</span></div>"
            "<header><h1>🔎 %s</h1><p>%s</p></header>" % (E(AUTHOR), APP, VERSION, APP, sub))

def build_reports(host, stamp):
    fails = [f for f in FINDINGS if f["status"] == "FAIL"]
    warns = [f for f in FINDINGS if f["status"] == "WARN"]
    passes = [f for f in FINDINGS if f["status"] == "PASS"]
    comps = D["components"]; score = D["score"]; age = D["age"]; cond = D["condition"]
    buy, bcls, why = D["verdict"]
    cs = F("cs")
    demo = "<div class='demo'>SAMPLE DATA: this report was made in test mode and is NOT a real laptop.</div>" if DEMO else ""
    sub = "Full laptop health report for %s &middot; %s" % (E(model_name() or host), datetime.datetime.now().strftime("%d %b %Y, %H:%M"))
    issues_name = "Issues_%s.html" % stamp
    # ---------- summary
    am = age.get("months_best")
    agetxt = ("%.0f months (about %.1f years)" % (am, am / 12)) if am is not None else "unknown"
    hero = ("<div class='panel hero'>%s<div><div class='k fix'>VERDICT</div><div class='big %s'>%s</div><p>%s</p>"
            "<p><b>Time since first use:</b> %s<br><span class='fix'>Powered-on time: %s &middot; Battery charge cycles: %s</span></p></div>%s</div>"
            % (ch.donut(score, "Overall health", "of 100%"), bcls, E(buy), E(why), E(agetxt),
               ("%s days" % age["powered_days"]) if age.get("powered_days") is not None else "n/a", age.get("cycles") if age.get("cycles") is not None else "n/a",
               ch.pie([("OK", len(passes), "var(--ok)"), ("Warning", len(warns), "var(--warn)"), ("Failed", len(fails), "var(--fail)")])))
    probs = D["problems"]
    ph = "".join("<div class='prob %s'><b>%s</b> <span class='tag'>%s</span><div>%s</div>%s%s</div>" % (p["sev"], E(p["name"]), "PROBLEM FOUND" if p["sev"] == "FAIL" else "NEEDS ATTENTION", E(p["detail"]),
                 ("<div class='fix'>Why it matters: %s</div>" % E(p["why"])) if p["why"] else "", ("<div class='fix'>➜ %s</div>" % E(p["fix"])) if p["fix"] else "") for p in probs[:12])
    bl = D.get("blockers") or []
    bl_html = ("<h2>🔧 Settings to change so the scan can see everything</h2>" + "".join("<div class='prob FAIL'><b>%s</b><div>%s</div></div>" % (E(a), E(b)) for a, b in bl)) if bl else ""
    cleanup_hint = "<div class='panel' style='margin:10px 0'><b>🧹 Want to fix these?</b> Close this window and double-click <b>Run_Cleanup.bat</b>. It scans every folder for malware, junk, hijacks and open doors, shows them in a page, and removes only what you approve (with Undo).</div>" if D.get("problems") else ""
    prob_html = cleanup_hint + "<h2>⚠ What is hurting this laptop</h2>" + (ph or "<p class='ok'>Nothing harmful was found 🎉</p>") + ("<p class='fix'>%d more in the tables below.</p>" % (len(probs) - 12) if len(probs) > 12 else "")
    # ---------- component health
    rows = [(c["name"], c["pct"], c["note"], c["basis"]) for c in comps]
    crow = "".join("<tr><td>%s</td><td><b class='%s'>%s</b></td><td><span class='tag'>%s</span></td><td>%s</td><td class='fix'>%s</td></tr>" % (
        E(c["name"]), ("ok" if c["pct"] >= 80 else "warn" if c["pct"] >= 55 else "fail") if c["pct"] is not None else "info", ("%d%%" % c["pct"]) if c["pct"] is not None else "n/a",
        {"measured": "measured", "software": "software check only", "none": "no data"}[c["basis"]], ("%.0f months" % c["months"]) if c.get("months") is not None else "&ndash;", E(c["note"])) for c in comps)
    comp_html = ("<h2>📊 Exact health of every part (percentage)</h2><div class='panel'>%s<p class='fix'>100%% = no fault visible to software. Solid bars were measured; pale bars with * are software checks only. &ldquo;software check only&rdquo; parts (screen, keys, ports, camera) can still have physical damage: use the manual tests at the bottom.</p></div>"
                 "<details open><summary>Table: health, how it was checked, and months since first used</summary><table><tr><th>Part</th><th>Health</th><th>How</th><th>In service</th><th>Note</th></tr>%s</table></details>" % (ch.hbars(rows), crow))
    # ---------- charts
    mo = months_in_service()
    bh = (X.get("batrep") or {}).get("history") or []
    bpts = [(h["date"], round(h["full"] * 100 / h["design"], 1)) for h in bh if h.get("design")] or [(h["date"], h["full"]) for h in bh]
    vols = [(v.get("DeviceID"), int(100 - num(v.get("FreeSpace")) * 100 / max(num(v.get("Size")), 1)), "%s GB free of %s GB" % (gb(v.get("FreeSpace")), gb(v.get("Size"), 0))) for v in L("vols")]
    charts = ("<h2>📈 Graphs</h2><div class='grid2'>"
              "<div class='panel'><h3>Months each part has been in use</h3>%s<p class='fix'>From the date Windows first saw the part (resets if Windows was reinstalled) and the screen's factory date.</p></div>"
              "<div class='panel'><h3>Battery capacity over time</h3>%s<p class='fix'>%% of original capacity (powercfg battery report). Falling line = wearing out.</p></div>"
              "<div class='panel'><h3>Storage used</h3>%s</div>"
              "<div class='panel'><h3>CPU load per core (now)</h3>%s%s</div></div>"
              % (ch.vbars(sorted(mo.items(), key=lambda t: -t[1])), ch.line(bpts, "%" if bh and bh[0].get("design") else " mWh", title="Battery"), ch.stack(vols) or "<p class='fix'>No drives found.</p>",
                 ch.cores((X.get("psutil") or {}).get("percore") or []) or "<p class='fix'>psutil not available.</p>", bench_html()))
    # ---------- age
    arows = "".join("<tr><td>%s</td><td>%s</td><td>%.0f months ago</td><td><span class='tag'>%s</span></td></tr>" % (E(n), d, m, k) for n, d, k, m in age["evidence"])
    aflags = "".join("<div class='note'>⚠ %s</div>" % E(f) for f in age["flags"])
    age_html = ("<h2>⏳ How long has this laptop been used?</h2>%s<table><tr><th>Evidence</th><th>Date</th><th>Age</th><th>Type</th></tr>%s</table>"
                "<p class='fix'>&ldquo;software&rdquo; dates reset when Windows is reinstalled. &ldquo;hardware&rdquo; dates (screen factory date, drive power-on hours, battery cycles) cannot be reset. Best estimate: %s.</p>" % (aflags, arows or "<tr><td colspan=4>No dates available.</td></tr>", E(agetxt)))
    # ---------- v3 sections: authenticity, life, registry
    sm = X.get("smbios") or {}
    ar = "".join("<tr><td>%s</td><td>%s</td><td>%s</td><td><span class='b %s'>%s</span></td></tr>" % (E(a["check"]), E(a["a"]), E(a["b"]), "PASS" if a["ok"] is True else "FAIL" if a["ok"] is False else "INFO", "MATCH" if a["ok"] is True else "MISMATCH" if a["ok"] is False else "n/a") for a in AUTH)
    mem_rows = "".join("<tr><td>%s</td><td>%s MB</td><td>%s MT/s</td><td>%s</td><td>%s</td></tr>" % (E(m["slot"]), m["mb"], m["mhz"] or "?", E(m["maker"]), E(m["part"])) for m in sm.get("mem") or [])
    bt_ = (sm.get("battery") or [None])[0]
    bat_row = ("<tr><td>Battery (firmware)</td><td colspan=4>%s %s &middot; made %s &middot; design %s mWh &middot; %s mV</td></tr>" % (E(bt_["maker"]), E(bt_["name"]), E(bt_["date"] or "?"), bt_["design_mwh"], bt_["volt_mv"])) if bt_ else ""
    ac = next((c for c in comps if c["name"] == "Authenticity"), None)
    auth_html = ("<h2>🧬 Is the data real? (fake / tampered data check)</h2><div class='panel hero'>%s<div><p>Every important fact is read from <b>several independent places</b>: the firmware table itself, Windows WMI, the registry, the CPU chip (CPUID), and speed/measurement tests. If they disagree, something was edited, swapped or faked.</p>"
                 "<p class='fix'>Matches: %d &middot; Mismatches: %d</p></div></div><table><tr><th>Check</th><th>Source A</th><th>Source B</th><th>Result</th></tr>%s</table>%s%s" % (
                 ch.donut(ac["pct"] if ac and ac["pct"] is not None else 0, "Authenticity", "data is real"), sum(1 for a in AUTH if a["ok"] is True), sum(1 for a in AUTH if a["ok"] is False), ar or "<tr><td colspan=4>Firmware table could not be read (needs Administrator).</td></tr>",
                 ("<h3>RAM modules (read from firmware)</h3><table><tr><th>Slot</th><th>Size</th><th>Speed</th><th>Maker</th><th>Part number</th></tr>%s</table>" % mem_rows) if mem_rows else "",
                 ("<table>%s</table>" % bat_row) if bat_row else "")) if (AUTH or sm) else ""
    lf = D.get("life") or []
    life_html = ("<h2>⏳ Estimated life left</h2><div class='panel'>%s<table style='margin-top:10px'>%s</table><p class='fix'>Estimates from wear numbers and rules of thumb, not guarantees.</p></div>" % (
                 ch.hbars([(x["name"], x["pct"], x["note"]) for x in lf]), "".join("<tr><td><b>%s</b></td><td class='fix'>%s</td></tr>" % (E(x["name"]), E(x["note"])) for x in lf))) if lf else ""
    rg = X.get("registry") or []
    rrows = "".join("<tr><td>%s</td><td>%s</td><td>%s</td><td style='word-break:break-all'>%s</td><td><span class='b %s'>%s</span></td></tr>" % (E(r["area"]), E(r["key"]), E(r["name"]), E(r["data"]), {"fail": "FAIL", "warn": "WARN"}.get(r["level"], "INFO"), r["level"].upper()) for r in rg if not r["area"].startswith("_") and r["level"] != "ok")
    reg_html = ("<h2>🗝 Registry scan (everything Windows starts or changes)</h2><div style='max-height:420px;overflow:auto'><table><tr><th>Area</th><th>Key</th><th>Name</th><th>Data</th><th>Level</th></tr>%s</table></div>" % rrows) if rrows else ""
    # ---------- previous blocks
    cn = "".join("<tr><td>%s</td><td>%s</td></tr>" % (E(t), "●" * p or "–") for t, p in cond["notes"])
    flags = "".join("<div class='note'>⚠ %s</div>" % E(f) for f in cond["flags"])
    condhtml = ("<h2>🕵 Is it new, old, or used by someone else?</h2><p><b>%s</b></p>%s<table><tr><th>Evidence</th><th style='width:110px'>Wear</th></tr>%s</table>"
                "<p class='fix'>Indicators, not proof. A reseller can wipe Windows, but cannot reset disk hours, battery cycles or USB history.</p>" % (E(cond["verdict"]), flags, cn))
    sw_rows = "".join("<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (E(s.get("DisplayName")), E(s.get("DisplayVersion")), E(s.get("Publisher"))) for s in L("sw"))
    swhtml = "<h2>📦 All installed software</h2><div style='max-height:420px;overflow:auto'><table><tr><th>Name</th><th>Version</th><th>Publisher</th></tr>%s</table></div>" % sw_rows
    su_rows = "".join("<tr><td>%s</td><td>%s</td></tr>" % (E(s.get("Name")), E(s.get("Command"))) for s in L("startup"))
    suhtml = "<h2>🚀 Startup programs</h2><div style='max-height:300px;overflow:auto'><table><tr><th>Name</th><th>Command</th></tr>%s</table></div>" % su_rows
    # ---------- engines
    lrows = "".join("<tr><td>%s</td><td>%s</td><td><span class='b %s'>%s</span> %s</td><td class='fix'>%s</td></tr>" % (E(k), E(v["purpose"]), "PASS" if v["ok"] else "WARN", "USED" if v["ok"] else "MISSING", E(v["ver"]), E(v["note"])) for k, v in eng.LIBS.items())
    langs = {}
    for c in eng.LOG: langs.setdefault(c["shell"].split("/")[0], []).append(c)
    lg = "".join("<tr><td>%s</td><td>%d</td><td>%s</td></tr>" % (E(k), len(v), E("; ".join(sorted({x["cmd"][:48] for x in v}))[:150])) for k, v in sorted(langs.items()))
    nat = X.get("native") or {}
    nrows = "".join("<tr><td>%s</td><td>%s</td></tr>" % (n, ("ran OK" if (nat.get(k) or {}).get("ran") else "skipped: " + E((nat.get(k) or {}).get("why", "not run")))) for k, n in (("c", "C program"), ("cpp", "C++ program")))
    crows = "".join("<tr><td>%s</td><td>%s</td><td>%s s</td><td>%s</td></tr>" % (E(c["shell"]), E(c["cmd"]), c["secs"], "✔" if c["ok"] else "✖ " + E(c["note"])) for c in eng.LOG)
    eng_html = ("<h2>🧰 Tools used for this report</h2><div class='grid2'><div class='panel'><h3>Python libraries</h3><table><tr><th>Library</th><th>Used for</th><th>Status</th><th></th></tr>%s</table></div>"
                "<div class='panel'><h3>Languages / shells</h3><table><tr><th>Shell</th><th>Commands</th><th>Examples</th></tr>%s</table><table style='margin-top:10px'>%s</table></div></div>"
                "<details><summary>Every command that was run (%d)</summary><div style='max-height:340px;overflow:auto'><table><tr><th>Shell</th><th>Command</th><th>Time</th><th>OK</th></tr>%s</table></div></details>" % (lrows, lg, nrows, len(eng.LOG), crows))
    data = json.dumps({"app": APP, "version": VERSION, "author": AUTHOR, "generated": datetime.datetime.now().isoformat(), "score": score, "verdict": buy,
                       "months_since_first_use": age.get("months_best"), "components": comps, "age": age, "condition": cond, "findings": FINDINGS, "libraries": eng.LIBS, "commands": eng.LOG, "authenticity": AUTH, "life": D.get("life"), "registry": [r for r in (X.get("registry") or []) if not r["area"].startswith("_")], "smbios": X.get("smbios")},
                      ensure_ascii=False, default=str).replace("</", "<\\/")
    btns = ("<div class='btns'><button onclick='dlHtml()'>⬇ Download this report (HTML)</button><button class='alt' onclick='dlJson()'>⬇ Download data (JSON)</button>"
            "<button class='alt' onclick='window.print()'>🖨 Save as PDF / Print</button><a class='btn alt' href='%s'>🛠 Open issues-only report</a></div>" % issues_name)
    body = (demo + header(sub) + "<main><div style='height:16px'></div>" + hero + btns + bl_html + prob_html + comp_html + charts + age_html + auth_html + life_html + condhtml + cat_tables(FINDINGS) + reg_html + eng_html + suhtml + swhtml + MANUAL + "</main>" + footer()
            + "<script type='application/json' id='data'>%s</script>" % data)
    main_html = page("FindTheLaptop_%s" % stamp, body, DL_JS + MANUAL_JS)
    ib = ["<div class='cards' style='margin-top:16px'><div class='card'><div class='k'>Not working</div><div class='v fail'>%d</div></div><div class='card'><div class='k'>Needs attention</div><div class='v warn'>%d</div></div>"
          "<div class='card'><div class='k'>Verdict</div><div class='v %s' style='font-size:18px'>%s</div></div><div class='card'><div class='k'>Health</div><div class='v'>%d%%</div></div></div>" % (len(fails), len(warns), bcls, E(buy), score)]
    ib.append("<div class='btns'><button onclick='window.print()'>🖨 Save as PDF / Print</button><button class='alt' onclick='dlHtml()'>⬇ Download (HTML)</button><a class='btn alt' href='FindTheLaptop_%s.html'>⬅ Back to full report</a></div>" % stamp)
    ib.append(prob_html if probs else "<h2 class='ok'>No problems found 🎉</h2>")
    ib.append("<p class='fix'>Dead pixels, loose ports and a bad hinge need the manual tests in the full report.</p>")
    issues_html = page("Issues_%s" % stamp, demo + header("Issues-only report for %s &middot; %s" % (E(cs.get("Model", host)), datetime.datetime.now().strftime("%d %b %Y, %H:%M"))) + "<main>" + "".join(ib) + "</main>" + footer(), DL_JS)
    return main_html, issues_html, data, issues_name


# ------------------------------------------------------------- never-stop helpers
class Tee:
    """Copy everything printed to a log file, so errors can be read even if the window closes."""
    def __init__(self, path):
        self.f = open(path, "a", encoding="utf-8", errors="replace"); self.o = sys.stdout
    def write(self, t):
        try: self.o.write(t); self.f.write(t)
        except Exception: pass
    def flush(self):
        try: self.o.flush(); self.f.flush()
        except Exception: pass

STAGE_ERRORS = []
def stage(name, fn, default=None):
    """Run a step; if it crashes, record why and carry on with a safe default (never stop)."""
    try:
        return fn()
    except BaseException as e:
        if isinstance(e, KeyboardInterrupt): raise
        import traceback
        STAGE_ERRORS.append((name, "%s: %s" % (type(e).__name__, e)))
        print("\n  ! Step '%s' failed (%s). Continuing with the next step..." % (name, e))
        try:
            with open(os.path.join(BASE, "Reports", "error_details.txt"), "a", encoding="utf-8") as fh:
                fh.write("--- %s ---\n%s\n" % (name, traceback.format_exc()))
        except Exception: pass
        return default

def ensure_libs():
    """Alternative path: if the launcher could not install libraries, try here (online only)."""
    missing = []
    for pipn, imp, _ in eng.LIB_SPEC:
        try: __import__(imp.split(".")[0])
        except Exception: missing.append(pipn)
    need_cc = not (shutil.which("gcc") or shutil.which("clang"))
    if need_cc: missing.append("ziglang")          # C/C++ compiler delivered as a Python package
    if not missing: return
    try:
        socket.create_connection(("pypi.org", 443), timeout=5).close()
    except Exception:
        print("  Offline: cannot download missing libraries (%s). Continuing without them." % ", ".join(missing)); return
    print("  Downloading and installing missing libraries: %s" % ", ".join(missing))
    for pk in missing:
        for extra in ([], ["--user"], ["--user", "--trusted-host", "pypi.org", "--trusted-host", "files.pythonhosted.org"]):
            r = subprocess.run([sys.executable, "-m", "pip", "install", "-q", "--disable-pip-version-check", pk] + extra, capture_output=True, timeout=900)
            eng.log("Python/pip", "pip install %s %s" % (pk, " ".join(extra)), 0, r.returncode == 0)
            if r.returncode == 0: break
    import importlib; importlib.invalidate_caches()

def blockers():
    """Plain-language list of settings that stopped or limited the scan, and what to change."""
    out = []
    try:
        import ctypes
        if IS_WIN and not ctypes.windll.shell32.IsUserAnAdmin():
            out.append(("Run as Administrator", "Not running as Administrator, so disk wear, BitLocker, Defender settings and some event logs could not be read. Close this window, start again and click YES on the Windows prompt."))
    except Exception: pass
    if IS_WIN and not DEMO:
        empty = [k for k in ("cs", "bios", "os", "disks", "mp") if not D.get(k)]
        if len(empty) >= 3:
            out.append(("PowerShell looks blocked", "Most PowerShell queries returned nothing (%s). An antivirus or company policy is probably blocking PowerShell. Pause your third-party antivirus for a few minutes, or add this folder to its exclusions, then run again." % ", ".join(empty)))
    mp = F("mp")
    if mp and mp.get("RealTimeProtectionEnabled") is False:
        out.append(("Virus protection is OFF", "Windows Security > Virus & threat protection > Manage settings > turn ON Real-time protection."))
    if S("cfa") in (1, True):
        out.append(("Controlled folder access is ON", "It can block reports from being saved. If a report is missing: Windows Security > Virus & threat protection > Ransomware protection > allow python.exe, or turn it off for this run."))
    if str(S("mic_priv")).lower() == "deny":
        out.append(("Microphone access is OFF", "Settings > Privacy & security > Microphone > turn ON 'Microphone access' and 'Let desktop apps access your microphone', so the sound test can listen."))
    au = X.get("audio") or {}
    if au.get("result") == "error":
        out.append(("Sound test could not run", "%s. Check that a speaker and microphone are enabled in Sound settings, and that no other app is using them." % au.get("error")))
    miss = [k for k, v in eng.LIBS.items() if not v["ok"]]
    if miss and not DEMO:
        out.append(("Some Python libraries are missing", "%s. Connect to the internet and run again (the launcher installs them), or run Prepare_Offline.bat once while online." % ", ".join(miss)))
    nat = X.get("native") or {}
    if nat and not any((nat.get(k) or {}).get("ran") for k in ("c", "cpp")):
        out.append(("No C / C++ compiler", "The C and C++ checks were skipped. Run again online and choose the full check: the launcher installs a compiler (WinLibs) with winget."))
    for n, why in STAGE_ERRORS:
        out.append(("A step failed: " + n, why + " (the rest of the scan still finished; details in Reports\\error_details.txt)"))
    return out

def bench_html():
    cp = ((X.get("native") or {}).get("cpp") or {}).get("data", {})
    py = (X.get("pybench") or {}).get("runs_ms")
    r = []
    if cp: r += [("C++ integer test, 3 runs", "%s / %s / %s ms" % (cp.get("int_ms_run1"), cp.get("int_ms_run2"), cp.get("int_ms_run3"))), ("C++ multi-core scaling", "x%s on %s threads" % (cp.get("multi_core_scaling"), cp.get("threads"))), ("Memory copy speed", "%s MB/s" % cp.get("mem_copy_mb_s"))]
    if py: r.append(("Python loop test, 4 runs", " / ".join(map(str, py)) + " ms"))
    if not r: return ""
    return "<table style='margin-top:10px'>%s</table>" % "".join("<tr><td>%s</td><td>%s</td></tr>" % (E(a), E(b)) for a, b in r)

def open_in_browser(url):
    """Open directly in Microsoft Edge, else Chrome, else the default browser."""
    if IS_WIN:
        for exe in ("msedge", "chrome", "firefox"):
            try:
                if subprocess.run('start "" %s "%s"' % (exe, url), shell=True, capture_output=True, timeout=15).returncode == 0:
                    return exe
            except Exception:
                pass
    webbrowser.open(url)
    return "default browser"

def deep_scans():
    """Optional slow checks (Defender quick scan). Run in a background thread while the rest is analysed."""
    t0 = time.time()
    run(["powershell", "-NoProfile", "-Command", "Start-MpScan -ScanType QuickScan"], 900, "PowerShell 5.1")
    D["threats_after"] = psj("Get-MpThreatDetection | select -First 20 ThreatID,ProcessName", 60)

def serve(folder, first):
    class H(SimpleHTTPRequestHandler):
        def __init__(self, *a, **k): super().__init__(*a, directory=folder, **k)
        def log_message(self, *a): pass
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, "http://127.0.0.1:%d/%s" % (srv.server_address[1], first)

def main():
    quick = "--quick" in sys.argv
    os.makedirs(os.path.join(BASE, "Reports"), exist_ok=True)
    try: sys.stdout = Tee(os.path.join(BASE, "Reports", "run_log.txt"))
    except Exception: pass
    if os.name == "nt":
        os.system("title %s - by %s" % (APP, AUTHOR))
    print("=" * 62); print("  %s v%s" % (APP.upper(), VERSION)); print("  %s" % AUTHOR); print("=" * 62)
    if not IS_WIN and not DEMO:
        print("This tool only works on Windows 10/11."); return
    if not DEMO and "--consented" not in sys.argv:
        print("\nThis tool will read your hardware, settings and security state, play a short test tone,\n"
              "listen briefly with the microphone (nothing is saved), and run CMD/PowerShell/C/C++ commands.\nNothing is uploaded.")
        if input("Continue? [Y/N]: ").strip().lower() not in ("y", "yes"): print("Cancelled."); return
    bg = None
    if DEMO:
        import ftl_demo; ftl_demo.fill(D, X, eng); print("\n[TEST MODE] using sample data.")
    else:
        stage("install libraries", ensure_libs)
        print("\n[1/4] Reading hardware, security, software and running Python / CMD / PowerShell / C / C++ tools...")
        if not quick:
            bg = threading.Thread(target=deep_scans, daemon=True); bg.start()
        stage("collect", lambda: collect(deep=not quick))
        print("[2/4] Testing internet connection (skipped automatically when offline)...")
        D["net"] = stage("network tests", network_tests, {})
        if bg:
            print("[3/4] Waiting for the Defender quick scan (up to 15 min; use --quick to skip)...")
            bg.join(900)
    print("[4/4] Analysing results...")
    stage("evaluate", evaluate); stage("evaluate extras", evaluate_extras); stage("authenticity + registry + events", evaluate_v3)
    ta = D.get("threats_after") or []
    if ta: add("Security & Malware", "Defender quick scan (just now)", "FAIL", "%d threat(s) on record after scanning" % len(ta), "Open Windows Security > Protection history and remove them.")
    elif not DEMO and not quick and "threats_after" in D: add("Security & Malware", "Defender quick scan (just now)", "PASS", "Completed, no threats found")
    D["condition"] = stage("condition", assess_condition, {"verdict": "unknown", "cls": "warn", "points": 0, "notes": [], "flags": []})
    D["age"] = stage("age", estimate_age, {"evidence": [], "months_software": None, "months_hardware": None, "months_best": None, "powered_days": None, "cycles": None, "flags": []})
    comps = stage("components", components, []); D["components"] = comps
    D["score"] = stage("score", lambda: overall(comps), 0); D["verdict"] = stage("verdict", lambda: verdict(D["score"], comps), ("Result incomplete - see notes", "warn", "Some steps failed; see the settings list."))
    D["life"] = stage("life", life, []); D["problems"] = stage("problems", problems, []); D["blockers"] = stage("blockers", blockers, [])
    host = (F("cs").get("Model") or os.environ.get("COMPUTERNAME", "PC"))
    stamp = "%s_%s" % (re.sub(r"[^\w-]+", "_", str(host))[:30], datetime.datetime.now().strftime("%Y%m%d_%H%M"))
    out = os.path.join(BASE, "Reports" if not DEMO else "Reports_demo"); os.makedirs(out, exist_ok=True)
    main_name = "FindTheLaptop_%s.html" % stamp
    built = stage("build report", lambda: build_reports(host, stamp))
    if built:
        main_html, issues_html, data, issues_name = built
        for n, c in ((main_name, main_html), (issues_name, issues_html)):
            with open(os.path.join(out, n), "w", encoding="utf-8") as fh: fh.write(c)
        with open(os.path.join(out, "FindTheLaptop_%s.json" % stamp), "w", encoding="utf-8") as fh: fh.write(data.replace("<\\/", "</"))
    else:   # emergency plain report so you always get a result
        rows = "".join("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (E(f["status"]), E(f["cat"]), E(f["name"]), E(f["detail"])) for f in FINDINGS)
        with open(os.path.join(out, main_name), "w", encoding="utf-8") as fh:
            fh.write(page("Emergency report", header("Basic report (the full report failed)") + "<main><table>%s</table></main>" % rows + footer()))
    print("\nHEALTH %d%%  -  %s\nReports saved in: %s" % (D["score"], D["verdict"][0], out))
    for a_, b_ in (D.get("blockers") or []): print("  SETTING: %s - %s" % (a_, b_))
    srv, url = serve(out, main_name)
    if DEMO: print("Report: " + os.path.join(out, main_name)); return
    print("Opening in %s: %s" % (open_in_browser(url), url))
    print("\nKeep this window open while you use the report (camera/mic tests).")

def pause_forever():
    try: input("\nPress ENTER to close this window...")
    except Exception: time.sleep(600)

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: pass
    except BaseException:
        import traceback; traceback.print_exc()
        print("\nSomething went wrong. The details above (and Reports\\run_log.txt) show why.")
    if not DEMO: pause_forever()
