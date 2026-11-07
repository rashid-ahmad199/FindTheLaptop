# -*- coding: utf-8 -*-
"""SAMPLE data used only by test mode (FTL_DEMO=1) to check the report layout. Not a real laptop."""
import datetime

def fill(D, X, eng):
    today = datetime.date.today()
    ago = lambda days: (today - datetime.timedelta(days=days)).strftime("%Y-%m-%d")
    D.update({
        "cs": [{"Manufacturer": "SAMPLE", "Model": "Demo Laptop 15", "SystemType": "x64-based PC", "TotalPhysicalMemory": 8 * 1024**3, "UserName": "DEMO\\user", "Domain": "WORKGROUP", "PartOfDomain": False}],
        "bios": [{"Manufacturer": "SAMPLE", "SMBIOSBIOSVersion": "1.12", "SerialNumber": "DEMO12345", "ReleaseDate": ago(1100)}],
        "board": [{"Manufacturer": "SAMPLE", "Product": "BoardX", "SerialNumber": "B123", "Version": "A"}],
        "cpu": [{"Name": "Demo CPU i5", "NumberOfCores": 4, "NumberOfLogicalProcessors": 8, "MaxClockSpeed": 3400, "LoadPercentage": 12, "VirtualizationFirmwareEnabled": True}],
        "ram": [{"Manufacturer": "X", "PartNumber": "P", "Capacity": 8 * 1024**3, "Speed": 3200, "BankLabel": "A"}],
        "os": [{"Caption": "Microsoft Windows 11 Home", "Version": "10.0", "BuildNumber": "26100", "OSArchitecture": "64-bit", "FreePhysicalMemory": 3000000, "TotalVisibleMemorySize": 8000000, "InstallDate": ago(300), "LastBoot": ago(1) + " 09:00"}],
        "disks": [{"FriendlyName": "Demo NVMe 512GB", "MediaType": "SSD", "BusType": "NVMe", "HealthStatus": "Healthy", "OperationalStatus": "OK", "Size": 512 * 10**9}],
        "reli": [{"DeviceId": "0", "PowerOnHours": 5200, "Wear": 12, "Temperature": 41, "ReadErrorsTotal": 0, "WriteErrorsTotal": 0}],
        "vols": [{"DeviceID": "C:", "VolumeName": "", "FileSystem": "NTFS", "Size": 480 * 10**9, "FreeSpace": 120 * 10**9}],
        "gpu": [{"Name": "Demo Graphics", "DriverVersion": "31.0", "CurrentHorizontalResolution": 1920, "CurrentVerticalResolution": 1080, "CurrentRefreshRate": 60, "ConfigManagerErrorCode": 0}],
        "monitors": [{"Name": "DemoPanel", "Maker": "SMP", "WeekOfManufacture": 20, "YearOfManufacture": today.year - 3}],
        "battery": [{"Name": "Demo", "EstimatedChargeRemaining": 80, "BatteryStatus": 2}],
        "bat_design": [{"DesignedCapacity": 50000, "ManufactureName": "X"}], "bat_full": [{"FullChargedCapacity": 36500}], "bat_cycle": [{"CycleCount": 410}],
        "thermal": [{"InstanceName": "TZ", "CurrentTemperature": 3280}],
        "badpnp": [], "audio": [{"Name": "Demo Audio", "Status": "OK"}], "cam": [{"FriendlyName": "Demo Cam", "Status": "OK"}], "bt": [{"FriendlyName": "BT", "Status": "OK"}],
        "kbd": [{"Name": "Standard keyboard", "Status": "OK"}], "mouse": [{"Name": "Touchpad", "Status": "OK"}], "usbctl": [{"Name": "USB xHCI", "Status": "OK"}], "usbdev": [],
        "nics": [{"Name": "Wi-Fi", "InterfaceDescription": "Wireless AX", "Status": "Up", "LinkSpeed": "866 Mbps", "MacAddress": "AA", "PhysicalMediaType": "Native 802.11"}],
        "av": [{"displayName": "Windows Defender", "productState": 397568}],
        "mp": [{"AntivirusEnabled": True, "RealTimeProtectionEnabled": True, "AntivirusSignatureAge": 1, "QuickScanAge": 12, "IsTamperProtected": True}],
        "threats": [], "fw": [{"Name": "Domain", "Enabled": 1}, {"Name": "Private", "Enabled": 1}, {"Name": "Public", "Enabled": 1}],
        "tpm": [{"TpmPresent": True, "TpmReady": True}], "secboot": [True], "smb1": [{"EnableSMB1Protocol": False}], "rdp": [{"fDenyTSConnections": 1}], "uac": [{"EnableLUA": 1}],
        "users": [{"Name": "user", "Enabled": True, "PasswordRequired": True}], "hotfix": [{"HotFixID": "KB1", "InstalledOn": ago(25)}],
        "sw": [{"DisplayName": "Demo App %d" % i, "DisplayVersion": "1.%d" % i, "Publisher": "Demo"} for i in range(30)] + [{"DisplayName": "Driver Booster Pro", "DisplayVersion": "9", "Publisher": "IObit"}],
        "startup": [{"Name": "DemoStart", "Command": "C:\\Program Files\\x.exe", "Location": "HKLM", "User": "u"}], "svc": [], "topproc": [{"Name": "chrome", "MB": 900}], "proccount": [210],
        "events": [{"Count": 14, "Name": "Demo-Provider"}], "kpower": [1], "bugcheck": [0], "oldest_event": [{"T": ago(300)}], "profiles": [{"LocalPath": "C:\\Users\\user"}], "usbstor": [3],
        "winold": [False], "activation": [{"Name": "Windows 11 Home", "LicenseStatus": 1, "PartialProductKey": "ABCDE"}], "key": ["DEMO-KEY"], "ports": [], "proxy": [{"ProxyEnable": 0}], "docs": [120],
        "profile_dates": [{"Name": "user", "Created": ago(300)}],
        "dev_first": [{"Name": "Cam", "Class": "Camera", "First": ago(300)}, {"Name": "KB", "Class": "Keyboard", "First": ago(300)}, {"Name": "Touchpad", "Class": "Mouse", "First": ago(299)},
                      {"Name": "BT", "Class": "Bluetooth", "First": ago(300)}, {"Name": "WiFi", "Class": "Net", "First": ago(300)}, {"Name": "Audio", "Class": "MEDIA", "First": ago(295)},
                      {"Name": "Batt", "Class": "Battery", "First": ago(300)}, {"Name": "NVMe", "Class": "DiskDrive", "First": ago(300)}, {"Name": "Display", "Class": "Display", "First": ago(120)},
                      {"Name": "Panel", "Class": "Monitor", "First": ago(300)}, {"Name": "CPU", "Class": "Processor", "First": ago(300)}],
        "drivers": [{"DeviceName": "Wireless AX", "DeviceClass": "NET", "DriverDate": ago(600), "Manufacturer": "Intel"}, {"DeviceName": "Card reader", "DeviceClass": "SYSTEM", "DriverDate": ago(2400), "Manufacturer": "Realtek"},
                    {"DeviceName": "Audio", "DeviceClass": "MEDIA", "DriverDate": ago(900), "Manufacturer": "Realtek"}, {"DeviceName": "Display", "DeviceClass": "DISPLAY", "DriverDate": ago(120), "Manufacturer": "Intel"}],
        "defexcl": [{"ExclusionPath": ["C:\\Users\\user\\Downloads\\tools"], "ExclusionExtension": None, "ExclusionProcess": None, "DisableRealtimeMonitoring": False, "DisableBehaviorMonitoring": False}],
        "tasks": [{"TaskName": "GoogleUpdate", "TaskPath": "\\", "Action": "C:\\Program Files\\Google\\Update.exe /c"}], "oddsvc": [], "pendreboot": [False], "boottimes": [41000, 45000, 39000],
        "wifi_txt": ["SSID : DemoNet\nSignal : 82%"], "wifi_profiles": ["All User Profile : a\nAll User Profile : b\nAll User Profile : c"], "dism": ["No component store corruption detected."],
        "dirty": ["Volume - C: is NOT Dirty"], "hosts": [[]], "net": {"ping": 28, "lost": 0, "dns": 20, "https": 190, "mbps": 42.5},
    })
    D.update({"av2": [{"Name": "FakeShield Pro 2026", "Path": "C:\\Program Files\\FakeShield\\fs.exe", "Exists": False, "Status": "", "Signer": ""}],
              "kmsfiles": ["C:\\Windows\\AutoKMS"], "kmstasks": [], "procpaths": [{"Name": "svchost", "Path": "C:\\Users\\user\\AppData\\Local\\Temp\\svchost.exe"}, {"Name": "explorer", "Path": "C:\\Windows\\explorer.exe"}],
              "procnames": ["chrome", "svchost", "scvhost", "AnyDesk", "explorer"], "sigs": [{"Path": "C:\\Program Files\\A\\a.exe", "Status": "Valid", "Signer": "CN=A"}, {"Path": "C:\\Users\\u\\Downloads\\x.exe", "Status": "NotSigned", "Signer": ""}, {"Path": "C:\\Program Files\\B\\b.exe", "Status": "HashMismatch", "Signer": "CN=B"}],
              "whea": [2], "diskerr": [0], "throttle": [3], "crashes": [{"Name": "chrome.exe", "Count": 4}], "minidumps": [1], "memdiag": [], "wmipersist": [], "localadmins": [{"Name": "PC\\user", "ObjectClass": "User", "PrincipalSource": "Local"}], "bits": [], "newest_evt": [{"T": ago(0) + " 08:00"}],
              "hosts": [["0.0.0.0 activation.sls.microsoft.com"]]})
    X.update({"smbios": {"bios": {"vendor": "HP", "version": "1.12", "date": "01/10/2023"}, "system": {"manufacturer": "HP", "product": "Demo Laptop 15", "serial": "DEMO12345"}, "board": {"serial": "Default string"}, "chassis": {},
                         "cpu": [{"cores": 4, "threads": 8, "max_mhz": 3400}], "mem": [{"slot": "DIMM A", "mb": 4096, "mhz": 2400, "maker": "Samsung", "part": "M471", "serial": ""}, {"slot": "DIMM B", "mb": 4096, "mhz": 2400, "maker": "Samsung", "part": "M471", "serial": ""}],
                         "battery": [{"maker": "HP", "name": "Primary", "date": "2023-03-01", "design_mwh": 50000, "volt_mv": 11400}]},
              "registry": [{"area": "_identity", "key": "", "name": "", "data": {"SystemProductName": "Demo Laptop 15", "SystemManufacturer": "HP", "BIOSVersion": "1.12"}, "level": "ok", "why": ""},
                           {"area": "Auto-start", "key": "HKCU Run", "name": "Updater", "data": "powershell -w hidden -enc AAA", "level": "fail", "why": "Starts from a risky place or with a hidden script/command."},
                           {"area": "Auto-start", "key": "HKLM Run", "name": "OneDrive", "data": "C:\\Program Files\\OneDrive.exe", "level": "info", "why": ""},
                           {"area": "Activation", "key": "SoftwareProtectionPlatform", "name": "KeyManagementServiceName", "data": "kms.fake-server.net", "level": "warn", "why": "Windows is told to activate against this server."}],
              "camera": {"result": "pass", "index": 0, "w": 1280, "h": 720, "mean": 96.4, "std": 41.2}, "clock": {"drift_s": 2.4, "source": "www.google.com"}, "vbs": {"License Status": "Licensed", "Name": "Windows 11 Home", "Registered KMS machine name": "kms.fake-server.net:1688"},
              "bcd": "testsigning             Yes"})
    h = []
    for i in range(14):
        d = today - datetime.timedelta(days=300 - i * 22)
        h.append({"date": d.strftime("%Y-%m-%d"), "full": 49000 - i * 950, "design": 50000})
    X.update({
        "psutil": {"percore": [14, 9, 22, 6, 31, 11, 8, 17], "odd_procs": [], "conns": [{"proc": "chrome.exe", "ip": "142.250.1.1", "port": 443}]},
        "cpuinfo": {"brand": "Demo CPU i5", "l2": "5 MB", "l3": "12 MB", "avx2": True, "vmx": True}, "wmi": {}, "gpu": [], "serial": [], "input": {"kbd_type": 4, "kbd_fkeys": 12, "stuck": [], "monitors": 1, "screen": "1920x1080", "mouse": 1, "buttons": 3, "wheel": 1, "touch": 0},
        "audio": {"result": "pass", "tone_ratio": 0.62, "outputs": 2, "inputs": 1}, "ram": {"mb": 128, "errors": 0, "secs": 1.4}, "pybench": {"runs_ms": [210, 214, 230, 262]},
        "native": {"c": {"ran": True, "why": "", "data": {"ram_total_mb": "7900", "logical_cpus": "8", "monitors": "1", "screen": "1920x1080", "uptime_hours": "22.4", "ac_line": "1"}},
                   "cpp": {"ran": True, "why": "", "data": {"threads": "8", "int_ms_run1": "310", "int_ms_run2": "338", "int_ms_run3": "372", "multi_core_scaling": "5.8", "mem_copy_mb_s": "9800"}}},
        "batrep": {"batteries": [], "history": h}, "cmd": {"driverquery": '"Module Name","Display Name","Is Signed","Manufacturer"\n"abc","ABC","TRUE","X"', "sfc": "Windows Resource Protection did not find any integrity violations."},
    })
    X.setdefault("native", {})["cpuid"] = {"ran": True, "why": "", "data": {"cpu_vendor": "GenuineIntel", "cpu_brand": "Intel(R) Core(TM) i5-9999 CPU @ 3.40GHz", "hypervisor_bit": "0", "hypervisor_vendor": "", "tsc_ghz": "2.100"}}
    X.setdefault("native", {})["disktest"] = {"ran": True, "why": "", "runs": [{"root": "C:\\", "disk_write_ok": "1", "disk_mismatches": "0", "disk_write_mb_s": "820", "disk_read_mb_s": "1500", "disk_tested_mb": "128"}]}
    eng.LIBS.update({k: {"pip": k, "purpose": p, "ok": k != "wmi", "ver": "1.0", "note": "" if k != "wmi" else "not installed (ImportError)"} for _, k, p in [(0, n, pu) for n, _, pu in eng.LIB_SPEC]})
    eng.LOG.extend([{"shell": "CMD", "cmd": "systeminfo", "secs": 4.2, "ok": True, "note": ""}, {"shell": "PowerShell 5.1", "cmd": "Get-CimInstance Win32_BIOS", "secs": 1.1, "ok": True, "note": ""},
                    {"shell": "Python/psutil", "cmd": "cpu, memory, processes", "secs": 1.0, "ok": True, "note": ""}, {"shell": "C++ (native)", "cmd": "probe_cpp.exe", "secs": 5, "ok": True, "note": ""}])
