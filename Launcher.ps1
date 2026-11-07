# Find the Laptop v2.1 - PowerShell launcher (Rashid Ahmad)
# Never stops on one error: every step has a backup. The window stays open on purpose.
param([switch]$Consented, [string]$Mode = "", [string]$Tool = "scan")

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"
Set-Location -Path $PSScriptRoot
try { Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force } catch {}
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

$LogDir = Join-Path $PSScriptRoot "Reports"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$LogFile = Join-Path $LogDir "launcher_log.txt"
$Started = Get-Date

function Say([string]$m, [string]$c = "White") {
    Write-Host $m -ForegroundColor $c
    try { Add-Content -Path $LogFile -Value ("[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $m) } catch {}
}
function Step([string]$n) { Say ""; Say ("==== " + $n + " ====") "Cyan" }
function Test-Online {
    try { $r = Invoke-WebRequest -Uri "https://pypi.org" -Method Head -UseBasicParsing -TimeoutSec 6; return ($r.StatusCode -ge 200) } catch { return $false }
}
$script:LastExit = 0
function Run-Timed([string]$exe, [string[]]$a, [int]$sec = 120) {
    # Runs a program with a time limit, so one stuck command can never freeze the launcher.
    $o = [IO.Path]::GetTempFileName(); $e = [IO.Path]::GetTempFileName()
    try {
        $q = @(); foreach ($x in $a) { if ($x -match '\s') { $q += ('"' + $x + '"') } else { $q += $x } }
        if ($q.Count -gt 0) { $p = Start-Process -FilePath $exe -ArgumentList $q -NoNewWindow -PassThru -RedirectStandardOutput $o -RedirectStandardError $e }
        else { $p = Start-Process -FilePath $exe -NoNewWindow -PassThru -RedirectStandardOutput $o -RedirectStandardError $e }
        $null = $p.Handle
        if (-not $p.WaitForExit($sec * 1000)) { try { $p.Kill() } catch {}; $script:LastExit = -999; Say ("    (timed out after {0}s: {1})" -f $sec, $exe) "Yellow"; return "" }
        $script:LastExit = $p.ExitCode
        return ("" + (Get-Content $o -Raw) + (Get-Content $e -Raw))
    } catch { $script:LastExit = -1; return "" }
    finally { Remove-Item $o, $e -ErrorAction SilentlyContinue }
}
function Refresh-Path {
    try { $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User") + ";" + $env:Path } catch {}
}

try {
    # ---------- 0. remove the "downloaded from internet" block on our own files (a common reason scripts fail)
    try { Get-ChildItem -Path $PSScriptRoot -Recurse -File | Unblock-File -ErrorAction SilentlyContinue } catch {}

    # ---------- 1. permission (asked every time)
    if (-not $Consented) {
        Clear-Host
        Write-Host "============================================================" -ForegroundColor Cyan
        Write-Host "  FIND THE LAPTOP v2.1   -   Rashid Ahmad"
        Write-Host "============================================================" -ForegroundColor Cyan
        Write-Host ""
        if ($Tool -eq "cleanup") {
            Write-Host "  CLEANER MODE: finds malware, junk, hijacks and open doors." -ForegroundColor Yellow
            Write-Host "  It only SCANS. Nothing is deleted until you tick items in the page that opens,"
            Write-Host "  type CLEAN and press Approve. Malware is quarantined (undoable), backups are made."
            Write-Host ""
        }
        Write-Host " On THIS computer only, this program will:"
        Write-Host "   - read hardware, BIOS, battery, disks, drivers and security settings"
        Write-Host "   - download and install what is missing: Python, Python libraries,"
        Write-Host "     PowerShell 7 and a C/C++ compiler (only if you are online)"
        Write-Host "   - run CMD, PowerShell, Python, C and C++ checks"
        Write-Host "   - play a short test tone and listen briefly with the microphone (not saved)"
        Write-Host "   - run a Windows Defender quick scan (full mode)"
        Write-Host "   - save reports in the Reports folder and open them in Edge or Chrome"
        Write-Host " Nothing is uploaded. It does NOT change your security settings:"
        Write-Host " if a setting must be changed, it will tell you which one."
        Write-Host ""
        Write-Host "   F = Full check  (5-20 minutes, virus scan + system file check)"
        Write-Host "   Q = Quick check (2-4 minutes)"
        Write-Host "   N = Cancel"
        $ans = Read-Host "Give permission? Type F, Q or N and press Enter"
        switch ($ans.Trim().ToUpper()) {
            "F" { $Mode = "full" }
            "Q" { $Mode = "quick" }
            default { Say "Cancelled." "Yellow"; exit 0 }
        }
    }
    if (-not $Mode) { $Mode = "full" }

    # ---------- 2. Administrator (forced; if refused we continue with less)
    $isAdmin = $false
    try { $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch {}
    if (-not $isAdmin) {
        Say "Windows will now ask for Administrator permission. Please click YES." "Yellow"
        try {
            $al = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-NoExit", "-File", ('"{0}"' -f $PSCommandPath), "-Consented", "-Mode", $Mode, "-Tool", $Tool)
            Start-Process -FilePath "powershell.exe" -ArgumentList $al -Verb RunAs -ErrorAction Stop
            Say "A new Administrator window opened. Continue there. You can close this one." "Green"
            exit 0
        } catch {
            Say "Administrator was refused or blocked. Continuing WITHOUT it (disk wear, BitLocker and some security checks will be missing)." "Yellow"
        }
    }

    # ---------- 3. pre-flight: settings that can block the scan
    Step "Pre-flight: settings that can block or limit the scan"
    $notes = New-Object System.Collections.ArrayList
    try {
        $av = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop
        $other = $av | Where-Object { $_.displayName -notmatch "Defender" }
        foreach ($o in $other) { [void]$notes.Add(("Third-party antivirus '{0}' is installed. If this window or the scan stops, pause that antivirus for a few minutes (or add this folder to its exclusions) and run again." -f $o.displayName)) }
    } catch {}
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        if (-not $mp.RealTimeProtectionEnabled) { [void]$notes.Add("VIRUS PROTECTION IS OFF. Turn it ON: Windows Security > Virus & threat protection > Manage settings > Real-time protection.") }
        $pref = Get-MpPreference -ErrorAction Stop
        if ($pref.EnableControlledFolderAccess -eq 1) { [void]$notes.Add("Controlled folder access is ON. It can stop reports from being saved. If a report is missing, allow python.exe there or switch it off for this run.") }
        if ($pref.ExclusionPath -or $pref.ExclusionProcess -or $pref.ExclusionExtension) { [void]$notes.Add("Windows Defender has exclusions (places it does not scan). Malware likes to hide there. See the report.") }
    } catch {}
    try { if ((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction Stop).EnableLUA -eq 0) { [void]$notes.Add("User Account Control (UAC) is OFF. Turn it ON for safety.") } } catch {}
    try {
        $mic = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" -ErrorAction Stop).Value
        if ($mic -eq "Deny") { [void]$notes.Add("Microphone access is OFF. The sound test needs it: Settings > Privacy & security > Microphone > ON, and allow desktop apps.") }
    } catch {}
    try {
        foreach ($e in (Get-ExecutionPolicy -List)) { if (($e.Scope -eq "MachinePolicy" -or $e.Scope -eq "UserPolicy") -and $e.ExecutionPolicy -ne "Undefined") { [void]$notes.Add("A group policy restricts PowerShell scripts. This launcher works around it for itself only.") } }
    } catch {}
    try { $free = (Get-PSDrive -Name ($PSScriptRoot.Substring(0,1))).Free; if ($free -lt 1GB) { [void]$notes.Add("Less than 1 GB free on this drive. Free some space so the libraries and reports can be saved.") } } catch {}
    if ($notes.Count -eq 0) { Say "Nothing is blocking the scan." "Green" }
    else { foreach ($n in $notes) { Say ("  SETTING: " + $n) "Yellow" }; Say "(The scan will go on anyway. Change these if the result looks incomplete.)" "Gray" }

    # ---------- 4. Python (find it, else install it, with 3 different methods)
    Step "Python"
    function Find-Python {
        $cands = @(
            @{ Exe = "py"; Args = @("-3") },
            @{ Exe = "python"; Args = @() },
            @{ Exe = "python3"; Args = @() }
        )
        Say "  Looking for installed Python folders..." "Gray"
        foreach ($root in @("$env:LOCALAPPDATA\Programs\Python", "$env:ProgramFiles", "C:\")) {
            try {
                Get-ChildItem -Path $root -Directory -Filter "Python3*" -ErrorAction SilentlyContinue | ForEach-Object {
                    $f = Join-Path $_.FullName "python.exe"; if (Test-Path $f) { $cands += @{ Exe = $f; Args = @() } }
                }
            } catch {}
        }
        foreach ($c in $cands) {
            $full = $c.Exe
            try { $cmd = Get-Command $c.Exe -ErrorAction SilentlyContinue; if ($cmd) { $full = $cmd.Source } } catch {}
            if ($full -match "WindowsApps") { Say ("  skip Store shortcut: " + $full) "Gray"; continue }
            Say ("  checking " + $c.Exe + " ...") "Gray"
            $v = Run-Timed $c.Exe (@($c.Args) + @("--version")) 8
            if ($script:LastExit -eq 0 -and ($v -match "Python 3")) { return $c }
        }
        return $null
    }
    $py = Find-Python
    Say "  Checking internet..." "Gray"
    $online = Test-Online
    Say ("  Internet: " + $online) "Gray"
    if (-not $py -and $online) {
        Say "Python not found. Installing it (method 1: winget)..." "Yellow"
        $null = Run-Timed "winget" @("install","-e","--id","Python.Python.3.12","--silent","--accept-package-agreements","--accept-source-agreements") 600
        Refresh-Path; $py = Find-Python
    }
    if (-not $py -and $online) {
        Say "Method 2: downloading the official installer from python.org..." "Yellow"
        try {
            $inst = Join-Path $env:TEMP "python-installer.exe"
            Invoke-WebRequest -Uri "https://www.python.org/ftp/python/3.12.8/python-3.12.8-amd64.exe" -OutFile $inst -UseBasicParsing
            Start-Process -FilePath $inst -ArgumentList "/quiet", "InstallAllUsers=0", "PrependPath=1", "Include_test=0" -Wait
        } catch { Say ("  method 2 failed: " + $_.Exception.Message) "Yellow" }
        Refresh-Path; $py = Find-Python
    }
    if (-not $py -and $online) {
        Say "Method 3: Microsoft Store version via winget..." "Yellow"
        $null = Run-Timed "winget" @("install","-e","--id","9NCVDN91XZQP","--silent","--accept-package-agreements","--accept-source-agreements") 600
        Refresh-Path; $py = Find-Python
    }
    if ($py) { Say ("Python ready: " + $py.Exe + " " + ($py.Args -join " ")) "Green" }
    else { Say "Python could not be installed (offline or blocked). A basic PowerShell-only report will be made instead." "Yellow" }

    function Invoke-PyT([string[]]$a, [int]$sec = 240) { $all = @($py.Args) + $a; return (Run-Timed $py.Exe $all $sec) }
    function Invoke-Py([string[]]$a) { $all = @($py.Args) + $a; & $py.Exe $all }

    # ---------- 5. libraries (online: install; each package separately, 4 ways; offline: saved copies)
    if ($py) {
        Step "Python libraries"
        Say "  preparing pip..." "Gray"; $null = Invoke-PyT @("-m", "ensurepip", "--upgrade") 90
        $reqs = @(); try { $reqs = Get-Content -Path (Join-Path $PSScriptRoot "requirements.txt") | Where-Object { $_.Trim() } } catch {}
        $wheels = Join-Path $PSScriptRoot "wheels"
        if ($online) {
            $null = Invoke-PyT @("-m", "pip", "install", "--upgrade", "pip", "--quiet", "--disable-pip-version-check") 120
        }
        foreach ($r in $reqs) {
            $ok = $false
            $tries = @()
            if ($online) {
                $tries += , @("install", "--quiet", "--disable-pip-version-check", $r)
                $tries += , @("install", "--quiet", "--disable-pip-version-check", "--user", $r)
                $tries += , @("install", "--quiet", "--disable-pip-version-check", "--user", "--trusted-host", "pypi.org", "--trusted-host", "files.pythonhosted.org", $r)
            }
            if (Test-Path $wheels) { $tries += , @("install", "--quiet", "--disable-pip-version-check", "--user", "--no-index", "--find-links", $wheels, $r) }
            foreach ($t in $tries) {
                Say ("  installing " + $r + " ...") "Gray"
                $null = Invoke-PyT (@("-m", "pip") + $t) 240
                if ($script:LastExit -eq 0) { $ok = $true; break }
            }
            if ($ok) { Say ("  OK   " + $r) "Green" } else { Say ("  skip " + $r + "  (could not install; the scan will use its other tools)") "Yellow" }
        }
        if ($online -and -not (Test-Path $wheels)) {
            Say "Saving a copy of the libraries in 'wheels' so it also works offline next time..." "Gray"
            $null = Invoke-PyT @("-m", "pip", "download", "--quiet", "--disable-pip-version-check", "-r", (Join-Path $PSScriptRoot "requirements.txt"), "-d", $wheels) 300
        }
    }

    # ---------- 6. extra power tools (full mode, online): PowerShell 7 + C/C++ compiler
    if ($online) {
        Step "Extra tools (PowerShell 7, C/C++ compiler)"
        if (-not (Get-Command pwsh -ErrorAction SilentlyContinue)) {
            Say "Installing PowerShell 7 (the newer, stronger PowerShell)..." "Gray"
            $null = Run-Timed "winget" @("install","-e","--id","Microsoft.PowerShell","--silent","--accept-package-agreements","--accept-source-agreements") 600
            Refresh-Path
            if (Test-Path "$env:ProgramFiles\PowerShell\7") { $env:Path += ";$env:ProgramFiles\PowerShell\7" }
        }
        if (-not (Get-Command gcc -ErrorAction SilentlyContinue)) {
            Say "Installing a C/C++ compiler (WinLibs, about 300 MB)..." "Gray"
            $null = Run-Timed "winget" @("install","-e","--id","BrechtSanders.WinLibs.POSIX.UCRT","--silent","--accept-package-agreements","--accept-source-agreements") 900
            Refresh-Path
            try {
                $g = Get-ChildItem -Path "$env:LOCALAPPDATA\Microsoft\WinGet\Packages" -Filter gcc.exe -Recurse -Depth 4 -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($g) { $env:Path = $g.DirectoryName + ";" + $env:Path }
            } catch {}
        }
        if (-not (Get-Command gcc -ErrorAction SilentlyContinue) -and $py) {
            Say "No gcc after winget. Backup: getting the Zig C/C++ compiler through pip (about 80 MB)..." "Gray"
            $null = Invoke-PyT @("-m", "pip", "install", "--quiet", "--disable-pip-version-check", "--user", "ziglang") 600
        }
        Say ("pwsh: " + [bool](Get-Command pwsh -ErrorAction SilentlyContinue) + "   gcc: " + [bool](Get-Command gcc -ErrorAction SilentlyContinue)) "Gray"
    }

    # ---------- 7. run the scanner (retry once with a different mode, then fall back to a PowerShell-only report)
    Step "Running"
    $made = $false
    if ($Tool -eq "cleanup") {
        if ($py) {
            $pa = @((Join-Path $PSScriptRoot "ftl_cleaner.py"), "--consented")
            if ($Mode -eq "quick") { $pa += "--quick" }
            try { Invoke-Py $pa } catch { Say ("Cleaner stopped: " + $_.Exception.Message) "Yellow" }
        } else { Say "Python is required for the cleaner and could not be installed. Connect to the internet and run again." "Red" }
        Say "Cleaner finished. Logs: Cleanup\cleaner_log.txt" "Green"
        exit 0
    }
    function Latest-Report { Get-ChildItem -Path $LogDir -Filter "FindTheLaptop_*.html" -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt $Started } | Select-Object -First 1 }
    if ($py) {
        $pa = @((Join-Path $PSScriptRoot "findthelaptop.py"), "--consented")
        if ($Mode -eq "quick") { $pa += "--quick" }
        try { Invoke-Py $pa } catch { Say ("Scanner stopped: " + $_.Exception.Message) "Yellow" }
        if (Latest-Report) { $made = $true }
        if (-not $made) {
            Say "No report was made. Trying again in quick mode..." "Yellow"
            try { Invoke-Py @((Join-Path $PSScriptRoot "findthelaptop.py"), "--consented", "--quick") } catch {}
            if (Latest-Report) { $made = $true }
        }
    }
    if (-not $made) {
        Say "Making a basic report with PowerShell only..." "Yellow"
        try {
            $cs = Get-CimInstance Win32_ComputerSystem; $bios = Get-CimInstance Win32_BIOS; $os = Get-CimInstance Win32_OperatingSystem
            $bd = Get-CimInstance -Namespace root\wmi -ClassName BatteryStaticData -ErrorAction SilentlyContinue | Select-Object -First 1
            $bf = Get-CimInstance -Namespace root\wmi -ClassName BatteryFullChargedCapacity -ErrorAction SilentlyContinue | Select-Object -First 1
            $bat = "no battery data"; if ($bd -and $bf -and $bd.DesignedCapacity) { $bat = ("{0}% of original capacity" -f [math]::Round($bf.FullChargedCapacity * 100 / $bd.DesignedCapacity)) }
            $disks = (Get-PhysicalDisk | ForEach-Object { "{0}: {1}" -f $_.FriendlyName, $_.HealthStatus }) -join "<br>"
            $def = ""; try { $m = Get-MpComputerStatus; $def = ("Real-time protection: {0}, signatures {1} day(s) old" -f $m.RealTimeProtectionEnabled, $m.AntivirusSignatureAge) } catch { $def = "not readable" }
            $ramGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
            $rows = @(
                @("Computer", "$($cs.Manufacturer) $($cs.Model)"), @("Windows installed", "$($os.InstallDate)"), @("BIOS", "$($bios.SMBIOSBIOSVersion) ($($bios.ReleaseDate))"),
                @("Serial number", "$($bios.SerialNumber)"), @("RAM", "$ramGB GB"), @("Battery health", $bat), @("Disks", $disks), @("Virus protection", $def)
            )
            $trs = ($rows | ForEach-Object { "<tr><td><b>{0}</b></td><td>{1}</td></tr>" -f $_[0], $_[1] }) -join ""
            $html = "<!doctype html><meta charset=utf-8><title>Basic laptop report</title><body style='font:15px Segoe UI,Arial;max-width:800px;margin:20px auto'><div style='background:#0d1b4d;color:#fff;padding:10px 14px'><b>Rashid Ahmad</b></div><h1>Find the Laptop - basic report</h1><p>The full Python report could not run, so this is the PowerShell-only version.</p><table border=1 cellpadding=8 style='border-collapse:collapse'>$trs</table></body>"
            $f = Join-Path $LogDir ("FindTheLaptop_basic_{0}.html" -f (Get-Date -Format "yyyyMMdd_HHmm"))
            Set-Content -Path $f -Value $html -Encoding UTF8
            try { Start-Process "msedge.exe" $f } catch { try { Start-Process "chrome.exe" $f } catch { Invoke-Item $f } }
            Say ("Basic report saved: " + $f) "Green"
        } catch { Say ("Even the basic report failed: " + $_.Exception.Message) "Red" }
    }
    Say ""
    Say "Finished. Reports are in the Reports folder. Log: Reports\launcher_log.txt" "Green"
    exit 0
}
catch {
    Say ("The launcher hit an unexpected problem: " + $_.Exception.Message) "Red"
    exit 1
}
