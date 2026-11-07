# User Guide

Everything you need to run **Find the Laptop** and read its report.

## 1. Running the health scan

1. Extract the **whole** ZIP to a folder. Do not run it from inside the ZIP.
2. Double-click `Run_FindTheLaptop.bat`. It starts `Launcher.ps1`, a PowerShell launcher.
3. It asks for your permission every time: type **F** (full check, about 5 to 20 minutes) or **Q** (quick check, about 2 to 4 minutes).
4. Click **Yes** on the Windows Administrator prompt.
5. Edge or Chrome opens the report automatically.

The window never closes by itself, and the scan does not stop on a single error:

- Python is installed through winget, then python.org, then the Microsoft Store.
- Each library is tried several ways. A failing check is skipped and the next one runs.
- If the full report fails, a basic PowerShell-only report is still created.
- Logs: `Reports\launcher_log.txt`, `Reports\run_log.txt`, `Reports\error_details.txt`.

If something blocks the scan (antivirus, microphone privacy, Controlled folder access, and so on), the launcher and the report list a `SETTING:` line with exactly what to change. The tool never changes your security settings by itself.

## 2. What the scan checks

**Automatic:** BIOS, battery capacity and history, disk health and wear, RAM pattern test, CPU speed and overheating test, speaker and microphone loopback test, stuck-key check, drivers and their dates, virus and hidden-setting checks (Defender exclusions, scheduled tasks, odd services, unsigned drivers), first-use dates of each part, Windows system file check.

**Needs a human:** pressing every key, dead pixels, each physical USB or HDMI port, the camera image, hinges. Software cannot press keys or feel a loose port. Use the **Manual tests** section of the report.

### Fake-data and tampering checks

- **Model, manufacturer, serial, BIOS:** raw firmware table vs WMI vs registry. Disagreement suggests an edited ID.
- **CPU:** name and real clock speed read from the chip (CPUID/TSC) vs what Windows reports.
- **RAM:** installed (firmware) vs visible (Windows) vs the C program. **Battery:** firmware vs Windows, plus a "cannot hold more than new" check.
- **Time:** clock vs internet time, log entries dated in the future, install-date mismatch.
- **Fake Windows activation:** KMS servers, KMSpico files and tasks, hosts-file blocks.
- **Fake programs:** system names running from wrong folders, look-alike names, files changed after signing, antivirus registered but missing or unsigned, cracks and keygens, spyware, remote-control tools.
- **Registry:** Run keys, Winlogon, IFEO debugger hijacks, AppInit DLLs, BootExecute, security-switch policies, services, DNS.
- **Hidden items:** WMI auto-run, BITS downloads, test-signing mode, extra administrator accounts.

## 3. Running the Cleaner

Double-click `Run_Cleanup.bat`. It scans, then opens a page listing:

- malware and suspicious files, with where each came from
- hidden hijacks
- what is making Task Manager hit 100%
- the ways in and out of your laptop
- junk files and big folders

**Nothing is deleted until you tick items, type `CLEAN` and press "Approve & clean selected".**

- Malware is **quarantined** by default (harmless and restorable).
- **Undo everything** restores files, registry values, tasks, services and the hosts file.
- A Windows restore point is created first, if System Protection is on.
- Keep the black window open while using the page. It is the local server (`127.0.0.1` only, secret token).
- Logs: `Cleanup\cleaner_log.txt`. Backups: `Cleanup\Backups`. Quarantine: `Cleanup\Quarantine`.

**Limits:** the Cleaner is not a replacement for a full antivirus. It finds heuristic and known-bad patterns and asks Windows Defender to confirm. A rootkit can hide from any user-mode scanner. If the report shows "Hidden connections", or Defender cannot remove a threat, run a Defender Offline scan.

## 4. Offline use

- The first run online installs the libraries and saves a copy in the `wheels` folder.
- Later runs with no internet use that folder. `Prepare_Offline.bat` only downloads the copy.
- Internet speed tests are skipped automatically when offline.
- To use another laptop offline, copy the whole folder to a Windows machine that already has Python 3.

## 5. Reading the report

- **Health %** is what software can see. Pale bars (`*`) are software checks only, not lab tests.
- **Months since first use** is an estimate from several dates. A Windows reinstall resets software dates, so the report also uses hardware facts (screen factory date, disk hours, battery cycles).
- The report contains the **serial number and Windows product key**. Do not share it publicly.
- **Test mode** (`FTL_DEMO=1`) uses fake sample data. Never use it for a real decision.

## 6. Libraries used

`psutil`, `py-cpuinfo`, `wmi`, `nvidia-ml-py`, `sounddevice`, `numpy`, `pyserial`, `opencv-python-headless` (camera test), `pycaw` and `comtypes` (un-mute for the sound test). The scanner also uses `winreg` and `ctypes` from the standard library.
