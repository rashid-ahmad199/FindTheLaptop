# How It Works

## Design goals

1. **One click for non-technical users.** The launcher installs what is missing and explains every problem in plain English.
2. **Never stop on one error.** Every step has a fallback, and a failing check is skipped, not fatal.
3. **Trust the hardware, not the label.** Important facts are read from several independent sources and compared.
4. **Nothing changes without consent.** The scanner is read-only. The Cleaner acts only on items the user approves, and every change is undoable.

## Flow

```
Run_FindTheLaptop.bat
        │
        ▼
Launcher.ps1 ── asks permission, requests Administrator, checks blocking settings,
        │       finds or installs Python, libraries, PowerShell 7 and a C/C++ compiler
        ▼
findthelaptop.py ── runs engines in parallel, scores the results, builds the HTML report
        │
        ├── ftl_engines.py / ftl_engines2.py ── hardware, security and authenticity checks
        ├── ftl_queries.py ──────────────────── extra PowerShell queries
        ├── native/*.c, *.cpp ───────────────── probes compiled on the fly
        └── ftl_charts.py ───────────────────── offline SVG charts

Run_Cleanup.bat → Launcher.ps1 -Tool cleanup → ftl_cleaner.py
        ├── ftl_clean_scan.py / ftl_clean_scan2.py ── scanners (change nothing)
        ├── ftl_clean_core.py ─────────────────────── shared state: the ITEMS table
        ├── ftl_clean_web.py ──────────────────────── local page + server (127.0.0.1)
        └── ftl_clean_act.py ──────────────────────── approved actions, backups, undo
```

## Modules

| File | Role |
|---|---|
| `Launcher.ps1` | Permission prompt, Administrator elevation, pre-flight checks, tool installation, fallback report. |
| `findthelaptop.py` | Entry point. Runs checks, scores them, writes the HTML and JSON reports. |
| `ftl_engines.py` | Read-only hardware and OS diagnostics and small benchmarks. |
| `ftl_engines2.py` | Authenticity checks, registry scan, camera, clock and VBScript licence check. |
| `ftl_queries.py` | Extra PowerShell queries, kept as raw strings. |
| `ftl_charts.py` | Pure SVG charts, so reports work offline and support dark mode. |
| `ftl_demo.py` | Sample data for test mode. |
| `ftl_cleaner.py` | Cleaner entry point. |
| `ftl_clean_core.py` | Shared state. The `ITEMS` table is the **only** source of what may be changed. |
| `ftl_clean_scan.py`, `ftl_clean_scan2.py` | Junk, big folders, malware files, persistence, Task Manager hogs, exposure paths. |
| `ftl_clean_web.py` | Local web page and server. |
| `ftl_clean_act.py` | Executors that act only on approved item ids. |

## Native probes (`native/`)

| File | Purpose |
|---|---|
| `cpuid.c` | Reads the CPU's identity from the chip and measures the real clock speed. |
| `probe.c`, `probe.cpp` | Hardware facts from Windows, and a quick CPU and memory benchmark. |
| `ramtest.cpp` | Classic memory-test algorithms on a large block. |
| `disktest.cpp` | Writes random data to a temporary file, reads it back and compares. |
| `ports.c` | Asks the network driver for every TCP connection, to cross-check for hidden ones. |
| `filescan.cpp` | Fast file scanner: SHA-256, entropy, disguised or hidden programs. |

If no compiler is present, the launcher installs one (WinLibs through winget, or Zig through pip).

## Cleaner safety model

- The web page can only send **item ids**, never paths or commands.
- The server binds to `127.0.0.1`, checks `Host` and `Origin`, and requires a secret token.
- Malware is quarantined, not deleted, unless permanent deletion is chosen.
- A restore point is created, each change is backed up, and an undo manifest is written.
- Dry-run mode (`FTL_DRY=1`, or any non-Windows system) changes nothing.
