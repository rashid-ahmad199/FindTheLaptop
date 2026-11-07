# Changelog

All notable changes to this project are documented here.

## [2.1] - Cleaner

### Added
- `Run_Cleanup.bat` and `ftl_cleaner.py`: scan the laptop and show every finding in an HTML page. Nothing changes until you tick items, type `CLEAN` and press **Approve & clean**.
- Malware scan: C++ file scanner (SHA-256, packed-file entropy, programs disguised as pictures or documents, double extensions, hidden programs), signature rules for hidden or encoded PowerShell, miners and ransomware commands, Windows Defender confirmation of the worst files, and each file's origin (download URL via Zone.Identifier, folder, creation time).
- Hijack removal: Run keys, Winlogon, IFEO, AppInit, security-switch policies, services, scheduled tasks, hidden WMI auto-run, Defender exclusions and hosts-file lines. Each is backed up first.
- Task Manager analysis: who is using CPU, RAM and disk, and why, in plain English.
- "Ways in / ways out" map: open ports with the owning program, Remote Desktop, SMBv1, firewall holes, remote-control tools, auto-login, proxy and DNS hijack, open Wi-Fi, risky browser extensions and live connections, with a C cross-check.
- Hardening buttons (firewall, SMBv1, RDP, WinRM, Guest, Defender), junk and big-folder cleanup, system repair.
- Safety: local-only server (`127.0.0.1`) with a secret token and Host/Origin checks, quarantine instead of delete, restore point, undo manifest and a dry-run mode.

### Changed
- License changed from MIT to a proprietary "All Rights Reserved" license: free to download and run, not free to modify or redistribute.
- Batch files now use Windows (CRLF) line endings.
- Version labels unified to 2.1.

## [2.0] - Authenticity checks

### Added
- Authenticity checks: firmware vs WMI vs registry vs CPUID.
- Registry scan, camera test, sound test with automatic un-mute, VBScript licence check.
- C and C++ probes, life-left estimates.
- PowerShell launcher that never stops on one error, and an offline library cache.

## [1.0] - First version

- System scan with an HTML report.
