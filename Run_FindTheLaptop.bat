@echo off
title Find the Laptop v2.1 - by Rashid Ahmad
cd /d "%~dp0"
echo Starting Find the Laptop...
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Launcher.ps1" %*
if errorlevel 1 goto backup
goto end

:backup
echo.
echo The PowerShell launcher stopped. Trying the backup method: Python directly...
py -3 "%~dp0findthelaptop.py"
if errorlevel 1 python "%~dp0findthelaptop.py"
if errorlevel 1 echo Backup also failed. Install Python 3 from https://www.python.org/downloads/ and run again.

:end
echo.
echo This window stays open on purpose. Press any key to close it.
pause >nul
