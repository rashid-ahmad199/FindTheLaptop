@echo off
title Find the Laptop CLEANER - by Rashid Ahmad
cd /d "%~dp0"
echo Starting the Find the Laptop CLEANER...
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Launcher.ps1" -Tool cleanup %*
if errorlevel 1 goto backup
goto end

:backup
echo.
echo The PowerShell launcher stopped. Trying the backup method: Python directly...
py -3 "%~dp0ftl_cleaner.py"
if errorlevel 1 python "%~dp0ftl_cleaner.py"

:end
echo.
echo This window stays open on purpose. Press any key to close it.
pause >nul
