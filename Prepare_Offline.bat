@echo off
title Find the Laptop - prepare offline use
cd /d "%~dp0"
set "PY="
py -3 --version >nul 2>&1 && set "PY=py -3"
if not defined PY (python --version >nul 2>&1 && set "PY=python")
if not defined PY ( echo Python 3 is not installed. & pause & exit /b 1 )
echo Downloading all libraries into the "wheels" folder (needs internet once)...
%PY% -m pip download -r requirements.txt -d "%~dp0wheels"
echo.
echo Done. Copy this whole folder to any Windows laptop that has Python 3 and it works with no internet.
pause
