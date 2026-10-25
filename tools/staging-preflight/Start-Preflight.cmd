@echo off
setlocal DisableDelayedExpansion
powershell.exe -NoLogo -NoProfile -File "%~dp0Run-Preflight.ps1"
set "preflight_exit=%ERRORLEVEL%"
echo.
if "%preflight_exit%"=="0" (echo Preflight completed. PASS does not authorize provisioning.) else (echo STOP. Do not provision or change database settings.)
pause
exit /b %preflight_exit%
