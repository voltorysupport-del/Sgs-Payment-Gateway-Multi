@echo off
setlocal DisableDelayedExpansion
rem Block Node preload/debug options before Node starts. Never expand their values.
if defined NODE_OPTIONS goto unsafe
if defined NODE_DEBUG goto unsafe
if defined NODE_DEBUG_NATIVE goto unsafe
if defined NODE_TLS_REJECT_UNAUTHORIZED goto unsafe
if defined NODE_PG_FORCE_NATIVE goto unsafe
node.exe "%~dp0launcher.js"
set "preflight_exit=%ERRORLEVEL%"
goto finished
:unsafe
echo STOP: unsafe Node environment options. No program or connection was started.
set "preflight_exit=2"
:finished
echo.
if "%preflight_exit%"=="0" (echo Preparation completed. STOP before provisioning. Separate issuance approval required.) else (echo STOP. No issuance attempted. Do not provision or change database settings.)
pause
exit /b %preflight_exit%
