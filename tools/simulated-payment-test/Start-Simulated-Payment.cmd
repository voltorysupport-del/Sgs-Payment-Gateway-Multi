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
if "%preflight_exit%"=="0" (echo Simulated payment test completed. No real money was charged.) else (echo STOP. Simulated outcome may need review. Preserve the test journal; do not rerun blindly.)
pause
exit /b %preflight_exit%
