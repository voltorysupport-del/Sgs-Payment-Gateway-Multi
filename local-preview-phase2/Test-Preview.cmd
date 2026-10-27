@echo off
setlocal
cd /d "%~dp0"
node scripts\verify.mjs
if errorlevel 1 (pause & exit /b 1)
node --test tests\smoke.test.mjs
pause
