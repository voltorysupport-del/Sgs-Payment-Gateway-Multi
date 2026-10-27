@echo off
setlocal
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (echo Install Node.js 24 LTS from nodejs.org first. & pause & exit /b 1)
node scripts\verify.mjs
if errorlevel 1 (pause & exit /b 1)
node scripts\server.mjs
if errorlevel 1 pause
