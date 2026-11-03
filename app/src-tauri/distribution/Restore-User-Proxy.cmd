@echo off
rem Run only as the affected NORMAL user, never administrator.
"%~dp0kat-proxy-watchdog.exe" --restore-user-proxy
if errorlevel 1 (echo Kat only-own recovery failed. Reopen GUI for diagnostics.) else (echo Kat owned user proxy settings restored or already released.)
pause
