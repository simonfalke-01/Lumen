@echo off
setlocal

rem Get Lumen root directory
for %%I in ("%~dp0\..") do set "ROOT_DIR=%%~fI"

set "TCP_RULE_NAME=Lumen TCP"
set "UDP_RULE_NAME=Lumen UDP"
set "LEGACY_RULE_NAME=Lumen"
set "PROGRAM_BIN=%ROOT_DIR%\Lumen.exe"

rem Remove only rules owned by this exact Lumen.exe path. Missing rules are an
rem already-clean result, so every delete is intentionally idempotent.
netsh advfirewall firewall delete rule name="%TCP_RULE_NAME%" program="%PROGRAM_BIN%" >nul 2>&1
netsh advfirewall firewall delete rule name="%UDP_RULE_NAME%" program="%PROGRAM_BIN%" >nul 2>&1
netsh advfirewall firewall delete rule name="%LEGACY_RULE_NAME%" program="%PROGRAM_BIN%" >nul 2>&1

exit /b 0
