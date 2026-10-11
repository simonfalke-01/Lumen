@echo off
setlocal

rem Get Lumen root directory
for %%I in ("%~dp0\..") do set "ROOT_DIR=%%~fI"

set "TCP_RULE_NAME=Lumen TCP"
set "UDP_RULE_NAME=Lumen UDP"
set "LEGACY_RULE_NAME=Lumen"
set "PROGRAM_BIN=%ROOT_DIR%\Lumen.exe"

rem Remove only rules owned by this exact Lumen.exe path. This makes repeated
rem setup converge without touching identically named rules for other programs.
netsh advfirewall firewall delete rule name="%TCP_RULE_NAME%" program="%PROGRAM_BIN%" >nul 2>&1
netsh advfirewall firewall delete rule name="%UDP_RULE_NAME%" program="%PROGRAM_BIN%" >nul 2>&1
netsh advfirewall firewall delete rule name="%LEGACY_RULE_NAME%" program="%PROGRAM_BIN%" >nul 2>&1

rem Match the MSI-owned rules: inbound TCP and UDP for the canonical executable,
rem on every profile and from any remote address (including forwarded LSP UDP).
netsh advfirewall firewall add rule name="%TCP_RULE_NAME%" dir=in action=allow protocol=tcp program="%PROGRAM_BIN%" enable=yes profile=any remoteip=any
if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%
netsh advfirewall firewall add rule name="%UDP_RULE_NAME%" dir=in action=allow protocol=udp program="%PROGRAM_BIN%" enable=yes profile=any remoteip=any
if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%

exit /b 0
