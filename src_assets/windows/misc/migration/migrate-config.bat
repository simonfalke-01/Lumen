@echo off

rem Create the configuration directories Lumen expects under its install root.
for %%I in ("%~dp0\..") do set "ROOT_DIR=%%~fI"
if not exist "%ROOT_DIR%\config\" mkdir "%ROOT_DIR%\config"
if not exist "%ROOT_DIR%\config\credentials\" mkdir "%ROOT_DIR%\config\credentials"

rem The shared setup script applies the final per-object SYSTEM and
rem Administrators ACL after this script runs.
