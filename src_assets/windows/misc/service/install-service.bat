@echo off
setlocal enabledelayedexpansion

rem Get Lumen root directory
for %%I in ("%~dp0\..") do set "ROOT_DIR=%%~fI"

set "SERVICE_NAME=Lumen"
set "LEGACY_SERVICE_NAME=LumenService"
set "SERVICE_BIN=%ROOT_DIR%\tools\lumensvc.exe"
set "SERVICE_CONFIG_DIR=%LOCALAPPDATA%\simonfalke\Lumen"
set "SERVICE_CONFIG_FILE=%SERVICE_CONFIG_DIR%\service_start_type.txt"
set "TRANSITIONAL_SERVICE_CONFIG_FILE=%LOCALAPPDATA%\simonfalke-01\Lumen\service_start_type.txt"
set "LEGACY_SERVICE_CONFIG_FILE=%LOCALAPPDATA%\LizardByte\Sunshine\service_start_type.txt"

rem New installations start automatically. A saved or migrated explicit mode
rem overrides this default below.
set SERVICE_START_TYPE=auto

rem Legacy Sunshine service names are intentionally not removed: official
rem Sunshine may be installed side-by-side and has a different product identity.

rem Reconfigure the canonical service when it already exists.
sc qc %SERVICE_NAME% > nul 2>&1
if %ERRORLEVEL%==0 (
    for /f "tokens=3" %%i in ('sc qc %SERVICE_NAME% ^| findstr /C:"START_TYPE"') do (
        set "CURRENT_START_TYPE=%%i"
    )
    if "!CURRENT_START_TYPE!"=="2" (
        sc qc %SERVICE_NAME% | findstr /C:"(DELAYED)" >nul
        if !ERRORLEVEL!==0 (
            set SERVICE_START_TYPE=delayed-auto
        ) else (
            set SERVICE_START_TYPE=auto
        )
    ) else if "!CURRENT_START_TYPE!"=="3" (
        set SERVICE_START_TYPE=demand
    ) else if "!CURRENT_START_TYPE!"=="4" (
        set SERVICE_START_TYPE=disabled
    )

    rem Stop the existing service if running
    net stop %SERVICE_NAME%

    rem Reconfigure the existing service
    set SC_CMD=config
) else (
    rem Preserve the old Lumen service's explicit start mode during the one-time
    rem service-name migration.
    sc qc %LEGACY_SERVICE_NAME% >nul 2>&1
    if !ERRORLEVEL!==0 (
        for /f "tokens=3" %%i in ('sc qc %LEGACY_SERVICE_NAME% ^| findstr /C:"START_TYPE"') do (
            set "MIGRATED_START_TYPE=%%i"
        )
        if "!MIGRATED_START_TYPE!"=="2" (
            sc qc %LEGACY_SERVICE_NAME% | findstr /C:"(DELAYED)" >nul
            if !ERRORLEVEL!==0 (
                set SERVICE_START_TYPE=delayed-auto
            ) else (
                set SERVICE_START_TYPE=auto
            )
        ) else if "!MIGRATED_START_TYPE!"=="3" (
            set SERVICE_START_TYPE=demand
        ) else if "!MIGRATED_START_TYPE!"=="4" (
            set SERVICE_START_TYPE=disabled
        )
    )
    set SC_CMD=create
)

rem The legacy name is Lumen-owned. Remove it idempotently so an update cannot
rem leave two wrappers launching the same Lumen.exe installation.
sc qc %LEGACY_SERVICE_NAME% >nul 2>&1
if !ERRORLEVEL!==0 (
    net stop %LEGACY_SERVICE_NAME% >nul 2>&1
    sc delete %LEGACY_SERVICE_NAME%
    if !ERRORLEVEL! NEQ 0 exit /b !ERRORLEVEL!
)

rem Check if we have a saved start type from previous installation
if not exist "%SERVICE_CONFIG_FILE%" if exist "%TRANSITIONAL_SERVICE_CONFIG_FILE%" (
    if not exist "%SERVICE_CONFIG_DIR%\" mkdir "%SERVICE_CONFIG_DIR%\"
    copy /y "%TRANSITIONAL_SERVICE_CONFIG_FILE%" "%SERVICE_CONFIG_FILE%" >nul
)
if not exist "%SERVICE_CONFIG_FILE%" if exist "%LEGACY_SERVICE_CONFIG_FILE%" (
    if not exist "%SERVICE_CONFIG_DIR%\" mkdir "%SERVICE_CONFIG_DIR%\"
    copy /y "%LEGACY_SERVICE_CONFIG_FILE%" "%SERVICE_CONFIG_FILE%" >nul
)
if exist "%SERVICE_CONFIG_FILE%" (
    rem Debug output file content
    type "%SERVICE_CONFIG_FILE%"

    rem Read the saved start type
    for /f "usebackq delims=" %%a in ("%SERVICE_CONFIG_FILE%") do (
        set "SAVED_START_TYPE=%%a"
    )

    echo Raw saved start type: [!SAVED_START_TYPE!]

    rem Check start type
    if "!SAVED_START_TYPE!"=="2-delayed" (
        set SERVICE_START_TYPE=delayed-auto
    ) else if "!SAVED_START_TYPE!"=="2" (
        set SERVICE_START_TYPE=auto
    ) else if "!SAVED_START_TYPE!"=="3" (
        set SERVICE_START_TYPE=demand
    ) else if "!SAVED_START_TYPE!"=="4" (
        set SERVICE_START_TYPE=disabled
    )

    del "%SERVICE_CONFIG_FILE%"
)

echo Setting service start type set to: [!SERVICE_START_TYPE!]

rem Run the sc command to create/reconfigure the service
sc %SC_CMD% %SERVICE_NAME% binPath= "\"%SERVICE_BIN%\"" start= %SERVICE_START_TYPE% DisplayName= "Lumen"
if !ERRORLEVEL! NEQ 0 exit /b !ERRORLEVEL!

rem Set the description of the service
sc description %SERVICE_NAME% "Lumen is a self-hosted game stream host for Moonlight."
if !ERRORLEVEL! NEQ 0 exit /b !ERRORLEVEL!

rem Start the new service
if "!SERVICE_START_TYPE!"=="disabled" exit /b 0
net start %SERVICE_NAME%
