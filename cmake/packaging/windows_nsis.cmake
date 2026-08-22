# NSIS Packaging
# see options at: https://cmake.org/cmake/help/latest/cpack_gen/nsis.html

set(CPACK_NSIS_INSTALLED_ICON_NAME "${PROJECT__DIR}\\\\${PROJECT_EXE}")

# Enable detailed logging only on AMD64
if(CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64")
    set(NSIS_LOGSET_COMMAND "LogSet on")
else()
    set(NSIS_LOGSET_COMMAND "")
endif()

# Extra install commands
# Runs the main setup script which handles all installation tasks
SET(CPACK_NSIS_EXTRA_INSTALL_COMMANDS
        "${CPACK_NSIS_EXTRA_INSTALL_COMMANDS}
        ${NSIS_LOGSET_COMMAND}
        IfSilent lumen_install_silent lumen_install_interactive
        lumen_install_interactive:
        nsExec::ExecToLog \
          'powershell -ExecutionPolicy Bypass \
          -File \\\"$INSTDIR\\\\scripts\\\\lumen-setup.ps1\\\" -Action install'
        Goto lumen_install_check
        lumen_install_silent:
        nsExec::ExecToLog \
          'powershell -ExecutionPolicy Bypass \
          -File \\\"$INSTDIR\\\\scripts\\\\lumen-setup.ps1\\\" -Action install -Silent'
        lumen_install_check:
        Pop $0
        StrCmp $0 '0' lumen_install_done
        StrCmp $0 '3010' lumen_install_reboot
        StrCpy $1 $0
        nsExec::ExecToLog \
          'powershell -ExecutionPolicy Bypass \
          -File \\\"$INSTDIR\\\\scripts\\\\lumen-setup.ps1\\\" -Action rollback -Silent'
        Pop $2
        StrCmp $2 '0' lumen_install_rollback_done
        StrCmp $2 '3010' lumen_install_rollback_reboot
        Abort 'Lumen setup failed with exit code $1, and rollback failed with exit code $2. Protected recovery state was preserved.'
        lumen_install_rollback_reboot:
        SetRebootFlag true
        lumen_install_rollback_done:
        Abort 'Lumen setup failed with exit code $1. Installation changes were rolled back.'
        lumen_install_reboot:
        SetRebootFlag true
        lumen_install_done:
        ")

# Extra uninstall commands
# Runs the main setup script which handles all uninstallation tasks
set(CPACK_NSIS_EXTRA_UNINSTALL_COMMANDS
        "${CPACK_NSIS_EXTRA_UNINSTALL_COMMANDS}
        ${NSIS_LOGSET_COMMAND}
        nsExec::ExecToLog \
          'powershell -ExecutionPolicy Bypass \
          -File \\\"$INSTDIR\\\\scripts\\\\lumen-setup.ps1\\\" -Action uninstall'
        Pop $0
        StrCmp $0 '0' lumen_uninstall_done
        StrCmp $0 '3010' lumen_uninstall_reboot
        Abort 'Lumen cleanup failed with exit code $0. See the setup log for recovery details.'
        lumen_uninstall_reboot:
        SetRebootFlag true
        lumen_uninstall_done:
        MessageBox MB_YESNO|MB_ICONQUESTION \
          'Do you want to remove $INSTDIR (this includes the configuration, cover images, and settings)?' \
          /SD IDNO IDNO no_delete
          RMDir /r \\\"$INSTDIR\\\"; skipped if no
        no_delete:
        ")

# Adding an option for the start menu
set(CPACK_NSIS_MODIFY_PATH OFF)
set(CPACK_NSIS_EXECUTABLES_DIRECTORY ".")
# This will be shown on the installed apps Windows settings
set(CPACK_NSIS_INSTALLED_ICON_NAME "${CMAKE_PROJECT_NAME}.exe")
set(CPACK_NSIS_CREATE_ICONS_EXTRA
        "${CPACK_NSIS_CREATE_ICONS_EXTRA}
        SetOutPath '\$INSTDIR'
        CreateShortCut '\$SMPROGRAMS\\\\$STARTMENU_FOLDER\\\\${CMAKE_PROJECT_NAME}.lnk' \
            '\$INSTDIR\\\\${CMAKE_PROJECT_NAME}.exe' '--shortcut'
        ")
set(CPACK_NSIS_DELETE_ICONS_EXTRA
        "${CPACK_NSIS_DELETE_ICONS_EXTRA}
        Delete '\$SMPROGRAMS\\\\$MUI_TEMP\\\\${CMAKE_PROJECT_NAME}.lnk'
        ")

# Checking for previous installed versions
set(CPACK_NSIS_ENABLE_UNINSTALL_BEFORE_INSTALL "ON")

set(CPACK_NSIS_HELP_LINK "https://github.com/simonfalke-01/Lumen")
set(CPACK_NSIS_URL_INFO_ABOUT "https://github.com/simonfalke-01/Lumen")
set(CPACK_NSIS_CONTACT "https://github.com/simonfalke-01/Lumen/issues")

set(CPACK_NSIS_MENU_LINKS
        "https://github.com/simonfalke-01/Lumen" "Lumen on GitHub"
        "https://github.com/simonfalke-01/Lumen/releases" "Lumen releases"
        "https://github.com/simonfalke-01/Lumen/issues" "Lumen support")
set(CPACK_NSIS_MANIFEST_DPI_AWARE true)
