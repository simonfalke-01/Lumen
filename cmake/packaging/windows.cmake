# windows specific packaging
install(TARGETS sunshine RUNTIME DESTINATION "." COMPONENT application)

# Hardening: include zlib1.dll (loaded via LoadLibrary() in openssl's libcrypto.a)
install(FILES "${ZLIB}" DESTINATION "." COMPONENT application)

# ARM64: include minhook-detours DLL (shared library for ARM64)
if(NOT CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64" AND DEFINED _MINHOOK_DLL)
    install(FILES "${_MINHOOK_DLL}" DESTINATION "." COMPONENT application)
endif()

# ViGEmBus installer
set(SUNSHINE_THIRD_PARTY_DIR "third-party")
set(VIGEMBUS_INSTALLER "${CMAKE_BINARY_DIR}/${SUNSHINE_THIRD_PARTY_DIR}/vigembus_installer.exe")
set(VIGEMBUS_DOWNLOAD_URL_1 "https://github.com/nefarius/ViGEmBus/releases/download")
set(VIGEMBUS_DOWNLOAD_URL_2 "v${VIGEMBUS_PACKAGED_V_2}/ViGEmBus_${VIGEMBUS_PACKAGED_V}_x64_x86_arm64.exe")
file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/${SUNSHINE_THIRD_PARTY_DIR}")
file(DOWNLOAD
        "${VIGEMBUS_DOWNLOAD_URL_1}/${VIGEMBUS_DOWNLOAD_URL_2}"
        ${VIGEMBUS_INSTALLER}
        SHOW_PROGRESS
        EXPECTED_HASH SHA256=155c50f1eec07bdc28d2f61a3e3c2c6c132fee7328412de224695f89143316bc
        TIMEOUT 60
)
install(FILES ${VIGEMBUS_INSTALLER}
        DESTINATION "${SUNSHINE_THIRD_PARTY_DIR}"
        RENAME "vigembus_installer.exe"
        COMPONENT gamepad)

# Adding tools
install(TARGETS dxgi-info RUNTIME DESTINATION "tools" COMPONENT dxgi)
install(TARGETS audio-info RUNTIME DESTINATION "tools" COMPONENT audio)

# Mandatory tools
install(TARGETS sunshinesvc RUNTIME DESTINATION "tools" COMPONENT application)

# Lumen Virtual HID driver
#
# The Virtual HID driver is built separately with MSBuild/WDK. The application build
# receives the architecture-matched, validated package directory from CI (or a
# local packager) and stages it without attempting to rebuild MSVC artifacts
# from the MSYS2 toolchain.
set(SUNSHINE_VIRTUAL_HID_DRIVER_PACKAGE_DIR "" CACHE PATH
        "Directory containing the architecture-matched Lumen Virtual HID INF, CAT, and driver binary")
option(SUNSHINE_VIRTUAL_HID_BUNDLED_CERTIFICATE
        "Package the bundled Virtual HID certificate"
        OFF)

if(SUNSHINE_VIRTUAL_HID_DRIVER_PACKAGE_DIR)
    if(NOT IS_DIRECTORY "${SUNSHINE_VIRTUAL_HID_DRIVER_PACKAGE_DIR}")
        message(FATAL_ERROR
                "SUNSHINE_VIRTUAL_HID_DRIVER_PACKAGE_DIR does not exist: "
                "${SUNSHINE_VIRTUAL_HID_DRIVER_PACKAGE_DIR}")
    endif()

    set(VIRTUAL_HID_DRIVER_INF
            "${SUNSHINE_VIRTUAL_HID_DRIVER_PACKAGE_DIR}/LumenVirtualHid.inf")
    set(VIRTUAL_HID_DRIVER_CAT
            "${SUNSHINE_VIRTUAL_HID_DRIVER_PACKAGE_DIR}/LumenVirtualHid.cat")
    set(VIRTUAL_HID_DRIVER_DLL
            "${SUNSHINE_VIRTUAL_HID_DRIVER_PACKAGE_DIR}/LumenVirtualHid.dll")
    set(VIRTUAL_HID_DRIVER_FILES
            "${VIRTUAL_HID_DRIVER_INF}"
            "${VIRTUAL_HID_DRIVER_CAT}"
            "${VIRTUAL_HID_DRIVER_DLL}")

    if(SUNSHINE_VIRTUAL_HID_BUNDLED_CERTIFICATE)
        set(VIRTUAL_HID_DRIVER_CERT
                "${SUNSHINE_VIRTUAL_HID_DRIVER_PACKAGE_DIR}/LumenVirtualHid.cer")
        list(APPEND VIRTUAL_HID_DRIVER_FILES "${VIRTUAL_HID_DRIVER_CERT}")
        set(VIRTUAL_HID_DRIVER_EXPECTED_FILE_COUNT 4)
    else()
        set(VIRTUAL_HID_DRIVER_EXPECTED_FILE_COUNT 3)
    endif()

    foreach(VIRTUAL_HID_DRIVER_FILE IN LISTS VIRTUAL_HID_DRIVER_FILES)
        if(NOT EXISTS "${VIRTUAL_HID_DRIVER_FILE}")
            message(FATAL_ERROR
                    "The Lumen Virtual HID package is missing: ${VIRTUAL_HID_DRIVER_FILE}")
        endif()
    endforeach()

    file(GLOB VIRTUAL_HID_DRIVER_PACKAGE_FILES
            LIST_DIRECTORIES false
            "${SUNSHINE_VIRTUAL_HID_DRIVER_PACKAGE_DIR}/*")
    list(LENGTH VIRTUAL_HID_DRIVER_PACKAGE_FILES VIRTUAL_HID_DRIVER_PACKAGE_FILE_COUNT)
    if(NOT VIRTUAL_HID_DRIVER_PACKAGE_FILE_COUNT EQUAL VIRTUAL_HID_DRIVER_EXPECTED_FILE_COUNT)
        if(SUNSHINE_VIRTUAL_HID_BUNDLED_CERTIFICATE)
            set(VIRTUAL_HID_DRIVER_PACKAGE_CONTENTS
                    "LumenVirtualHid.inf, LumenVirtualHid.cat, LumenVirtualHid.dll, and LumenVirtualHid.cer")
        else()
            set(VIRTUAL_HID_DRIVER_PACKAGE_CONTENTS
                    "LumenVirtualHid.inf, LumenVirtualHid.cat, and LumenVirtualHid.dll")
        endif()
        message(FATAL_ERROR
                "The Lumen Virtual HID package must contain exactly ${VIRTUAL_HID_DRIVER_PACKAGE_CONTENTS}: "
                "${SUNSHINE_VIRTUAL_HID_DRIVER_PACKAGE_DIR}")
    endif()

    if(NOT TARGET lumen-vhidctl)
        message(FATAL_ERROR
                "The lumen-vhidctl target is required when packaging the Lumen Virtual HID driver")
    endif()

    install(TARGETS lumen-vhidctl
            RUNTIME DESTINATION "tools"
            COMPONENT virtual_hid_driver)
    install(FILES ${VIRTUAL_HID_DRIVER_FILES}
            DESTINATION "drivers/virtual-hid"
            COMPONENT virtual_hid_driver)
else()
    message(STATUS
            "Lumen Virtual HID driver package not supplied; installer generation will not include the driver")
endif()

# Lumen Virtual Microphone driver
#
# The WaveRT driver is built separately with MSBuild/WDK. Only an exact x64
# INF/SYS/CAT package may be supplied to the MSYS2 application packager.
set(SUNSHINE_VIRTUAL_MICROPHONE_DRIVER_PACKAGE_DIR "" CACHE PATH
        "Directory containing the architecture-matched Lumen Virtual Microphone INF, SYS, and CAT")

if(SUNSHINE_VIRTUAL_MICROPHONE_DRIVER_PACKAGE_DIR)
    if(NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^(AMD64|amd64|x86_64)$")
        message(FATAL_ERROR
                "The current Lumen Virtual Microphone package supports AMD64 packaging only")
    endif()
    if(NOT IS_DIRECTORY "${SUNSHINE_VIRTUAL_MICROPHONE_DRIVER_PACKAGE_DIR}")
        message(FATAL_ERROR
                "SUNSHINE_VIRTUAL_MICROPHONE_DRIVER_PACKAGE_DIR does not exist: "
                "${SUNSHINE_VIRTUAL_MICROPHONE_DRIVER_PACKAGE_DIR}")
    endif()

    set(VIRTUAL_MICROPHONE_DRIVER_INF
            "${SUNSHINE_VIRTUAL_MICROPHONE_DRIVER_PACKAGE_DIR}/LumenVirtualMicrophone.inf")
    set(VIRTUAL_MICROPHONE_DRIVER_SYS
            "${SUNSHINE_VIRTUAL_MICROPHONE_DRIVER_PACKAGE_DIR}/LumenVirtualMicrophone.sys")
    set(VIRTUAL_MICROPHONE_DRIVER_CAT
            "${SUNSHINE_VIRTUAL_MICROPHONE_DRIVER_PACKAGE_DIR}/LumenVirtualMicrophone.cat")
    set(VIRTUAL_MICROPHONE_DRIVER_FILES
            "${VIRTUAL_MICROPHONE_DRIVER_INF}"
            "${VIRTUAL_MICROPHONE_DRIVER_SYS}"
            "${VIRTUAL_MICROPHONE_DRIVER_CAT}")

    foreach(VIRTUAL_MICROPHONE_DRIVER_FILE IN LISTS VIRTUAL_MICROPHONE_DRIVER_FILES)
        if(NOT EXISTS "${VIRTUAL_MICROPHONE_DRIVER_FILE}")
            message(FATAL_ERROR
                    "The Lumen Virtual Microphone package is missing: ${VIRTUAL_MICROPHONE_DRIVER_FILE}")
        endif()
    endforeach()

    file(GLOB VIRTUAL_MICROPHONE_DRIVER_PACKAGE_FILES
            LIST_DIRECTORIES false
            "${SUNSHINE_VIRTUAL_MICROPHONE_DRIVER_PACKAGE_DIR}/*")
    list(LENGTH VIRTUAL_MICROPHONE_DRIVER_PACKAGE_FILES VIRTUAL_MICROPHONE_DRIVER_PACKAGE_FILE_COUNT)
    if(NOT VIRTUAL_MICROPHONE_DRIVER_PACKAGE_FILE_COUNT EQUAL 3)
        message(FATAL_ERROR
                "The Lumen Virtual Microphone package must contain exactly "
                "LumenVirtualMicrophone.inf, LumenVirtualMicrophone.sys, and "
                "LumenVirtualMicrophone.cat: ${SUNSHINE_VIRTUAL_MICROPHONE_DRIVER_PACKAGE_DIR}")
    endif()

    file(READ "${VIRTUAL_MICROPHONE_DRIVER_INF}" VIRTUAL_MICROPHONE_DRIVER_INF_CONTENTS)
    foreach(VIRTUAL_MICROPHONE_INF_IDENTITY IN ITEMS
            "ROOT\\LumenVirtualMicrophone"
            "NTamd64"
            "LumenVirtualMicrophone.sys")
        string(FIND
                "${VIRTUAL_MICROPHONE_DRIVER_INF_CONTENTS}"
                "${VIRTUAL_MICROPHONE_INF_IDENTITY}"
                VIRTUAL_MICROPHONE_INF_IDENTITY_OFFSET)
        if(VIRTUAL_MICROPHONE_INF_IDENTITY_OFFSET EQUAL -1)
            message(FATAL_ERROR
                    "The Lumen Virtual Microphone INF does not match this package: "
                    "missing ${VIRTUAL_MICROPHONE_INF_IDENTITY}")
        endif()
    endforeach()

    if(NOT TARGET lumen-vmicctl)
        message(FATAL_ERROR
                "The lumen-vmicctl target is required when packaging the Lumen Virtual Microphone driver")
    endif()
    install(TARGETS lumen-vmicctl
            RUNTIME DESTINATION "tools"
            COMPONENT virtual_microphone_driver)
    install(FILES ${VIRTUAL_MICROPHONE_DRIVER_FILES}
            DESTINATION "drivers/virtual-microphone"
            COMPONENT virtual_microphone_driver)
else()
    message(STATUS
            "Lumen Virtual Microphone driver package not supplied; installer generation will not include the driver")
endif()

# Mandatory scripts. The source filename is retained as a build compatibility
# alias, but new packages expose only the Lumen script name.
install(FILES "${SUNSHINE_SOURCE_ASSETS_DIR}/windows/misc/sunshine-setup.ps1"
        DESTINATION "scripts"
        RENAME "lumen-setup.ps1"
        COMPONENT assets)
install(DIRECTORY "${SUNSHINE_SOURCE_ASSETS_DIR}/windows/misc/service/"
        DESTINATION "scripts"
        COMPONENT assets)
install(DIRECTORY "${SUNSHINE_SOURCE_ASSETS_DIR}/windows/misc/migration/"
        DESTINATION "scripts"
        COMPONENT assets)
# Configurable options for the service
install(DIRECTORY "${SUNSHINE_SOURCE_ASSETS_DIR}/windows/misc/autostart/"
        DESTINATION "scripts"
        COMPONENT autostart)

# scripts
install(DIRECTORY "${SUNSHINE_SOURCE_ASSETS_DIR}/windows/misc/firewall/"
        DESTINATION "scripts"
        COMPONENT firewall)

# Lumen assets
install(DIRECTORY "${SUNSHINE_SOURCE_ASSETS_DIR}/windows/assets/"
        DESTINATION "${SUNSHINE_ASSETS_DIR}"
        COMPONENT assets)

# copy assets (excluding shaders) to build directory, for running without install
file(COPY "${SUNSHINE_SOURCE_ASSETS_DIR}/windows/assets/"
        DESTINATION "${CMAKE_BINARY_DIR}/assets"
        PATTERN "shaders" EXCLUDE)
# use junction for shaders directory
cmake_path(CONVERT "${SUNSHINE_SOURCE_ASSETS_DIR}/windows/assets/shaders"
        TO_NATIVE_PATH_LIST shaders_in_build_src_native)
cmake_path(CONVERT "${CMAKE_BINARY_DIR}/assets/shaders" TO_NATIVE_PATH_LIST shaders_in_build_dest_native)
execute_process(COMMAND cmd.exe /c mklink /J "${shaders_in_build_dest_native}" "${shaders_in_build_src_native}")

set(CPACK_PACKAGE_ICON "${CMAKE_SOURCE_DIR}\\\\sunshine.ico")

# The name of the directory that will be created in C:/Program files/
set(CPACK_PACKAGE_INSTALL_DIRECTORY "${CPACK_PACKAGE_NAME}")

# Setting components groups and dependencies
set(CPACK_COMPONENT_GROUP_CORE_EXPANDED true)
set(CPACK_COMPONENT_GROUP_THIRDPARTY_DISPLAY_NAME "Third Party")
set(CPACK_COMPONENT_GROUP_THIRDPARTY_DESCRIPTION "Bundled third-party installers and optional components.")

# Lumen binary
set(CPACK_COMPONENT_APPLICATION_DISPLAY_NAME "${CMAKE_PROJECT_NAME}")
set(CPACK_COMPONENT_APPLICATION_DESCRIPTION "${CMAKE_PROJECT_NAME} main application and required components.")
set(CPACK_COMPONENT_APPLICATION_GROUP "Core")
set(CPACK_COMPONENT_APPLICATION_REQUIRED true)
set(CPACK_COMPONENT_APPLICATION_DEPENDS assets)

# service auto-start script
set(CPACK_COMPONENT_AUTOSTART_DISPLAY_NAME "Launch on Startup")
set(CPACK_COMPONENT_AUTOSTART_DESCRIPTION "If enabled, launches Lumen automatically on system startup.")
set(CPACK_COMPONENT_AUTOSTART_GROUP "Core")

# assets
set(CPACK_COMPONENT_ASSETS_DISPLAY_NAME "Required Assets")
set(CPACK_COMPONENT_ASSETS_DESCRIPTION "Shaders, default box art, and web UI.")
set(CPACK_COMPONENT_ASSETS_GROUP "Core")
set(CPACK_COMPONENT_ASSETS_REQUIRED true)

# Lumen Virtual HID driver and management helper
set(CPACK_COMPONENT_VIRTUAL_HID_DRIVER_DISPLAY_NAME "Lumen Virtual Input")
if(SUNSHINE_VIRTUAL_HID_BUNDLED_CERTIFICATE)
    set(CPACK_COMPONENT_VIRTUAL_HID_DRIVER_DESCRIPTION
            "Optional Lumen Virtual HID keyboard, mouse, consumer-control, and modern gamepad driver.")
else()
    set(CPACK_COMPONENT_VIRTUAL_HID_DRIVER_DESCRIPTION
            "Optional Lumen Virtual HID keyboard, mouse, consumer-control, and modern gamepad driver. "
            "Leave disabled to use SendInput and ViGEm-backed Xbox 360 controllers.")
endif()
set(CPACK_COMPONENT_VIRTUAL_HID_DRIVER_GROUP "Core")
set(CPACK_COMPONENT_VIRTUAL_HID_DRIVER_DEPENDS application)
set(CPACK_COMPONENT_VIRTUAL_HID_DRIVER_DISABLED true)

# Lumen Virtual Microphone driver and lifecycle helper
set(CPACK_COMPONENT_VIRTUAL_MICROPHONE_DRIVER_DISPLAY_NAME "Client Microphone Passthrough")
set(CPACK_COMPONENT_VIRTUAL_MICROPHONE_DRIVER_DESCRIPTION
        "Optional Lumen virtual capture endpoint for client microphone passthrough.")
set(CPACK_COMPONENT_VIRTUAL_MICROPHONE_DRIVER_GROUP "Core")
set(CPACK_COMPONENT_VIRTUAL_MICROPHONE_DRIVER_DEPENDS application)
set(CPACK_COMPONENT_VIRTUAL_MICROPHONE_DRIVER_DISABLED true)

# ZIP packages are intentionally non-privileged. Keep the driver package and
# its install/remove helper out of the lite archive so unpacked builds use the
# SendInput fallback unless a matching driver is already installed.
get_cmake_property(SUNSHINE_WINDOWS_PACKAGE_COMPONENTS COMPONENTS)
set(SUNSHINE_WINDOWS_CPACK_PROJECT_CONFIG
        "${CMAKE_CURRENT_BINARY_DIR}/LumenWindowsCPackOptions.cmake")
string(CONCAT SUNSHINE_WINDOWS_CPACK_PROJECT_CONFIG_CONTENT
        "if(CPACK_GENERATOR STREQUAL \"ZIP\")\n"
        "  set(CPACK_ARCHIVE_COMPONENT_INSTALL ON)\n"
        "  set(CPACK_COMPONENTS_GROUPING ALL_COMPONENTS_IN_ONE)\n"
        "  set(CPACK_COMPONENTS_ALL \"${SUNSHINE_WINDOWS_PACKAGE_COMPONENTS}\")\n"
        "  list(REMOVE_ITEM CPACK_COMPONENTS_ALL virtual_hid_driver)\n"
        "  list(REMOVE_ITEM CPACK_COMPONENTS_ALL virtual_microphone_driver)\n"
        "endif()\n")
file(GENERATE
        OUTPUT "${SUNSHINE_WINDOWS_CPACK_PROJECT_CONFIG}"
        CONTENT "${SUNSHINE_WINDOWS_CPACK_PROJECT_CONFIG_CONTENT}")
set(CPACK_PROJECT_CONFIG_FILE "${SUNSHINE_WINDOWS_CPACK_PROJECT_CONFIG}")

# audio tool
set(CPACK_COMPONENT_AUDIO_DISPLAY_NAME "audio-info")
set(CPACK_COMPONENT_AUDIO_DESCRIPTION "CLI tool providing information about sound devices.")
set(CPACK_COMPONENT_AUDIO_GROUP "Tools")

# display tool
set(CPACK_COMPONENT_DXGI_DISPLAY_NAME "dxgi-info")
set(CPACK_COMPONENT_DXGI_DESCRIPTION "CLI tool providing information about graphics cards and displays.")
set(CPACK_COMPONENT_DXGI_GROUP "Tools")

# firewall scripts
set(CPACK_COMPONENT_FIREWALL_DISPLAY_NAME "Add Firewall Exclusions")
set(CPACK_COMPONENT_FIREWALL_DESCRIPTION "Scripts to enable or disable firewall rules.")
set(CPACK_COMPONENT_FIREWALL_GROUP "Scripts")

# gamepad third-party installer
set(CPACK_COMPONENT_GAMEPAD_DISPLAY_NAME "Virtual Gamepad")
set(CPACK_COMPONENT_GAMEPAD_DESCRIPTION "ViGEmBus installer for virtual gamepad support.")
set(CPACK_COMPONENT_GAMEPAD_GROUP "ThirdParty")

# include specific packaging
include(${CMAKE_MODULE_PATH}/packaging/windows_nsis.cmake)
include(${CMAKE_MODULE_PATH}/packaging/windows_wix.cmake)
