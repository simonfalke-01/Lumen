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
# The kernel driver is built separately with MSBuild/WDK. The application build
# receives the architecture-matched, validated package directory from CI (or a
# local packager) and stages it without attempting to rebuild MSVC artifacts
# from the MSYS2 toolchain.
set(SUNSHINE_VIRTUAL_HID_DRIVER_PACKAGE_DIR "" CACHE PATH
        "Directory containing the architecture-matched Lumen Virtual HID INF, CAT, and SYS files")

if(SUNSHINE_VIRTUAL_HID_DRIVER_PACKAGE_DIR)
    if(NOT IS_DIRECTORY "${SUNSHINE_VIRTUAL_HID_DRIVER_PACKAGE_DIR}")
        message(FATAL_ERROR
                "SUNSHINE_VIRTUAL_HID_DRIVER_PACKAGE_DIR does not exist: "
                "${SUNSHINE_VIRTUAL_HID_DRIVER_PACKAGE_DIR}")
    endif()

    file(GLOB VIRTUAL_HID_DRIVER_INF
            CONFIGURE_DEPENDS
            "${SUNSHINE_VIRTUAL_HID_DRIVER_PACKAGE_DIR}/*.inf")
    file(GLOB VIRTUAL_HID_DRIVER_CAT
            CONFIGURE_DEPENDS
            "${SUNSHINE_VIRTUAL_HID_DRIVER_PACKAGE_DIR}/*.cat")
    file(GLOB VIRTUAL_HID_DRIVER_SYS
            CONFIGURE_DEPENDS
            "${SUNSHINE_VIRTUAL_HID_DRIVER_PACKAGE_DIR}/*.sys")
    file(GLOB VIRTUAL_HID_DRIVER_CERT
            CONFIGURE_DEPENDS
            "${SUNSHINE_VIRTUAL_HID_DRIVER_PACKAGE_DIR}/*.cer")

    list(LENGTH VIRTUAL_HID_DRIVER_INF VIRTUAL_HID_DRIVER_INF_COUNT)
    list(LENGTH VIRTUAL_HID_DRIVER_CAT VIRTUAL_HID_DRIVER_CAT_COUNT)
    list(LENGTH VIRTUAL_HID_DRIVER_SYS VIRTUAL_HID_DRIVER_SYS_COUNT)
    list(LENGTH VIRTUAL_HID_DRIVER_CERT VIRTUAL_HID_DRIVER_CERT_COUNT)
    if(NOT VIRTUAL_HID_DRIVER_INF_COUNT EQUAL 1
            OR NOT VIRTUAL_HID_DRIVER_CAT_COUNT EQUAL 1
            OR NOT VIRTUAL_HID_DRIVER_SYS_COUNT EQUAL 1
            OR NOT VIRTUAL_HID_DRIVER_CERT_COUNT EQUAL 1)
        message(FATAL_ERROR
                "The Lumen Virtual HID package must contain exactly one INF, CAT, SYS, and CER file: "
                "${SUNSHINE_VIRTUAL_HID_DRIVER_PACKAGE_DIR}")
    endif()

    if(NOT TARGET lumen-vhidctl)
        message(FATAL_ERROR
                "The lumen-vhidctl target is required when packaging the Lumen Virtual HID driver")
    endif()

    install(TARGETS lumen-vhidctl
            RUNTIME DESTINATION "tools"
            COMPONENT virtual_hid_driver)
    install(FILES
            ${VIRTUAL_HID_DRIVER_INF}
            ${VIRTUAL_HID_DRIVER_CAT}
            ${VIRTUAL_HID_DRIVER_SYS}
            ${VIRTUAL_HID_DRIVER_CERT}
            DESTINATION "drivers/virtual-hid"
            COMPONENT virtual_hid_driver)
else()
    message(STATUS
            "Lumen Virtual HID driver package not supplied; installer generation will not include the driver")
endif()

# Mandatory scripts
install(FILES "${SUNSHINE_SOURCE_ASSETS_DIR}/windows/misc/sunshine-setup.ps1"
        DESTINATION "scripts"
        COMPONENT assets)
install(DIRECTORY "${SUNSHINE_SOURCE_ASSETS_DIR}/windows/misc/service/"
        DESTINATION "scripts"
        COMPONENT assets)
install(DIRECTORY "${SUNSHINE_SOURCE_ASSETS_DIR}/windows/misc/migration/"
        DESTINATION "scripts"
        COMPONENT assets)
install(DIRECTORY "${SUNSHINE_SOURCE_ASSETS_DIR}/windows/misc/path/"
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

# Sunshine assets
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

# sunshine binary
set(CPACK_COMPONENT_APPLICATION_DISPLAY_NAME "${CMAKE_PROJECT_NAME}")
set(CPACK_COMPONENT_APPLICATION_DESCRIPTION "${CMAKE_PROJECT_NAME} main application and required components.")
set(CPACK_COMPONENT_APPLICATION_GROUP "Core")
set(CPACK_COMPONENT_APPLICATION_REQUIRED true)
set(CPACK_COMPONENT_APPLICATION_DEPENDS assets)

# service auto-start script
set(CPACK_COMPONENT_AUTOSTART_DISPLAY_NAME "Launch on Startup")
set(CPACK_COMPONENT_AUTOSTART_DESCRIPTION "If enabled, launches Sunshine automatically on system startup.")
set(CPACK_COMPONENT_AUTOSTART_GROUP "Core")

# assets
set(CPACK_COMPONENT_ASSETS_DISPLAY_NAME "Required Assets")
set(CPACK_COMPONENT_ASSETS_DESCRIPTION "Shaders, default box art, and web UI.")
set(CPACK_COMPONENT_ASSETS_GROUP "Core")
set(CPACK_COMPONENT_ASSETS_REQUIRED true)

# Lumen Virtual HID driver and management helper
set(CPACK_COMPONENT_VIRTUAL_HID_DRIVER_DISPLAY_NAME "Virtual Keyboard and Mouse")
set(CPACK_COMPONENT_VIRTUAL_HID_DRIVER_DESCRIPTION
        "Required Lumen Virtual HID keyboard and mouse driver and management tool.")
set(CPACK_COMPONENT_VIRTUAL_HID_DRIVER_GROUP "Core")
set(CPACK_COMPONENT_VIRTUAL_HID_DRIVER_REQUIRED true)
set(CPACK_COMPONENT_VIRTUAL_HID_DRIVER_DEPENDS application)

# ZIP packages are intentionally non-privileged. Keep the driver package and
# its install/remove helper out of the lite archive so unpacked builds use the
# SendInput fallback unless a matching driver is already installed.
get_cmake_property(SUNSHINE_WINDOWS_PACKAGE_COMPONENTS COMPONENTS)
set(SUNSHINE_WINDOWS_CPACK_PROJECT_CONFIG
        "${CMAKE_CURRENT_BINARY_DIR}/SunshineWindowsCPackOptions.cmake")
string(CONCAT SUNSHINE_WINDOWS_CPACK_PROJECT_CONFIG_CONTENT
        "if(CPACK_GENERATOR STREQUAL \"ZIP\")\n"
        "  set(CPACK_ARCHIVE_COMPONENT_INSTALL ON)\n"
        "  set(CPACK_COMPONENTS_GROUPING ALL_COMPONENTS_IN_ONE)\n"
        "  set(CPACK_COMPONENTS_ALL \"${SUNSHINE_WINDOWS_PACKAGE_COMPONENTS}\")\n"
        "  list(REMOVE_ITEM CPACK_COMPONENTS_ALL virtual_hid_driver)\n"
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
