# WIX Packaging
# see options at: https://cmake.org/cmake/help/latest/cpack_gen/wix.html

# find dotnet
find_program(DOTNET_EXECUTABLE dotnet HINTS "C:/Program Files/dotnet")

if(NOT DOTNET_EXECUTABLE)
    message(WARNING "Dotnet executable not found, skipping WiX packaging.")
    return()
endif()

set(CPACK_WIX_VERSION 4)
set(WIX_VERSION 4.0.4)
set(WIX_UI_VERSION 4.0.4)  # extension versioning is independent of the WiX version
set(WIX_FIREWALL_VERSION 4.0.4)
set(WIX_BUILD_PARENT_DIRECTORY "${CMAKE_BINARY_DIR}/wix_packaging")
set(WIX_BUILD_DIRECTORY "${CPACK_PACKAGE_DIRECTORY}/_CPack_Packages/win64/WIX")

# Download and install WiX tools locally in the build directory
set(WIX_TOOL_PATH "${CMAKE_BINARY_DIR}/.wix")
file(MAKE_DIRECTORY ${WIX_TOOL_PATH})

# Install WiX locally using dotnet. Reconfiguration must reuse the exact tool
# already installed in this build tree rather than treating it as an error.
if(NOT EXISTS "${WIX_TOOL_PATH}/wix.exe")
    execute_process(
            COMMAND ${DOTNET_EXECUTABLE} tool install --tool-path ${WIX_TOOL_PATH} wix --version ${WIX_VERSION}
            ERROR_VARIABLE WIX_INSTALL_OUTPUT
            RESULT_VARIABLE WIX_INSTALL_RESULT
    )

    if(NOT WIX_INSTALL_RESULT EQUAL 0)
        message(FATAL_ERROR "Failed to install WiX tools locally.
         WiX packaging may not work correctly, error: ${WIX_INSTALL_OUTPUT}")
    endif()
endif()

# Install WiX UI Extension
if(NOT EXISTS "${WIX_TOOL_PATH}/extensions/WixToolset.UI.wixext/${WIX_UI_VERSION}/wixext4/WixToolset.UI.wixext.dll")
    execute_process(
            COMMAND "${WIX_TOOL_PATH}/wix" extension add WixToolset.UI.wixext/${WIX_UI_VERSION}
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
            ERROR_VARIABLE WIX_UI_INSTALL_OUTPUT
            RESULT_VARIABLE WIX_UI_INSTALL_RESULT
    )

    if(NOT WIX_UI_INSTALL_RESULT EQUAL 0)
        message(FATAL_ERROR "Failed to install WiX UI extension, error: ${WIX_UI_INSTALL_OUTPUT}")
    endif()
endif()

# Install WiX Util Extension
if(NOT EXISTS "${WIX_TOOL_PATH}/extensions/WixToolset.Util.wixext/${WIX_UI_VERSION}/wixext4/WixToolset.Util.wixext.dll")
    execute_process(
            COMMAND "${WIX_TOOL_PATH}/wix" extension add WixToolset.Util.wixext/${WIX_UI_VERSION}
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
            ERROR_VARIABLE WIX_UTIL_INSTALL_OUTPUT
            RESULT_VARIABLE WIX_UTIL_INSTALL_RESULT
    )

    if(NOT WIX_UTIL_INSTALL_RESULT EQUAL 0)
        message(FATAL_ERROR "Failed to install WiX Util extension, error: ${WIX_UTIL_INSTALL_OUTPUT}")
    endif()
endif()

# Install WiX Firewall Extension. Firewall rules authored in the MSI tables are
# removed automatically on uninstall and restored automatically on rollback.
if(NOT EXISTS "${WIX_TOOL_PATH}/extensions/WixToolset.Firewall.wixext/${WIX_FIREWALL_VERSION}/wixext4/WixToolset.Firewall.wixext.dll")
    execute_process(
            COMMAND "${WIX_TOOL_PATH}/wix" extension add WixToolset.Firewall.wixext/${WIX_FIREWALL_VERSION}
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
            ERROR_VARIABLE WIX_FIREWALL_INSTALL_OUTPUT
            RESULT_VARIABLE WIX_FIREWALL_INSTALL_RESULT
    )

    if(NOT WIX_FIREWALL_INSTALL_RESULT EQUAL 0)
        message(FATAL_ERROR "Failed to install WiX Firewall extension, error: ${WIX_FIREWALL_INSTALL_OUTPUT}")
    endif()
endif()

# Set WiX-specific variables
set(CPACK_WIX_ROOT "${WIX_TOOL_PATH}")
set(CPACK_WIX_UPGRADE_GUID "89721553-C582-4D70-8BBF-1E6C5431C8D5")

# Installer metadata
set(CPACK_WIX_HELP_LINK "https://github.com/simonfalke-01/Lumen")
set(CPACK_WIX_PRODUCT_ICON "${SUNSHINE_ICON_PATH}")
set(CPACK_WIX_PRODUCT_URL "${CMAKE_PROJECT_HOMEPAGE_URL}")
set(CPACK_WIX_PROGRAM_MENU_FOLDER "Lumen")
# Force package files to replace existing files when switching between release
# and PR builds, regardless of their embedded file versions.
# https://learn.microsoft.com/en-us/windows/win32/msi/reinstallmode
set(CPACK_WIX_PROPERTY_REINSTALLMODE "amus")

set(CPACK_WIX_EXTENSIONS
        "WixToolset.UI.wixext"
        "WixToolset.Util.wixext"
        "WixToolset.Firewall.wixext"
)
set(CPACK_WIX_CUSTOM_XMLNS
        "fw=http://wixtoolset.org/schemas/v4/wxs/firewall"
)

message(STATUS "cpack package directory: ${CPACK_PACKAGE_DIRECTORY}")

# copy custom wxs files to the build directory
file(COPY "${CMAKE_CURRENT_LIST_DIR}/wix_resources/"
        DESTINATION "${WIX_BUILD_PARENT_DIRECTORY}/")
set(LUMEN_MSICA_BINARY "${CMAKE_BINARY_DIR}/tools/lumen_msica.dll")
file(TO_NATIVE_PATH "${LUMEN_MSICA_BINARY}" LUMEN_MSICA_BINARY_WIX)
if(SUNSHINE_VIRTUAL_DISPLAY_DRIVER_PACKAGE_DIR)
    set(LUMEN_INSTALL_VDD_DEFAULT 1)
else()
    set(LUMEN_INSTALL_VDD_DEFAULT 0)
endif()
configure_file(
        "${CMAKE_CURRENT_LIST_DIR}/wix_resources/sunshine-installer.wxs"
        "${WIX_BUILD_PARENT_DIRECTORY}/sunshine-installer.wxs"
        @ONLY)

function(lumen_remove_marked_wix_block file_path start_marker end_marker)
    file(READ "${file_path}" contents)
    string(FIND "${contents}" "${start_marker}" start_index)
    string(FIND "${contents}" "${end_marker}" end_index)
    if(start_index EQUAL -1 OR end_index EQUAL -1 OR end_index LESS start_index)
        message(FATAL_ERROR "Missing conditional WiX markers in ${file_path}")
    endif()
    string(LENGTH "${end_marker}" end_marker_length)
    math(EXPR suffix_index "${end_index} + ${end_marker_length}")
    string(SUBSTRING "${contents}" 0 ${start_index} prefix)
    string(SUBSTRING "${contents}" ${suffix_index} -1 suffix)
    file(WRITE "${file_path}" "${prefix}${suffix}")
endfunction()

if(NOT SUNSHINE_VIRTUAL_HID_DRIVER_PACKAGE_DIR)
    lumen_remove_marked_wix_block(
            "${WIX_BUILD_PARENT_DIRECTORY}/patch.xml"
            "<!-- LUMEN_VHID_FEATURE_START -->"
            "<!-- LUMEN_VHID_FEATURE_END -->")
    lumen_remove_marked_wix_block(
            "${WIX_BUILD_PARENT_DIRECTORY}/sunshine-installer.wxs"
            "<!-- LUMEN_VHID_FEATURE_START -->"
            "<!-- LUMEN_VHID_FEATURE_END -->")
endif()

if(NOT SUNSHINE_VIRTUAL_MICROPHONE_DRIVER_PACKAGE_DIR)
    lumen_remove_marked_wix_block(
            "${WIX_BUILD_PARENT_DIRECTORY}/patch.xml"
            "<!-- LUMEN_VMIC_FEATURE_START -->"
            "<!-- LUMEN_VMIC_FEATURE_END -->")
    lumen_remove_marked_wix_block(
            "${WIX_BUILD_PARENT_DIRECTORY}/sunshine-installer.wxs"
            "<!-- LUMEN_VMIC_FEATURE_START -->"
            "<!-- LUMEN_VMIC_FEATURE_END -->")
endif()

if(NOT SUNSHINE_VIRTUAL_DISPLAY_DRIVER_PACKAGE_DIR)
    lumen_remove_marked_wix_block(
            "${WIX_BUILD_PARENT_DIRECTORY}/patch.xml"
            "<!-- LUMEN_VDD_FEATURE_START -->"
            "<!-- LUMEN_VDD_FEATURE_END -->")
    lumen_remove_marked_wix_block(
            "${WIX_BUILD_PARENT_DIRECTORY}/sunshine-installer.wxs"
            "<!-- LUMEN_VDD_FEATURE_START -->"
            "<!-- LUMEN_VDD_FEATURE_END -->")
endif()

set(CPACK_WIX_EXTRA_SOURCES
        "${WIX_BUILD_PARENT_DIRECTORY}/sunshine-installer.wxs"
)
set(CPACK_WIX_PATCH_FILE
        "${WIX_BUILD_PARENT_DIRECTORY}/patch.xml"
)
# CPack's default WiX template blocks downgrades. Lumen users commonly switch
# between release and PR builds, so allow any build to replace the installed one.
# https://docs.firegiant.com/wix/schema/wxs/majorupgrade/#allowdowngrades
set(CPACK_WIX_TEMPLATE
        "${WIX_BUILD_PARENT_DIRECTORY}/wix.template.in"
)

# Copy root LICENSE and rename to have .txt extension
file(COPY "${CMAKE_SOURCE_DIR}/LICENSE"
        DESTINATION "${CMAKE_BINARY_DIR}")
file(RENAME "${CMAKE_BINARY_DIR}/LICENSE" "${CMAKE_BINARY_DIR}/LICENSE.txt")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_BINARY_DIR}/LICENSE.txt")  # cpack will covert this to an RTF if it is txt

# https://cmake.org/cmake/help/latest/cpack_gen/wix.html#variable:CPACK_WIX_ARCHITECTURE
if(CMAKE_SYSTEM_PROCESSOR MATCHES "ARM64")
    set(CPACK_WIX_ARCHITECTURE "arm64")
else()
    set(CPACK_WIX_ARCHITECTURE "x64")
endif()
