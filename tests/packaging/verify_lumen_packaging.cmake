cmake_minimum_required(VERSION 3.20)

get_filename_component(LUMEN_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)

function(assert_file_contains relative_path expected_pattern description)
    file(READ "${LUMEN_ROOT}/${relative_path}" file_contents)
    if(NOT file_contents MATCHES "${expected_pattern}")
        message(FATAL_ERROR "${description}: ${relative_path}")
    endif()
endfunction()

function(assert_file_excludes relative_path rejected_pattern description)
    file(READ "${LUMEN_ROOT}/${relative_path}" file_contents)
    if(file_contents MATCHES "${rejected_pattern}")
        message(FATAL_ERROR "${description}: ${relative_path}")
    endif()
endfunction()

function(assert_file_contains_literal relative_path expected_text description)
    file(READ "${LUMEN_ROOT}/${relative_path}" file_contents)
    string(FIND "${file_contents}" "${expected_text}" match_offset)
    if(match_offset EQUAL -1)
        message(FATAL_ERROR "${description}: ${relative_path}")
    endif()
endfunction()

assert_file_contains_literal(
    "cmake/packaging/common.cmake"
    [=[set(CPACK_PACKAGE_VERSION ${LUMEN_VERSION_CORE})]=]
    "CPack must use the numeric version core")
assert_file_contains(
    "cmake/packaging/common.cmake"
    "CPACK_PACKAGE_NAME \"Lumen\""
    "CPack must publish the Lumen product name")
assert_file_contains_literal(
    "cmake/packaging/common.cmake"
    [=[${CPACK_PACKAGE_NAME}-${PROJECT_VERSION}-${CMAKE_SYSTEM_NAME}]=]
    "Artifact names must retain the full release or prerelease version")
assert_file_contains_literal(
    "cmake/prep/build_version.cmake"
    [=[set(RC_VERSION_BUILD "${PROJECT_VERSION_PATCH}")]=]
    "Windows file metadata must preserve the SemVer patch component")
assert_file_contains_literal(
    "cmake/prep/build_version.cmake"
    [=[set(RC_VERSION_REVISION "0")]=]
    "Windows file metadata must reserve the fourth version component")
assert_file_contains(
    "CMakeLists.txt"
    "LUMEN_VERSION_MAJOR GREATER 255"
    "Canonical versions must enforce Windows MSI component limits")
assert_file_contains_literal(
    "src_assets/macos/build/Info.plist.in"
    [=[<string>@LUMEN_VERSION_CORE@</string>]=]
    "macOS bundle fields must use the numeric version core")
assert_file_contains_literal(
    "src_assets/macos/build/Info.plist.in"
    [=[<key>LumenVersion</key>
  <string>@PROJECT_VERSION@</string>]=]
    "macOS bundles must retain the full Lumen release version")
assert_file_contains(
    "cmake/packaging/windows_wix.cmake"
    "89721553-C582-4D70-8BBF-1E6C5431C8D5"
    "WiX must use the permanent Lumen UpgradeCode")
assert_file_excludes(
    "cmake/packaging/windows_wix.cmake"
    "512A3D1B-BE16-401B-A0D1-59BBA3942FB8"
    "Lumen must not reuse the official Sunshine UpgradeCode")
assert_file_contains(
    "cmake/packaging/wix_resources/patch.xml"
    "Name=\"LumenService\""
    "The MSI service must use the Lumen product identity")
assert_file_excludes(
    "cmake/packaging/wix_resources/patch.xml"
    "SunshineService"
    "The Lumen MSI must not claim the official Sunshine service")
assert_file_contains(
    "cmake/packaging/wix_resources/sunshine-installer.wxs"
    "Property Id=\"LUMEN_INSTALL_VHID\" Value=\"0\""
    "Virtual HID must remain explicit opt-in")
assert_file_contains(
    "cmake/packaging/wix_resources/sunshine-installer.wxs"
    "Target=\"\\[INSTALL_ROOT\\]Lumen.exe\""
    "Installer shortcuts must launch Lumen.exe")
assert_file_contains(
    "cmake/packaging/wix_resources/sunshine-installer.wxs"
    "Software\\\\simonfalke\\\\Lumen"
    "Installer registry keys must use the canonical publisher identity")
assert_file_excludes(
    "tools/sunshinesvc.cpp"
    "Sunshine.exe"
    "The Lumen service must never execute an upstream Sunshine binary")
assert_file_excludes(
    "src_assets/windows/misc/sunshine-setup.ps1"
    "Join-Path \\$RootDir \"Sunshine.exe\""
    "The Lumen setup path must never execute an upstream Sunshine binary")
assert_file_contains_literal(
    ".github/workflows/ci-windows.yml"
    [=[$driverVersion = "$($versionParts[0]).$($versionParts[1]).$($versionParts[2]).$driverRevision"]=]
    "Windows CI must derive a monotonic Virtual HID driver version")
assert_file_contains_literal(
    ".github/workflows/ci-windows.yml"
    [=[DriverVer\s*=]=]
    "Windows CI must stamp and verify the Virtual HID INF rank")
assert_file_contains(
    ".github/workflows/ci-windows.yml"
    "VersionInfo.FileVersion"
    "Windows CI must verify the Virtual HID DLL resource version")
assert_file_contains(
    "src_assets/bsd/misc/+POST_INSTALL"
    "RULESET_NUM=48371"
    "FreeBSD must use the stable Lumen-owned devfs ruleset")
assert_file_excludes(
    "src_assets/bsd/misc/+PRE_DEINSTALL"
    "RULESET_NUM=47989"
    "Lumen uninstall must not delete Sunshine's devfs ruleset")
assert_file_contains_literal(
    "packaging/sunshine.rb"
    [=[-DSUNSHINE_PUBLISHER_NAME=simonfalke]=]
    "Homebrew must pass the exact publisher without quote characters")
assert_file_excludes(
    "packaging/sunshine.rb"
    "PUBLISHER_NAME='simonfalke'"
    "Homebrew must not embed shell quotes in the publisher value")
assert_file_contains_literal(
    "packaging/linux/flatpak/dev.lizardbyte.app.Sunshine.yml"
    [=[-DSUNSHINE_PUBLISHER_NAME=simonfalke]=]
    "Flatpak must pass the exact publisher without quote characters")
assert_file_contains(
    "cmake/packaging/linux.cmake"
    "60-lumen.rules"
    "Linux packages must install Lumen-owned udev rules")
assert_file_excludes(
    "cmake/packaging/linux.cmake"
    "60-sunshine.rules"
    "Linux packages must not claim upstream Sunshine udev paths")
assert_file_excludes(
    "packaging/linux/app-dev.lizardbyte.app.Sunshine.service.in"
    "Alias=sunshine.service"
    "Lumen systemd units must not claim the upstream service alias")
assert_file_contains(
    "src_assets/windows/misc/sunshine-setup.ps1"
    "Detected a separate Sunshine installation.*will not replace or uninstall it"
    "Legacy Sunshine detection must be non-destructive")
assert_file_excludes(
    "src_assets/windows/misc/service/uninstall-service.bat"
    "sc delete SunshineService"
    "Lumen uninstall must not delete the official Sunshine service")

message(STATUS "Verified Lumen packaging identity and compatibility contracts.")
