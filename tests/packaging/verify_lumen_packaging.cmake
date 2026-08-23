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
assert_file_contains_literal(
    "cmake/packaging/windows.cmake"
    [=[set(CPACK_COMPONENT_VIRTUAL_HID_DRIVER_DISPLAY_NAME "Lumen Virtual Input")]=]
    "The single Virtual HID feature must describe every Lumen virtual input class")
assert_file_contains_literal(
    "cmake/packaging/windows.cmake"
    [=[COMPONENT virtual_hid_driver]=]
    "Keyboard, mouse, and dynamic gamepads must remain in one Virtual HID MSI feature")
assert_file_excludes(
    "cmake/packaging/windows.cmake"
    "libvirtualhid(_broker|_driver|_service)?"
    "Windows packaging must not add the upstream broker, service, or second driver")
assert_file_contains_literal(
    "cmake/packaging/windows.cmake"
    [=[RENAME "vigembus_installer.exe"]=]
    "Windows packaging must retain ViGEm for Xbox 360/XInput compatibility")
assert_file_contains_literal(
    "cmake/packaging/windows.cmake"
    [=[COMPONENT gamepad]=]
    "ViGEm must remain an independently selectable compatibility component")
foreach(vhid_gamepad_helper_contract IN ITEMS
        "IOCTL_LUMEN_VHID_GAMEPAD_GET_CAPABILITIES"
        "IOCTL_LUMEN_VHID_GAMEPAD_CREATE"
        "IOCTL_LUMEN_VHID_GAMEPAD_SUBMIT_REPORT"
        "IOCTL_LUMEN_VHID_GAMEPAD_READ_OUTPUT"
        "IOCTL_LUMEN_VHID_GAMEPAD_DESTROY"
        "count_gamepad_collections"
        "open_gamepad_collection"
        "round_trip_generic_io"
        "kProtocolGeneration = 3"
        "running_as_local_system"
        "smoke-gamepad"
        "smoke-vigem")
    assert_file_contains_literal(
        "tools/lumen-vhidctl.cpp"
        "${vhid_gamepad_helper_contract}"
        "The Virtual HID helper must retain ${vhid_gamepad_helper_contract}")
endforeach()
assert_file_contains_literal(
    ".github/scripts/test-windows-msi.ps1"
    [=[& '$escapedHelper' smoke-gamepad --json]=]
    "MSI validation must run the dynamic-gamepad smoke as LocalSystem")
assert_file_contains_literal(
    ".github/scripts/test-windows-msi.ps1"
    [=[& '$escapedHelper' smoke-vigem --json]=]
    "MSI validation must run the ViGEm/XInput smoke as LocalSystem")
assert_file_contains_literal(
    "tools/CMakeLists.txt"
    "xinput9_1_0"
    "The Virtual HID helper must link the XInput validation API")
assert_file_contains_literal(
    ".github/scripts/test-windows-msi.ps1"
    [=[New-ScheduledTaskPrincipal]=]
    "MSI validation must use a service-account task for the SYSTEM-only control interface")
foreach(vhid_uninstall_contract IN ITEMS
        "Assert-VirtualHidRemoved"
        "ROOT\\LUMENVIRTUALHID"
        "VID_4C42&PID_0001"
        "VID_1209&PID_0001"
        "LumenVirtualHid\\.inf")
    assert_file_contains_literal(
        ".github/scripts/test-windows-msi.ps1"
        "${vhid_uninstall_contract}"
        "MSI uninstall verification must retain ${vhid_uninstall_contract}")
endforeach()
assert_file_contains(
    "cmake/packaging/wix_resources/sunshine-installer.wxs"
    "Property Id=\"LUMEN_INSTALL_VMIC\" Value=\"0\""
    "Virtual Microphone must remain explicit opt-in")
assert_file_contains(
    "cmake/packaging/wix_resources/patch.xml"
    "Condition=\"NOT Installed AND LUMEN_INSTALL_VHID = 0\""
    "Virtual HID opt-out must not suppress removal of an installed feature")
assert_file_excludes(
    "cmake/packaging/wix_resources/patch.xml"
    "Condition=\"LUMEN_INSTALL_VHID = 0\""
    "Virtual HID opt-out must only apply during a fresh install")
assert_file_contains(
    "cmake/packaging/wix_resources/patch.xml"
    "CM_C_virtual_microphone_driver"
    "WiX must patch the optional Virtual Microphone feature")
assert_file_contains(
    "cmake/packaging/wix_resources/patch.xml"
    "NOT Installed AND LUMEN_INSTALL_VMIC = 0"
    "Virtual Microphone must default off only on fresh installs")
assert_file_contains_literal(
    "cmake/packaging/windows.cmake"
    [=[SUNSHINE_VIRTUAL_MICROPHONE_DRIVER_PACKAGE_DIR]=]
    "Windows packaging must accept an isolated Virtual Microphone package")
foreach(virtual_microphone_package_file IN ITEMS
        "LumenVirtualMicrophone.inf"
        "LumenVirtualMicrophone.sys"
        "LumenVirtualMicrophone.cat")
    assert_file_contains_literal(
        "cmake/packaging/windows.cmake"
        "${virtual_microphone_package_file}"
        "Windows packaging must require ${virtual_microphone_package_file}")
endforeach()
assert_file_contains_literal(
    "cmake/packaging/windows.cmake"
    [=[DESTINATION "drivers/virtual-microphone"]=]
    "The Virtual Microphone package must use its isolated directory")
assert_file_contains_literal(
    "cmake/packaging/windows.cmake"
    [=[list(REMOVE_ITEM CPACK_COMPONENTS_ALL virtual_microphone_driver)]=]
    "Lite ZIP packages must exclude the Virtual Microphone component")
assert_file_contains_literal(
    "tools/CMakeLists.txt"
    [=[add_executable(lumen-vmicctl lumen-vmicctl.cpp)]=]
    "Windows builds must produce the microphone lifecycle helper")
assert_file_contains_literal(
    "tools/lumen-vmicctl.cpp"
    [=[LUMEN_VMIC_ROOT_HARDWARE_ID_W]=]
    "The helper must scope mutations to the exact microphone root")
assert_file_contains_literal(
    "tools/lumen-vmicctl.cpp"
    [=[IOCTL_LUMEN_VMIC_QUERY_ABI]=]
    "The helper must validate the microphone control ABI")
assert_file_contains_literal(
    "tools/lumen-vmicctl.cpp"
    [=[PKEY_Device_FriendlyName]=]
    "The helper must retain the endpoint display name for diagnostics")
assert_file_contains_literal(
    "tools/lumen-vmicctl.cpp"
    [=[constexpr int kReadyWaitAttempts = 300;]=]
    "The helper must allow Core Audio endpoint materialization to complete")
assert_file_contains_literal(
    "tools/lumen-vmicctl.cpp"
    [=[PKEY_DeviceInterface_FriendlyName]=]
    "The helper must read the INF-owned audio-adapter identity")
assert_file_contains_literal(
    "tools/lumen-vmicctl.cpp"
    [=[_wcsicmp(adapter_name.pwszVal, kAdapterFriendlyName) == 0]=]
    "The helper must match the exact INF-owned adapter name")
assert_file_excludes(
    "tools/lumen-vmicctl.cpp"
    "PKEY_Device_InstanceId"
    "The helper must not require the absent MMDevice instance-ID property")
foreach(virtual_microphone_readiness_field IN ITEMS
        "roots_ready="
        "tree_ready="
        "endpoint_ready="
        "control_ready="
        "endpoint_property_hresult="
        "endpoint_names="
        "adapter_names=")
    assert_file_contains_literal(
        "tools/lumen-vmicctl.cpp"
        "${virtual_microphone_readiness_field}"
        "VMIC readiness failures must identify ${virtual_microphone_readiness_field}")
endforeach()
assert_file_contains_literal(
    "src_assets/windows/misc/sunshine-setup.ps1"
    [=[[string]$InstallVirtualMicrophone]=]
    "Setup must accept MSI microphone feature ownership")
assert_file_contains_literal(
    "src_assets/windows/misc/sunshine-setup.ps1"
    [=[Start-PersistedVirtualMicrophoneTransaction]=]
    "Setup must persist microphone rollback state before mutation")
assert_file_contains_literal(
    "src_assets/windows/misc/sunshine-setup.ps1"
    [=[Invoke-AllPersistedRollbacks]=]
    "Setup failures must roll back both optional device drivers")
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
