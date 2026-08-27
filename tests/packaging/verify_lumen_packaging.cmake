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

function(assert_file_literal_count relative_path expected_text expected_count description)
    file(READ "${LUMEN_ROOT}/${relative_path}" remaining_contents)
    set(actual_count 0)
    string(LENGTH "${expected_text}" expected_length)
    while(TRUE)
        string(FIND "${remaining_contents}" "${expected_text}" match_offset)
        if(match_offset EQUAL -1)
            break()
        endif()
        math(EXPR actual_count "${actual_count} + 1")
        math(EXPR next_offset "${match_offset} + ${expected_length}")
        string(SUBSTRING "${remaining_contents}" ${next_offset} -1 remaining_contents)
    endwhile()
    if(NOT actual_count EQUAL expected_count)
        message(FATAL_ERROR
            "${description}: expected ${expected_count}, found ${actual_count}: ${relative_path}")
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
    "Valid versions must enforce Windows MSI component limits")
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
assert_file_contains_literal(
    "cmake/packaging/wix_resources/patch.xml"
    [=[Start="auto"]=]
    "The MSI service must remain automatic across reboot after silent cutover")
assert_file_excludes(
    "cmake/packaging/wix_resources/patch.xml"
    "SunshineService"
    "The Lumen MSI must not claim the official Sunshine service")
assert_file_contains_literal(
    "cmake/packaging/wix_resources/patch.xml"
    [=[CPackWiXFragment Id="CM_FP_application.Lumen.exe"]=]
    "The MSI firewall rules must be attached to Lumen.exe")
foreach(lumen_firewall_contract IN ITEMS
        [=[Name="Lumen TCP"]=]
        [=[Protocol="tcp"]=]
        [=[Name="Lumen UDP"]=]
        [=[Protocol="udp"]=]
        [=[IgnoreFailure="no"]=])
    assert_file_contains_literal(
        "cmake/packaging/wix_resources/patch.xml"
        "${lumen_firewall_contract}"
        "The MSI must retain its transactional Lumen firewall contract")
endforeach()
assert_file_contains_literal(
    "cmake/packaging/windows_wix.cmake"
    [=["WixToolset.Firewall.wixext"]=]
    "WiX packaging must load the Firewall extension")
assert_file_contains_literal(
    "cmake/packaging/windows_wix.cmake"
    [=["fw=http://wixtoolset.org/schemas/v4/wxs/firewall"]=]
    "Generated WiX sources must declare the Firewall namespace")
assert_file_contains_literal(
    "src_assets/windows/misc/sunshine-setup.ps1"
    [=[Windows Installer owns the Lumen firewall rules.]=]
    "MSI setup must not duplicate declarative firewall rules")
assert_file_contains_literal(
    ".github/scripts/validate-windows-msi.ps1"
    [=[FROM `Wix4FirewallException`]=]
    "Windows CI must validate the compiled firewall table")
assert_file_contains_literal(
    ".github/scripts/validate-windows-msi.ps1"
    [=[$env:EXPECT_VHID_FEATURE]=]
    "Compiled MSI validation must support packages without the optional Virtual HID payload")
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
    [=[@(& $helper smoke-vigem --json)]=]
    "MSI validation must run the ViGEm/XUSB smoke in the interactive runner session")
assert_file_contains_literal(
    "tools/lumen-vhidctl.cpp"
    "vigem_target_x360_get_user_index"
    "The ViGEm smoke must retain XUSB user-index diagnostics")
assert_file_contains_literal(
    "tools/lumen-vhidctl.cpp"
    "vigem_target_get_index"
    "The ViGEm smoke must verify an indexed bus target")
assert_file_contains_literal(
    "tools/lumen-vhidctl.cpp"
    "vigem_target_is_attached"
    "The ViGEm smoke must verify a live bus target")
assert_file_contains_literal(
    "tools/lumen-vhidctl.cpp"
    "VIGEM_ERROR_XUSB_USERINDEX_OUT_OF_RANGE"
    "The ViGEm smoke must tolerate a missing hosted-session XUSB user index")
foreach(vigem_smoke_field IN ITEMS
        "busDeviceIndex"
        "userIndexAvailable"
        "xinputApiVisible")
    assert_file_contains_literal(
        ".github/scripts/test-windows-msi.ps1"
        "${vigem_smoke_field}"
        "MSI validation must retain the ${vigem_smoke_field} ViGEm smoke field")
endforeach()
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
assert_file_contains_literal(
    "cmake/packaging/windows_wix.cmake"
    [=[if(NOT SUNSHINE_VIRTUAL_HID_DRIVER_PACKAGE_DIR)]=]
    "WiX generation must omit Virtual HID feature references when no package is supplied")
assert_file_contains_literal(
    "cmake/packaging/wix_resources/patch.xml"
    [=[<!-- LUMEN_VHID_FEATURE_START -->]=]
    "The optional Virtual HID patch must retain its generation markers")
assert_file_contains_literal(
    "cmake/packaging/wix_resources/sunshine-installer.wxs"
    [=[<!-- LUMEN_VHID_FEATURE_START -->]=]
    "The optional Virtual HID MSI state resolvers must retain their generation markers")
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
    "Setup failures must roll back every selected device driver")
foreach(identity_disposition_contract IN ITEMS
        [=[protocol_v3_identity.bin]=]
        [=[protocol_v3_identity.journal]=]
        [=[Start-ProtectedIdentityUninstallTransaction]=]
        [=[Invoke-ProtectedIdentityRemoval]=]
        [=[Invoke-ProtectedIdentityRollback]=]
        [=[Restored exact protected identity bytes and ACL metadata during rollback.]=])
    assert_file_contains_literal(
        "src_assets/windows/misc/sunshine-setup.ps1"
        "${identity_disposition_contract}"
        "Installer identity disposition must retain ${identity_disposition_contract}")
endforeach()
assert_file_contains_literal(
    "cmake/packaging/wix_resources/sunshine-installer.wxs"
    [=[-IdentityDisposition preserve]=]
    "Repair, feature changes, and related upgrades must preserve protected identity")
assert_file_contains_literal(
    "cmake/packaging/wix_resources/sunshine-installer.wxs"
    [=[-IdentityDisposition remove]=]
    "Full uninstall must explicitly remove protected identity")
assert_file_contains_literal(
    ".github/scripts/test-windows-msi.ps1"
    [=['identity-reinstall']=]
    "Windows MSI validation must scaffold exact identity preservation across reinstall")
assert_file_contains_literal(
    ".github/scripts/validate-windows-msi.ps1"
    [=[`StartName` FROM `ServiceInstall`]=]
    "MSI table validation must verify the service principal")
assert_file_contains_literal(
    "cmake/packaging/windows.cmake"
    [=[LUMEN_WINDOWS_FULL_PROFILE]=]
    "Windows packaging must expose one strict full-profile gate")
assert_file_contains_literal(
    "cmake/packaging/windows.cmake"
    [=[SUNSHINE_VIRTUAL_DISPLAY_DRIVER_PACKAGE_DIR]=]
    "Windows packaging must accept an isolated Virtual Display package")
foreach(virtual_display_package_file IN ITEMS
        "LumenVirtualDisplay.inf"
        "LumenVirtualDisplay.cat"
        "LumenVirtualDisplay.dll")
    assert_file_contains_literal(
        "cmake/packaging/windows.cmake"
        "${virtual_display_package_file}"
        "Windows packaging must require ${virtual_display_package_file}")
endforeach()
assert_file_contains_literal(
    "tools/CMakeLists.txt"
    [=[add_executable(lumen-vddctl lumen-vddctl.cpp)]=]
    "The Virtual Display package must build its root-device lifecycle helper")
assert_file_contains_literal(
    "cmake/packaging/windows.cmake"
    [=[install(TARGETS lumen-vddctl]=]
    "Every Windows package must install the Virtual Display lifecycle helper")
assert_file_contains_literal(
    "cmake/packaging/windows.cmake"
    [=[# Keep the lifecycle helper in every Windows MSI. A driver-less major upgrade]=]
    "Driver-less MSI packages must retain the Virtual Display lifecycle helper")
assert_file_contains_literal(
    "cmake/packaging/windows.cmake"
    [=[DESTINATION "drivers/virtual-display"]=]
    "The Virtual Display package must use its isolated directory")
assert_file_contains_literal(
    "cmake/packaging/windows.cmake"
    [=[list(REMOVE_ITEM CPACK_COMPONENTS_ALL virtual_display_driver)]=]
    "Lite ZIP packages must exclude the Virtual Display component")
assert_file_contains_literal(
    "cmake/packaging/wix_resources/patch.xml"
    [=[CM_C_virtual_display_driver]=]
    "WiX must patch the optional Virtual Display feature")
assert_file_contains_literal(
    "cmake/packaging/wix_resources/sunshine-installer.wxs"
    [=[Property Id="LUMEN_INSTALL_VDD" Value="@LUMEN_INSTALL_VDD_DEFAULT@"]=]
    "Virtual Display selection must follow whether its package is present")
assert_file_contains_literal(
    "cmake/packaging/windows_wix.cmake"
    [=[set(LUMEN_INSTALL_VDD_DEFAULT 1)]=]
    "WiX packages containing the Virtual Display driver must select it by default")
assert_file_contains_literal(
    "cmake/packaging/windows_wix.cmake"
    [=[set(LUMEN_INSTALL_VDD_DEFAULT 0)]=]
    "WiX packages without the Virtual Display driver must keep its transaction disabled")
assert_file_contains_literal(
    "cmake/packaging/windows.cmake"
    [=[set(CPACK_COMPONENT_VIRTUAL_DISPLAY_DRIVER_DISABLED false)]=]
    "The packaged Virtual Display feature must be selected by default")
assert_file_contains_literal(
    "src_assets/windows/misc/sunshine-setup.ps1"
    [=[drivers\virtual-display\LumenVirtualDisplay.inf]=]
    "Direct setup must select Virtual Display only when its package is present")
assert_file_contains_literal(
    "src_assets/windows/misc/sunshine-setup.ps1"
    [=[[string]$InstallVirtualDisplay]=]
    "Setup must accept MSI Virtual Display feature ownership")
foreach(vdd_upgrade_contract IN ITEMS
        [=[LumenResolveUpgradeVddOwnership]=]
        [=[MsiEnumRelatedProductsW]=]
        [=[MsiQueryFeatureStateW]=]
        [=[LUMEN_UPGRADE_OWNED_VDD]=]
        [=[lumen_vdd_owner_selection_add]=]
        [=[LUMEN_VDD_OWNER_SELECTION_AMBIGUOUS]=])
    assert_file_contains_literal(
        "tools/lumen-msica.c"
        "${vdd_upgrade_contract}"
        "MSI upgrade ownership resolution must retain ${vdd_upgrade_contract}")
endforeach()
assert_file_contains_literal(
    "tools/lumen-msica-ownership.h"
    [=[Retain exactly one normalized related ProductCode and reject ambiguity.]=]
    "MSI owner selection must be portable and executable offline")
assert_file_contains_literal(
    "tests/packaging/test-lumen-msica-owner-selection.c"
    [=[multiple related feature owners must fail closed]=]
    "The offline C fixture must reject ambiguous related owners")
assert_file_contains_literal(
    "cmake/packaging/wix_resources/sunshine-installer.wxs"
    [=[-UpgradeOwnedVirtualDisplay [LUMEN_UPGRADE_OWNED_VDD]]=]
    "Deferred install actions must receive verified prior-product VDD ownership")
assert_file_contains_literal(
    "src_assets/windows/misc/sunshine-setup.ps1"
    [=[$upgradeOwnedVirtualDisplaySelected]=]
    "Setup must remove a replaced product's VDD when the new feature is absent")
foreach(vdd_upgrade_authority_contract IN ITEMS
        [=[$upgradeOwnerRequired = $Msi -and $TransactionKind -eq "install"]=]
        [=[UpgradeVddOwnerProduct is valid only for a verified related MSI ownership transaction.]=]
        [=[A verified related MSI VDD owner ProductCode is required for ownership transfer.]=])
    assert_file_contains_literal(
        "src_assets/windows/misc/sunshine-setup.ps1"
        "${vdd_upgrade_authority_contract}"
        "MSI ownership transfer authority must retain ${vdd_upgrade_authority_contract}")
endforeach()
assert_file_contains_literal(
    "src_assets/windows/misc/virtual-display-setup.ps1"
    [=[LumenVirtualDisplayInstallerV1]=]
    "Virtual Display setup must persist rollback state before mutation")
assert_file_contains_literal(
    "src_assets/windows/misc/virtual-display-setup.ps1"
    [=[/export-driver]=]
    "Virtual Display rollback must export the previous driver package")
assert_file_contains_literal(
    "src_assets/windows/misc/virtual-display-setup.ps1"
    [=[PreviousPublishedInfName]=]
    "Virtual Display replacement must retain the exact previous published INF identity")
foreach(vdd_identity_contract IN ITEMS
        [=[PreviousPublishedInfSha256]=]
        [=[PreviousPackageManifestSha256]=]
        [=[ForwardPublishedInfSha256]=]
        [=[ForwardPackageManifestSha256]=]
        [=[Assert-InstalledDriverIdentity]=]
        [=[now refers to a different driver package]=])
    assert_file_contains_literal(
        "src_assets/windows/misc/virtual-display-setup.ps1"
        "${vdd_identity_contract}"
        "Persisted VDD deletion identity must retain ${vdd_identity_contract}")
endforeach()
foreach(vdd_durable_ownership_contract IN ITEMS
        [=[owned-driver.json]=]
        [=[Write-OwnedDriverIdentity]=]
        [=[Read-OwnedDriverIdentity]=]
        [=[DeferredPreviousPackageRemoval]=]
        [=[Apply-CommittedOwnership]=]
        [=[Remove-DeferredPreviousPackage]=]
        [=[Set-PendingReboot -State $state -Phase "commit-remove-previous"]=]
        [=[UpgradeOwnerProductCode]=]
        [=[Resolve-VirtualDisplayOwnership]=]
        [=[PreviousOwnershipManifestSha256]=]
        [=[Resolve-OwnershipCommitAction]=]
        [=[Resolve-OwnershipRollbackAction]=]
        [=[Assert-VirtualDisplayResumeAfterRestart]=]
        [=[PendingPhase = "commit-ownership"]=]
        [=[OwnershipCommitted]=]
        [=[No device or durable VDD ownership manifest exists]=])
    assert_file_contains_literal(
        "src_assets/windows/misc/virtual-display-setup.ps1"
        "${vdd_durable_ownership_contract}"
        "Durable device-absent VDD cleanup must retain ${vdd_durable_ownership_contract}")
endforeach()
assert_file_excludes(
    "src_assets/windows/misc/virtual-display-setup.ps1"
    [=[Ignoring a VDD ownership manifest belonging to a different Lumen product.]=]
    "A foreign ProductCode manifest must never be downgraded to unowned hardware")
assert_file_contains_literal(
    "tests/packaging/test-virtual-display-ownership-contract.ps1"
    [=[ProductCode ownership transfer/refusal contract]=]
    "The offline PowerShell fixture must execute ownership, rollback, and resume decisions")
assert_file_contains_literal(
    "tests/packaging/run-gate5-msi-offline-fixtures.cmake"
    [=[Verified Gate 5 MSI ownership fixtures.]=]
    "Gate 5 MSI fixtures must have one portable runner")
assert_file_contains_literal(
    "cmake/packaging/wix_resources/sunshine-installer.wxs"
    [=[<Custom Action="CA_LumenResolveUpgradeVddOwnership" After="CostFinalize"
              Condition="NOT (REMOVE=&quot;ALL&quot;)"/>]=]
    "MSI owner resolution must precede every deferred ownership action")
foreach(vdd_transaction_order_contract IN ITEMS
        [=[<Custom Action="CA_LumenInstallRollback" After="SetLumenInstallCommitData"]=]
        [=[<Custom Action="CA_LumenInstall" After="CA_LumenInstallRollback"]=]
        [=[<Custom Action="CA_LumenInstallCommit" After="CA_LumenInstall"]=]
        [=[After="InstallFiles" Sequence="execute"]=]
        [=[After="SetLumenInstallRollbackData" Sequence="execute"]=]
        [=[After="SetLumenInstallData" Sequence="execute"]=])
    assert_file_contains_literal(
        "cmake/packaging/wix_resources/sunshine-installer.wxs"
        "${vdd_transaction_order_contract}"
        "MSI ownership transaction ordering must retain ${vdd_transaction_order_contract}")
endforeach()
assert_file_literal_count(
    "cmake/packaging/wix_resources/sunshine-installer.wxs"
    [=[-UpgradeVddOwnerProduct &quot;[LUMEN_UPGRADE_VDD_OWNER_PRODUCT]&quot;]=]
    3
    "Install rollback/forward/commit must receive the same verified prior ProductCode")
assert_file_contains_literal(
    ".github/workflows/ci-windows.yml"
    [=[EXPECT_VDD_FEATURE: 'true']=]
    "The live MSI scenario must receive the same VDD payload expectation as table validation")
assert_file_contains_literal(
    "src_assets/windows/misc/virtual-display-setup.ps1"
    [=[Remove-StateLessBootstrap]=]
    "A failed pre-mutation VDD bootstrap must clean retry-blocking artifacts")
assert_file_contains_literal(
    "src_assets/windows/misc/virtual-display-setup.ps1"
    [=[throw $bootstrapError]=]
    "VDD bootstrap cleanup must preserve the original failure after restoring retryability")
assert_file_contains_literal(
    "src_assets/windows/misc/virtual-display-setup.ps1"
    [=[if ([bool]$state.RollbackComplete) {]=]
    "Completed VDD rollback cleanup must remain retryable after state publication")
assert_file_contains_literal(
    "src_assets/windows/misc/virtual-display-setup.ps1"
    [=[Remove-PublishedDriverPackage]=]
    "Virtual Display replacement and uninstall must remove the exact superseded package")
assert_file_contains_literal(
    "src_assets/windows/misc/virtual-display-setup.ps1"
    [=[remained staged after removal]=]
    "Virtual Display cleanup must verify that the superseded package left Driver Store")
assert_file_contains_literal(
    "src_assets/windows/misc/virtual-display-setup.ps1"
    [=[if ([bool]$state.DesiredPresent) {]=]
    "Virtual Display reboot resume must reinstall only when the transaction still desires the driver")
assert_file_excludes(
    "src_assets/windows/misc/virtual-display-setup.ps1"
    [=[if ([string]$state.TransactionKind -eq "install") {]=]
    "Virtual Display feature deselection must not reinstall the driver after a reboot")
foreach(vdd_msi_contract IN ITEMS
        [=['install-vdd']=]
        [=[MSI default Virtual Display installation failed.]=]
        [=[New-MajorUpgradeFixture]=]
        [=[Lumen major upgrade with Virtual Display deselected failed.]=]
        [=[orphaned the previous VDD]=]
        [=[package-only cleanup validation]=]
        [=[owned device-absent package staged]=]
        [=[ROOT\LumenVirtualDisplay]=]
        [=[LumenVirtualDisplay\.inf]=])
    assert_file_contains_literal(
        ".github/scripts/test-windows-msi.ps1"
        "${vdd_msi_contract}"
        "MSI validation must retain the Virtual Display contract ${vdd_msi_contract}")
endforeach()
assert_file_excludes(
    ".github/scripts/test-windows-msi.ps1"
    [=[LUMEN_INSTALL_VDD=1]=]
    "MSI live validation must prove Virtual Display installation without a property override")
assert_file_contains_literal(
    "scripts/windows/build-full-profile.ps1"
    [=[LUMEN_MSQUIC_SHIM_DLL_SHA256]=]
    "The full-profile builder must pass the built MsQuic DLL pin")
assert_file_contains_literal(
    "scripts/windows/build-full-profile.ps1"
    [=[SUNSHINE_VIRTUAL_DISPLAY_DRIVER_PACKAGE_DIR]=]
    "The full-profile builder must pass the signed Virtual Display package root")
assert_file_contains_literal(
    "scripts/windows/build-full-profile.ps1"
    [=[Expand-VerifiedFullProfileSource]=]
    "The full-profile builder must compile from a verified extracted source freeze")
assert_file_contains_literal(
    "scripts/windows/build-full-profile.ps1"
    [=[$SourceRoot = $sourceProvenance.SourceRoot]=]
    "The full-profile builder must replace the mutable source root before compilation")
assert_file_contains_literal(
    "scripts/windows/build-full-profile.ps1"
    [=[--gtest_filter='-EncoderVariants/EncoderTest.*']=]
    "The disposable full-profile builder must leave physical encoder probes to the hardware gate")
foreach(full_profile_toolchain_contract IN ITEMS
        [=[[string]$PythonPath]=]
        [=[[string]$DotNetRoot]=]
        [=[[string]$NodeRoot]=]
        [=[export UV_PYTHON=]=]
        [=[export DOTNET_ROOT=]=]
        [=[sync --locked --no-python-downloads --no-install-project]=]
        [=[-DBUILD_WERROR=ON]=]
        [=[-DDOTNET_EXECUTABLE=]=]
        [=[-DNPM=]=])
    assert_file_contains_literal(
        "scripts/windows/build-full-profile.ps1"
        "${full_profile_toolchain_contract}"
        "The full-profile builder must retain toolchain contract ${full_profile_toolchain_contract}")
endforeach()
foreach(full_profile_clean_boundary IN ITEMS
        [=[Remove-Item -LiteralPath $freezeDirectory]=]
        [=[Remove-Item -LiteralPath $PackageDirectory]=]
        [=[Remove-Item -LiteralPath $shimOutput]=]
        [=[Remove-Item -LiteralPath $buildRoot]=]
        [=[Remove-Item -LiteralPath $artifacts]=])
    assert_file_contains_literal(
        "scripts/windows/build-full-profile.ps1"
        "${full_profile_clean_boundary}"
        "The full-profile builder must clean generated boundary ${full_profile_clean_boundary}")
endforeach()
foreach(full_profile_archive_stream_contract IN ITEMS
        [=[[string]$ArchiveCreateTarPath]=]
        [=[Write-FullProfileTarList -Paths ([string[]]$files.RelativePath)]=]
        [=[$tarStartInfo.Environment['PATH']]=]
        [=[$tarDirectory + [IO.Path]::PathSeparator]=]
        [=[$tarStartInfo.RedirectStandardOutput = $true]=]
        [=[$tarStartInfo.RedirectStandardError = $true]=]
        [=[@('-czh', '-f', '-', '-C', $SourceRoot, '-T', $listPath)]=]
        [=[$tarProcess.StandardError.ReadToEndAsync()]=]
        [=[$tarProcess.StandardOutput.BaseStream.CopyTo($archiveStream)]=]
        [=[$tarProcess.WaitForExit(5000)]=]
        [=[if ($null -ne $stderrTask -and $tarExitedAfterFailure)]=]
        [=[Remove-Item -LiteralPath $archivePath -Force -ErrorAction SilentlyContinue]=])
    assert_file_contains_literal(
        "scripts/windows/freeze-full-profile-source.ps1"
        "${full_profile_archive_stream_contract}"
        "Source freeze must retain streamed archive contract ${full_profile_archive_stream_contract}")
endforeach()
foreach(full_profile_archive_builder_contract IN ITEMS
        [=[Join-Path $Msys2Root "usr\bin\tar.exe"]=]
        [=['-ArchiveCreateTarPath']=]
        [=[msys2-tar]=])
    assert_file_contains_literal(
        "scripts/windows/build-full-profile.ps1"
        "${full_profile_archive_builder_contract}"
        "Full-profile builds must retain archive creator contract ${full_profile_archive_builder_contract}")
endforeach()
assert_file_excludes(
    "scripts/windows/freeze-full-profile-source.ps1"
    [=[-czhf $archivePath]=]
    "Source freeze must not let bsdtar open its output filename directly")
assert_file_excludes(
    "scripts/windows/freeze-full-profile-source.ps1"
    [=[WriteAllLines]=]
    "Source freeze tar list must not use platform-native line endings or a trailing record")
foreach(full_profile_workflow_contract IN ITEMS
        [=[steps.setup-python.outputs.python-path]=]
        [=[-PythonPath $env:PYTHON_PATH]=]
        [=[-DotNetRoot $env:DOTNET_ROOT]=]
        [=[-NodeRoot $env:NODEJS_PATH]=]
        [=[-WdkApiValidatorBinRoot $env:WDK_API_VALIDATOR_BIN_ROOT]=]
        [=[-WdkUniversalDdisRoot $env:WDK_UNIVERSAL_DDIS_ROOT]=]
        [=[Microsoft.Windows.WDK.x64.10.0.26100.1.nupkg]=]
        [=[$expectedPackageBytes = 110015300]=]
        [=[247B2919AE451F65BA5F1CD51C7C39730FB0FC383D607F3E8AB317FDDC8A8239]=]
        [=[5aHxX9Jh7tv9wqfXR2taMxP0LOwz1t/2UwAx70Z3uyKlkkYmNOxCTQ3rod1mShsJJ63e6Nmq/53gPJkcLOQIAg==]=]
        [=[$installedApiValidator = Get-ChildItem $kitsRoot]=]
        [=[$installedUniversalDdis = Get-ChildItem $kitsRoot]=]
        [=[-BuildOnly]=]
        [=[sign-full-profile-local-test.ps1]=])
    assert_file_contains_literal(
        ".github/workflows/ci-windows.yml"
        "${full_profile_workflow_contract}"
        "Windows CI must pass exact toolchain contract ${full_profile_workflow_contract}")
endforeach()
assert_file_excludes(
    ".github/workflows/ci-windows.yml"
    [=[LUMEN_BUILD_PROFILE=legacy]=]
    "Windows CI must never downgrade the canonical build to the legacy profile")
foreach(full_profile_build_only_contract IN ITEMS
        [=[FULL_PROFILE_BUILD_STATUS=driver-submission-ready]=]
        [=[-DPython3_ROOT_DIR=]=]
        [=[-DPython3_EXECUTABLE=]=]
        [=[[string]$WdkApiValidatorBinRoot]=]
        [=[[string]$WdkUniversalDdisRoot]=]
        [=[full-profile inventory is missing]=]
        [=[UsePreparedDriverSubmission]=]
        [=[FULL_PROFILE_MSQUIC_SHIM_LIB_SHA256]=]
        [=[vdd-shader-inventory.json]=]
        [=[local-test-only-non-production]=])
    assert_file_contains_literal(
        "scripts/windows/build-full-profile.ps1"
        "${full_profile_build_only_contract}"
        "The build-only full-profile lane must retain ${full_profile_build_only_contract}")
endforeach()
assert_file_contains_literal(
    "scripts/windows/sign-full-profile-local-test.ps1"
    [=[purpose = "local-test-only"]=]
    "Local test signing must emit an explicit non-release marker")
assert_file_contains(
    "cmake/packaging/wix_resources/sunshine-installer.wxs"
    "Target=\"\\[INSTALL_ROOT\\]Lumen.exe\""
    "Installer shortcuts must launch Lumen.exe")
assert_file_contains(
    "cmake/packaging/wix_resources/sunshine-installer.wxs"
    "Software\\\\simonfalke\\\\Lumen"
    "Installer registry keys must use the expected publisher identity")
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
