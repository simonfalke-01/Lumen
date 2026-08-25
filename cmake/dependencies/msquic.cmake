# Optional, local-only MsQuic 2.6.0 Schannel artifact discovery.
#
# This module never downloads or builds MsQuic. The explicit experimental
# option requires an extracted official NuGet package and validates the pinned
# package version plus the x64 header/import-library/DLL hashes before exposing
# MsQuic::MsQuic. The package's MIT LICENSE is staged for packaging handoff.

set(LUMEN_MSQUIC_PINNED_VERSION "2.6.0")
set(LUMEN_MSQUIC_NUGET_SHA256
    "37636dbc4fbb527f7a2f4505893bb2619862aa5879cc65499a048401c44eb590")
set(LUMEN_MSQUIC_SHIM_DLL_SHA256 "" CACHE STRING
    "SHA-256 of the approved ABI3 lumen_msquic_shim.dll Release artifact")
set(LUMEN_MSQUIC_SHIM_LIB_SHA256 "" CACHE STRING
    "SHA-256 of the approved ABI3 lumen_msquic_shim.lib Release artifact")

set(LUMEN_MSQUIC_ROOT "" CACHE PATH
    "Extracted Microsoft.Native.Quic.MsQuic.Schannel 2.6.0 NuGet package root")
set(LUMEN_MSQUIC_VERSION "" CACHE STRING "Validated local MsQuic package version")
set(LUMEN_MSQUIC_SHIM_ROOT "" CACHE PATH
    "MSVC x64 output containing lumen_msquic_shim.lib and lumen_msquic_shim.dll")

if(NOT LUMEN_MSQUIC_VERSION STREQUAL LUMEN_MSQUIC_PINNED_VERSION)
    message(FATAL_ERROR
        "LUMEN_EXPERIMENTAL_MSQUIC requires LUMEN_MSQUIC_VERSION=${LUMEN_MSQUIC_PINNED_VERSION}.")
endif()
if(NOT IS_DIRECTORY "${LUMEN_MSQUIC_ROOT}")
    message(FATAL_ERROR "LUMEN_MSQUIC_ROOT must be an extracted official Schannel NuGet package.")
endif()

set(_lumen_msquic_include "${LUMEN_MSQUIC_ROOT}/build/native/include")
set(_lumen_msquic_library "${LUMEN_MSQUIC_ROOT}/build/native/lib/x64/msquic.lib")
set(_lumen_msquic_runtime "${LUMEN_MSQUIC_ROOT}/build/native/bin/x64/msquic.dll")
set(_lumen_msquic_license "${LUMEN_MSQUIC_ROOT}/LICENSE")

foreach(_required IN ITEMS
        "${_lumen_msquic_include}/msquic.h"
        "${_lumen_msquic_library}"
        "${_lumen_msquic_runtime}"
        "${_lumen_msquic_license}")
    if(NOT EXISTS "${_required}")
        message(FATAL_ERROR "Incomplete MsQuic package: missing ${_required}")
    endif()
endforeach()

file(SHA256 "${_lumen_msquic_include}/msquic.h" _lumen_msquic_header_sha256)
file(SHA256 "${_lumen_msquic_library}" _lumen_msquic_library_sha256)
file(SHA256 "${_lumen_msquic_runtime}" _lumen_msquic_runtime_sha256)
file(SHA256 "${_lumen_msquic_license}" _lumen_msquic_license_sha256)
if(NOT _lumen_msquic_header_sha256 STREQUAL
       "ebd3499686c2b3008ed0ee5b06dae1a62a50192816abfe9a67bbbba97cabb861" OR
   NOT _lumen_msquic_library_sha256 STREQUAL
       "aa08808c1ca29166ea476a66410b73c7d0d85a34459ea59a30de63cca7ad7327" OR
   NOT _lumen_msquic_runtime_sha256 STREQUAL
       "c981e61cd207f42d46b54ef7dbf1049f1f836424c3ba981f4469ac2b2bea9610" OR
   NOT _lumen_msquic_license_sha256 STREQUAL
       "903df5512f7d02609fed0c780a9b704f5a3eeb6e4d84ebe42a29845c81899a3c")
    message(FATAL_ERROR "MsQuic 2.6.0 artifact hashes do not match the approved x64 Schannel package.")
endif()

set(_lumen_msquic_shim_library "${LUMEN_MSQUIC_SHIM_ROOT}/lumen_msquic_shim.lib")
set(_lumen_msquic_shim_runtime "${LUMEN_MSQUIC_SHIM_ROOT}/lumen_msquic_shim.dll")
set(_lumen_msquic_shim_manifest "${LUMEN_MSQUIC_SHIM_ROOT}/manifest.json")
if(NOT EXISTS "${_lumen_msquic_shim_library}" OR NOT EXISTS "${_lumen_msquic_shim_runtime}" OR
   NOT EXISTS "${_lumen_msquic_shim_manifest}")
    message(FATAL_ERROR
        "LUMEN_EXPERIMENTAL_MSQUIC requires the separately MSVC-built lumen_msquic_shim DLL/import library.")
endif()
if(LUMEN_MSQUIC_SHIM_DLL_SHA256 STREQUAL "" OR LUMEN_MSQUIC_SHIM_LIB_SHA256 STREQUAL "")
    message(FATAL_ERROR
        "Lumen MsQuic ABI3 bulk-stream artifact pins are pending the next approved MSVC Release build.")
endif()

file(SHA256 "${CMAKE_SOURCE_DIR}/src/platform/windows/msquic_shim/lumen_msquic_shim.h"
     _lumen_msquic_shim_header_sha256)
file(SHA256 "${CMAKE_SOURCE_DIR}/src/platform/windows/msquic_shim/lumen_msquic_shim.cpp"
     _lumen_msquic_shim_source_sha256)
file(SHA256 "${CMAKE_SOURCE_DIR}/src/platform/windows/msquic_shim/cng_key_journal.h"
     _lumen_msquic_shim_cng_journal_sha256)
file(SHA256 "${CMAKE_SOURCE_DIR}/src/platform/windows/msquic_shim/LumenMsQuicShim.vcxproj"
     _lumen_msquic_shim_project_sha256)
if(NOT _lumen_msquic_shim_header_sha256 STREQUAL
       "0649ca20aeb3a883200842456ffee4ac1e76f07144a41b972d666c4cb10267fa" OR
   NOT _lumen_msquic_shim_source_sha256 STREQUAL
       "72ded95fa3d1f57846c1b22186aa79c4e1f1a50062534492c80d94747c032db1" OR
   NOT _lumen_msquic_shim_cng_journal_sha256 STREQUAL
       "7fb567a6ac16050bc7b2b4bd1da650644a49958bae6aed0b683ca37b69d24962" OR
   NOT _lumen_msquic_shim_project_sha256 STREQUAL
       "36be00e3274561990716bd952c8f7d178feb898b3cd2c64acba7956e57f90aef")
    message(FATAL_ERROR "Lumen MsQuic shim ABI/source/toolset manifest validation failed.")
endif()
file(READ "${_lumen_msquic_shim_manifest}" _lumen_msquic_manifest_json)
string(JSON _lumen_msquic_manifest_abi GET "${_lumen_msquic_manifest_json}" abi)
string(JSON _lumen_msquic_manifest_header GET "${_lumen_msquic_manifest_json}" header_sha256)
string(JSON _lumen_msquic_manifest_source GET "${_lumen_msquic_manifest_json}" source_sha256)
string(JSON _lumen_msquic_manifest_cng_journal GET "${_lumen_msquic_manifest_json}" cng_key_journal_sha256)
string(JSON _lumen_msquic_manifest_project GET "${_lumen_msquic_manifest_json}" project_sha256)
string(JSON _lumen_msquic_manifest_arch GET "${_lumen_msquic_manifest_json}" architecture)
string(JSON _lumen_msquic_manifest_toolset GET "${_lumen_msquic_manifest_json}" toolset)
string(JSON _lumen_msquic_manifest_dll GET "${_lumen_msquic_manifest_json}" shim_dll_sha256)
string(JSON _lumen_msquic_manifest_lib GET "${_lumen_msquic_manifest_json}" shim_import_library_sha256)
file(SHA256 "${_lumen_msquic_shim_runtime}" _lumen_msquic_shim_runtime_sha256)
file(SHA256 "${_lumen_msquic_shim_library}" _lumen_msquic_shim_library_sha256)
if(NOT _lumen_msquic_manifest_abi EQUAL 3 OR
   NOT _lumen_msquic_manifest_arch STREQUAL "x64" OR
   NOT _lumen_msquic_manifest_toolset STREQUAL "v143" OR
   NOT _lumen_msquic_manifest_header STREQUAL _lumen_msquic_shim_header_sha256 OR
   NOT _lumen_msquic_manifest_source STREQUAL _lumen_msquic_shim_source_sha256 OR
   NOT _lumen_msquic_manifest_cng_journal STREQUAL _lumen_msquic_shim_cng_journal_sha256 OR
   NOT _lumen_msquic_manifest_project STREQUAL _lumen_msquic_shim_project_sha256 OR
   NOT _lumen_msquic_manifest_dll STREQUAL LUMEN_MSQUIC_SHIM_DLL_SHA256 OR
   NOT _lumen_msquic_manifest_lib STREQUAL LUMEN_MSQUIC_SHIM_LIB_SHA256 OR
   NOT _lumen_msquic_manifest_dll STREQUAL _lumen_msquic_shim_runtime_sha256 OR
   NOT _lumen_msquic_manifest_lib STREQUAL _lumen_msquic_shim_library_sha256)
    message(FATAL_ERROR "Lumen MsQuic shim DLL/import-library identity validation failed.")
endif()

add_library(Lumen::MsQuicShim SHARED IMPORTED GLOBAL)
set_target_properties(Lumen::MsQuicShim PROPERTIES
    IMPORTED_IMPLIB "${_lumen_msquic_shim_library}"
    IMPORTED_LOCATION "${_lumen_msquic_shim_runtime}"
    INTERFACE_INCLUDE_DIRECTORIES
        "${CMAKE_SOURCE_DIR}/src/platform/windows/msquic_shim")

set(LUMEN_MSQUIC_RUNTIME "${_lumen_msquic_runtime}" CACHE INTERNAL "Pinned MsQuic runtime")
set(LUMEN_MSQUIC_SHIM_RUNTIME "${_lumen_msquic_shim_runtime}" CACHE INTERNAL "MSVC-built Lumen MsQuic shim")
set(LUMEN_MSQUIC_LICENSE "${_lumen_msquic_license}" CACHE INTERNAL "Pinned MsQuic MIT license")
file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/third_party_notices")
configure_file("${_lumen_msquic_license}"
               "${CMAKE_BINARY_DIR}/third_party_notices/MsQuic-2.6.0-LICENSE.txt" COPYONLY)

unset(_lumen_msquic_header_sha256)
unset(_lumen_msquic_library_sha256)
unset(_lumen_msquic_runtime_sha256)
unset(_lumen_msquic_license_sha256)
