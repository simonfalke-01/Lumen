# common compile definitions
# this file will also load platform specific definitions

list(APPEND LUMEN_COMPILE_OPTIONS -Wall -Wno-sign-compare)
# Wall - enable all warnings
# Werror - treat warnings as errors
# Wno-maybe-uninitialized/Wno-uninitialized - disable warnings for maybe uninitialized variables
# Wno-sign-compare - disable warnings for signed/unsigned comparisons
# Wno-restrict - disable warnings for memory overlap
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    # GCC specific compile options

    # GCC 12 and higher will complain about maybe-uninitialized
    if(CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 12)
        list(APPEND LUMEN_COMPILE_OPTIONS -Wno-maybe-uninitialized)

        # Disable the bogus warning that may prevent compilation (only for GCC 12).
        # See https://gcc.gnu.org/bugzilla/show_bug.cgi?id=105651.
        if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS 13)
            list(APPEND LUMEN_COMPILE_OPTIONS -Wno-restrict)
        endif()
    endif()

    # GCC 15 will complain about uninitialized variables in some cases (Simple-Web-Server)
    if(CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 15)
        list(APPEND LUMEN_COMPILE_OPTIONS -Wno-uninitialized)
    endif()
elseif(CMAKE_CXX_COMPILER_ID MATCHES "^(Apple)?Clang$")
    # Clang specific compile options

    # Clang doesn't actually complain about this this, so disabling for now
    # list(APPEND LUMEN_COMPILE_OPTIONS -Wno-uninitialized)

    # Some libc++ versions on Apple and FreeBSD guard std::jthread behind this flag.
    if(APPLE OR CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
        list(APPEND LUMEN_COMPILE_OPTIONS -fexperimental-library)
        list(APPEND LUMEN_LINK_OPTIONS -fexperimental-library)
    endif()
endif()
if(BUILD_WERROR)
    list(APPEND LUMEN_COMPILE_OPTIONS -Werror)
endif()

if(WIN32 AND LUMEN_BUILD_PROFILE STREQUAL "full")
    list(APPEND LUMEN_DEFINITIONS LUMEN_LSP_DEFAULT_ENABLED=1)
else()
    list(APPEND LUMEN_DEFINITIONS LUMEN_LSP_DEFAULT_ENABLED=0)
endif()

set(LUMEN_PHOTON_DIRECTORY "${CMAKE_SOURCE_DIR}/src/protocol_lsp")
set(LUMEN_PHOTON_LOCK "${LUMEN_PHOTON_DIRECTORY}/photon.lock")
set(LUMEN_PHOTON_MANIFEST "${LUMEN_PHOTON_DIRECTORY}/photon-source-manifest.txt")
set(LUMEN_PHOTON_DIGEST "${LUMEN_PHOTON_DIRECTORY}/photon-source-digest.sha256")
set(LUMEN_PHOTON_EXPECTED_LOCK
        "repository=git@github.com:simonfalke-01/Photon.git\ncommit=6a504910dfeb0489eb33af02e4bd3659e8c11e24\ndigest=d565644e8c3a00d6c474d6c118b8b8eccd3140d35eda54dbb0bba7c42f1ca7f0\n")
file(READ "${LUMEN_PHOTON_LOCK}" LUMEN_PHOTON_ACTUAL_LOCK)
if(NOT LUMEN_PHOTON_ACTUAL_LOCK STREQUAL LUMEN_PHOTON_EXPECTED_LOCK)
    message(FATAL_ERROR "Lumen's Photon lock does not match the reviewed repository, commit, and digest")
endif()
file(STRINGS "${LUMEN_PHOTON_MANIFEST}" LUMEN_PHOTON_FILES ENCODING UTF-8)
if(NOT LUMEN_PHOTON_FILES)
    message(FATAL_ERROR "Lumen's Photon source manifest is empty")
endif()
set(LUMEN_PHOTON_DIGEST_INPUT "")
foreach(LUMEN_PHOTON_FILE IN LISTS LUMEN_PHOTON_FILES)
    if(NOT LUMEN_PHOTON_FILE MATCHES "^(core|input_plane|media|transport)/[a-z0-9_]+\\.h$")
        message(FATAL_ERROR "Invalid Photon source manifest entry: ${LUMEN_PHOTON_FILE}")
    endif()
    if(NOT EXISTS "${LUMEN_PHOTON_DIRECTORY}/${LUMEN_PHOTON_FILE}")
        message(FATAL_ERROR "Missing mirrored Photon source: ${LUMEN_PHOTON_FILE}")
    endif()
    file(SHA256
            "${LUMEN_PHOTON_DIRECTORY}/${LUMEN_PHOTON_FILE}"
            LUMEN_PHOTON_FILE_DIGEST)
    string(TOLOWER "${LUMEN_PHOTON_FILE_DIGEST}" LUMEN_PHOTON_FILE_DIGEST)
    string(APPEND LUMEN_PHOTON_DIGEST_INPUT
            "${LUMEN_PHOTON_FILE}\n${LUMEN_PHOTON_FILE_DIGEST}\n")
endforeach()
file(GLOB_RECURSE LUMEN_PHOTON_PRESENT_FILES
        RELATIVE "${LUMEN_PHOTON_DIRECTORY}"
        "${LUMEN_PHOTON_DIRECTORY}/core/*.h"
        "${LUMEN_PHOTON_DIRECTORY}/input_plane/*.h"
        "${LUMEN_PHOTON_DIRECTORY}/media/*.h"
        "${LUMEN_PHOTON_DIRECTORY}/transport/*.h")
set(LUMEN_PHOTON_EXPECTED_FILES ${LUMEN_PHOTON_FILES})
list(SORT LUMEN_PHOTON_PRESENT_FILES)
list(SORT LUMEN_PHOTON_EXPECTED_FILES)
if(NOT LUMEN_PHOTON_PRESENT_FILES STREQUAL LUMEN_PHOTON_EXPECTED_FILES)
    message(FATAL_ERROR "Lumen's mirrored Photon header set differs from photon-source-manifest.txt")
endif()
string(SHA256 LUMEN_PHOTON_ACTUAL_DIGEST "${LUMEN_PHOTON_DIGEST_INPUT}")
file(READ "${LUMEN_PHOTON_DIGEST}" LUMEN_PHOTON_EXPECTED_DIGEST)
string(STRIP "${LUMEN_PHOTON_EXPECTED_DIGEST}" LUMEN_PHOTON_EXPECTED_DIGEST)
string(TOLOWER "${LUMEN_PHOTON_EXPECTED_DIGEST}" LUMEN_PHOTON_EXPECTED_DIGEST)
if(NOT LUMEN_PHOTON_EXPECTED_DIGEST STREQUAL "d565644e8c3a00d6c474d6c118b8b8eccd3140d35eda54dbb0bba7c42f1ca7f0")
    message(FATAL_ERROR "Lumen's Photon digest file differs from photon.lock")
endif()
if(NOT LUMEN_PHOTON_ACTUAL_DIGEST STREQUAL LUMEN_PHOTON_EXPECTED_DIGEST)
    message(FATAL_ERROR
            "Pinned Photon LSP core digest mismatch: expected "
            "${LUMEN_PHOTON_EXPECTED_DIGEST}, computed ${LUMEN_PHOTON_ACTUAL_DIGEST}. "
            "Run scripts/sync-photon-core.sh --check for details.")
endif()

# setup assets directory
if(NOT LUMEN_ASSETS_DIR)
    set(LUMEN_ASSETS_DIR "assets")
endif()

# platform specific compile definitions
if(WIN32)
    include(${CMAKE_MODULE_PATH}/compile_definitions/windows.cmake)
elseif(UNIX)
    include(${CMAKE_MODULE_PATH}/compile_definitions/unix.cmake)

    if(APPLE)
        include(${CMAKE_MODULE_PATH}/compile_definitions/macos.cmake)
    else()
        include(${CMAKE_MODULE_PATH}/compile_definitions/linux.cmake)
    endif()
endif()

set(NVENC_PUBLIC_SOURCES
        "${CMAKE_SOURCE_DIR}/src/nvenc/nvenc_config.h"
        "${CMAKE_SOURCE_DIR}/src/nvenc/nvenc_d3d11_interface.h"
        "${CMAKE_SOURCE_DIR}/src/nvenc/nvenc_dynamic_factory.cpp"
        "${CMAKE_SOURCE_DIR}/src/nvenc/nvenc_dynamic_factory.h"
        "${CMAKE_SOURCE_DIR}/src/nvenc/nvenc_dynamic_factory_versions.h"
        "${CMAKE_SOURCE_DIR}/src/nvenc/nvenc_encoded_frame.h"
        "${CMAKE_SOURCE_DIR}/src/nvenc/nvenc_encoder.h"
        "${CMAKE_SOURCE_DIR}/src/nvenc/nvenc_hdr_metadata.h"
        "${CMAKE_SOURCE_DIR}/src/nvenc/nvenc_shared_dll.h"
        "${CMAKE_SOURCE_DIR}/src/nvenc/nvenc_version.h"
)
set(NVENC_SOURCES ${NVENC_PUBLIC_SOURCES})

if(WIN32)
    set(NVENC_IMPLEMENTATION_SOURCES
            "${CMAKE_SOURCE_DIR}/src/nvenc/nvenc_base.cpp"
            "${CMAKE_SOURCE_DIR}/src/nvenc/nvenc_d3d11.cpp"
            "${CMAKE_SOURCE_DIR}/src/nvenc/nvenc_d3d11_native.cpp"
            "${CMAKE_SOURCE_DIR}/src/nvenc/nvenc_d3d11_on_cuda.cpp"
            "${CMAKE_SOURCE_DIR}/src/nvenc/nvenc_dynamic_factory_impl.cpp"
            "${CMAKE_SOURCE_DIR}/src/nvenc/nvenc_utils.cpp"
    )

    # Add a version-isolated NVENC implementation object library.
    # add_nvenc_sdk_implementation: args = `target_name`, `sdk_version`, `sdk_include_dir`
    function(add_nvenc_sdk_implementation target_name sdk_version sdk_include_dir)
        add_library(${target_name} OBJECT ${NVENC_IMPLEMENTATION_SOURCES})
        target_include_directories(${target_name} BEFORE PRIVATE "${sdk_include_dir}")
        target_compile_definitions(${target_name} PRIVATE
                NVENC_FACTORY_SUFFIX=${sdk_version}
                NVENC_NAMESPACE=nvenc_${sdk_version}
                NVENC_SDK_VERSION=${sdk_version}
        )
        target_link_libraries(${target_name} PRIVATE ${Boost_LIBRARIES})
        target_compile_options(${target_name} PRIVATE ${LUMEN_COMPILE_OPTIONS})
    endfunction()

    add_nvenc_sdk_implementation(nvenc_sdk_1100 1100 "${NV_CODEC_HEADERS_11_INCLUDE_DIR}")
    add_nvenc_sdk_implementation(nvenc_sdk_1200 1200 "${NV_CODEC_HEADERS_12_INCLUDE_DIR}")
    add_nvenc_sdk_implementation(nvenc_sdk_1300 1300 "${NV_CODEC_HEADERS_13_INCLUDE_DIR}")

    list(APPEND NVENC_SOURCES
            $<TARGET_OBJECTS:nvenc_sdk_1100>
            $<TARGET_OBJECTS:nvenc_sdk_1200>
            $<TARGET_OBJECTS:nvenc_sdk_1300>
    )
endif()

list(APPEND PLATFORM_TARGET_FILES ${NVENC_SOURCES})

set(FFMPEG_CONFIG_HEADER "${FFMPEG_PREPARED_BINARIES}/include/config.h")
if(NOT EXISTS "${FFMPEG_CONFIG_HEADER}")
    message(FATAL_ERROR "Pinned FFmpeg package is missing include/config.h")
else()
    file(STRINGS
            "${FFMPEG_CONFIG_HEADER}"
            FFMPEG_HAVE_FAST_64BIT_DEFINITION
            REGEX "^#define HAVE_FAST_64BIT [01]$")
    if(NOT FFMPEG_HAVE_FAST_64BIT_DEFINITION MATCHES "^#define HAVE_FAST_64BIT ([01])$")
        message(FATAL_ERROR "Pinned FFmpeg config does not define HAVE_FAST_64BIT")
    endif()
    list(APPEND LUMEN_DEFINITIONS "HAVE_FAST_64BIT=${CMAKE_MATCH_1}")
endif()

set(LUMEN_TARGET_FILES
        "${CMAKE_SOURCE_DIR}/third-party/moonlight-common-c/src/Input.h"
        "${CMAKE_SOURCE_DIR}/third-party/moonlight-common-c/src/Rtsp.h"
        "${CMAKE_SOURCE_DIR}/third-party/moonlight-common-c/src/RtspParser.c"
        "${CMAKE_SOURCE_DIR}/third-party/moonlight-common-c/src/Video.h"
        "${CMAKE_SOURCE_DIR}/third-party/moonlight-common-c/nanors/deps/obl/oblas_common.c"
        "${CMAKE_SOURCE_DIR}/third-party/moonlight-common-c/nanors/deps/obl/oblas_lite.c"
        "${CMAKE_SOURCE_DIR}/third-party/moonlight-common-c/nanors/rs.c"
        "${CMAKE_SOURCE_DIR}/src/upnp.cpp"
        "${CMAKE_SOURCE_DIR}/src/upnp.h"
        "${CMAKE_SOURCE_DIR}/src/cbs.cpp"
        "${CMAKE_SOURCE_DIR}/src/utility.h"
        "${CMAKE_SOURCE_DIR}/src/uuid.h"
        "${CMAKE_SOURCE_DIR}/src/config.h"
        "${CMAKE_SOURCE_DIR}/src/config.cpp"
        "${CMAKE_SOURCE_DIR}/src/display_device.h"
        "${CMAKE_SOURCE_DIR}/src/display_device.cpp"
        "${CMAKE_SOURCE_DIR}/src/entry_handler.cpp"
        "${CMAKE_SOURCE_DIR}/src/entry_handler.h"
        "${CMAKE_SOURCE_DIR}/src/file_handler.cpp"
        "${CMAKE_SOURCE_DIR}/src/file_handler.h"
        "${CMAKE_SOURCE_DIR}/src/globals.cpp"
        "${CMAKE_SOURCE_DIR}/src/globals.h"
        "${CMAKE_SOURCE_DIR}/src/logging.cpp"
        "${CMAKE_SOURCE_DIR}/src/logging.h"
        "${CMAKE_SOURCE_DIR}/src/main.cpp"
        "${CMAKE_SOURCE_DIR}/src/main.h"
        "${CMAKE_SOURCE_DIR}/src/crypto.cpp"
        "${CMAKE_SOURCE_DIR}/src/crypto.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_common/cbor.cpp"
        "${CMAKE_SOURCE_DIR}/src/protocol_common/cbor.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_common/crypto.cpp"
        "${CMAKE_SOURCE_DIR}/src/protocol_common/crypto.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_common/secure_buffer.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_common/status.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/core/control.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/core/core.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/core/input.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/core/packet.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/core/rtp.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/core/telemetry.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/core/transport.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/core/wire.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/input_plane/feedback.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/input_plane/input_plane.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/input_plane/rate.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/input_plane/state.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/input_plane/wire.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/media/audio.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/media/av1.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/media/common.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/media/frame_pipeline.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/media/h264.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/media/hevc.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/media/media.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/packet_classifier.cpp"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/packet_classifier.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/runtime/control_server.cpp"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/runtime/control_server.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/runtime/control/wire.cpp"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/runtime/control/wire.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/runtime/audio_sender.cpp"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/runtime/audio_sender.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/runtime/host_forward_path.cpp"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/runtime/host_forward_path.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/runtime/host_runtime.cpp"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/runtime/host_runtime.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/runtime/identity.cpp"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/runtime/identity.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/runtime/input_owner.cpp"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/runtime/input_owner.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/runtime/libsrtp_provider.cpp"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/runtime/libsrtp_provider.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/runtime/microphone_receiver.cpp"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/runtime/microphone_receiver.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/runtime/udp_socket.cpp"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/runtime/udp_socket.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/runtime/video_sender.cpp"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/runtime/video_sender.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/security/wolfssl_dtls_server.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/security/secure_zero.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/security_provider.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/service.cpp"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/service.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/session_authority.cpp"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/session_authority.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/ssrc_registry.cpp"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/ssrc_registry.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/transport/congestion.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/transport/generation_fence.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/transport/repair.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/transport/rtcp.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/transport/transport.h"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/types.cpp"
        "${CMAKE_SOURCE_DIR}/src/protocol_lsp/types.h"
        "${CMAKE_SOURCE_DIR}/src/nvhttp.cpp"
        "${CMAKE_SOURCE_DIR}/src/nvhttp.h"
        "${CMAKE_SOURCE_DIR}/src/httpcommon.cpp"
        "${CMAKE_SOURCE_DIR}/src/httpcommon.h"
        "${CMAKE_SOURCE_DIR}/src/confighttp.cpp"
        "${CMAKE_SOURCE_DIR}/src/confighttp.h"
        "${CMAKE_SOURCE_DIR}/src/rtsp.cpp"
        "${CMAKE_SOURCE_DIR}/src/rtsp.h"
        "${CMAKE_SOURCE_DIR}/src/stream.cpp"
        "${CMAKE_SOURCE_DIR}/src/stream.h"
        "${CMAKE_SOURCE_DIR}/src/video_packetizer.cpp"
        "${CMAKE_SOURCE_DIR}/src/video_packetizer.h"
        "${CMAKE_SOURCE_DIR}/src/stream_policy.cpp"
        "${CMAKE_SOURCE_DIR}/src/stream_policy.h"
        "${CMAKE_SOURCE_DIR}/src/video.cpp"
        "${CMAKE_SOURCE_DIR}/src/video.h"
        "${CMAKE_SOURCE_DIR}/src/video_egress_queue.cpp"
        "${CMAKE_SOURCE_DIR}/src/video_egress_queue.h"
        "${CMAKE_SOURCE_DIR}/src/video_colorspace.cpp"
        "${CMAKE_SOURCE_DIR}/src/video_colorspace.h"
        "${CMAKE_SOURCE_DIR}/src/input.cpp"
        "${CMAKE_SOURCE_DIR}/src/input.h"
        "${CMAKE_SOURCE_DIR}/src/audio.cpp"
        "${CMAKE_SOURCE_DIR}/src/audio.h"
        "${CMAKE_SOURCE_DIR}/src/client_microphone.cpp"
        "${CMAKE_SOURCE_DIR}/src/client_microphone.h"
        "${CMAKE_SOURCE_DIR}/src/client_microphone_protocol.cpp"
        "${CMAKE_SOURCE_DIR}/src/client_microphone_protocol.h"
        "${CMAKE_SOURCE_DIR}/src/platform/common.h"
        "${CMAKE_SOURCE_DIR}/src/process.cpp"
        "${CMAKE_SOURCE_DIR}/src/process.h"
        "${CMAKE_SOURCE_DIR}/src/network.cpp"
        "${CMAKE_SOURCE_DIR}/src/network.h"
        "${CMAKE_SOURCE_DIR}/src/move_by_copy.h"
        "${CMAKE_SOURCE_DIR}/src/system_tray.cpp"
        "${CMAKE_SOURCE_DIR}/src/system_tray.h"
        "${CMAKE_SOURCE_DIR}/src/task_pool.h"
        "${CMAKE_SOURCE_DIR}/src/thread_pool.h"
        "${CMAKE_SOURCE_DIR}/src/thread_safe.h"
        "${CMAKE_SOURCE_DIR}/src/sync.h"
        "${CMAKE_SOURCE_DIR}/src/round_robin.h"
        "${CMAKE_SOURCE_DIR}/src/stat_trackers.h"
        "${CMAKE_SOURCE_DIR}/src/stat_trackers.cpp"
        ${PLATFORM_TARGET_FILES})

if(LUMEN_ENABLE_LSP_RUNTIME)
    list(APPEND LUMEN_TARGET_FILES
            "${CMAKE_SOURCE_DIR}/src/protocol_lsp/security/wolfssl_spake2.cpp"
            "${CMAKE_SOURCE_DIR}/src/protocol_lsp/security/wolfssl_dtls_server.cpp")
    list(APPEND LUMEN_DEFINITIONS
            LUMEN_LSP_WOLFSSL_AVAILABLE=1
            LUMEN_LSP_LIBSRTP_AVAILABLE=1
            LUMEN_LSP_RUNTIME_AVAILABLE=1)
    list(APPEND LUMEN_EXTERNAL_LIBRARIES
            Lumen::wolfssl
            Lumen::srtp2)
else()
    list(APPEND LUMEN_DEFINITIONS
            LUMEN_LSP_WOLFSSL_AVAILABLE=0
            LUMEN_LSP_LIBSRTP_AVAILABLE=0
            LUMEN_LSP_RUNTIME_AVAILABLE=0)
endif()

if(NOT LUMEN_ASSETS_DIR_DEF)
    set(LUMEN_ASSETS_DIR_DEF "${LUMEN_ASSETS_DIR}")
endif()
list(APPEND LUMEN_DEFINITIONS LUMEN_ASSETS_DIR="${LUMEN_ASSETS_DIR_DEF}")

# Publisher metadata
list(APPEND LUMEN_DEFINITIONS LUMEN_PUBLISHER_NAME="${LUMEN_PUBLISHER_NAME}")
list(APPEND LUMEN_DEFINITIONS LUMEN_PUBLISHER_WEBSITE="${LUMEN_PUBLISHER_WEBSITE}")
list(APPEND LUMEN_DEFINITIONS LUMEN_PUBLISHER_ISSUE_URL="${LUMEN_PUBLISHER_ISSUE_URL}")

include_directories(BEFORE "${CMAKE_SOURCE_DIR}")

include_directories(
        BEFORE
        SYSTEM
        "${CMAKE_SOURCE_DIR}/third-party"
        "${CMAKE_SOURCE_DIR}/third-party/moonlight-common-c/enet/include"
        "${CMAKE_SOURCE_DIR}/third-party/moonlight-common-c/nanors"
        "${CMAKE_SOURCE_DIR}/third-party/moonlight-common-c/nanors/deps/obl"
        ${OPENSSL_INCLUDE_DIR}
        ${Opus_INCLUDE_DIR}
        ${FFMPEG_INCLUDE_DIRS}
        ${Boost_INCLUDE_DIRS}  # has to be the last, or we get runtime error on macOS ffmpeg encoder
)

if(WIN32)
    include_directories(BEFORE SYSTEM "${NV_CODEC_HEADERS_13_INCLUDE_DIR}")
else()
    include_directories(
            BEFORE SYSTEM
            "${CMAKE_SOURCE_DIR}/third-party/build-deps/third-party/FFmpeg/nv-codec-headers/include"
    )
endif()

list(APPEND LUMEN_EXTERNAL_LIBRARIES
        ${MINIUPNP_LIBRARIES}
        ${CMAKE_THREAD_LIBS_INIT}
        enet
        libdisplaydevice::display_device
        lizardbyte::common
        nlohmann_json::nlohmann_json
        ${Opus_LIBRARY}
        ${FFMPEG_LIBRARIES}
        ${Boost_LIBRARIES}
        ${OPENSSL_LIBRARIES}
        ${PLATFORM_LIBRARIES})

if(WIN32)
    list(APPEND LUMEN_EXTERNAL_LIBRARIES Lumen::libvirtualhid_gamepad_core)
endif()

# tray icon
if(LUMEN_ENABLE_TRAY)
    list(APPEND LUMEN_EXTERNAL_LIBRARIES tray::tray)
else()
    set(LUMEN_TRAY 0)
    message(STATUS "Tray icon disabled")
endif()
list(APPEND LUMEN_DEFINITIONS LUMEN_TRAY=${LUMEN_TRAY})
