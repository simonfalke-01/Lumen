cmake_minimum_required(VERSION 3.20)

project(sunshine_tools)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT DEFINED CMAKE_CUDA_STANDARD)
    set(CMAKE_CUDA_STANDARD 17)
    set(CMAKE_CUDA_STANDARD_REQUIRED ON)
endif()

include_directories(
        "${CMAKE_SOURCE_DIR}"
        "${FFMPEG_INCLUDE_DIRS}"  # this is included only for logging
)

set(TOOL_SOURCES
        "${CMAKE_SOURCE_DIR}/src/logging.cpp"
        "${CMAKE_SOURCE_DIR}/src/platform/windows/utf_utils.cpp"
)

add_executable(dxgi-info dxgi.cpp ${TOOL_SOURCES})
target_link_libraries(dxgi-info
        ${Boost_LIBRARIES}
        ${CMAKE_THREAD_LIBS_INIT}
        ${FFMPEG_LIBRARIES}  # this is included only for logging
        dxgi
        libdisplaydevice::display_device  # this is included only for logging
        ${PLATFORM_LIBRARIES}
)
target_compile_options(dxgi-info PRIVATE ${SUNSHINE_COMPILE_OPTIONS})

add_executable(audio-info audio.cpp ${TOOL_SOURCES})
target_link_libraries(audio-info
        ${Boost_LIBRARIES}
        ${CMAKE_THREAD_LIBS_INIT}
        ${FFMPEG_LIBRARIES}  # this is included only for logging
        libdisplaydevice::display_device  # this is included only for logging
        ksuser
        ${PLATFORM_LIBRARIES}
)
target_compile_options(audio-info PRIVATE ${SUNSHINE_COMPILE_OPTIONS})

add_executable(sunshinesvc sunshinesvc.cpp)
target_link_libraries(sunshinesvc
        ${CMAKE_THREAD_LIBS_INIT}
        wtsapi32
        ${PLATFORM_LIBRARIES})
target_compile_options(sunshinesvc PRIVATE ${SUNSHINE_COMPILE_OPTIONS})

add_executable(lumen-vhidctl
        lumen-vhidctl.cpp
        ${CMAKE_SOURCE_DIR}/third-party/ViGEmClient/src/ViGEmClient.cpp)
set_source_files_properties(
        ${CMAKE_SOURCE_DIR}/third-party/ViGEmClient/src/ViGEmClient.cpp
        PROPERTIES
        COMPILE_DEFINITIONS "UNICODE=1;ERROR_INVALID_DEVICE_OBJECT_PARAMETER=650"
        COMPILE_OPTIONS "-Wno-unknown-pragmas;-Wno-misleading-indentation;-Wno-class-memaccess;-Wno-unused-function;-Wno-unused-variable;-Wno-missing-field-initializers;-Wno-cast-function-type")
target_include_directories(lumen-vhidctl PRIVATE
        ${CMAKE_SOURCE_DIR}/third-party/ViGEmClient/include
        ${CMAKE_SOURCE_DIR}/third-party/ViGEmClient/src)
target_link_libraries(lumen-vhidctl
        cfgmgr32
        hid
        setupapi
        shell32
        xinput9_1_0)
target_compile_options(lumen-vhidctl PRIVATE ${SUNSHINE_COMPILE_OPTIONS})

# Dedicated Windows device lifecycle helper for the optional capture-only
# virtual microphone. It dynamically resolves NewDev mutations so the binary
# remains compatible with the Windows versions supported by Lumen.
add_executable(lumen-vmicctl lumen-vmicctl.cpp)
target_link_libraries(lumen-vmicctl
        cfgmgr32
        ole32
        setupapi
        shell32)
target_compile_options(lumen-vmicctl PRIVATE ${SUNSHINE_COMPILE_OPTIONS})

# Dedicated root-device installer for the optional UMDF2 indirect display
# driver. PnPUtil can stage the package, but it cannot create a new root
# enumerated device on a clean machine.
add_executable(lumen-vddctl lumen-vddctl.cpp)
target_link_libraries(lumen-vddctl
        cfgmgr32
        setupapi
        shell32)
target_compile_options(lumen-vddctl PRIVATE ${SUNSHINE_COMPILE_OPTIONS})
if(MINGW)
    target_link_options(lumen-vddctl PRIVATE -static)
endif()

# Native MSI bridge used after deferred driver work. A child PowerShell
# process cannot call MsiSetMode on its parent installation session.
add_library(lumen_msica SHARED lumen-msica.c)
set_target_properties(lumen_msica PROPERTIES PREFIX "" OUTPUT_NAME "lumen_msica")
target_link_libraries(lumen_msica msi)
target_compile_options(lumen_msica PRIVATE ${SUNSHINE_COMPILE_OPTIONS})
