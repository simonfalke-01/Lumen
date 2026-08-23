# Build only libvirtualhid's portable profile, report, and type model. Lumen
# deliberately owns all backend selection, device lifetime, driver transport,
# packaging, and product UI.
set(LUMEN_LIBVIRTUALHID_SOURCE_DIR
        "${CMAKE_SOURCE_DIR}/third-party/libvirtualhid")

set(LUMEN_LIBVIRTUALHID_CORE_SOURCES
        "${LUMEN_LIBVIRTUALHID_SOURCE_DIR}/src/core/profiles.cpp"
        "${LUMEN_LIBVIRTUALHID_SOURCE_DIR}/src/core/report.cpp"
        "${LUMEN_LIBVIRTUALHID_SOURCE_DIR}/src/core/types.cpp"
        "${LUMEN_LIBVIRTUALHID_SOURCE_DIR}/src/include/libvirtualhid/profiles.hpp"
        "${LUMEN_LIBVIRTUALHID_SOURCE_DIR}/src/include/libvirtualhid/report.hpp"
        "${LUMEN_LIBVIRTUALHID_SOURCE_DIR}/src/include/libvirtualhid/types.hpp")

add_library(lumen_lvh_core STATIC ${LUMEN_LIBVIRTUALHID_CORE_SOURCES})
add_library(Lumen::libvirtualhid_core ALIAS lumen_lvh_core)

# This invariant prevents a future upstream CMake change from silently pulling
# in its runtime, adapters, backends, broker, licensing, installer, or UI.
get_target_property(_lumen_lvh_actual_sources lumen_lvh_core SOURCES)
if(NOT "${_lumen_lvh_actual_sources}" STREQUAL "${LUMEN_LIBVIRTUALHID_CORE_SOURCES}")
    message(FATAL_ERROR "lumen_lvh_core contains sources outside the reviewed portable core boundary")
endif()
unset(_lumen_lvh_actual_sources)

target_include_directories(lumen_lvh_core
        SYSTEM
        PUBLIC
        "${LUMEN_LIBVIRTUALHID_SOURCE_DIR}/src/include")
target_compile_features(lumen_lvh_core PUBLIC cxx_std_23)

if(MSVC)
    target_compile_options(lumen_lvh_core PRIVATE /W4 /WX)
else()
    target_compile_options(lumen_lvh_core PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

set_target_properties(lumen_lvh_core PROPERTIES
        CXX_EXTENSIONS OFF
        POSITION_INDEPENDENT_CODE ON)

# The only production consumer is Lumen's private gamepad facade. The facade
# deliberately hides every upstream type and excludes upstream keyboard/mouse,
# runtime, backend, broker, installer, license, and UI APIs. Keep it available
# on every host for portable integration tests; production links it only on
# Windows.
add_library(lumen_lvh_gamepad_core STATIC
        "${LUMEN_LIBVIRTUALHID_SOURCE_DIR}/src/platform/windows/shared/generic_pid_protocol.hpp"
        "${LUMEN_LIBVIRTUALHID_SOURCE_DIR}/src/platform/windows/shared/generic_pid_rumble.hpp"
        "${CMAKE_SOURCE_DIR}/src/platform/windows/gamepad_profile.h"
        "${CMAKE_SOURCE_DIR}/src/platform/windows/libvirtualhid_gamepad_core.cpp"
        "${CMAKE_SOURCE_DIR}/src/platform/windows/libvirtualhid_gamepad_core.h")
add_library(Lumen::libvirtualhid_gamepad_core ALIAS lumen_lvh_gamepad_core)
target_include_directories(lumen_lvh_gamepad_core PUBLIC "${CMAKE_SOURCE_DIR}")
target_include_directories(lumen_lvh_gamepad_core
        SYSTEM
        PRIVATE
        "${LUMEN_LIBVIRTUALHID_SOURCE_DIR}/src/platform/windows/shared")
target_compile_features(lumen_lvh_gamepad_core PUBLIC cxx_std_23)
target_link_libraries(lumen_lvh_gamepad_core PRIVATE lumen_lvh_core)
set_target_properties(lumen_lvh_gamepad_core PROPERTIES CXX_EXTENSIONS OFF)
if(MSVC)
    target_compile_options(lumen_lvh_gamepad_core PRIVATE /W4 /WX)
else()
    target_compile_options(lumen_lvh_gamepad_core PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()
