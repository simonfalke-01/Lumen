# load common dependencies
# this file will also load platform specific dependencies

# Resolve OpenSSL before subprojects run their own find_package(OpenSSL) calls.
# This ensures a user-provided OPENSSL_ROOT_DIR is honored consistently.
find_package(OpenSSL REQUIRED)

if(LUMEN_ENABLE_LSP_RUNTIME)
    include("${CMAKE_MODULE_PATH}/dependencies/lsp_security.cmake")
endif()

# boost, this should be before Simple-Web-Server as it also depends on boost
include(dependencies/Boost_Lumen)

# submodules
# gamestream common library
set(ENET_NO_INSTALL ON CACHE BOOL "Don't install any libraries built for enet")
add_subdirectory("${CMAKE_SOURCE_DIR}/third-party/moonlight-common-c/enet")

# web server
add_subdirectory("${CMAKE_SOURCE_DIR}/third-party/Simple-Web-Server")

# lizardbyte common helpers
set(LIZARDBYTE_COMMON_BUILD_TEST_SUPPORT ${BUILD_TESTS}
        CACHE BOOL "Build lizardbyte-common GoogleTest support helpers" FORCE)
add_subdirectory("${CMAKE_SOURCE_DIR}/third-party/lizardbyte-common")

# libdisplaydevice
add_subdirectory("${CMAKE_SOURCE_DIR}/third-party/libdisplaydevice")

# Portable libvirtualhid gamepad profiles and report codecs only. Lumen keeps
# exclusive ownership of its input router, Windows driver, and installer.
include("${CMAKE_MODULE_PATH}/dependencies/libvirtualhid_core.cmake")

if(LUMEN_ENABLE_TRAY)
    if(LUMEN_USE_STATIC_QT)
        set(_lumen_find_library_suffixes "${CMAKE_FIND_LIBRARY_SUFFIXES}")
        set(_lumen_import_library_suffix "${CMAKE_IMPORT_LIBRARY_SUFFIX}")
        set(_lumen_pkg_config_argn "${PKG_CONFIG_ARGN}")
        set(_lumen_disable_find_package_harfbuzz "${CMAKE_DISABLE_FIND_PACKAGE_harfbuzz}")
        set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
        set(CMAKE_IMPORT_LIBRARY_SUFFIX ".a")
        set(PKG_CONFIG_ARGN --static)

        # HarfBuzz's config-file target omits dependencies needed by its static archive.
        # Use Qt's pkg-config fallback so --static supplies the complete link interface.
        set(CMAKE_DISABLE_FIND_PACKAGE_harfbuzz TRUE)

        # CMake's FindTIFF module does not propagate dependencies of the static archive.
        # Provide its standard target from pkg-config before Qt imports the TIFF plugin.
        find_package(PkgConfig REQUIRED)
        pkg_check_modules(LUMEN_STATIC_TIFF REQUIRED IMPORTED_TARGET libtiff-4)
        add_library(TIFF::TIFF INTERFACE IMPORTED)
        target_link_libraries(TIFF::TIFF INTERFACE PkgConfig::LUMEN_STATIC_TIFF)

        set(_lumen_module_path "${CMAKE_MODULE_PATH}")
        find_package(Qt6 REQUIRED COMPONENTS Widgets Svg)
        get_target_property(_lumen_qt_core_type Qt6::Core TYPE)
        if(NOT _lumen_qt_core_type STREQUAL "STATIC_LIBRARY")
            message(FATAL_ERROR "LUMEN_USE_STATIC_QT requires a static Qt 6 installation.")
        endif()
        set(CMAKE_MODULE_PATH "${_lumen_module_path}")
    endif()

    add_subdirectory("${CMAKE_SOURCE_DIR}/third-party/tray")

    if(LUMEN_USE_STATIC_QT)
        set(CMAKE_FIND_LIBRARY_SUFFIXES "${_lumen_find_library_suffixes}")
        set(CMAKE_IMPORT_LIBRARY_SUFFIX "${_lumen_import_library_suffix}")
        set(PKG_CONFIG_ARGN "${_lumen_pkg_config_argn}")
        set(CMAKE_DISABLE_FIND_PACKAGE_harfbuzz "${_lumen_disable_find_package_harfbuzz}")
        unset(_lumen_disable_find_package_harfbuzz)
        unset(_lumen_find_library_suffixes)
        unset(_lumen_import_library_suffix)
        unset(_lumen_module_path)
        unset(_lumen_pkg_config_argn)
        unset(_lumen_qt_core_type)
    endif()
endif()

# common dependencies
include("${CMAKE_MODULE_PATH}/dependencies/nv_codec_headers.cmake")
include("${CMAKE_MODULE_PATH}/dependencies/nlohmann_json.cmake")
find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)
pkg_check_modules(CURL REQUIRED libcurl)

# miniupnp
pkg_check_modules(MINIUPNP miniupnpc REQUIRED)
include_directories(SYSTEM ${MINIUPNP_INCLUDE_DIRS})

# ffmpeg pre-compiled binaries
include("${CMAKE_MODULE_PATH}/dependencies/ffmpeg.cmake")

# Opus
# Homebrew provides opus as a dynamic library only, so disable static linking for Homebrew builds
if(LUMEN_BUILD_HOMEBREW)
    set(OPUS_USE_STATIC OFF CACHE BOOL "Static linking for libopus")
else()
    set(OPUS_USE_STATIC ON CACHE BOOL "Static linking for libopus")
endif()
include("${CMAKE_MODULE_PATH}/dependencies/FindOpus.cmake")

# platform specific dependencies
if(WIN32)
    include("${CMAKE_MODULE_PATH}/dependencies/windows.cmake")
elseif(UNIX)
    include("${CMAKE_MODULE_PATH}/dependencies/unix.cmake")

    if(APPLE)
        include("${CMAKE_MODULE_PATH}/dependencies/macos.cmake")
    else()
        include("${CMAKE_MODULE_PATH}/dependencies/linux.cmake")
    endif()
endif()
