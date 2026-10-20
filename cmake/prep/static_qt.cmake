# Configure the standard MSYS2 static Qt prefix automatically for Windows builds.

if(WIN32 AND LUMEN_ENABLE_TRAY AND LUMEN_USE_STATIC_QT AND NOT Qt6_DIR)
    set(_lumen_static_qt_prefix "")

    # Prefer the prefix exported by an interactive MSYS2 environment.
    if(DEFINED ENV{MINGW_PREFIX} AND NOT "$ENV{MINGW_PREFIX}" STREQUAL "")  # cmake-lint: disable=W0106
        file(TO_CMAKE_PATH "$ENV{MINGW_PREFIX}/qt6-static" _lumen_static_qt_candidate)
        if(EXISTS "${_lumen_static_qt_candidate}/lib/cmake/Qt6/Qt6Config.cmake")
            set(_lumen_static_qt_prefix "${_lumen_static_qt_candidate}")
        endif()
    endif()

    # IDEs may not inherit MINGW_PREFIX, so derive the toolchain root from the compiler path.
    if(NOT _lumen_static_qt_prefix)
        get_filename_component(_lumen_compiler_bin_dir "${CMAKE_CXX_COMPILER}" DIRECTORY)
        get_filename_component(_lumen_compiler_prefix "${_lumen_compiler_bin_dir}" DIRECTORY)
        set(_lumen_static_qt_candidate "${_lumen_compiler_prefix}/qt6-static")
        if(EXISTS "${_lumen_static_qt_candidate}/lib/cmake/Qt6/Qt6Config.cmake")
            set(_lumen_static_qt_prefix "${_lumen_static_qt_candidate}")
        endif()
    endif()

    if(_lumen_static_qt_prefix)
        list(APPEND CMAKE_PREFIX_PATH "${_lumen_static_qt_prefix}")
        list(REMOVE_DUPLICATES CMAKE_PREFIX_PATH)
        message(STATUS "Using static Qt prefix: ${_lumen_static_qt_prefix}")
    endif()

    unset(_lumen_compiler_bin_dir)
    unset(_lumen_compiler_prefix)
    unset(_lumen_static_qt_candidate)
    unset(_lumen_static_qt_prefix)
endif()
