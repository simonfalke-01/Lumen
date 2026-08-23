# common packaging

# common cpack options
set(CPACK_PACKAGE_NAME "Lumen")
set(CPACK_PACKAGE_VENDOR "simonfalke")
# MSI and native package formats require a numeric version core. Artifact names
# retain PROJECT_VERSION so prerelease identifiers remain visible to users.
set(CPACK_PACKAGE_VERSION ${LUMEN_VERSION_CORE})
set(CPACK_PACKAGE_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${PROJECT_VERSION_PATCH})
set(CPACK_PACKAGE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/cpack_artifacts)
set(CPACK_PACKAGE_CONTACT "https://github.com/simonfalke-01/Lumen/issues")
set(CPACK_PACKAGE_DESCRIPTION ${CMAKE_PROJECT_DESCRIPTION})
set(CPACK_PACKAGE_HOMEPAGE_URL "https://github.com/simonfalke-01/Lumen")
set(CPACK_RESOURCE_FILE_LICENSE ${PROJECT_SOURCE_DIR}/LICENSE)
set(CPACK_PACKAGE_ICON ${PROJECT_SOURCE_DIR}/sunshine.png)
set(CPACK_PACKAGE_FILE_NAME
        "${CPACK_PACKAGE_NAME}-${PROJECT_VERSION}-${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}")
set(CPACK_STRIP_FILES YES)

# Retain the exact MIT notice for the portable libvirtualhid core. The
# separately licensed upstream Windows driver and broker are not distributed.
install(FILES "${CMAKE_SOURCE_DIR}/NOTICE"
        DESTINATION "share/licenses/Lumen"
        COMPONENT application)
install(FILES "${CMAKE_SOURCE_DIR}/third-party/libvirtualhid/LICENSES/MIT.md"
        DESTINATION "share/licenses/Lumen"
        RENAME "libvirtualhid-MIT.txt"
        COMPONENT application)
install(FILES "${CMAKE_SOURCE_DIR}/third-party/libvirtualhid/LICENSES/README.md"
        DESTINATION "share/licenses/Lumen"
        RENAME "libvirtualhid-license-map.txt"
        COMPONENT application)

# install common assets
install(DIRECTORY "${SUNSHINE_SOURCE_ASSETS_DIR}/common/assets/"
        DESTINATION "${SUNSHINE_ASSETS_DIR}"
        PATTERN "web" EXCLUDE)
# copy assets to build directory, for running without install
file(GLOB_RECURSE ALL_ASSETS
        RELATIVE "${SUNSHINE_SOURCE_ASSETS_DIR}/common/assets/" "${SUNSHINE_SOURCE_ASSETS_DIR}/common/assets/*")
list(FILTER ALL_ASSETS EXCLUDE REGEX "^web/.*$")  # Filter out the web directory
foreach(asset ${ALL_ASSETS})  # Copy assets to build directory, excluding the web directory
    file(COPY "${SUNSHINE_SOURCE_ASSETS_DIR}/common/assets/${asset}"
            DESTINATION "${CMAKE_CURRENT_BINARY_DIR}/assets")
endforeach()

# Copy the primary application icon into the built web assets for the system tray.
file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/assets/web/images")
configure_file(
        "${CMAKE_SOURCE_DIR}/sunshine.svg"
        "${CMAKE_CURRENT_BINARY_DIR}/assets/web/images/logo-sunshine.svg"
        COPYONLY)

# install built vite assets
install(DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/assets/web"
        DESTINATION "${SUNSHINE_ASSETS_DIR}")

# platform specific packaging
if(WIN32)
    include(${CMAKE_MODULE_PATH}/packaging/windows.cmake)
elseif(UNIX)
    include(${CMAKE_MODULE_PATH}/packaging/unix.cmake)

    if(APPLE)
        include(${CMAKE_MODULE_PATH}/packaging/macos.cmake)
    else()
        include(${CMAKE_MODULE_PATH}/packaging/linux.cmake)
    endif()
endif()

include(CPack)
