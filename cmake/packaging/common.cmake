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
set(CPACK_PACKAGE_ICON ${PROJECT_SOURCE_DIR}/lumen.png)
set(CPACK_PACKAGE_FILE_NAME
        "${CPACK_PACKAGE_NAME}-${PROJECT_VERSION}-${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}")
set(CPACK_STRIP_FILES YES)

file(SHA256 "${CMAKE_SOURCE_DIR}/OPENSSL_LICENSE.txt" LUMEN_OPENSSL_LICENSE_SHA256)
if(NOT LUMEN_OPENSSL_LICENSE_SHA256 STREQUAL
   "7d5450cb2d142651b8afa315b5f238efc805dad827d91ba367d8516bc9d49e7a")
    message(FATAL_ERROR "OPENSSL_LICENSE.txt does not match the reviewed OpenSSL Apache-2.0 text")
endif()
file(SHA256 "${CMAKE_SOURCE_DIR}/OPUS_LICENSE.txt" LUMEN_OPUS_LICENSE_SHA256)
if(NOT LUMEN_OPUS_LICENSE_SHA256 STREQUAL
   "01e1167d54a096d123cf6dfbbeb19587278845c6481d2d66d545669846079551")
    message(FATAL_ERROR "OPUS_LICENSE.txt does not match the reviewed Opus BSD/patent notice")
endif()

# Retain the exact MIT notice for the portable libvirtualhid core. The
# separately licensed upstream Windows driver and broker are not distributed.
install(FILES "${CMAKE_SOURCE_DIR}/NOTICE"
        DESTINATION "share/licenses/Lumen"
        COMPONENT application)
install(FILES "${CMAKE_SOURCE_DIR}/LICENSE"
        DESTINATION "share/licenses/Lumen"
        RENAME "Lumen-GPL-3.0.txt"
        COMPONENT application)
install(FILES "${CMAKE_SOURCE_DIR}/OPENSSL_LICENSE.txt"
        DESTINATION "share/licenses/Lumen"
        RENAME "OpenSSL-Apache-2.0.txt"
        COMPONENT application)
install(FILES "${CMAKE_SOURCE_DIR}/OPUS_LICENSE.txt"
        DESTINATION "share/licenses/Lumen"
        RENAME "Opus-BSD-3-Clause.txt"
        COMPONENT application)
install(FILES "${CMAKE_SOURCE_DIR}/third-party/moonlight-common-c/LICENSE.txt"
        DESTINATION "share/licenses/Lumen"
        RENAME "moonlight-common-c-GPL-3.0.txt"
        COMPONENT application)
install(FILES "${CMAKE_SOURCE_DIR}/third-party/moonlight-common-c/enet/LICENSE"
        DESTINATION "share/licenses/Lumen"
        RENAME "ENet-MIT.txt"
        COMPONENT application)
install(FILES "${CMAKE_SOURCE_DIR}/third-party/moonlight-common-c/nanors/LICENSE"
        DESTINATION "share/licenses/Lumen"
        RENAME "nanors-MIT.txt"
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
install(DIRECTORY "${LUMEN_SOURCE_ASSETS_DIR}/common/assets/"
        DESTINATION "${LUMEN_ASSETS_DIR}"
        PATTERN "web" EXCLUDE)
# copy assets to build directory, for running without install
file(GLOB_RECURSE ALL_ASSETS
        RELATIVE "${LUMEN_SOURCE_ASSETS_DIR}/common/assets/" "${LUMEN_SOURCE_ASSETS_DIR}/common/assets/*")
list(FILTER ALL_ASSETS EXCLUDE REGEX "^web/.*$")  # Filter out the web directory
foreach(asset ${ALL_ASSETS})  # Copy assets to build directory, excluding the web directory
    file(COPY "${LUMEN_SOURCE_ASSETS_DIR}/common/assets/${asset}"
            DESTINATION "${CMAKE_CURRENT_BINARY_DIR}/assets")
endforeach()

# install built vite assets
install(DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/assets/web"
        DESTINATION "${LUMEN_ASSETS_DIR}")

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
