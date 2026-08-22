cmake_minimum_required(VERSION 3.20)

if(NOT DEFINED RELEASE_TAG OR RELEASE_TAG STREQUAL "")
    message(FATAL_ERROR "RELEASE_TAG is required.")
endif()

get_filename_component(LUMEN_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
file(STRINGS "${LUMEN_ROOT}/version.txt" LUMEN_VERSION LIMIT_COUNT 1)
string(STRIP "${LUMEN_VERSION}" LUMEN_VERSION)
if(NOT LUMEN_VERSION MATCHES
   "^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(-(alpha|beta|rc)\\.(0|[1-9][0-9]*))?$")
    message(FATAL_ERROR
        "version.txt must contain X.Y.Z or an alpha.N, beta.N, or rc.N prerelease.")
endif()
if(CMAKE_MATCH_1 GREATER 255 OR CMAKE_MATCH_2 GREATER 255 OR
   CMAKE_MATCH_3 GREATER 65535)
    message(FATAL_ERROR
        "version.txt exceeds Windows MSI limits: major/minor <= 255 and patch <= 65535.")
endif()
set(LUMEN_EXPECTED_TAG "v${LUMEN_VERSION}")

if(NOT RELEASE_TAG STREQUAL LUMEN_EXPECTED_TAG)
    message(FATAL_ERROR
        "Tag '${RELEASE_TAG}' must exactly match version.txt as '${LUMEN_EXPECTED_TAG}'.")
endif()

message(STATUS "Validated Lumen release tag ${RELEASE_TAG} against version.txt ${LUMEN_VERSION}.")
