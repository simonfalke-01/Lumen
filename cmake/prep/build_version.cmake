# Set build variables used in configured package and update metadata.
if(DEFINED ENV{BRANCH})
    set(GITHUB_BRANCH "$ENV{BRANCH}")
endif()
if(DEFINED ENV{CLONE_URL})
    set(GITHUB_CLONE_URL "$ENV{CLONE_URL}")
endif()
if(DEFINED ENV{COMMIT})
    set(GITHUB_COMMIT "$ENV{COMMIT}")
endif()

set(LUMEN_RELEASE_TAG "v${LUMEN_VERSION}")
if(LUMEN_VERSION MATCHES "-")
    set(LUMEN_DEV_VERSION_PREFIX "${LUMEN_VERSION}.dev")
else()
    set(LUMEN_DEV_VERSION_PREFIX "${LUMEN_VERSION}-dev")
endif()
string(REPLACE "." "\\." LUMEN_DEV_VERSION_PREFIX_REGEX "${LUMEN_DEV_VERSION_PREFIX}")

set(LUMEN_REQUESTED_VERSION "")
if(DEFINED ENV{BUILD_VERSION} AND NOT "$ENV{BUILD_VERSION}" STREQUAL "")  # cmake-lint: disable=W0106
    set(LUMEN_REQUESTED_VERSION "$ENV{BUILD_VERSION}")
    string(REGEX REPLACE "^v" "" LUMEN_REQUESTED_VERSION "${LUMEN_REQUESTED_VERSION}")
endif()

set(LUMEN_REQUESTED_TAG "")
if(DEFINED ENV{TAG} AND NOT "$ENV{TAG}" STREQUAL "")
    set(LUMEN_REQUESTED_TAG "$ENV{TAG}")
endif()

find_package(Git QUIET)
if(GIT_EXECUTABLE)
    if(NOT GITHUB_BRANCH)
        execute_process(
                COMMAND ${GIT_EXECUTABLE} rev-parse --abbrev-ref HEAD
                WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
                OUTPUT_VARIABLE GITHUB_BRANCH
                OUTPUT_STRIP_TRAILING_WHITESPACE
                ERROR_QUIET
        )
    endif()
    if(NOT GITHUB_COMMIT)
        execute_process(
                COMMAND ${GIT_EXECUTABLE} rev-parse HEAD
                WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
                OUTPUT_VARIABLE GITHUB_COMMIT
                OUTPUT_STRIP_TRAILING_WHITESPACE
                ERROR_QUIET
        )
    endif()
endif()

if(LUMEN_REQUESTED_TAG)
    if(NOT LUMEN_REQUESTED_TAG STREQUAL LUMEN_RELEASE_TAG)
        message(FATAL_ERROR
            "Release tag '${LUMEN_REQUESTED_TAG}' must exactly match version.txt as '${LUMEN_RELEASE_TAG}'.")
    endif()
    if(LUMEN_REQUESTED_VERSION AND NOT LUMEN_REQUESTED_VERSION STREQUAL LUMEN_VERSION)
        message(FATAL_ERROR
            "BUILD_VERSION '${LUMEN_REQUESTED_VERSION}' does not match release tag '${LUMEN_REQUESTED_TAG}'.")
    endif()
    if(GIT_EXECUTABLE)
        execute_process(
                COMMAND ${GIT_EXECUTABLE} diff --quiet --exit-code
                WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
                RESULT_VARIABLE LUMEN_RELEASE_WORKTREE_DIRTY
                ERROR_QUIET
        )
        execute_process(
                COMMAND ${GIT_EXECUTABLE} diff --cached --quiet --exit-code
                WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
                RESULT_VARIABLE LUMEN_RELEASE_INDEX_DIRTY
                ERROR_QUIET
        )
        if(LUMEN_RELEASE_WORKTREE_DIRTY OR LUMEN_RELEASE_INDEX_DIRTY)
            message(FATAL_ERROR "Release identity requires a clean Git working tree.")
        endif()
    endif()
    set(PROJECT_VERSION "${LUMEN_VERSION}")
    set(GITHUB_TAG "${LUMEN_REQUESTED_TAG}")
elseif(LUMEN_REQUESTED_VERSION)
    if(LUMEN_REQUESTED_VERSION STREQUAL LUMEN_VERSION)
        message(FATAL_ERROR "Release-like BUILD_VERSION values require a matching TAG.")
    endif()
    if(NOT LUMEN_REQUESTED_VERSION MATCHES
       "^${LUMEN_DEV_VERSION_PREFIX_REGEX}\\.(0|[1-9][0-9]*)(\\+g[0-9a-f]+)?$")
        message(FATAL_ERROR
            "Untagged BUILD_VERSION '${LUMEN_REQUESTED_VERSION}' must use ${LUMEN_DEV_VERSION_PREFIX}.N[+gCOMMIT].")
    endif()
    set(PROJECT_VERSION "${LUMEN_REQUESTED_VERSION}")
else()
    set(LUMEN_SHORT_COMMIT "unknown")
    set(LUMEN_DIRTY_SUFFIX "")
    if(GIT_EXECUTABLE)
        execute_process(
                COMMAND ${GIT_EXECUTABLE} rev-parse --short HEAD
                WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
                OUTPUT_VARIABLE LUMEN_SHORT_COMMIT
                OUTPUT_STRIP_TRAILING_WHITESPACE
                ERROR_QUIET
        )
        execute_process(
                COMMAND ${GIT_EXECUTABLE} status --porcelain
                WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
                OUTPUT_VARIABLE LUMEN_GIT_STATUS
                OUTPUT_STRIP_TRAILING_WHITESPACE
                ERROR_QUIET
        )
        if(LUMEN_GIT_STATUS)
            set(LUMEN_DIRTY_SUFFIX ".dirty")
        endif()
    endif()
    set(PROJECT_VERSION "${LUMEN_DEV_VERSION_PREFIX}.0+g${LUMEN_SHORT_COMMIT}${LUMEN_DIRTY_SUFFIX}")
endif()

set(BUILD_VERSION "${PROJECT_VERSION}")
message(STATUS "Lumen branch: ${GITHUB_BRANCH}")
message(STATUS "Lumen version: ${PROJECT_VERSION}")

# Package metadata uses the build date in UTC. CMake honors SOURCE_DATE_EPOCH
# here, so reproducible release builds can pin this to the tagged commit time.
string(TIMESTAMP PROJECT_YEAR "%Y" UTC)
string(TIMESTAMP PROJECT_MONTH "%m" UTC)
string(TIMESTAMP PROJECT_DAY "%d" UTC)

# Parse PROJECT_VERSION to extract major, minor, and patch components
if(PROJECT_VERSION MATCHES "([0-9]+)\\.([0-9]+)\\.([0-9]+)")
    set(PROJECT_VERSION_MAJOR "${CMAKE_MATCH_1}")
    set(CMAKE_PROJECT_VERSION_MAJOR "${CMAKE_MATCH_1}")

    set(PROJECT_VERSION_MINOR "${CMAKE_MATCH_2}")
    set(CMAKE_PROJECT_VERSION_MINOR "${CMAKE_MATCH_2}")

    set(PROJECT_VERSION_PATCH "${CMAKE_MATCH_3}")
    set(CMAKE_PROJECT_VERSION_PATCH "${CMAKE_MATCH_3}")
endif()

# Windows VERSIONINFO uses major, minor, patch, revision. The SemVer patch is
# already constrained to 65535, so preserve it exactly and reserve revision.
set(RC_VERSION_BUILD "${PROJECT_VERSION_PATCH}")
set(RC_VERSION_REVISION "0")

message("PROJECT_FQDN: ${PROJECT_FQDN}")
message("PROJECT_NAME: ${PROJECT_NAME}")
message("PROJECT_VERSION: ${PROJECT_VERSION}")
message("PROJECT_VERSION_MAJOR: ${PROJECT_VERSION_MAJOR}")
message("PROJECT_VERSION_MINOR: ${PROJECT_VERSION_MINOR}")
message("PROJECT_VERSION_PATCH: ${PROJECT_VERSION_PATCH}")
message("CMAKE_PROJECT_VERSION: ${CMAKE_PROJECT_VERSION}")
message("CMAKE_PROJECT_VERSION_MAJOR: ${CMAKE_PROJECT_VERSION_MAJOR}")
message("CMAKE_PROJECT_VERSION_MINOR: ${CMAKE_PROJECT_VERSION_MINOR}")
message("CMAKE_PROJECT_VERSION_PATCH: ${CMAKE_PROJECT_VERSION_PATCH}")
message("RC_VERSION_BUILD: ${RC_VERSION_BUILD}")
message("RC_VERSION_REVISION: ${RC_VERSION_REVISION}")
message("PROJECT_YEAR: ${PROJECT_YEAR}")
message("PROJECT_MONTH: ${PROJECT_MONTH}")
message("PROJECT_DAY: ${PROJECT_DAY}")

list(APPEND SUNSHINE_DEFINITIONS PROJECT_FQDN="${PROJECT_FQDN}")
list(APPEND SUNSHINE_DEFINITIONS PROJECT_LEGACY_FQDN="${PROJECT_LEGACY_FQDN}")
list(APPEND SUNSHINE_DEFINITIONS PROJECT_NAME="${PROJECT_NAME}")
list(APPEND SUNSHINE_DEFINITIONS PROJECT_VERSION="${PROJECT_VERSION}")
list(APPEND SUNSHINE_DEFINITIONS PROJECT_VERSION_MAJOR="${PROJECT_VERSION_MAJOR}")
list(APPEND SUNSHINE_DEFINITIONS PROJECT_VERSION_MINOR="${PROJECT_VERSION_MINOR}")
list(APPEND SUNSHINE_DEFINITIONS PROJECT_VERSION_PATCH="${PROJECT_VERSION_PATCH}")
list(APPEND SUNSHINE_DEFINITIONS PROJECT_VERSION_COMMIT="${GITHUB_COMMIT}")
