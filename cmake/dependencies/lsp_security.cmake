# Pinned LSP security dependencies.
#
# wolfSSL is consumed under the operator's commercial license. License files
# and credentials are deliberately not stored in this repository.

include(FetchContent)
find_package(Git REQUIRED)

set(LUMEN_WOLFSSL_VERSION "5.9.2" CACHE INTERNAL "Pinned wolfSSL version")
set(LUMEN_WOLFSSL_COMMIT
        "ac01707f552c611fbd135cc723b2682b3e7f80f2"
        CACHE INTERNAL "Pinned wolfSSL v5.9.2-stable commit")
set(LUMEN_LIBSRTP_VERSION "2.8.0" CACHE INTERNAL "Pinned libSRTP version")
set(LUMEN_LIBSRTP_COMMIT
        "24b3bf8f19b6f5ab4cd2bcceb4f4064efca86fd5"
        CACHE INTERNAL "Pinned libSRTP v2.8.0 commit")

set(_lumen_saved_build_shared_libs "${BUILD_SHARED_LIBS}")
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build static LSP security dependencies" FORCE)

# Exact wolfSSL LSP profile. Explicit DTLSv1.3 methods still reject older
# versions at association creation; older TLS/DTLS code is disabled here to
# keep the bundled attack surface narrow.
set(WOLFSSL_INSTALL no CACHE STRING "Disable wolfSSL install rules" FORCE)
set(WOLFSSL_EXAMPLES no CACHE STRING "Disable wolfSSL examples" FORCE)
set(WOLFSSL_CRYPT_TESTS no CACHE STRING "Disable wolfSSL broad crypto tests" FORCE)
set(WOLFSSL_DTLS yes CACHE STRING "Enable DTLS" FORCE)
set(WOLFSSL_TLS13 yes CACHE STRING "Enable TLS 1.3 primitives" FORCE)
set(WOLFSSL_DTLS13 yes CACHE STRING "Enable DTLS 1.3" FORCE)
set(WOLFSSL_TLSV12 no CACHE STRING "Disable TLS/DTLS 1.2" FORCE)
set(WOLFSSL_OLD_TLS no CACHE STRING "Disable older TLS/DTLS" FORCE)
set(WOLFSSL_HRR_COOKIE yes CACHE STRING "Require DTLS 1.3 HRR cookies" FORCE)
set(WOLFSSL_DTLS_CH_FRAG yes CACHE STRING "Permit bounded second ClientHello fragmentation" FORCE)
set(WOLFSSL_SRTP yes CACHE STRING "Enable DTLS-SRTP use_srtp" FORCE)
set(WOLFSSL_KEYING_MATERIAL yes CACHE STRING "Enable RFC exporter material" FORCE)
set(WOLFSSL_ALPN yes CACHE STRING "Enable LSP ALPN" FORCE)
set(WOLFSSL_CURVE25519 yes CACHE STRING "Enable X25519" FORCE)
set(WOLFSSL_ED25519 yes CACHE STRING "Enable LSP application identity keys" FORCE)
set(WOLFSSL_AESGCM yes CACHE STRING "Enable required AES-GCM" FORCE)
set(WOLFSSL_HKDF yes CACHE STRING "Enable TLS 1.3 HKDF" FORCE)
set(WOLFSSL_PWDBASED yes CACHE STRING "Enable wolfCrypt password derivation" FORCE)
set(WOLFSSL_PUBLIC_MP yes CACHE STRING "Expose reviewed wolfCrypt scalar APIs" FORCE)
set(WOLFSSL_HARDEN yes CACHE STRING "Require timing resistance and blinding" FORCE)
set(WOLFSSL_ECC yes CACHE STRING "Enable hardened P-256 SPAKE2 operations" FORCE)
set(WOLFSSL_SP_MATH_ALL yes CACHE STRING "Use reviewed SP math implementation" FORCE)
set(WOLFSSL_KEYGEN yes CACHE STRING "Enable fresh LSP identity key generation" FORCE)
set(WOLFSSL_CERTGEN yes CACHE STRING "Enable fresh LSP certificate generation" FORCE)
set(WOLFSSL_CERTEXT yes CACHE STRING "Enable generated certificate extensions" FORCE)
set(WOLFSSL_OPENSSLEXTRA yes CACHE STRING "Enable reviewed compatibility APIs" FORCE)
set(WOLFSSL_SESSION_TICKET no CACHE STRING "Disable LSP/1 session resumption" FORCE)
set(WOLFSSL_SYS_CA_CERTS no CACHE STRING "LSP uses explicit SPKI trust" FORCE)
set(WOLFSSL_MLKEM no CACHE STRING "Disable unused post-quantum groups" FORCE)
set(WOLFSSL_PQC_HYBRIDS no CACHE STRING "Disable unused hybrid groups" FORCE)

FetchContent_Declare(
        lumen_wolfssl
        GIT_REPOSITORY https://github.com/wolfSSL/wolfssl.git
        GIT_TAG ${LUMEN_WOLFSSL_COMMIT}
        GIT_SHALLOW FALSE
        GIT_PROGRESS TRUE)
FetchContent_MakeAvailable(lumen_wolfssl)
if(NOT TARGET wolfssl::wolfssl)
    message(FATAL_ERROR "Pinned wolfSSL did not provide wolfssl::wolfssl")
endif()

# wolfSSL 5.9.2's CMake profile has no first-class scrypt or public ECC
# add/double switches. Keep the library and every consumer on one reviewed
# configuration rather than defining private ABI-shaping macros in a source
# file. The generated header is also installed by Umbra's matching bootstrap.
set(_lumen_wolfssl_spake2_include
        "${lumen_wolfssl_BINARY_DIR}/lsp-spake2-include")
file(MAKE_DIRECTORY "${_lumen_wolfssl_spake2_include}/wolfssl")
file(WRITE "${_lumen_wolfssl_spake2_include}/wolfssl/lsp_spake2_settings.h"
        "#pragma once\n"
        "#include <wolfssl/options.h>\n"
        "#ifndef HAVE_SCRYPT\n#define HAVE_SCRYPT\n#endif\n"
        "#ifndef WOLFSSL_PUBLIC_MP\n#define WOLFSSL_PUBLIC_MP\n#endif\n"
        "#ifndef WOLFSSL_PUBLIC_ECC_ADD_DBL\n#define WOLFSSL_PUBLIC_ECC_ADD_DBL\n#endif\n"
        "#ifndef WOLFSSL_ECC_GEN_REJECT_SAMPLING\n#define WOLFSSL_ECC_GEN_REJECT_SAMPLING\n#endif\n"
        "#ifndef WOLFSSL_SP_MATH_ALL\n#define WOLFSSL_SP_MATH_ALL\n#endif\n")
target_compile_definitions(wolfssl PUBLIC
        HAVE_SCRYPT
        WOLFSSL_PUBLIC_MP
        WOLFSSL_PUBLIC_ECC_ADD_DBL
        WOLFSSL_ECC_GEN_REJECT_SAMPLING
        WOLFSSL_SP_MATH_ALL)
target_include_directories(wolfssl PUBLIC
        "$<BUILD_INTERFACE:${_lumen_wolfssl_spake2_include}>")
if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    # GCC 15 diagnoses wolfSSL's size-checked GCM counter helper as an
    # out-of-bounds write after inlining even though the runtime size is the
    # fixed 12-byte nonce. Keep upstream -Werror and suppress only that proven
    # false-positive diagnostic on the third-party target.
    target_compile_options(wolfssl PRIVATE -Wno-stringop-overflow)
endif()

FetchContent_Declare(
        lumen_libsrtp
        GIT_REPOSITORY https://github.com/cisco/libsrtp.git
        GIT_TAG ${LUMEN_LIBSRTP_COMMIT}
        GIT_SHALLOW FALSE
        GIT_PROGRESS TRUE)
FetchContent_GetProperties(lumen_libsrtp)
if(NOT lumen_libsrtp_POPULATED)
    FetchContent_Populate(lumen_libsrtp)

    set(_lumen_libsrtp_patch_dir
            "${CMAKE_SOURCE_DIR}/cmake/patches/libsrtp-wolfssl")
    file(COPY
            "${_lumen_libsrtp_patch_dir}/aes_gcm_wolfssl.c"
            DESTINATION "${lumen_libsrtp_SOURCE_DIR}/crypto/cipher")
    file(COPY
            "${_lumen_libsrtp_patch_dir}/aes_icm_wolfssl.c"
            DESTINATION "${lumen_libsrtp_SOURCE_DIR}/crypto/cipher")

    set(_lumen_libsrtp_patch
            "${_lumen_libsrtp_patch_dir}/libsrtp-2.8.0-wolfssl.patch")
    execute_process(
            COMMAND "${GIT_EXECUTABLE}" apply --check "${_lumen_libsrtp_patch}"
            WORKING_DIRECTORY "${lumen_libsrtp_SOURCE_DIR}"
            RESULT_VARIABLE _lumen_libsrtp_patch_check
            OUTPUT_QUIET ERROR_QUIET)
    if(_lumen_libsrtp_patch_check EQUAL 0)
        execute_process(
                COMMAND "${GIT_EXECUTABLE}" apply "${_lumen_libsrtp_patch}"
                WORKING_DIRECTORY "${lumen_libsrtp_SOURCE_DIR}"
                RESULT_VARIABLE _lumen_libsrtp_patch_result)
        if(NOT _lumen_libsrtp_patch_result EQUAL 0)
            message(FATAL_ERROR "Unable to apply the pinned libSRTP wolfCrypt patch")
        endif()
    else()
        execute_process(
                COMMAND "${GIT_EXECUTABLE}" apply --reverse --check "${_lumen_libsrtp_patch}"
                WORKING_DIRECTORY "${lumen_libsrtp_SOURCE_DIR}"
                RESULT_VARIABLE _lumen_libsrtp_reverse_check
                OUTPUT_QUIET ERROR_QUIET)
        if(NOT _lumen_libsrtp_reverse_check EQUAL 0)
            message(FATAL_ERROR "libSRTP source does not match the pinned wolfCrypt patch")
        endif()
    endif()

    set(ENABLE_OPENSSL OFF CACHE BOOL "Do not use OpenSSL for LSP SRTP" FORCE)
    set(ENABLE_MBEDTLS OFF CACHE BOOL "Do not use MbedTLS for LSP SRTP" FORCE)
    set(ENABLE_NSS OFF CACHE BOOL "Do not use NSS for LSP SRTP" FORCE)
    set(ENABLE_WOLFSSL ON CACHE BOOL "Use the LSP wolfCrypt backend" FORCE)
    set(LIBSRTP_TEST_APPS OFF CACHE BOOL "Build LSP's focused tests separately" FORCE)
    add_subdirectory(
            "${lumen_libsrtp_SOURCE_DIR}"
            "${lumen_libsrtp_BINARY_DIR}"
            EXCLUDE_FROM_ALL)
endif()

if(NOT TARGET srtp2)
    message(FATAL_ERROR "Pinned libSRTP did not provide srtp2")
endif()

add_library(Lumen::wolfssl ALIAS wolfssl)
add_library(Lumen::srtp2 ALIAS srtp2)

set(BUILD_SHARED_LIBS "${_lumen_saved_build_shared_libs}" CACHE BOOL "Build shared libraries" FORCE)
unset(_lumen_saved_build_shared_libs)
unset(_lumen_libsrtp_patch_check)
unset(_lumen_libsrtp_patch_result)
unset(_lumen_libsrtp_reverse_check)
unset(_lumen_wolfssl_spake2_include)
