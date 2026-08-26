cmake_minimum_required(VERSION 3.20)

get_filename_component(LUMEN_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
find_program(LUMEN_POWERSHELL NAMES pwsh powershell REQUIRED)
find_program(LUMEN_C_COMPILER NAMES clang cc gcc REQUIRED)

if(DEFINED ENV{TMPDIR} AND NOT "$ENV{TMPDIR}" STREQUAL "")
    set(fixture_temp_root "$ENV{TMPDIR}")
else()
    set(fixture_temp_root "/tmp")
endif()
string(RANDOM LENGTH 12 ALPHABET 0123456789abcdef fixture_suffix)
set(owner_fixture_binary "${fixture_temp_root}/lumen-msi-owner-${fixture_suffix}")
if(WIN32)
    string(APPEND owner_fixture_binary ".exe")
endif()

execute_process(
    COMMAND "${LUMEN_C_COMPILER}"
            -std=c17 -Wall -Wextra -Werror
            "${LUMEN_ROOT}/tests/packaging/test-lumen-msica-owner-selection.c"
            -o "${owner_fixture_binary}"
    RESULT_VARIABLE compile_result
    OUTPUT_VARIABLE compile_stdout
    ERROR_VARIABLE compile_stderr)
if(NOT compile_result EQUAL 0)
    message(FATAL_ERROR
        "Could not build offline MSI owner fixture (${compile_result}):\n"
        "${compile_stdout}${compile_stderr}")
endif()

execute_process(
    COMMAND "${owner_fixture_binary}"
    RESULT_VARIABLE c_fixture_result
    OUTPUT_VARIABLE c_fixture_stdout
    ERROR_VARIABLE c_fixture_stderr)
file(REMOVE "${owner_fixture_binary}")
if(NOT c_fixture_result EQUAL 0)
    message(FATAL_ERROR
        "Offline MSI owner fixture failed (${c_fixture_result}):\n"
        "${c_fixture_stdout}${c_fixture_stderr}")
endif()

execute_process(
    COMMAND "${LUMEN_POWERSHELL}" -NoProfile -NonInteractive -File
            "${LUMEN_ROOT}/tests/packaging/test-virtual-display-ownership-contract.ps1"
    RESULT_VARIABLE powershell_fixture_result
    OUTPUT_VARIABLE powershell_fixture_stdout
    ERROR_VARIABLE powershell_fixture_stderr)
if(NOT powershell_fixture_result EQUAL 0)
    message(FATAL_ERROR
        "Offline PowerShell ownership fixture failed (${powershell_fixture_result}):\n"
        "${powershell_fixture_stdout}${powershell_fixture_stderr}")
endif()

string(STRIP "${c_fixture_stdout}" c_fixture_stdout)
string(STRIP "${powershell_fixture_stdout}" powershell_fixture_stdout)
message(STATUS "${c_fixture_stdout}")
message(STATUS "${powershell_fixture_stdout}")
message(STATUS "Verified Gate 5 MSI ownership fixtures.")
