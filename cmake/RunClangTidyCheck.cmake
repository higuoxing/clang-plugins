# Run clang-tidy and pipe diagnostics through FileCheck.
# Required -D variables: CLANG_TIDY, PLUGIN, SOURCE, CHECKS, FILECHECK,
# CHECK_PREFIX, BINARY_DIR, TEST_NAME.
# Optional: FILECHECK_SCRIPT (python FileCheck replacement).

foreach(var CLANG_TIDY PLUGIN SOURCE CHECKS FILECHECK CHECK_PREFIX BINARY_DIR
            TEST_NAME)
  if(NOT DEFINED ${var} OR "${${var}}" STREQUAL "")
    message(FATAL_ERROR "RunClangTidyCheck.cmake missing -D${var}")
  endif()
endforeach()

execute_process(
  COMMAND "${CLANG_TIDY}"
          "-load=${PLUGIN}"
          "-checks=-*,${CHECKS}"
          "${SOURCE}"
          "--"
  RESULT_VARIABLE tidy_rc
  OUTPUT_VARIABLE tidy_stdout
  ERROR_VARIABLE tidy_stderr)

set(tidy_output "${tidy_stdout}${tidy_stderr}")
file(MAKE_DIRECTORY "${BINARY_DIR}/Testing")
set(log_file "${BINARY_DIR}/Testing/${TEST_NAME}.tidy.log")
file(WRITE "${log_file}" "${tidy_output}")

if(tidy_output STREQUAL "")
  message(FATAL_ERROR
    "clang-tidy produced no output (exit ${tidy_rc}): ${CLANG_TIDY}")
endif()

set(fc_cmd "${FILECHECK}")
if(DEFINED FILECHECK_SCRIPT AND NOT "${FILECHECK_SCRIPT}" STREQUAL "")
  list(APPEND fc_cmd "${FILECHECK_SCRIPT}")
endif()
list(APPEND fc_cmd "${SOURCE}" "--check-prefix=${CHECK_PREFIX}")

execute_process(
  COMMAND ${fc_cmd}
  INPUT_FILE "${log_file}"
  RESULT_VARIABLE fc_rc
  OUTPUT_VARIABLE fc_stdout
  ERROR_VARIABLE fc_stderr)

if(NOT fc_rc EQUAL 0)
  message("${tidy_output}")
  message(FATAL_ERROR
    "FileCheck failed for ${TEST_NAME} (exit ${fc_rc}):\n${fc_stdout}${fc_stderr}")
endif()
