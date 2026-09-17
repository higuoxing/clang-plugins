cmake_minimum_required(VERSION 3.13.4)
project(postgres-checkers)

find_program(LLVM_CONFIG "llvm-config")
if(${LLVM_CONFIG} STREQUAL LLVM_CONFIG-NOTFOUND)
  message(FATAL_ERROR "llvm-config not found")
endif()

#===============================================================================
# 1. VERIFY CLANG INSTALLATION DIR
#===============================================================================
execute_process(COMMAND llvm-config --includedir
                OUTPUT_VARIABLE LLVM_INCLUDE_DIR
                OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT EXISTS "${LLVM_INCLUDE_DIR}/llvm")
  message(FATAL_ERROR "LLVM header files not found")
endif()

execute_process(COMMAND llvm-config --cmakedir
                OUTPUT_VARIABLE LLVM_CMAKE_DIR
                OUTPUT_STRIP_TRAILING_WHITESPACE)
set(LLVM_CMAKE_FILE
  "${LLVM_CMAKE_DIR}/../clang/ClangConfig.cmake")
if(NOT EXISTS "${LLVM_CMAKE_FILE}")
message(FATAL_ERROR
  "LLVM CMake files not found")
endif()

#===============================================================================
# 2. LOAD CLANG CONFIGURATION
#    Extracted from:
#    http://llvm.org/docs/CMake.html#embedding-llvm-in-your-project
#===============================================================================
list(APPEND CMAKE_PREFIX_PATH "${LLVM_CMAKE_DIR}/clang/")

find_package(Clang REQUIRED CONFIG)

message(STATUS "Found Clang ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using ClangConfig.cmake in: ${LLVM_CMAKE_DIR}/clang/")

message("CLANG STATUS:
  Includes (clang)    ${CLANG_INCLUDE_DIRS}
  Includes (llvm)     ${LLVM_INCLUDE_DIRS}"
)

# Set the LLVM and Clang header and library paths
include_directories(SYSTEM "${LLVM_INCLUDE_DIRS};${CLANG_INCLUDE_DIRS}")

#===============================================================================
# 3. CLANG-TUTOR BUILD CONFIGURATION
#===============================================================================
# Use the same C++ standard as LLVM does
set(CMAKE_CXX_STANDARD 17 CACHE STRING "")

# Build type
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug CACHE
      STRING "Build type (default Debug):" FORCE)
endif()

# Compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall\
    -fdiagnostics-color=always")

# LLVM/Clang is normally built without RTTI. Be consistent with that.
if(NOT LLVM_ENABLE_RTTI)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti")
endif()

# -fvisibility-inlines-hidden is set when building LLVM and on Darwin warnings
# are triggered if llvm-tutor is built without this flag (though otherwise it
# builds fine). For consistency, add it here too.
include(CheckCXXCompilerFlag)
check_cxx_compiler_flag("-fvisibility-inlines-hidden"
  SUPPORTS_FVISIBILITY_INLINES_HIDDEN_FLAG)
if(${SUPPORTS_FVISIBILITY_INLINES_HIDDEN_FLAG} EQUAL "1")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility-inlines-hidden")
endif()

# Set the build directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/lib")

#===============================================================================
# 4. ADD SUB-TARGETS
# Doing this at the end so that all definitions and link/include paths are
# available for the sub-projects.
#===============================================================================
add_subdirectory(clang-tidy)

#===============================================================================
# 5. TESTING
#===============================================================================
enable_testing()

execute_process(COMMAND ${LLVM_CONFIG} --bindir
                OUTPUT_VARIABLE LLVM_BINDIR
                OUTPUT_STRIP_TRAILING_WHITESPACE)

find_program(CLANG_TIDY_PROGRAM clang-tidy HINTS "${LLVM_BINDIR}")
if(NOT CLANG_TIDY_PROGRAM)
  message(FATAL_ERROR "clang-tidy not found (looked in ${LLVM_BINDIR})")
endif()
find_program(FILECHECK_PROGRAM FileCheck HINTS "${LLVM_BINDIR}")
find_program(PYTHON3_PROGRAM python3 python)

if(FILECHECK_PROGRAM)
  set(FILECHECK_COMMAND "${FILECHECK_PROGRAM}")
  set(FILECHECK_SCRIPT "")
  message(STATUS "FileCheck: ${FILECHECK_PROGRAM}")
else()
  if(NOT PYTHON3_PROGRAM)
    message(FATAL_ERROR
      "FileCheck not found and python3 is required for tools/filecheck.py")
  endif()
  set(FILECHECK_COMMAND "${PYTHON3_PROGRAM}")
  set(FILECHECK_SCRIPT "${CMAKE_SOURCE_DIR}/tools/filecheck.py")
  message(STATUS "FileCheck: ${PYTHON3_PROGRAM} ${FILECHECK_SCRIPT}")
endif()
message(STATUS "clang-tidy: ${CLANG_TIDY_PROGRAM}")

function(add_clang_tidy_check name source checks prefix)
  add_test(
    NAME ${name}
    COMMAND ${CMAKE_COMMAND}
      "-DCLANG_TIDY=${CLANG_TIDY_PROGRAM}"
      "-DPLUGIN=$<TARGET_FILE:PostgresTidyModule>"
      "-DSOURCE=${source}"
      "-DCHECKS=${checks}"
      "-DFILECHECK=${FILECHECK_COMMAND}"
      "-DFILECHECK_SCRIPT=${FILECHECK_SCRIPT}"
      "-DCHECK_PREFIX=${prefix}"
      "-DBINARY_DIR=${CMAKE_BINARY_DIR}"
      "-DTEST_NAME=${name}"
      -P "${CMAKE_SOURCE_DIR}/cmake/RunClangTidyCheck.cmake")
endfunction()

add_clang_tidy_check(
  pg-palloc-runtime-mul
  "${CMAKE_SOURCE_DIR}/test/test_palloc_runtime_mul.c"
  pg-palloc-runtime-mul
  TIDY)
add_clang_tidy_check(
  pg-missing-volatile-in-pg-try
  "${CMAKE_SOURCE_DIR}/test/test_missing_volatile_in_pg_try.c"
  pg-missing-volatile-in-pg-try
  TIDY)
add_clang_tidy_check(
  pg-missing-memory-context-restore
  "${CMAKE_SOURCE_DIR}/test/test_missing_memory_context_restore.c"
  pg-missing-memory-context-restore
  TIDY)
add_clang_tidy_check(
  pg-return-in-pg-try-block
  "${CMAKE_SOURCE_DIR}/test/test_return_in_pg_try.c"
  pg-return-in-pg-try-block
  CHECK)
add_clang_tidy_check(
  pg-catch-missing-flush-or-rethrow
  "${CMAKE_SOURCE_DIR}/test/test_catch_missing_flush_or_rethrow.c"
  pg-catch-missing-flush-or-rethrow
  TIDY)
add_clang_tidy_check(
  pg-typedef-mismatch
  "${CMAKE_SOURCE_DIR}/test/test_typedef_mismatch.c"
  pg-typedef-mismatch
  TIDY)
add_clang_tidy_check(
  pg-unsafe-in-crit-section
  "${CMAKE_SOURCE_DIR}/test/test_unsafe_in_crit_section.c"
  pg-unsafe-in-crit-section
  TIDY)
