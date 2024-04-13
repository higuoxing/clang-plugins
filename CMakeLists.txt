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
add_subdirectory(lib)
