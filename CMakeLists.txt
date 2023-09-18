cmake_minimum_required(VERSION 3.20)

#
# Policies
#

cmake_policy(SET CMP0074 NEW)

#
# Global definitions
#

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

#
# Compiler configuration
#

set(CMAKE_C_COMPILER_NAMES clang gcc)
set(CMAKE_CXX_COMPILER_NAMES clang++ g++)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

#
# Project definition
#

project("TULIPS" C CXX)

#
# Options declaration
#

option(TULIPS_TESTS "Enable tests" OFF)
option(TULIPS_TOOLS "Build apps and tools" ON)

option(TULIPS_ENABLE_ARP "Enable ARP support" OFF)
option(TULIPS_ENABLE_ICMP "Enable ICMP support" OFF)
option(TULIPS_ENABLE_RAW "Enable RAW support" OFF)

option(TULIPS_ENABLE_LATENCY_MONITOR "Enable client latency monitoring" OFF)
option(TULIPS_ENABLE_ASAN "Enable address sanitizer" OFF)
option(TULIPS_ENABLE_UBSAN "Enable undefined behavior sanitizer" OFF)

option(TULIPS_DISABLE_CHECKSUM_CHECK "Disable checksum checks" OFF)
option(TULIPS_HAS_HW_CHECKSUM "Target has hardware checksum" OFF)
option(TULIPS_HAS_HW_TSO "Target has hardware TSO" OFF)
option(TULIPS_IGNORE_INCOMPATIBLE_HW "Ignore when HW lacks features (e.g. TCO)" OFF)

#
# Library dependencies
#

find_package(PkgConfig 1.8 REQUIRED)

pkg_check_modules(LibPCAP REQUIRED libpcap>=1.10)
pkg_check_modules(OpenSSL REQUIRED openssl>=3.0)
pkg_check_modules(LibDPDK libdpdk>=22.11)
pkg_check_modules(LibIBVerbs libibverbs>=1.14)

if (TULIPS_TOOLS)
  pkg_check_modules(TCLAP REQUIRED tclap>=1.2)
endif (TULIPS_TOOLS)

#
# Tooling dependencies
#

find_package(Threads REQUIRED)
find_package(ClangFormat)
find_package(ClangTidy)

if (TULIPS_TESTS)
  find_package(GTest REQUIRED)
endif (TULIPS_TESTS)

#
# Compiler flags
#

set(CMAKE_C_FLAGS "-Wall -Wextra -Werror -Wfatal-errors -mssse3")
set(CMAKE_C_FLAGS_DEBUG "-g3 -O0")
set(CMAKE_C_FLAGS_RELEASE "-O3")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-g3 -O3")

set(CMAKE_CXX_FLAGS "-Wall -Wextra -Werror -Wfatal-errors -mssse3")
set(CMAKE_CXX_FLAGS_DEBUG "-g3 -O0")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-g3 -O3")

#
# Option definitions
#

message(STATUS "[ TULIPS COMPILATION OPTIONS ]")

if (TULIPS_TESTS)

  set(TULIPS_ENABLE_ARP ON)
  set(TULIPS_ENABLE_ICMP ON)
  set(TULIPS_ENABLE_RAW ON)

  set(TULIPS_ENABLE_ASAN ON)
  set(TULIPS_ENABLE_UBSAN ON)

  set(TULIPS_IGNORE_INCOMPATIBLE_HW ON)

  add_definitions(-DTULIPS_TESTS)
  add_definitions(-DTULIPS_CLOCK_HAS_OFFSET)
  add_definitions(-DTULIPS_FIFO_RUNTIME_CHECKS)
  add_definitions(-DTULIPS_STACK_RUNTIME_CHECKS)
  add_definitions(-DTULIPS_TRANSPORT_RUNTIME_CHECKS)

  add_definitions(-DTULIPS_SOURCE_ROOT="${CMAKE_SOURCE_DIR}")

  message(STATUS "Test mode: ON")

endif (TULIPS_TESTS)

#
# Compilation options
#

if (TULIPS_ENABLE_ASAN)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address")
  add_link_options(-fsanitize=address)
  message(STATUS "Address sanitizer: ON")
endif (TULIPS_ENABLE_ASAN)

if (TULIPS_ENABLE_UBSAN)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=undefined")
  add_link_options(-fsanitize=undefined)
  message(STATUS "Undefined behavior sanitizer: ON")
endif (TULIPS_ENABLE_UBSAN)

#
# Offload options
#

message(STATUS "[ TULIPS OFFLOAD OPTIONS ]")

if (TULIPS_HAS_HW_CHECKSUM)
  add_definitions(-DTULIPS_HAS_HW_CHECKSUM)
  message(STATUS "Hardware checksum: ON")
else (TULIPS_HAS_HW_CHECKSUM)
  message(STATUS "Hardware checksum: OFF")
endif (TULIPS_HAS_HW_CHECKSUM)

if (TULIPS_DISABLE_CHECKSUM_CHECK)
  add_definitions(-DTULIPS_DISABLE_CHECKSUM_CHECK)
  message(STATUS "Disable checksum check: ON")
else (TULIPS_DISABLE_CHECKSUM_CHECK)
  message(STATUS "Disable checksum check: OFF")
endif (TULIPS_DISABLE_CHECKSUM_CHECK)

if (TULIPS_HAS_HW_TSO)
  add_definitions(-DTULIPS_HAS_HW_TSO)
  message(STATUS "TCP segmentation offload: ON")
else (TULIPS_HAS_HW_TSO)
  message(STATUS "TCP segmentation offload: OFF")
endif (TULIPS_HAS_HW_TSO)

if (TULIPS_IGNORE_INCOMPATIBLE_HW)
  add_definitions(-DTULIPS_IGNORE_INCOMPATIBLE_HW)
  message(STATUS "Ignore incompatible hardware: ON")
else (TULIPS_IGNORE_INCOMPATIBLE_HW)
  message(STATUS "Ignore incompatible hardware: OFF")
endif (TULIPS_IGNORE_INCOMPATIBLE_HW)

message(STATUS "[ TULIPS PROTOCOL OPTIONS ]")

if (TULIPS_ENABLE_ARP)
  add_definitions(-DTULIPS_ENABLE_ARP)
  message(STATUS "ARP protocol support: ON")
else (TULIPS_ENABLE_ARP)
  message(STATUS "ARP protocol support: OFF")
endif (TULIPS_ENABLE_ARP)

if (TULIPS_ENABLE_ICMP)
  add_definitions(-DTULIPS_ENABLE_ICMP)
  message(STATUS "ICMP protocol support: ON")
else (TULIPS_ENABLE_ICMP)
  message(STATUS "ICMP protocol support: OFF")
endif (TULIPS_ENABLE_ICMP)

if (TULIPS_ENABLE_RAW)
  add_definitions(-DTULIPS_ENABLE_RAW)
  message(STATUS "RAW packets support: ON")
else (TULIPS_ENABLE_RAW)
  message(STATUS "RAW packets support: OFF")
endif (TULIPS_ENABLE_RAW)

if (TULIPS_ENABLE_LATENCY_MONITOR)
  add_definitions(-DTULIPS_ENABLE_LATENCY_MONITOR)
  message(STATUS "Client latency monitor: ON")
else (TULIPS_ENABLE_LATENCY_MONITOR)
  message(STATUS "Client latency monitor: OFF")
endif (TULIPS_ENABLE_LATENCY_MONITOR)

#
# Done with options.
#

message(STATUS "[ TULIPS OPTIONS END ]")

#
# Per-compiler options
#

if (${CMAKE_CXX_COMPILER_ID} STREQUAL "Clang")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-address-of-packed-member")
endif ()

if (${CMAKE_CXX_COMPILER_ID} STREQUAL "GNU")
  if (CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 9.0)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-address-of-packed-member")
  endif ()
endif ()

#
# Include directories
#

include_directories(${CMAKE_SOURCE_DIR}/include)

#
# Subdirectories
#

add_subdirectory(src)

if (TULIPS_TOOLS)
  add_subdirectory(apps)
  add_subdirectory(tools)
endif (TULIPS_TOOLS)

#
# Testing
#

if (TULIPS_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif (TULIPS_TESTS)

#
# Install all headers
#

install(DIRECTORY include/tulips DESTINATION include PATTERN "*.swp" EXCLUDE)

#
# Formatting
#

file(GLOB_RECURSE SOURCES RELATIVE ${CMAKE_SOURCE_DIR}
  apps/*.h apps/*.cpp
  include/*.h
  src/*.h src/*.cpp
  tests/*.h tests/*.cpp
  tools/*.h tools/*.cpp)

list(FILTER SOURCES EXCLUDE REGEX ".*linenoise.h")

if (APPLE)
  list(FILTER SOURCES EXCLUDE REGEX ".*linux.*")
  list(FILTER SOURCES EXCLUDE REGEX ".*openbsd.*")
  list(FILTER SOURCES EXCLUDE REGEX ".*tap.*")
endif (APPLE)

if (BSD)
  list(FILTER SOURCES EXCLUDE REGEX ".*darwin.*")
  list(FILTER SOURCES EXCLUDE REGEX ".*linux.*")
endif (BSD)

if (LINUX)
  list(FILTER SOURCES EXCLUDE REGEX ".*darwin.*")
  list(FILTER SOURCES EXCLUDE REGEX ".*openbsd.*")
  list(FILTER SOURCES EXCLUDE REGEX ".*tap.*")
endif (LINUX)

if (NOT LibIBVerbs_FOUND)
  list(FILTER SOURCES EXCLUDE REGEX ".*ofed.*")
  list(FILTER SOURCES EXCLUDE REGEX ".*uspace.*")
endif (NOT LibIBVerbs_FOUND)

foreach (SOURCE ${SOURCES})
  string(REGEX REPLACE "[/.]" "_" TARGET ${SOURCE})
  string(TOLOWER ${TARGET} TARGET)
  #
  if (ClangFormat_FOUND)
    add_custom_target(${TARGET}_format COMMAND clang-format -i -style=file ${CMAKE_SOURCE_DIR}/${SOURCE})
    list(APPEND FORMAT_TARGETS ${TARGET}_format)
    add_custom_target(${TARGET}_format_check COMMAND clang-format -n -Werror -style=file ${CMAKE_SOURCE_DIR}/${SOURCE})
    list(APPEND FORMAT_CHECK_TARGETS ${TARGET}_format_check)
  endif ()
  #
  if (ClangTidy_FOUND)
    add_custom_target(${TARGET}_tidy COMMAND clang-tidy -quiet -format-style=file -p ${CMAKE_BINARY_DIR} ${CMAKE_SOURCE_DIR}/${SOURCE})
    list(APPEND TIDY_TARGETS ${TARGET}_tidy)
  endif ()
endforeach ()

if (ClangFormat_FOUND)
  add_custom_target(format DEPENDS ${FORMAT_TARGETS})
  add_custom_target(format-check DEPENDS ${FORMAT_CHECK_TARGETS})
endif ()

if (ClangTidy_FOUND)
  add_custom_target(tidy DEPENDS ${TIDY_TARGETS})
endif ()
