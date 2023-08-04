cmake_minimum_required(VERSION 3.3)

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
# Library dependencies
#

find_package(PkgConfig 1.8 REQUIRED)

pkg_check_modules(LibPCAP REQUIRED libpcap>=1.10)
pkg_check_modules(OpenSSL REQUIRED openssl>=3.0)
pkg_check_modules(TCLAP REQUIRED tclap>=1.2)

pkg_check_modules(LibDPDK libdpdk>=22.11)
pkg_check_modules(LibIBVerbs libibverbs>=1.14)

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
# Options
#

option(TULIPS_TESTS "Enable tests" OFF)
option(TULIPS_DEBUG "Enable debug logs" OFF)

option(TULIPS_DEBUG_TRANSPORT "Enable transport logs" OFF)
option(TULIPS_DEBUG_ETH "Enable ETH logs" OFF)
option(TULIPS_DEBUG_ARP "Enable ARP logs" OFF)
option(TULIPS_DEBUG_IP "Enable IP logs" OFF)
option(TULIPS_DEBUG_TCP "Enable TCP logs" OFF)
option(TULIPS_DEBUG_TCP_FLOW "Enable TCP flow logs" OFF)
option(TULIPS_DEBUG_TCP_OPTIONS "Enable TCP options logs" OFF)
option(TULIPS_DEBUG_SSL "Enable SSL logs" OFF)
option(TULIPS_DEBUG_CLIENT "Enable API client logs" OFF)
option(TULIPS_DEBUG_SERVER "Enable API server logs" OFF)

option(TULIPS_ENABLE_ARP "Enable ARP support" OFF)
option(TULIPS_ENABLE_ICMP "Enable ICMP support" OFF)
option(TULIPS_ENABLE_RAW "Enable RAW support" OFF)

option(TULIPS_ENABLE_LATENCY_MONITOR "Enable client latency monitoring" OFF)
option(TULIPS_ENABLE_SANITIZERS "Enable code sanitizers" OFF)

option(TULIPS_HAS_HW_CHECKSUM "Target has hardware checksum" OFF)
option(TULIPS_DISABLE_CHECKSUM_CHECK "Disable checksum checks" OFF)
option(TULIPS_HAS_HW_TSO "Target has hardware TSO" OFF)
option(TULIPS_IGNORE_INCOMPATIBLE_HW "Ignore when HW lacks features (e.g. TCO)" OFF)

message(STATUS "[ TULIPS OPTIONS BEGIN ]")

if (TULIPS_TESTS)

  set(TULIPS_DEBUG ON)
  set(TULIPS_DEBUG_TRANSPORT ON)
  set(TULIPS_DEBUG_ETH ON)
  set(TULIPS_DEBUG_ARP ON)
  set(TULIPS_DEBUG_IP ON)
  set(TULIPS_DEBUG_TCP ON)
  set(TULIPS_DEBUG_TCP_FLOW ON)
  set(TULIPS_DEBUG_TCP_OPTIONS ON)
  set(TULIPS_DEBUG_SSL ON)
  set(TULIPS_DEBUG_CLIENT ON)
  set(TULIPS_DEBUG_SERVER ON)

  set(TULIPS_ENABLE_ARP ON)
  set(TULIPS_ENABLE_ICMP ON)
  set(TULIPS_ENABLE_RAW ON)
  set(TULIPS_ENABLE_SANITIZERS ON)

  set(TULIPS_IGNORE_INCOMPATIBLE_HW ON)

  add_definitions(-DTULIPS_TESTS)
  add_definitions(-DTULIPS_CLOCK_HAS_OFFSET)
  add_definitions(-DTULIPS_FIFO_RUNTIME_CHECKS)
  add_definitions(-DTULIPS_STACK_RUNTIME_CHECKS)
  add_definitions(-DTULIPS_TRANSPORT_RUNTIME_CHECKS)

  add_definitions(-DTULIPS_SOURCE_ROOT="${CMAKE_SOURCE_DIR}")

  message(STATUS "Test mode: ON")

endif (TULIPS_TESTS)

if (TULIPS_DEBUG)
  add_definitions(-DTULIPS_DEBUG)
  message(STATUS "Debug logs: ON")
else (TULIPS_DEBUG)
  message(STATUS "Debug logs: OFF")
endif (TULIPS_DEBUG)

if (TULIPS_DEBUG AND TULIPS_DEBUG_TRANSPORT)
  add_definitions(-DTRANS_VERBOSE)
  message(STATUS "Transport logs: ON")
endif (TULIPS_DEBUG AND TULIPS_DEBUG_TRANSPORT)

if (TULIPS_DEBUG AND TULIPS_DEBUG_ETH)
  add_definitions(-DETH_VERBOSE)
  message(STATUS "Ethernet logs: ON")
endif (TULIPS_DEBUG AND TULIPS_DEBUG_ETH)

if (TULIPS_DEBUG AND TULIPS_DEBUG_ARP)
  add_definitions(-DARP_VERBOSE)
  message(STATUS "ARP logs: ON")
endif (TULIPS_DEBUG AND TULIPS_DEBUG_ARP)

if (TULIPS_DEBUG AND TULIPS_DEBUG_IP)
  add_definitions(-DIP_VERBOSE)
  message(STATUS "IP logs: ON")
endif (TULIPS_DEBUG AND TULIPS_DEBUG_IP)

if (TULIPS_DEBUG AND TULIPS_DEBUG_TCP)
  add_definitions(-DTCP_VERBOSE)
  message(STATUS "TCP logs: ON")
endif (TULIPS_DEBUG AND TULIPS_DEBUG_TCP)

if (TULIPS_DEBUG AND TULIPS_DEBUG_TCP_FLOW)
  add_definitions(-DTCP_FLOW_VERBOSE)
  message(STATUS "TCP flow logs: ON")
endif (TULIPS_DEBUG AND TULIPS_DEBUG_TCP_FLOW)

if (TULIPS_DEBUG AND TULIPS_DEBUG_TCP_OPTIONS)
  add_definitions(-DTCP_OPT_VERBOSE)
  message(STATUS "TCP options logs: ON")
endif (TULIPS_DEBUG AND TULIPS_DEBUG_TCP_OPTIONS)

if (TULIPS_DEBUG AND TULIPS_DEBUG_SSL)
  add_definitions(-DSSL_VERBOSE)
  message(STATUS "SSL logs: ON")
endif (TULIPS_DEBUG AND TULIPS_DEBUG_SSL)

if (TULIPS_DEBUG AND TULIPS_DEBUG_CLIENT)
  add_definitions(-DCLIENT_VERBOSE)
  message(STATUS "API client logs: ON")
endif (TULIPS_DEBUG AND TULIPS_DEBUG_CLIENT)

if (TULIPS_DEBUG AND TULIPS_DEBUG_SERVER)
  add_definitions(-DSERVER_VERBOSE)
  message(STATUS "API server logs: ON")
endif (TULIPS_DEBUG AND TULIPS_DEBUG_SERVER)

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

if (TULIPS_ENABLE_ARP)
  add_definitions(-DTULIPS_ENABLE_ARP)
  add_definitions(-DTULIPS_ENABLE_RAW)
  message(STATUS "ARP protocol support: ON")
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


if (TULIPS_ENABLE_SANITIZERS)
  message(STATUS "Sanitizers: ON")
else (TULIPS_ENABLE_SANITIZERS)
  message(STATUS "Sanitizers: OFF")
endif (TULIPS_ENABLE_SANITIZERS)

message(STATUS "[ TULIPS OPTIONS END ]")

#
# Flags preferences
#

set(CMAKE_C_FLAGS "-Wall -Wextra -Werror -Wfatal-errors -mssse3")
set(CMAKE_C_FLAGS_DEBUG "-g3 -O0")
set(CMAKE_C_FLAGS_RELEASE "-O3")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-g3 -O3")

set(CMAKE_CXX_FLAGS "-Wall -Wextra -Werror -Wfatal-errors -mssse3")
set(CMAKE_CXX_FLAGS_DEBUG "-g3 -O0")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-g3 -O3")

if (TULIPS_SANITIZERS)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address")
  add_link_options(-fsanitize=address)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=undefined")
  add_link_options(-fsanitize=undefined)
endif (TULIPS_SANITIZERS)

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

add_subdirectory(apps)
add_subdirectory(src)
add_subdirectory(tools)

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
