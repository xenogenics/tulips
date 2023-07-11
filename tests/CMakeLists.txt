include_directories(SYSTEM ${GTEST_INCLUDE_DIR})

set(CMAKE_POSITION_INDEPENDENT_CODE 1)
file(GLOB_RECURSE SOURCES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.cpp *.h)

if (${CMAKE_SYSTEM_NAME} MATCHES "Linux" OR ${CMAKE_SYSTEM_NAME} MATCHES "OpenBSD")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
endif ()

add_executable(tulips_tests ${SOURCES})
gtest_discover_tests(tulips_tests)

target_link_libraries(tulips_tests
  PRIVATE
  tulips_api
  tulips_fifo
  tulips_transport_list
  tulips_transport_pcap
  tulips_transport_shm
  tulips_ssl
  tulips_stack
  tulips_system
  PUBLIC
  ${GTEST_LIBRARIES})
