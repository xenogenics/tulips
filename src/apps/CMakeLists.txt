include_directories(${TCLAP_INCLUDE_DIR})

set(CMAKE_POSITION_INDEPENDENT_CODE 1)

# We need to disable format checking here because various versions of GCC/CLANG
# are not interpreting the Clock::Value type the same way.
#
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-format")

file(GLOB SOURCES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.cpp *.h)

add_library(tulips_apps_static STATIC ${SOURCES})
target_link_libraries(tulips_apps_static
  PRIVATE
  tulips_api
  tulips_ssl
  tulips_stack
  tulips_transport_pcap)
