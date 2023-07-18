set(CMAKE_POSITION_INDEPENDENT_CODE 1)
include_directories(${LibDPDK_INCLUDE_DIR})

file(GLOB SOURCES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.cpp *.h)

add_library(tulips_transport_dpdk SHARED ${SOURCES})
target_link_libraries(tulips_transport_dpdk PUBLIC tulips_stack ${LibDPDK_LIBRARIES})

add_library(tulips_transport_dpdk_static STATIC ${SOURCES})

install(TARGETS
  tulips_transport_dpdk
  tulips_transport_dpdk_static
  LIBRARY DESTINATION lib)
