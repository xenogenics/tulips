set(CMAKE_POSITION_INDEPENDENT_CODE 1)
include_directories(${LibPCAP_INCLUDE_DIRS})

file(GLOB SOURCES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.cpp *.h)

add_library(tulips_transport_pcap SHARED ${SOURCES})
target_link_libraries(tulips_transport_pcap
  PRIVATE
  tulips_stack
  PUBLIC ${LibPCAP_LINK_LIBRARIES})

add_library(tulips_transport_pcap_static STATIC ${SOURCES})
target_link_libraries(tulips_transport_pcap_static
  PRIVATE
  tulips_stack_static
  PUBLIC ${LibPCAP_LINK_LIBRARIES})

install(TARGETS
  tulips_transport_pcap
  tulips_transport_pcap_static
  LIBRARY DESTINATION lib)
