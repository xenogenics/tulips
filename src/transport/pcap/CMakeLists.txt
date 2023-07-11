set(CMAKE_POSITION_INDEPENDENT_CODE 1)
include_directories(${PCAP_INCLUDE_DIR})

file(GLOB SOURCES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.cpp *.h)

add_library(tulips_transport_pcap SHARED ${SOURCES})
target_link_libraries(tulips_transport_pcap PUBLIC tulips_stack ${PCAP_LIBRARY})

add_library(tulips_transport_pcap_static STATIC ${SOURCES})

install(TARGETS
  tulips_transport_pcap
  tulips_transport_pcap_static
  LIBRARY DESTINATION lib)
