set(CMAKE_POSITION_INDEPENDENT_CODE 1)
include_directories(${PCAP_INCLUDE_DIR})

file(GLOB SOURCES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.cpp *.h)

add_library(tulips_transport_erase SHARED ${SOURCES} ${PCAP_LIBRARY})
target_link_libraries(tulips_transport_erase PUBLIC tulips_stack)

add_library(tulips_transport_erase_static STATIC ${SOURCES} ${PCAP_LIBRARY})

install(TARGETS
  tulips_transport_erase
  tulips_transport_erase_static
  LIBRARY DESTINATION lib)
