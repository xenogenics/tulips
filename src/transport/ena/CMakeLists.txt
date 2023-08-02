set(CMAKE_POSITION_INDEPENDENT_CODE 1)
include_directories(${LibDPDK_INCLUDE_DIRS})

file(GLOB SOURCES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.cpp *.h)

add_library(tulips_transport_ena SHARED ${SOURCES})
target_link_libraries(tulips_transport_ena PUBLIC tulips_stack ${LibDPDK_LIBRARIES})

add_library(tulips_transport_ena_static STATIC ${SOURCES})

install(TARGETS
  tulips_transport_ena
  tulips_transport_ena_static
  LIBRARY DESTINATION lib)
