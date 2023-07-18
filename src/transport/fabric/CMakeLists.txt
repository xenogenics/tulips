set(CMAKE_POSITION_INDEPENDENT_CODE 1)
include_directories(${LibFabric_INCLUDE_DIR})

file(GLOB SOURCES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.cpp *.h)

add_library(tulips_transport_fabric SHARED ${SOURCES})
target_link_libraries(tulips_transport_fabric PUBLIC tulips_stack ${LibFabric_LIBRARIES})

add_library(tulips_transport_fabric_static STATIC ${SOURCES})

install(TARGETS
  tulips_transport_fabric
  tulips_transport_fabric_static
  LIBRARY DESTINATION lib)
