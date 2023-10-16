set(CMAKE_POSITION_INDEPENDENT_CODE 1)

file(GLOB SOURCES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.cpp *.h)

add_library(tulips_transport_bond SHARED ${SOURCES})
target_link_libraries(tulips_transport_bond PUBLIC tulips_stack)

add_library(tulips_transport_bond_static STATIC ${SOURCES})

install(TARGETS
  tulips_transport_bond
  tulips_transport_bond_static
  LIBRARY DESTINATION lib)
