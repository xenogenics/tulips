set(CMAKE_POSITION_INDEPENDENT_CODE 1)
file(GLOB SOURCES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.cpp *.h)

add_library(tulips_transport_npipe SHARED ${SOURCES})
target_link_libraries(tulips_transport_npipe PRIVATE tulips_stack)

add_library(tulips_transport_npipe_static STATIC ${SOURCES})
target_link_libraries(tulips_transport_npipe_static PRIVATE tulips_stack_static)

install(TARGETS
  tulips_transport_npipe
  tulips_transport_npipe_static
  LIBRARY DESTINATION lib)
