set(CMAKE_POSITION_INDEPENDENT_CODE 1)
file(GLOB SOURCES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.cpp *.h)

add_library(tulips_transport_list SHARED ${SOURCES})
target_link_libraries(tulips_transport_list PRIVATE tulips_stack)

add_library(tulips_transport_list_static STATIC ${SOURCES})
target_link_libraries(tulips_transport_list_static PRIVATE tulips_stack_static)

install(TARGETS
  tulips_transport_list
  tulips_transport_list_static
  LIBRARY DESTINATION lib)
