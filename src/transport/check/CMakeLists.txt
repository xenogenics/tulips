set(CMAKE_POSITION_INDEPENDENT_CODE 1)

file(GLOB SOURCES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.cpp *.h)

add_library(tulips_transport_check SHARED ${SOURCES})
target_link_libraries(tulips_transport_check PRIVATE tulips_stack)

add_library(tulips_transport_check_static STATIC ${SOURCES})
target_link_libraries(tulips_transport_check_static PRIVATE tulips_stack_static)

install(TARGETS
  tulips_transport_check
  tulips_transport_check_static
  LIBRARY DESTINATION lib)
