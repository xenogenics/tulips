set(CMAKE_POSITION_INDEPENDENT_CODE 1)
file(GLOB SOURCES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.cpp *.h)

add_library(tulips_transport_tap SHARED ${SOURCES})
target_link_libraries(tulips_transport_tap
  PRIVATE
  tulips_stack
  tulips_transport_stubs)

add_library(tulips_transport_tap_static STATIC ${SOURCES})

install(TARGETS
  tulips_transport_tap
  tulips_transport_tap_static
  LIBRARY DESTINATION lib)
