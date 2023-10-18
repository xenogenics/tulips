set(CMAKE_POSITION_INDEPENDENT_CODE 1)
file(GLOB SOURCES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.cpp *.h)

add_library(tulips_api SHARED ${SOURCES})
target_link_libraries(tulips_api PRIVATE tulips_stack)

add_library(tulips_api_static STATIC ${SOURCES})
target_link_libraries(tulips_api_static PRIVATE tulips_stack_static)

install(TARGETS
  tulips_api
  tulips_api_static
  LIBRARY DESTINATION lib)
