set(CMAKE_POSITION_INDEPENDENT_CODE 1)
file(GLOB SOURCES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.cpp *.h)

include_directories(${OpenSSL_INCLUDE_DIRS})

add_library(tulips_ssl SHARED ${SOURCES})
target_link_libraries(tulips_ssl PRIVATE tulips_api tulips_stack PUBLIC ${OpenSSL_LIBRARIES})

add_library(tulips_ssl_static STATIC ${SOURCES})

install(TARGETS
  tulips_ssl
  tulips_ssl_static
  LIBRARY DESTINATION lib)
