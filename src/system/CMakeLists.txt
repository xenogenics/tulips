set(CMAKE_POSITION_INDEPENDENT_CODE 1)
file(GLOB SOURCES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.cpp *.h)

add_library(tulips_system SHARED ${SOURCES})
target_link_libraries(tulips_system PUBLIC ${CMAKE_THREAD_LIBS_INIT})

add_library(tulips_system_static STATIC ${SOURCES})

install(TARGETS
  tulips_system
  tulips_system_static
  LIBRARY DESTINATION lib)
