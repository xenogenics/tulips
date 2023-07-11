set(CMAKE_POSITION_INDEPENDENT_CODE 1)
file(GLOB SOURCES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.cpp *.h)

add_library(tulips_transport_shm SHARED ${SOURCES})
target_link_libraries(tulips_transport_shm PUBLIC tulips_fifo tulips_stack)

add_library(tulips_transport_shm_static STATIC ${SOURCES})

install(TARGETS
  tulips_transport_shm
  tulips_transport_shm_static
  LIBRARY DESTINATION lib)
