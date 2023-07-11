set(CMAKE_POSITION_INDEPENDENT_CODE 1)
file(GLOB SOURCES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.c *.h)

add_library(tulips_fifo SHARED ${SOURCES})
set_property(TARGET tulips_fifo PROPERTY C_STANDARD 99)

add_library(tulips_fifo_static STATIC ${SOURCES})
set_property(TARGET tulips_fifo_static PROPERTY C_STANDARD 99)

install(TARGETS
  tulips_fifo
  tulips_fifo_static
  LIBRARY DESTINATION lib)
