set(CMAKE_POSITION_INDEPENDENT_CODE 1)
file(GLOB SOURCES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.cpp *.h)

if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  list(APPEND SOURCES stubs/linux.cpp)
elseif (${CMAKE_SYSTEM_NAME} MATCHES "OpenBSD")
  list(APPEND SOURCES stubs/openbsd.cpp)
else ()
  list(APPEND SOURCES stubs/dummy.cpp)
endif ()

add_library(tulips_stack_arp OBJECT ${SOURCES})
