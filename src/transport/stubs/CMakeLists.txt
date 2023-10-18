set(CMAKE_POSITION_INDEPENDENT_CODE 1)

if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  set(SOURCES linux.cpp)
elseif (${CMAKE_SYSTEM_NAME} MATCHES "OpenBSD")
  set(SOURCES openbsd.cpp)
elseif (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  set(SOURCES darwin.cpp)
else ()
  set(SOURCES stubs/dummy.cpp)
endif ()

add_library(tulips_transport_stubs SHARED ${SOURCES})
target_link_libraries(tulips_transport_stubs PRIVATE tulips_stack)

add_library(tulips_transport_stubs_static STATIC ${SOURCES})
target_link_libraries(tulips_transport_stubs_static PRIVATE tulips_stack_static)

install(TARGETS
  tulips_transport_stubs
  tulips_transport_stubs_static
  LIBRARY DESTINATION lib)
