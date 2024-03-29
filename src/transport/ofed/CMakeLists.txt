set(CMAKE_POSITION_INDEPENDENT_CODE 1)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-missing-field-initializers")
  
include_directories(${OFED_INCLUDE_DIRS})

file(GLOB SOURCES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.cpp *.h)

add_library(tulips_transport_ofed SHARED ${SOURCES} Utils.cpp Utils.h)
target_link_libraries(tulips_transport_ofed
  PRIVATE
  tulips_api
  tulips_stack
  tulips_transport_stubs
  tulips_system
  PUBLIC
  ${LibIBVerbs_LINK_LIBRARIES})

add_library(tulips_transport_ofed_static STATIC ${SOURCES})
target_link_libraries(tulips_transport_ofed_static
  PRIVATE
  tulips_api_static
  tulips_stack_static
  tulips_transport_stubs_static
  tulips_system_static
  PUBLIC
  ${LibIBVerbs_LINK_LIBRARIES})

install(TARGETS
  tulips_transport_ofed
  tulips_transport_ofed_static
  LIBRARY DESTINATION lib)
