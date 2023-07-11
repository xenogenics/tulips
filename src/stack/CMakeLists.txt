add_subdirectory(arp)
add_subdirectory(ethernet)
add_subdirectory(icmpv4)
add_subdirectory(ipv4)
add_subdirectory(tcpv4)

set(CMAKE_POSITION_INDEPENDENT_CODE 1)
file(GLOB SOURCES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.cpp *.h)

add_library(tulips_stack SHARED ${SOURCES}
  $<TARGET_OBJECTS:tulips_stack_arp>
  $<TARGET_OBJECTS:tulips_stack_ethernet>
  $<TARGET_OBJECTS:tulips_stack_ipv4>
  $<TARGET_OBJECTS:tulips_stack_icmpv4>
  $<TARGET_OBJECTS:tulips_stack_tcpv4>)
target_link_libraries(tulips_stack PUBLIC tulips_system)

add_library(tulips_stack_static STATIC ${SOURCES}
  $<TARGET_OBJECTS:tulips_stack_arp>
  $<TARGET_OBJECTS:tulips_stack_ethernet>
  $<TARGET_OBJECTS:tulips_stack_ipv4>
  $<TARGET_OBJECTS:tulips_stack_icmpv4>
  $<TARGET_OBJECTS:tulips_stack_tcpv4>)

install(TARGETS
  tulips_stack
  tulips_stack_static
  LIBRARY DESTINATION lib)
