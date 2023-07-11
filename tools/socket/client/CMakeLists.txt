set(CMAKE_POSITION_INDEPENDENT_CODE 1)

include_directories(${CMAKE_SOURCE_DIR/tools})
include_directories(${TCLAP_INCLUDE_DIR})

file(GLOB SOURCES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.cpp *.h)

add_executable(client-socket ${SOURCES}
  $<TARGET_OBJECTS:linenoise>
  $<TARGET_OBJECTS:utils>)

target_link_libraries(client-socket PUBLIC tulips_stack)
