set(CMAKE_POSITION_INDEPENDENT_CODE 1)
include_directories(${TCLAP_INCLUDE_DIRS})

if (${CMAKE_SYSTEM_NAME} MATCHES "Linux" OR ${CMAKE_SYSTEM_NAME} MATCHES "OpenBSD")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
endif ()

file(GLOB SOURCES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.cpp *.h)

add_executable(server-socket ${SOURCES}
  $<TARGET_OBJECTS:linenoise>
  $<TARGET_OBJECTS:utils>)

target_link_libraries(server-socket PUBLIC tulips_stack)
