set(CMAKE_POSITION_INDEPENDENT_CODE 1)

if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
endif ()

file(GLOB SOURCES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.cpp *.h)

add_executable(info ${SOURCES})
target_link_libraries(info PUBLIC tulips_stack)
