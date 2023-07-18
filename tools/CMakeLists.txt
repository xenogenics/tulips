include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(info)
add_subdirectory(linenoise)
add_subdirectory(socket)
add_subdirectory(utils)

if (LibFabric_FOUND OR LibIBVerbs_FOUND)
  add_subdirectory(uspace)
endif (LibFabric_FOUND OR LibIBVerbs_FOUND)
