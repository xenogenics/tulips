if (LibFabric_FOUND)
  add_subdirectory(fabric)
endif (LibFabric_FOUND)

if (LibIBVerbs_FOUND)
  add_subdirectory(ofed)
endif (LibIBVerbs_FOUND)
