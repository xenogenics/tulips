if (LibDPDK_FOUND)
  add_subdirectory(ena)
endif (LibDPDK_FOUND)

if (LibIBVerbs_FOUND)
  add_subdirectory(ofed)
endif (LibIBVerbs_FOUND)
