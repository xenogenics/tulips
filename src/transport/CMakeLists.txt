add_subdirectory(check)
add_subdirectory(erase)
add_subdirectory(list)
add_subdirectory(npipe)
add_subdirectory(pcap)
add_subdirectory(shm)
add_subdirectory(stubs)

if (LibDPDK_FOUND)
  add_subdirectory(ena)
endif (LibDPDK_FOUND)

if (LibIBVerbs_FOUND)
  add_subdirectory(ofed)
endif (LibIBVerbs_FOUND)

if (${CMAKE_SYSTEM_NAME} MATCHES "OpenBSD")
  add_subdirectory(tap)
endif (${CMAKE_SYSTEM_NAME} MATCHES "OpenBSD")
