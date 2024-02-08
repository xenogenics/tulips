set(CMAKE_POSITION_INDEPENDENT_CODE 1)

include_directories(${TCLAP_INCLUDE_DIRS})

if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
endif ()

if (LibDPDK_FOUND)
  include_directories(${LibDPDK_INCLUDE_DIRS})
  add_executable(lat_ena lat_ena.cpp)
  target_link_libraries(lat_ena
    PRIVATE
    tulips_apps_static
    tulips_stack_static
    tulips_transport_ena_static
    tulips_transport_stubs_static)
endif (LibDPDK_FOUND)

if (LibIBVerbs_FOUND)
  add_executable(lat_ofed lat_ofed.cpp)
  target_link_libraries(lat_ofed
    PRIVATE
    tulips_apps_static
    tulips_stack_static
    tulips_transport_ofed_static
    tulips_transport_stubs_static
    PUBLIC
    ${LibIBVerbs_LINK_LIBRARIES})
endif (LibIBVerbs_FOUND)

if (LibIBVerbs_FOUND AND TULIPS_ENABLE_RAW)
  add_executable(raw_ofed raw_ofed.cpp)
  target_link_libraries(raw_ofed
    PRIVATE
    tulips_api_static
    tulips_stack_static
    tulips_system_static
    tulips_transport_ofed_static
    tulips_transport_pcap_static
    tulips_transport_stubs_static
    PUBLIC
    ${LibIBVerbs_LINK_LIBRARIES}
    ${LibPCAP_LINK_LIBRARIES})
endif (LibIBVerbs_FOUND AND TULIPS_ENABLE_RAW)

if (NOT TULIPS_HAS_HW_CHECKSUM OR TULIPS_DISABLE_CHECKSUM_CHECK)
  if (TULIPS_ENABLE_ARP)
    add_executable(lat_pipe lat_pipe.cpp)
    target_link_libraries(lat_pipe
      PRIVATE
      tulips_apps_static
      tulips_transport_npipe)
  endif (TULIPS_ENABLE_ARP)
endif (NOT TULIPS_HAS_HW_CHECKSUM OR TULIPS_DISABLE_CHECKSUM_CHECK)
