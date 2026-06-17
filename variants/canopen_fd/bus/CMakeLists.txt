## ---------------------------------------------------------------------------
## SOFA / CANopen FD variant / bus
##
## fbsec_co_fd_bus - CAN FD bus simulator on top of bus_common. Carries
## CAN FD frames over TCP loopback to connected peers (server + client),
## broadcasting every received frame to every other peer (dumb relay).
## ---------------------------------------------------------------------------

add_executable(fbsec_co_fd_bus
  fbsec_co_fd_bus.c
  fbsec_co_fd_pcan.c
)

target_link_libraries(fbsec_co_fd_bus PRIVATE
  fbsec_bus_common
  fbsec_canopen_fd
)

if(WIN32)
  target_link_libraries(fbsec_co_fd_bus PRIVATE ws2_32)
endif()

set_target_properties(fbsec_co_fd_bus PROPERTIES
  C_STANDARD          99
  C_STANDARD_REQUIRED ON
  C_EXTENSIONS        OFF
)
