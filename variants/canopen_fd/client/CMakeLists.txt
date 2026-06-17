## ---------------------------------------------------------------------------
## SOFA / CANopen FD variant / client
##
## fbsec_co_fd_client - thin USDO-initiator main on top of fbsec_client_common
## and fbsec_canopen_fd. Carries CAN FD frames over TCP loopback to the bus
## simulator; transport vtable callbacks build USDO requests and decode USDO
## responses for the secure-tunnel core.
## ---------------------------------------------------------------------------

add_executable(fbsec_co_fd_client
  fbsec_co_fd_client.c
)

target_link_libraries(fbsec_co_fd_client PRIVATE
  fbsec_client_common
  fbsec_canopen_fd
  fbsec_crypto
)

if(WIN32)
  target_link_libraries(fbsec_co_fd_client PRIVATE ws2_32 advapi32)
endif()

set_target_properties(fbsec_co_fd_client PROPERTIES
  C_STANDARD          99
  C_STANDARD_REQUIRED ON
  C_EXTENSIONS        OFF
)
