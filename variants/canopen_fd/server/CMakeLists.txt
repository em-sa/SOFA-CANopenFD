## ---------------------------------------------------------------------------
## SOFA / CANopen FD variant / server
##
## fbsec_co_fd_server - thin USDO-responder main on top of fbsec_server_common
## and fbsec_canopen_fd. Carries CAN FD frames over TCP loopback to the bus
## simulator; recv loop decodes USDO requests, dispatch handles them, the
## send_reply callback wraps replies as USDO upload-response / download-confirm
## / abort frames.
## ---------------------------------------------------------------------------

add_executable(fbsec_co_fd_server
  fbsec_co_fd_server.c
)

target_link_libraries(fbsec_co_fd_server PRIVATE
  fbsec_server_common
  fbsec_canopen_fd
  fbsec_crypto
)

if(WIN32)
  target_link_libraries(fbsec_co_fd_server PRIVATE ws2_32 advapi32)
endif()

set_target_properties(fbsec_co_fd_server PROPERTIES
  C_STANDARD          99
  C_STANDARD_REQUIRED ON
  C_EXTENSIONS        OFF
)
