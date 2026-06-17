## ---------------------------------------------------------------------------
## SOFA - CANopen FD variant
##
## Builds the variant-common static library (fbsec_canopen_fd) over the four
## modules in `common/`. Bus simulator, client, and server executables are
## added as subdirectories once their main()s exist; until then this CMakeLists
## just produces the library so the modules compile cleanly under /W4 /WX.
##
## See doc/fieldbus_sim_canopen_fd_spec.txt for the wire contract.
##
## License: Apache License 2.0.
## ---------------------------------------------------------------------------

add_library(fbsec_canopen_fd STATIC
  common/fbsec_co_fd_addr.c
  common/fbsec_co_fd_addr.h
  common/fbsec_co_fd_frame.c
  common/fbsec_co_fd_frame.h
  common/fbsec_co_fd_usdo.c
  common/fbsec_co_fd_usdo.h
  common/fbsec_co_fd_carrier.c
  common/fbsec_co_fd_carrier.h
)

## AAD peer-id width advisory: this variant aligns literally with WP-105's
## "client node ID, server node ID" wording when built with
## FBSEC_AEAD_DEV_ID_SIZE=1 (1-byte node ids in the AAD prefix; prefix
## length 12 - the current default in the top-level CMakeLists.txt). A
## value of 2 also works (high byte of the node_id padded to zero) and
## widens the AAD prefix to 14 bytes; that path exists for the future
## 2-byte device_id variants. See top-level CMakeLists.txt.
if(NOT FBSEC_AEAD_DEV_ID_SIZE STREQUAL "1")
  message(STATUS
          "CANopen FD variant: FBSEC_AEAD_DEV_ID_SIZE=${FBSEC_AEAD_DEV_ID_SIZE} "
          "(reconfigure with -DFBSEC_AEAD_DEV_ID_SIZE=1 for the 1-byte "
          "literal node-id AAD layout described in WP-105).")
endif()

target_include_directories(fbsec_canopen_fd PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/common"
)

# Carrier needs winsock; expose it to anyone linking the variant lib.
target_link_libraries(fbsec_canopen_fd PUBLIC
  fbsec_crypto
  ws2_32
)

set_target_properties(fbsec_canopen_fd PROPERTIES
  C_STANDARD          99
  C_STANDARD_REQUIRED ON
  C_EXTENSIONS        OFF
)

## Subdirectories for bus / client / server executables. Each is gated on
## the main()'s presence; uncomment as they land.

add_subdirectory(server)
add_subdirectory(client)
add_subdirectory(bus)
