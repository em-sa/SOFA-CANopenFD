## ---------------------------------------------------------------------------
## SOFA / server_common
##
## Variant-agnostic server logic shared by every fieldbus flavor's server
## binary. Owns the secure-OD setup, port hooks (RNG / time / access /
## read_before / write_after), key store + key-file loader, dispatch glue,
## per-request trace formatter, and shared CLI helpers.
##
## Variants link this lib and supply only the wire-format-specific code:
## connect / recv-frame / send_reply / announce.
##
## License: Apache License 2.0.
## ---------------------------------------------------------------------------

set(FBSEC_SERVER_COMMON_SRC
  server_common_cfg.h
  server_common_platform.c
  server_common_platform.h
  server_common_keys.c
  server_common_keys.h
  server_common_hooks.c
  server_common_hooks.h
  server_common_od.c
  server_common_od.h
  server_common_const_od.c
  server_common_const_od.h
  server_common_security.c
  server_common_security.h
  server_common_trace.c
  server_common_trace.h
  server_common_dispatch.c
  server_common_dispatch.h
  server_common_cli.c
  server_common_cli.h
)

# Optional asymmetric identity store + handover (device side).
if(FBSEC_FEATURE_ASYM)
  list(APPEND FBSEC_SERVER_COMMON_SRC
    server_common_asym.c
    server_common_asym.h
    server_common_handover.c
    server_common_handover.h
  )
endif()

add_library(fbsec_server_common STATIC ${FBSEC_SERVER_COMMON_SRC})

target_include_directories(fbsec_server_common PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}"
)

target_link_libraries(fbsec_server_common PUBLIC
  fbsec_crypto
)

if(WIN32)
  # advapi32 for CryptGenRandom in the random port hook.
  target_link_libraries(fbsec_server_common PUBLIC advapi32)
endif()

set_target_properties(fbsec_server_common PROPERTIES
  C_STANDARD          99
  C_STANDARD_REQUIRED ON
  C_EXTENSIONS        OFF
)
