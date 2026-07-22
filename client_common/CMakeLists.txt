## ---------------------------------------------------------------------------
## SOFA / client_common
##
## Variant-agnostic client logic shared by every fieldbus flavor's client
## binary. Owns CLI helpers, secure verb runners (run_secure_read/write/poll),
## menu mode, secure-frame trace formatter, key store + RNG + KDF, and
## platform helpers (endian, timestamp).
##
## Variants link this lib and supply only the wire-format-specific code:
## the transport vtable callbacks (transport_read/write), connect / announce,
## and any plain rd/wr verbs they choose to support.
##
## License: Apache License 2.0.
## ---------------------------------------------------------------------------

set(FBSEC_CLIENT_COMMON_SRC
  client_common_cfg.h
  client_common_platform.c
  client_common_platform.h
  client_common_keys.c
  client_common_keys.h
  client_common_trace.c
  client_common_trace.h
  client_common_verbs.c
  client_common_verbs.h
  client_common_caps.c
  client_common_caps.h
  client_common_menu.c
  client_common_menu.h
  client_common_cli.c
  client_common_cli.h
)

# Optional asymmetric identity hooks + commissioning (client side).
if(FBSEC_FEATURE_ASYM)
  list(APPEND FBSEC_CLIENT_COMMON_SRC
    client_common_asym.c
    client_common_asym.h
    client_common_commission.c
    client_common_commission.h
    client_common_rpk.c
    client_common_rpk.h
  )
endif()

add_library(fbsec_client_common STATIC ${FBSEC_CLIENT_COMMON_SRC})

target_include_directories(fbsec_client_common PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}"
)

target_link_libraries(fbsec_client_common PUBLIC
  fbsec_crypto
)

if(WIN32)
  # advapi32 for CryptGenRandom in fbsec_secure_port_random.
  target_link_libraries(fbsec_client_common PUBLIC advapi32)
endif()

set_target_properties(fbsec_client_common PROPERTIES
  C_STANDARD          99
  C_STANDARD_REQUIRED ON
  C_EXTENSIONS        OFF
)
