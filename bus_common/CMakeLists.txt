## ---------------------------------------------------------------------------
## SOFA / bus_common
##
## Variant-agnostic bus simulator skeleton: accept loop, peer table,
## select() event loop, CSV trace primitives, ANSI color resolver,
## Ctrl-C lifecycle. Variants supply only per-frame parse / route /
## trace logic via three callbacks.
##
## License: Apache License 2.0.
## ---------------------------------------------------------------------------

add_library(fbsec_bus_common STATIC
  bus_common.c
  bus_common.h
)

target_include_directories(fbsec_bus_common PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}"
)

if(WIN32)
  target_link_libraries(fbsec_bus_common PUBLIC ws2_32)
endif()

set_target_properties(fbsec_bus_common PROPERTIES
  C_STANDARD          99
  C_STANDARD_REQUIRED ON
  C_EXTENSIONS        OFF
)
