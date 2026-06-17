## ---------------------------------------------------------------------------
## SOFA - Secure Object Fieldbus Access
##
## Top-level CMake build for the userspace fieldbus simulation suite.
##
## Per-fieldbus variants live under variants/<name>/ and share the
## fbsec_crypto + client_common + server_common + bus_common static
## libraries. Each variant brings its own bus simulator + client +
## server and is gated on its own CMake option so a downstream user
## can build only the fieldbus they need. Today only the CANopen FD
## variant is shipped; future CANopen CC and EtherCAT variants will
## plug in the same way. See doc/fieldbus_sim_canopen_fd_spec.txt
## for the CANopen FD wire contract.
##
## Build (Visual Studio 2026 generator example):
##   cmake -S . -B build -G "Visual Studio 18 2026" -A x64
##   cmake --build build --config Release
##
## Coding standard: EmSA-C:2025.
## License: Apache License 2.0.
## ---------------------------------------------------------------------------

cmake_minimum_required(VERSION 3.20)

project(SOFA
        VERSION       1.0.0
        DESCRIPTION   "Secure Object Fieldbus Access - userspace fieldbus simulation"
        LANGUAGES     C)

set(CMAKE_C_STANDARD          99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS        OFF)

## ---------------------------------------------------------------------------
## Statically link the MSVC C runtime so the produced .exes carry no
## VCRUNTIME140 / MSVCP140 dependency and can be copied to a clean
## Windows 10+ machine without the VC++ Redistributable installed.
## Must be set before any target is declared.
## ---------------------------------------------------------------------------
if(MSVC)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

if(MSVC)
  add_compile_options(/W4 /WX /permissive-)
  add_compile_definitions(_CRT_SECURE_NO_WARNINGS WIN32_LEAN_AND_MEAN)
endif()

## ---------------------------------------------------------------------------
## Compile-time feature subset (default: all features on)
##
## Override on the command line, e.g. for a write-only single-shot server:
##   cmake -S . -B build -DFBSEC_FEATURE_READ=0 -DFBSEC_FEATURE_WRITE=1 \
##                       -DFBSEC_FEATURE_CYCLIC=0
##
## At least one of READ/WRITE must be 1 (enforced in fbsec_config.h).
## ---------------------------------------------------------------------------

set(FBSEC_FEATURE_READ   1 CACHE STRING "Include read path  (0/1)")
set(FBSEC_FEATURE_WRITE  1 CACHE STRING "Include write path (0/1)")
set(FBSEC_FEATURE_CYCLIC 1 CACHE STRING "Include cyclic mode (0/1)")

# AAD peer-identifier width (server_device_id, client_device_id) in
# bytes. 1 = CANopen FD uint8 node_id (1..127), the literal AAD layout
# that mirrors EmSA-WP-105's "client node ID, server node ID" wording;
# this is the current default since CANopen FD is the only variant
# shipped today. 2 = uint16 device_id, reserved for the future generic
# simhub / CANopen CC / EtherCAT variants. The choice is project-wide
# because fbsec_crypto (which holds fbsec_aead.c) is built once and
# linked by every executable; peers compiled with mismatched values
# fail-closed at AEAD verify on the first secure verb. See
# doc/fieldbus_sim_secure_tunnel_spec.txt section 4.1.
set(FBSEC_AEAD_DEV_ID_SIZE 1 CACHE STRING
    "AAD peer-id width in bytes: 1 (CANopen FD node_id) or 2 (uint16 device_id, future variants)")

if(NOT FBSEC_AEAD_DEV_ID_SIZE STREQUAL "1" AND NOT FBSEC_AEAD_DEV_ID_SIZE STREQUAL "2")
  message(FATAL_ERROR
          "FBSEC_AEAD_DEV_ID_SIZE must be 1 or 2; got '${FBSEC_AEAD_DEV_ID_SIZE}'.")
endif()

add_compile_definitions(
  FBSEC_FEATURE_READ=${FBSEC_FEATURE_READ}
  FBSEC_FEATURE_WRITE=${FBSEC_FEATURE_WRITE}
  FBSEC_FEATURE_CYCLIC=${FBSEC_FEATURE_CYCLIC}
  FBSEC_AEAD_DEV_ID_SIZE=${FBSEC_AEAD_DEV_ID_SIZE}
)

## ---------------------------------------------------------------------------
## fbsec_crypto: mbedtls subset + AEAD wrappers + HKDF, shared by client
## and server. mbedtls is vendored locally under third_party/mbedtls so
## SOFA builds standalone with no sibling-project dependency. Subset
## shipped: AES, GCM, SHA-256, plus glue (same set used by
## MCOPSecureAccess).
## ---------------------------------------------------------------------------

set(MBEDTLS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/mbedtls")
if(NOT EXISTS "${MBEDTLS_DIR}/library/aes.c")
  message(FATAL_ERROR
          "mbedtls source not found at ${MBEDTLS_DIR}. The vendored "
          "subset should ship inside the project tree; re-extract the "
          "SOFA archive if third_party/mbedtls/ is missing.")
endif()

set(MBEDTLS_SRC
  "${MBEDTLS_DIR}/library/aes.c"
  "${MBEDTLS_DIR}/library/aesni.c"
  "${MBEDTLS_DIR}/library/block_cipher.c"
  "${MBEDTLS_DIR}/library/constant_time.c"
  "${MBEDTLS_DIR}/library/gcm.c"
  "${MBEDTLS_DIR}/library/platform_util.c"
  "${MBEDTLS_DIR}/library/sha256.c"
)

add_library(fbsec_crypto STATIC
  shared/fbsec_aead.c
  shared/fbsec_aead.h
  shared/fbsec_hkdf.c
  shared/fbsec_hkdf.h
  shared/fbsec_secure_proto.c
  shared/fbsec_secure_proto.h
  shared/fbsec_secure_od.c
  shared/fbsec_secure_od.h
  shared/mbedtls_fbsec_config.h
  ${MBEDTLS_SRC}
)

# mbedtls source files compile cleanly at /W3 but not at /W4 /WX, so
# relax warnings only for those translation units.
set_source_files_properties(${MBEDTLS_SRC} PROPERTIES
  COMPILE_OPTIONS "/W3;/wd4244;/wd4267;/wd4204;/wd4334"
)

target_include_directories(fbsec_crypto PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/shared"
  "${MBEDTLS_DIR}/include"
  "${MBEDTLS_DIR}/library"
)

target_compile_definitions(fbsec_crypto PUBLIC
  MBEDTLS_CONFIG_FILE="mbedtls_fbsec_config.h"
)

set_target_properties(fbsec_crypto PROPERTIES
  C_STANDARD          99
  C_STANDARD_REQUIRED ON
  C_EXTENSIONS        OFF
)

## ---------------------------------------------------------------------------
## Variant-agnostic libs sit between fbsec_crypto and the per-variant binaries.
## They contain the common server / client / bus logic so each new fieldbus
## flavor only needs to ship a thin main + per-bus codec.
## ---------------------------------------------------------------------------

add_subdirectory(server_common)
add_subdirectory(client_common)
add_subdirectory(bus_common)

## ---------------------------------------------------------------------------
## Per-fieldbus variants
##
## Each variant brings its own bus simulator + client + server, sharing the
## fbsec_crypto + server_common (+ later client_common, bus_common) static
## libraries above. Variants are gated on individual CMake options so a
## downstream user can build only what they need.
## ---------------------------------------------------------------------------

option(FBSEC_VARIANT_CANOPEN_FD "Build the CANopen FD variant (USDO expedited)" ON)

## ---------------------------------------------------------------------------
## Subdirectories
## ---------------------------------------------------------------------------

if(FBSEC_VARIANT_CANOPEN_FD)
  add_subdirectory(variants/canopen_fd)
endif()
