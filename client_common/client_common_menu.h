/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    client_common_menu.h
 * @brief   SOFA client_common, interactive menu mode (--menu).
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 07-MAY-2026
 *
 * REPL that prompts for a target device id, then offers a security-
 * parameter scan plus the AEAD and RPK demo actions:
 *
 *   0) unsecured scan of the constant security parameters
 *      (C000h capabilities, C001h status, C011h key ids, in an RPK build
 *      also C021h/C022h public keys, and 1018h identity)
 *   1) SRD 0xC018:00  - single 16-byte read (1018h authenticated identity)
 *   2) SWR 0x2016:00  - single 16-byte write (incrementing counter)
 *   3) SRD 0x2020:00  - single 4-byte read of the shadow value
 *   4) SWR 0x2010:00  - single 4-byte write (auto-increments)
 *   5) SRD 0x2020:00  - 300 cyclic reads, 200 ms apart
 *   6) SWR 0x2010:00  - 300 cyclic writes, 200 ms apart
 *
 * The RPK (Ed25519 signed) set is present only in an FBSEC_FEATURE_ASYM
 * build:
 *
 *   A) C028h          - signed identity read (device IDevID)
 *   B) C042h -> 0x2021 - signed generic read (signature replaces the tag)
 *   C) C042h -> 0x2017 - signed generic write (client signs)
 *   D) C049h          - signed function command
 *   Q)                - quit
 *
 * The AEAD options are secure verbs; the RPK options carry an Ed25519
 * signature in place of the AEAD tag. Demo key + encryption flag come from
 * `client_common_keys` (prompted at menu startup if not pre-set via
 * --key / --main-key).
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#ifndef CLIENT_COMMON_MENU_H
#define CLIENT_COMMON_MENU_H

#include <stdint.h>

#include "fbsec_secure_proto.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Variant-supplied setter to update the client's own node id from
 *        an interactive menu prompt. The variant is responsible for
 *        propagating the new value to its own globals (e.g. the trace's
 *        my_dev mirror plus any USDO src_node_id storage).
 *
 * Optional. NULL means "no interactive node-id prompt" (legacy: my_dev
 * stays at the value the variant supplied).
 */
typedef void (*fbsec_client_menu_set_node_id_fn)(uint8_t new_node_id);

/** Per-call menu configuration. */
typedef struct fbsec_client_menu_cfg_t {
  uint16_t    my_dev;       /**< client's own dev id (for collision check) */
  uint32_t    timeout_ms;   /**< per-secure-op timeout */
  const char *bus_label;    /**< printed in menu header (e.g. "127.0.0.1:5800") */
  fbsec_client_menu_set_node_id_fn set_node_id;  /**< nullable */
} fbsec_client_menu_cfg_t;

/**
 * @brief Run the interactive REPL until the user picks Q or stdin
 *        reaches EOF.
 *
 * @retval 0  graceful quit (always).
 */
int fbsec_client_run_menu(const fbsec_secure_transport_t *transport,
                          const fbsec_client_menu_cfg_t  *cfg);

#ifdef __cplusplus
}
#endif

#endif /* CLIENT_COMMON_MENU_H */
/* EOF */
