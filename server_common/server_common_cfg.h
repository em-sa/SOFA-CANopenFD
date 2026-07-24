/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    server_common_cfg.h
 * @brief   SOFA server_common, shared types (cfg, callbacks).
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.2 of 22-JUL-2026
 *
 * Header-only declarations of the configuration record populated by
 * the variant-agnostic CLI helpers (`server_common_cli.h`) and the
 * send-reply callback type the variant supplies to
 * @ref fbsec_server_dispatch_request.
 *
 * Variants extend their own per-flavor cfg around these fields; the
 * common layer only reads / writes the fields it owns.
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#ifndef SERVER_COMMON_CFG_H
#define SERVER_COMMON_CFG_H

#include <stdint.h>
#include <stdbool.h>

#include "fbsec_abort.h"

#ifdef __cplusplus
extern "C" {
#endif

/** ANSI colour preference. */
typedef enum {
  FBSEC_SERVER_COLOR_AUTO   = 0, /**< on iff stdout is a console */
  FBSEC_SERVER_COLOR_ALWAYS = 1,
  FBSEC_SERVER_COLOR_NEVER  = 2
} fbsec_server_color_pref_t;

/**
 * @brief Variant-agnostic server configuration.
 *
 * Fields are populated by the variant's argv loop, optionally
 * delegating each token to @ref fbsec_server_cli_try_common_flag
 * for the shared options. Variants add their own bus-specific
 * fields (host:port for TCP, node id mapping for CAN, ...)
 * alongside this in their own struct.
 */
typedef struct fbsec_server_cfg_t {
  uint16_t                  my_dev;        /**< responder device_id (0x0001..0xFFFE) */
  bool                      verbose;       /**< extra stderr informational lines    */
  bool                      quiet;         /**< suppress per-request log on stdout  */
  fbsec_server_color_pref_t color_pref;
  const char               *key_file_path; /**< NULL if --key-file not given        */
  const char               *od_file_path;  /**< NULL if --od-file not given         */
  bool                      demo_keys;     /**< --demo-keys: fill unset slots        */
} fbsec_server_cfg_t;

/**
 * @brief Send-reply callback the variant provides to
 *        @ref fbsec_server_dispatch_request.
 *
 * Called once per dispatch result. The variant wraps @p data in its
 * own wire envelope (USDO upload-response / abort frame on the
 * CANopen FD variant; future variants supply their own envelope) and
 * emits it to the requester.
 *
 * @param user      opaque pointer the variant passed to dispatch.
 * @param to_dev    request's src_device_id (becomes reply dst).
 * @param data_id   echoes the request's data_id.
 * @param status    FBSEC_ABORT_NONE = success / DEFER ACK; otherwise
 *                  the CiA 1301 USDO abort code (see fbsec_abort.h).
 * @param data      bytes to append after the variant's status header
 *                  (read result). NULL when @p data_len == 0.
 * @param data_len  length of @p data in bytes.
 *
 * @retval 0   reply emitted.
 * @retval !=0 transmit failure; logged by the variant.
 */
typedef int (*fbsec_send_reply_fn_t)(void          *user,
                                   uint16_t       to_dev,
                                   uint32_t       data_id,
                                   fbsec_abort_t  status,
                                   const uint8_t *data,
                                   uint16_t       data_len);

#ifdef __cplusplus
}
#endif

#endif /* SERVER_COMMON_CFG_H */
/* EOF */
