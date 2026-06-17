/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    server_common_dispatch.h
 * @brief   SOFA server_common, dispatch glue (variant-agnostic).
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 07-MAY-2026
 *
 * Wraps `fbsec_sod_dispatch` with verb detection and trace emission.
 * The variant calls @ref fbsec_server_dispatch_request once per
 * received request frame; the dispatch glue invokes the variant's
 * `send_reply` callback exactly once per request (for OK / DEFER /
 * ABORT) and emits the per-request trace line via
 * `server_common_trace`.
 *
 * Unknown data_id (not in the secure registry): the demonstrator no
 * longer accepts plain rd / wr; everything must go through the
 * secure tunnel. An unknown data_id triggers a 0x06020000 (ABORT_NO_ENTRY)
 * abort.
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#ifndef SERVER_COMMON_DISPATCH_H
#define SERVER_COMMON_DISPATCH_H

#include <stdint.h>

#include "server_common_cfg.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Dispatch one request frame to the secure-OD layer and emit
 *        the matching reply via @p send_reply.
 *
 * Stack-allocates the dispatch's reply scratch
 * (FBSEC_SERVER_DISPATCH_REPLY_MAX bytes; sized for the worst-case
 * secure reply: server_random + ciphertext + tag with N at
 * FBSEC_AEAD_MAX_PROTECTED). Caller-side reply buffering is none.
 *
 * @param src_dev      request's src_device_id (also used as
 *                     send_reply's @p to_dev).
 * @param data_id      request's data_id.
 * @param payload      request payload bytes (NULL when len == 0).
 * @param payload_len  request payload length in bytes.
 * @param send_reply   variant callback that wraps the reply in its
 *                     wire envelope. Must not be NULL.
 * @param user         opaque pointer forwarded to @p send_reply.
 */
void fbsec_server_dispatch_request(uint16_t            src_dev,
                                   uint32_t            data_id,
                                   const uint8_t      *payload,
                                   uint16_t            payload_len,
                                   fbsec_send_reply_fn_t send_reply,
                                   void               *user);

#ifdef __cplusplus
}
#endif

#endif /* SERVER_COMMON_DISPATCH_H */
/* EOF */
