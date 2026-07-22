/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    server_common_rpk.h
 * @brief   SOFA server_common, CiA 720 RPK secure-object handler.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 22-JUL-2026
 *
 * Serves the raw-public-key (Ed25519) security objects that sit beside
 * the handover verbs (which live in server_common_handover.{c,h}):
 *
 *   - C021h Public keys. Unauthenticated reads: sub 00h highest sub,
 *     sub 01h manufacturer anchor public key, sub 02h integrator public
 *     key (all-zero until an ownership voucher installs it).
 *   - C022h Public key types. Unauthenticated: one U32 per key, algorithm
 *     id in byte 0 (01h Ed25519) and key length in byte 1 (20h).
 *   - C042h Generic secure access (RPK). Signed read (sub 01h) and signed
 *     write (sub 02h) under the replacement model: an Ed25519 signature
 *     stands in for the AEAD tag. Freshness is a two-pass challenge; the
 *     signed transcript covers the server-contributed nonce.
 *   - C049h Secure function command (RPK). A signed U32 command; this pass
 *     verifies the signature, logs the code and acknowledges.
 *
 * Compiled only when FBSEC_FEATURE_ASYM == 1.
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#ifndef SERVER_COMMON_RPK_H
#define SERVER_COMMON_RPK_H

#include "fbsec_config.h"

#if FBSEC_FEATURE_ASYM

#include <stdint.h>
#include <stdbool.h>

#include "server_common_cfg.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Serve a request targeting a C021h/C022h/C042h/C049h object.
 *
 * @param src_dev      requester's device id.
 * @param data_id      requested data id ((index << 16) | (sub << 8)).
 * @param payload      request payload (NULL iff @p payload_len is 0).
 * @param payload_len  request payload length.
 * @param send_reply   variant reply callback.
 * @param user         opaque pointer forwarded to @p send_reply.
 * @return true if @p data_id targets one of these objects and a reply was
 *         sent; false to let later dispatch tiers run.
 */
bool fbsec_server_rpk_try(uint16_t src_dev, uint32_t data_id,
                          const uint8_t *payload, uint16_t payload_len,
                          fbsec_send_reply_fn_t send_reply, void *user);

#ifdef __cplusplus
}
#endif

#endif /* FBSEC_FEATURE_ASYM */

#endif /* SERVER_COMMON_RPK_H */
/* EOF */
