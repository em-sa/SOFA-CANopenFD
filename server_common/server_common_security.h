/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    server_common_security.h
 * @brief   SOFA server_common, CiA 720 AEAD security objects handler.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 22-JUL-2026
 *
 * Dedicated dispatch handler for the CiA 720 AEAD-block security objects
 * that do not fit the generic fbsec_sod registry (pass 1):
 *
 *   - C010h Session pre-requisites (session salt). Present but the
 *     salt-driven session arming is not implemented this pass: sub 00h
 *     and the all-zero salt read are served for discovery, a salt write
 *     returns C9h NOT_IMPLEMENTED.
 *   - C011h AEAD key identifiers. Fully implemented, read-only and
 *     unsecured: sub 00h is the slot count, subs 01h.. are the per-slot
 *     non-secret U32 key ids from the key store.
 *
 * C01Fh Key set is NO LONGER served here: it is a real SECURE_WO entry in
 * the fbsec_sod registry (see server_common_od.c) so it reuses the AEAD
 * challenge / verify path. The rolling-key install ladder it drives is
 * applied by fbsec_server_apply_key_set (server_common_keys.c).
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#ifndef SERVER_COMMON_SECURITY_H
#define SERVER_COMMON_SECURITY_H

#include <stdint.h>
#include <stdbool.h>

#include "server_common_cfg.h"

#ifdef __cplusplus
extern "C" {
#endif

/* OD indices owned by this handler. */
#define FBSEC_SEC_INDEX_SESSION_SALT  0xC010u
#define FBSEC_SEC_INDEX_KEY_IDS       0xC011u
#define FBSEC_SEC_INDEX_KEY_SET       0xC01Fu

/* C01Fh key-set object data id ((index << 16) | sub 00h). Served by the
   fbsec_sod registry as a SECURE_WO entry, not by this handler. */
#define FBSEC_SEC_KEY_SET_DATA_ID     ((uint32_t)FBSEC_SEC_INDEX_KEY_SET << 16)

/**
 * @brief Try to serve a request targeting a C010h/C011h object.
 *
 * @param src_dev      requester's device id.
 * @param data_id      requested data id ((index << 16) | (sub << 8)).
 * @param payload      request payload (NULL iff @p payload_len is 0).
 * @param payload_len  request payload length (0 = read, >0 = write).
 * @param send_reply   variant reply callback.
 * @param user         opaque pointer forwarded to @p send_reply.
 * @return true if @p data_id targets one of these objects and a reply
 *         was sent; false to let the normal secure dispatch run.
 */
bool fbsec_server_security_try(uint16_t src_dev, uint32_t data_id,
                               const uint8_t *payload, uint16_t payload_len,
                               fbsec_send_reply_fn_t send_reply, void *user);

#ifdef __cplusplus
}
#endif

#endif /* SERVER_COMMON_SECURITY_H */
/* EOF */
