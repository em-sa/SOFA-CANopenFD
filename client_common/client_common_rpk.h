/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    client_common_rpk.h
 * @brief   SOFA client_common, RPK signed secure-access driver.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 22-JUL-2026
 *
 * Tool-side of the CiA 720 RPK generic-access (C042h) and function-command
 * (C049h) verbs, over the transport vtable. Replacement model: an Ed25519
 * signature stands in for the AEAD tag, and a two-pass challenge gives the
 * freshness the signature covers. The client signs writes and commands with
 * its demo integrator keypair (whose public half the device holds as an
 * authorizing peer key) and verifies signed reads against the device IDevID.
 *
 * Compiled only when FBSEC_FEATURE_ASYM == 1.
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#ifndef CLIENT_COMMON_RPK_H
#define CLIENT_COMMON_RPK_H

#include "fbsec_config.h"

#if FBSEC_FEATURE_ASYM

#include <stdint.h>

#include "fbsec_secure_proto.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief C042h:01 signed read of @p target_index / @p target_sub.
 *
 * Sends a fresh client nonce, receives value + device signature, and
 * verifies the signature against the device IDevID public key.
 *
 * @param buf, buf_size  receive the plaintext value.
 * @param len_out        receives the value length (may be NULL).
 * @retval 0  read verified; value in @p buf.
 * @retval !=0 transport, length or signature failure.
 */
int fbsec_rpk_signed_read(const fbsec_secure_transport_t *transport,
                          uint16_t target, uint16_t target_index,
                          uint8_t target_sub, uint8_t *buf, uint32_t buf_size,
                          uint32_t *len_out, uint32_t timeout_ms);

/**
 * @brief C042h:02 signed write of @p value to @p target_index / @p target_sub.
 *
 * Two-pass: fetch a server challenge, then send value + client signature.
 *
 * @retval 0  write acknowledged.
 * @retval !=0 transport / signing failure or server abort.
 */
int fbsec_rpk_signed_write(const fbsec_secure_transport_t *transport,
                           uint16_t target, uint16_t target_index,
                           uint8_t target_sub, const uint8_t *value,
                           uint16_t value_len, uint32_t timeout_ms);

/**
 * @brief C049h signed function command @p code.
 *
 * Two-pass: fetch a server challenge, then send code + client signature.
 *
 * @retval 0  command acknowledged.
 * @retval !=0 transport / signing failure or server abort.
 */
int fbsec_rpk_command(const fbsec_secure_transport_t *transport,
                      uint16_t target, uint32_t code, uint32_t timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* FBSEC_FEATURE_ASYM */

#endif /* CLIENT_COMMON_RPK_H */
/* EOF */
