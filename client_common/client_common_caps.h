/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    client_common_caps.h
 * @brief   SOFA client_common, capability/status descriptor reader.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.1 of 22-JUL-2026
 *
 * Reads a device's C000h capability descriptor over the ordinary,
 * unauthenticated transport read path - no key or identity required - and
 * decodes it into fbsec_caps_t. The caller then fails closed on features
 * the peer does not advertise (fbsec_caps_supports_*). CiA 720 C000h.
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#ifndef CLIENT_COMMON_CAPS_H
#define CLIENT_COMMON_CAPS_H

#include <stdint.h>
#include <stdbool.h>

#include "fbsec_secure_proto.h"
#include "fbsec_descriptor.h"
#include "client_common_cfg.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Read a device's C000h capability descriptor.
 *
 * Reads sub-index 0 (highest sub-index) first, then every sub-index up to
 * it, decoding each into @p out.
 *
 * @param transport  connected transport vtable.
 * @param target     target device_id.
 * @param timeout_ms per-read timeout.
 * @param out        decoded capability descriptor (C000h).
 * @retval 0  success.
 * @retval 1  local / transport error or malformed descriptor.
 * @retval 2  server abort (object missing, etc.).
 */
int fbsec_client_read_caps(const fbsec_secure_transport_t *transport,
                           uint16_t target, uint32_t timeout_ms,
                           fbsec_caps_t *out);

/**
 * @brief Does a descriptor meet the client's minimum security floor?
 *
 * @param caps   decoded C000h descriptor.
 * @param floor  the client's local minimum (ANY / AEAD / SIGNED).
 * @retval true  floor is ANY, or the device advertises the required mechanism.
 * @retval false the device advertises less than the floor (or @p caps is NULL).
 */
bool fbsec_client_caps_meets_min(const fbsec_caps_t *caps,
                                 fbsec_client_min_sec_t floor);

/**
 * @brief Enforce the client's minimum security floor before any secure work.
 *
 * Reads the C000h descriptor and compares it against @p floor. The descriptor
 * is an optimization only: it may satisfy or fail the floor, but a client that
 * requires a mechanism the device does not advertise refuses rather than
 * falling back to a weaker one. A descriptor that cannot be read is treated as
 * failing closed.
 *
 * @retval 0  floor is ANY, or the device meets it.
 * @retval 1  floor not met (a refusal is printed to stderr); do not proceed.
 */
int fbsec_client_enforce_min_security(const fbsec_secure_transport_t *transport,
                                      uint16_t target, uint32_t timeout_ms,
                                      fbsec_client_min_sec_t floor, bool quiet);

#ifdef __cplusplus
}
#endif

#endif /* CLIENT_COMMON_CAPS_H */
/* EOF */
