/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    client_common_verbs.h
 * @brief   SOFA client_common, secure verb runners.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 07-MAY-2026
 *
 * Variant-agnostic implementations of the four secure verbs (single-shot
 * srd / swr and cyclic-mode srdpoll / swrpoll). Each takes a transport
 * vtable (the variant supplies it) plus the call-site addressing and
 * payload; the verb handles per-call trace state, dispatches to
 * `fbsec_secure_*`, and emits the summary line via `client_common_trace`.
 *
 * Return codes match the existing `fbsec_client` conventions:
 *   0 = success
 *   1 = local error (TX / timeout / protocol)
 *   2 = server abort (abort code in dispatch's *abort_out)
 *   3 = AEAD tag verify failed
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#ifndef CLIENT_COMMON_VERBS_H
#define CLIENT_COMMON_VERBS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "fbsec_secure_proto.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Single-shot --------------------------------------------------- */

int fbsec_client_run_secure_read(const fbsec_secure_transport_t *transport,
                                 uint16_t target,
                                 uint32_t data_id,
                                 uint32_t timeout_ms,
                                 uint8_t *out_buf, uint32_t out_buf_size,
                                 uint32_t *out_len);

int fbsec_client_run_secure_write(const fbsec_secure_transport_t *transport,
                                  uint16_t target,
                                  uint32_t data_id,
                                  const uint8_t *payload, uint16_t plen,
                                  uint32_t timeout_ms);

/* ---- Cyclic-mode --------------------------------------------------- */

int fbsec_client_run_secure_read_poll(const fbsec_secure_transport_t *transport,
                                      uint16_t target,
                                      uint32_t data_id,
                                      uint32_t count,
                                      uint32_t timeout_ms);

int fbsec_client_run_secure_write_poll(const fbsec_secure_transport_t *transport,
                                       uint16_t target,
                                       uint32_t data_id,
                                       const uint8_t *payload, uint16_t plen,
                                       uint32_t count,
                                       uint32_t timeout_ms);

/* ---- Status -> human-readable ------------------------------------- */

const char *fbsec_client_secp_strerror(fbsec_secure_status_t rc);

#ifdef __cplusplus
}
#endif

#endif /* CLIENT_COMMON_VERBS_H */
/* EOF */
