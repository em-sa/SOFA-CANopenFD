/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    server_common_handover.h
 * @brief   SOFA server_common, device-side handover object handler.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 19-JUL-2026
 *
 * Serves the manufacturer-to-integrator handover objects (spec 11.6.6,
 * FD spec section 3.3): identity read, ownership voucher, owner epoch,
 * Provisioning-Key install, and LDevID generate/export. Each is a single
 * stateless request/response; large replies (identity 168 B, LDevID 96 B)
 * are emitted directly through the variant send-reply callback.
 *
 * Compiled only when FBSEC_FEATURE_ASYM == 1. Authorized-only objects
 * (voucher, epoch) are present only when FBSEC_HANDOVER_AUTHORIZED == 1.
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#ifndef SERVER_COMMON_HANDOVER_H
#define SERVER_COMMON_HANDOVER_H

#include "fbsec_config.h"

#if FBSEC_FEATURE_ASYM

#include <stdint.h>
#include <stdbool.h>

#include "server_common_cfg.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Serve a handover object request if @p data_id names one.
 *
 * @param client_dev   requester device id.
 * @param data_id      target object.
 * @param req          request body (NULL when @p req_len == 0).
 * @param req_len      request length.
 * @param send_reply   variant reply callback.
 * @param user         opaque pointer for @p send_reply.
 * @retval true   @p data_id is a handover object and a reply was sent.
 * @retval false  not a handover object; let normal dispatch run.
 */
bool fbsec_server_handover_try(uint16_t client_dev, uint32_t data_id,
                               const uint8_t *req, uint16_t req_len,
                               fbsec_send_reply_fn_t send_reply, void *user);

/**
 * @brief Decommission the device: erase session keys and ownership and return
 *        to Uncommissioned, keeping the node online so it can be claimed again.
 *        Invoked by the C049h manufacturer-reset function command.
 */
void fbsec_server_handover_decommission(void);

#ifdef __cplusplus
}
#endif

#endif /* FBSEC_FEATURE_ASYM */

#endif /* SERVER_COMMON_HANDOVER_H */
/* EOF */
