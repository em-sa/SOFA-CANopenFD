/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    server_common_trace.h
 * @brief   SOFA server_common, per-request trace formatter.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.1 of 20-JUL-2026
 *
 * Two-line action-block log: one row for the incoming request
 * (RX, blue), one for the outgoing response (TX, magenta), with
 * per-segment hues for the AEAD payload structure (header / random /
 * cipher / tag / plaintext annotation).
 *
 * Quiet/colour state is set once at startup via
 * @ref fbsec_server_trace_set_quiet / _set_use_color and read by
 * the formatter. The trace is variant-agnostic; the variant just
 * provides the (src_dev, dst_dev, data_id, verb, status, payloads)
 * tuple per dispatch.
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#ifndef SERVER_COMMON_TRACE_H
#define SERVER_COMMON_TRACE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "fbsec_abort.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Suppress / re-enable per-request log on stdout. */
void fbsec_server_trace_set_quiet(bool quiet);

/** Enable / disable ANSI colour escapes in the per-request log. */
void fbsec_server_trace_set_use_color(bool use_color);

/** Print one line of legend showing the segment hues
 *  (no-op when colour is disabled). */
void fbsec_server_trace_print_legend(void);

/**
 * @brief Emit the two-line action block for one dispatched request.
 *
 * Variant calls this from inside its `send_reply` callback (or right
 * after, before returning from dispatch).
 *
 * @param src_dev      request's src_device_id.
 * @param dst_dev      request's dst_device_id (responder).
 * @param data_id      request's data_id.
 * @param verb         "SRD1" / "SRD2" / "SWR1" / "SWR2" / "SRD?"
 *                     / "SWR?"; the dispatch glue figures these out
 *                     from the entry shape.
 * @param status       FBSEC_ABORT_NONE = success / DEFER ACK;
 *                     otherwise the CiA 1301 USDO abort code.
 * @param req_payload  request payload bytes (NULL when len == 0).
 * @param req_len      request payload length.
 * @param out_data     reply payload bytes (NULL on abort or empty ACK).
 * @param out_len      reply payload length.
 */
void fbsec_server_trace_request(uint16_t       src_dev,
                                uint16_t       dst_dev,
                                uint32_t       data_id,
                                const char    *verb,
                                fbsec_abort_t  status,
                                const uint8_t *req_payload,
                                uint16_t       req_len,
                                const uint8_t *out_data,
                                size_t         out_len);

#ifdef __cplusplus
}
#endif

#endif /* SERVER_COMMON_TRACE_H */
/* EOF */
