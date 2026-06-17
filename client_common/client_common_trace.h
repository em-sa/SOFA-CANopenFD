/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    client_common_trace.h
 * @brief   SOFA client_common, secure-frame trace formatter.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 07-MAY-2026
 *
 * Per-frame action-block log mirroring the server's per-request log:
 * row-leading direction tint (blue request, magenta response) covers
 * the [ts] TX|RX verb addr [data_id] columns; per-segment hues take
 * over after ANSI_RESET (header / random / cipher / tag / plaintext).
 *
 * The variant's transport-vtable callbacks call
 * @ref fbsec_client_trace_secure_frame once per wire frame in each
 * direction; the verb runners in `client_common_verbs.h` close the
 * deferred RX line via @ref fbsec_client_trace_close_with_plain or
 * @ref fbsec_client_trace_close_no_plain after the AEAD operation
 * resolves.
 *
 * Quiet / colour / timestamp / per-verb context state is set once at
 * startup and updated per-call by the verb runners.
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#ifndef CLIENT_COMMON_TRACE_H
#define CLIENT_COMMON_TRACE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- One-shot configuration (set once at startup) -------------------- */

void fbsec_client_trace_set_quiet(bool quiet);
void fbsec_client_trace_set_use_color(bool use_color);
void fbsec_client_trace_set_show_ts(bool show_ts);

bool fbsec_client_trace_get_quiet(void);
bool fbsec_client_trace_get_use_color(void);

/** Print one-line legend showing segment hues (no-op when colour off). */
void fbsec_client_trace_print_legend(void);

/* ---- Per-verb context (set by verb runners around fbsec_secure_*) --- */

/**
 * @brief Set the verb tag the trace formatter prints (and uses to
 *        choose segment slicing rules).
 *
 * Valid tags: "srd", "swr", "armrd", "pollrd", "armwr", "pollwr".
 * Empty string disables the verb column.
 */
void fbsec_client_trace_set_verb(const char *verb_tag);

/** Reset the round counter (g_secure_round) to 0. */
void fbsec_client_trace_reset_round(void);

/** Increment the round counter (called by the variant's transport callbacks). */
void fbsec_client_trace_inc_round(void);

/* ---- Public per-frame entry points ----------------------------------- */

/**
 * @brief Emit one log row per wire frame from the client's perspective.
 *
 * @param is_tx     true if the frame was just sent; false if just received.
 * @param src       source device id (host order).
 * @param dst       destination device id (host order).
 * @param data_id   application data_id.
 * @param payload   wire payload bytes (pre-envelope on TX, post-envelope on RX).
 *                  May be NULL when @p plen == 0.
 * @param plen      payload length in bytes.
 * @param status    on RX rows, the variant's envelope status (0 = OK,
 *                  non-zero = abort code; pretty-printed inline).
 *                  Ignored on TX rows.
 */
void fbsec_client_trace_secure_frame(bool          is_tx,
                                     uint16_t      src,
                                     uint16_t      dst,
                                     uint32_t      data_id,
                                     const uint8_t *payload,
                                     uint32_t      plen,
                                     uint32_t      status);

/**
 * @brief Close a deferred secure-RX trace line by appending the
 *        decrypted plaintext as " Plain: <ascii or hex>" + newline.
 *        No-op if no line is currently open.
 */
void fbsec_client_trace_close_with_plain(uint32_t data_id,
                                         const uint8_t *plain,
                                         uint16_t plen);

/** Close a deferred secure-RX trace line with just a newline. */
void fbsec_client_trace_close_no_plain(void);

/* ---- Hex segment printer (public for verb runners) ------------------ */

/** Append " <hex bytes>" wrapped in the given colour escape. */
void fbsec_client_trace_print_hex_seg(const char *col,
                                      const uint8_t *p, uint16_t n);

/* ---- Colour escape accessors (verb runners may need them) ----------- */

const char *fbsec_client_trace_col_req(void);
const char *fbsec_client_trace_col_rsp(void);
const char *fbsec_client_trace_col_end(void);
const char *fbsec_client_trace_col_hdr(void);
const char *fbsec_client_trace_col_rand(void);
const char *fbsec_client_trace_col_tag(void);
const char *fbsec_client_trace_col_plain(void);
const char *fbsec_client_trace_col_abort(void);

#ifdef __cplusplus
}
#endif

#endif /* CLIENT_COMMON_TRACE_H */
/* EOF */
