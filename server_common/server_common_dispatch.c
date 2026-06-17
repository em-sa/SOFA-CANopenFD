/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    server_common_dispatch.c
 * @brief   SOFA server_common, dispatch glue, implementation.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 07-MAY-2026
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#include "server_common_dispatch.h"
#include "server_common_trace.h"
#include "server_common_hooks.h"

#include "fbsec_aead.h"
#include "fbsec_secure_od.h"

/* Worst-case secure reply: server_random[R] + cipher[N_MAX] + tag[T]
   = 12 + 32 + 8 = 52 bytes at default AEAD config. Round up to 64
   for a comfortable margin (fits the CAN FD 64-byte payload bound
   exactly). */
#define FBSEC_SERVER_DISPATCH_REPLY_MAX 64u

/* ABORT_NO_ENTRY (CiA-301 0x06020000): object does not exist. */
#define FBSEC_SERVER_ABORT_NO_ENTRY 0x06020000u

/**
 * @brief Detect the verb token from the entry's access flags + the
 *        request shape.
 *
 * Pass-1 = challenge/arm round-trip (SRD1/SWR1); Pass-2 =
 * data-bearing round-trip (SRD2/SWR2; includes cyclic polls). For
 * SECURE_RO the challenge carries (1 + R) bytes (keyid first, then
 * client_random); anything smaller is either the empty Pass-2 fetch
 * or a 1-byte cyclic-poll counter, both data-bearing. For
 * SECURE_WO Pass-1 is empty (single-shot) or 1 byte (cyclic-arm
 * keyid); anything bigger is a Pass-2 frame (single-shot framed
 * write, or cyclic-write poll).
 */
static const char *detect_verb(const fbsec_sod_entry_t *entry,
                               uint16_t                 payload_len) {
  if (entry == NULL) {
    return "??";
  }
  bool is_ro = (entry->access_flags & FBSEC_SOD_ACCESS_SECURE_RO) != 0u;
  bool is_wo = (entry->access_flags & FBSEC_SOD_ACCESS_SECURE_WO) != 0u;
  const uint16_t challenge_len = (uint16_t)(1u + FBSEC_AEAD_RAND_SIZE);
  if (is_ro && payload_len == challenge_len) {
    return "SRD1";
  }
  if (is_ro) {
    return "SRD2";
  }
  if (is_wo && payload_len <= 1u) {
    return "SWR1";
  }
  if (is_wo) {
    return "SWR2";
  }
  return "??";
}

void fbsec_server_dispatch_request(uint16_t            src_dev,
                                   uint32_t            data_id,
                                   const uint8_t      *payload,
                                   uint16_t            payload_len,
                                   fbsec_send_reply_fn_t send_reply,
                                   void               *user) {
  uint8_t  reply_buf[FBSEC_SERVER_DISPATCH_REPLY_MAX];
  uint16_t reply_len  = 0u;
  uint32_t abort_code = 0u;

  fbsec_sod_status_t srv = fbsec_sod_dispatch(src_dev, data_id,
                                              payload, payload_len,
                                              reply_buf, sizeof reply_buf,
                                              &reply_len, &abort_code);

  if (srv != FBSEC_SOD_NOT_HANDLED) {
    const fbsec_sod_entry_t *entry = fbsec_sod_find_entry(data_id);
    const char *verb = detect_verb(entry, payload_len);

    uint16_t dst_dev = fbsec_sod_port_get_device_id();
    /* MISRA-Dir-4.7 deviation: send_reply's transmit status is intentionally
       discarded on every result path below. Per the fbsec_send_reply_fn_t
       contract the variant logs any transmit failure itself; dispatch is
       fire-and-forget at this layer. */
    if (srv == FBSEC_SOD_OK) {
      (void)send_reply(user, src_dev, data_id, 0u, reply_buf, reply_len);
      fbsec_server_trace_request(src_dev, dst_dev, data_id, verb,
                                 0u,
                                 payload, payload_len,
                                 reply_buf, (size_t)reply_len);
    } else if (srv == FBSEC_SOD_DEFER) {
      (void)send_reply(user, src_dev, data_id, 0u, NULL, 0u);
      fbsec_server_trace_request(src_dev, dst_dev, data_id, verb,
                                 0u,
                                 payload, payload_len,
                                 NULL, 0u);
    } else {
      (void)send_reply(user, src_dev, data_id, abort_code, NULL, 0u);
      fbsec_server_trace_request(src_dev, dst_dev, data_id, verb,
                                 abort_code,
                                 payload, payload_len,
                                 NULL, 0u);
    }
    return;
  }

  /* Unknown data_id (not in the secure registry): abort. */
  const char *verb    = (payload_len == 0u) ? "SRD?" : "SWR?";
  uint16_t    dst_dev = fbsec_sod_port_get_device_id();
  /* MISRA-Dir-4.7 deviation: discard send_reply status; variant logs TX failure. */
  (void)send_reply(user, src_dev, data_id, FBSEC_SERVER_ABORT_NO_ENTRY, NULL, 0u);
  fbsec_server_trace_request(src_dev, dst_dev, data_id, verb,
                             FBSEC_SERVER_ABORT_NO_ENTRY,
                             payload, payload_len,
                             NULL, 0u);
}

/* EOF */
