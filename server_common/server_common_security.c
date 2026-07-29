/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    server_common_security.c
 * @brief   SOFA server_common, CiA 720 AEAD security objects handler, impl.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 22-JUL-2026
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#include "server_common_security.h"
#include "server_common_trace.h"

#include "fbsec_abort.h"
#include "fbsec_secure_od.h"

/* Emit one reply and trace it, mirroring the descriptor handler. */
static void serve(fbsec_send_reply_fn_t send_reply, void *user,
                  uint16_t src_dev, uint32_t data_id, const char *verb,
                  fbsec_abort_t abort_code,
                  const uint8_t *payload, uint16_t payload_len,
                  const uint8_t *reply, uint16_t reply_len) {
  uint16_t dst_dev = fbsec_sod_port_get_device_id();
  /* MISRA-Dir-4.7 deviation: send_reply's TX status is discarded; the
     variant logs any transmit failure itself. */
  (void)send_reply(user, src_dev, data_id, abort_code, reply, reply_len);
  fbsec_server_trace_request(src_dev, dst_dev, data_id, verb, abort_code,
                             payload, payload_len, reply, (size_t)reply_len);
}

/* C011h AEAD key identifiers: read-only, unsecured. sub 00h = slot count,
   subs 01h..N = per-slot non-secret U32 key id (little-endian). */
static void serve_key_ids(uint16_t src_dev, uint32_t data_id, uint8_t sub,
                          const uint8_t *payload, uint16_t payload_len,
                          fbsec_send_reply_fn_t send_reply, void *user) {
  uint8_t buf[4];

  if (payload_len != 0u) {                 /* a write to a read-only object */
    serve(send_reply, user, src_dev, data_id, "C011",
          FBSEC_ABORT_READ_ONLY, payload, payload_len, NULL, 0u);
    return;
  }
  if (sub == 0x00u) {
    buf[0] = (uint8_t)FBSEC_SOD_KEY_SLOTS;
    serve(send_reply, user, src_dev, data_id, "C011",
          FBSEC_ABORT_NONE, payload, payload_len, buf, 1u);
    return;
  }
  if (sub <= (uint8_t)FBSEC_SOD_KEY_SLOTS) {
    uint32_t id = fbsec_sod_get_key_id_value(sub);
    buf[0] = (uint8_t)(id & 0xFFu);
    buf[1] = (uint8_t)((id >> 8) & 0xFFu);
    buf[2] = (uint8_t)((id >> 16) & 0xFFu);
    buf[3] = (uint8_t)((id >> 24) & 0xFFu);
    serve(send_reply, user, src_dev, data_id, "C011",
          FBSEC_ABORT_NONE, payload, payload_len, buf, 4u);
    return;
  }
  serve(send_reply, user, src_dev, data_id, "C011",
        FBSEC_ABORT_NO_SUBINDEX, payload, payload_len, NULL, 0u);
}

/* C010h session salt: sub 00h highest sub-index, sub 01h salt (reads
   all-zero, no session). The salt-driven session arming is not
   implemented this pass, so a salt write returns NOT_IMPLEMENTED. */
static void serve_session_salt(uint16_t src_dev, uint32_t data_id, uint8_t sub,
                               const uint8_t *payload, uint16_t payload_len,
                               fbsec_send_reply_fn_t send_reply, void *user) {
  static const uint8_t zero_salt[16] = { 0 };

  if (sub == 0x00u) {
    uint8_t hi = 0x01u;                     /* highest sub-index = 1 */
    if (payload_len != 0u) {
      serve(send_reply, user, src_dev, data_id, "C010",
            FBSEC_ABORT_READ_ONLY, payload, payload_len, NULL, 0u);
    } else {
      serve(send_reply, user, src_dev, data_id, "C010",
            FBSEC_ABORT_NONE, payload, payload_len, &hi, 1u);
    }
    return;
  }
  if (sub == 0x01u) {
    if (payload_len != 0u) {                /* arm-a-session write: not built */
      serve(send_reply, user, src_dev, data_id, "C010",
            FBSEC_ABORT_NOT_IMPLEMENTED, payload, payload_len, NULL, 0u);
    } else {
      serve(send_reply, user, src_dev, data_id, "C010",
            FBSEC_ABORT_NONE, payload, payload_len, zero_salt,
            (uint16_t)sizeof zero_salt);
    }
    return;
  }
  serve(send_reply, user, src_dev, data_id, "C010",
        FBSEC_ABORT_NO_SUBINDEX, payload, payload_len, NULL, 0u);
}

bool fbsec_server_security_try(uint16_t src_dev, uint32_t data_id,
                               const uint8_t *payload, uint16_t payload_len,
                               fbsec_send_reply_fn_t send_reply, void *user) {
  uint16_t index = (uint16_t)(data_id >> 16);
  uint8_t  sub   = (uint8_t)((data_id >> 8) & 0xFFu);

  /* The low data_id byte is reserved and must be zero. */
  if ((data_id & 0xFFu) != 0u) {
    return false;
  }

  switch (index) {
    case FBSEC_SEC_INDEX_KEY_IDS:
      serve_key_ids(src_dev, data_id, sub, payload, payload_len,
                    send_reply, user);
      return true;
    case FBSEC_SEC_INDEX_SESSION_SALT:
      serve_session_salt(src_dev, data_id, sub, payload, payload_len,
                         send_reply, user);
      return true;
    /* C01Fh (FBSEC_SEC_INDEX_KEY_SET) is intentionally NOT handled here:
       it falls through to the fbsec_sod registry as a SECURE_WO entry. */
    default:
      return false;
  }
}

/* EOF */
