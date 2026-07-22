/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    server_common_dispatch.c
 * @brief   SOFA server_common, dispatch glue, implementation.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.2 of 22-JUL-2026
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#include "server_common_dispatch.h"
#include "server_common_trace.h"
#include "server_common_hooks.h"
#include "server_common_keys.h"
#include "server_common_const_od.h"
#include "server_common_security.h"

#include "fbsec_aead.h"
#include "fbsec_secure_od.h"
#include "fbsec_descriptor.h"

#if FBSEC_FEATURE_ASYM
#include "server_common_asym.h"
#include "server_common_handover.h"
#include "server_common_rpk.h"
#endif

/* Worst-case secure reply: server_random[R] + cipher[N_MAX] + tag[T]
   = 12 + 32 + 8 = 52 bytes at default AEAD config. Round up to 64
   for a comfortable margin (fits the CAN FD 64-byte payload bound
   exactly). */
#define FBSEC_SERVER_DISPATCH_REPLY_MAX 64u

/**
 * @brief Serve a read of the capability/status descriptor (read-only,
 *        unauthenticated; spec section 11.6.3).
 *
 * @param src_dev       requester's device id.
 * @param data_id       requested data id.
 * @param payload       request payload bytes (NULL iff @p payload_len is 0).
 * @param payload_len   request payload length.
 * @param send_reply    variant reply callback.
 * @param user          opaque pointer forwarded to @p send_reply.
 *
 * @return true if @p data_id targets a descriptor record and a reply was
 *         sent; false to let the normal secure dispatch run.
 */
static bool try_serve_descriptor(uint16_t src_dev, uint32_t data_id,
                                 const uint8_t *payload, uint16_t payload_len,
                                 fbsec_send_reply_fn_t send_reply, void *user) {
  uint16_t index = (uint16_t)(data_id >> 16);
  uint8_t  sub   = (uint8_t)((data_id >> 8) & 0xFFu);
  bool     is_status;
  uint8_t  buf[4];
  uint16_t n = 0u;
  uint8_t  highest;
  bool     sub_exists;
  uint16_t dst_dev = fbsec_sod_port_get_device_id();
  const char *verb;

  if ((index != FBSEC_DESC_CAP_INDEX) && (index != FBSEC_DESC_STAT_INDEX)) {
    return false;
  }
  is_status = (index == FBSEC_DESC_STAT_INDEX);
  verb = is_status ? "STAT" : "CAP";

  /* Descriptors are read-only and unauthenticated. Addressing is checked
     before access: an unknown sub-index (or a non-zero reserved low
     data_id byte) is 34h, and only then does a body-bearing request -
     a write, or a secure-read challenge these entries do not take - hit
     the read-only refusal 32h. C000h (capabilities) is build-computed;
     C001h (status) reflects live commissioning and key-slot state. */
  if (is_status) {
    fbsec_status_t stat;
    uint8_t keys = 0u;
    if (fbsec_sod_has_key(FBSEC_DEMO_KEYID_PROVISIONING)) {
      keys |= FBSEC_STAT_KEY_PROVISIONING;
    }
    if (fbsec_sod_has_key(FBSEC_DEMO_KEYID_INTEGRATOR)) {
      keys |= FBSEC_STAT_KEY_INTEGRATOR;
    }
    if (fbsec_sod_has_key(FBSEC_DEMO_KEYID_OPERATOR)) {
      keys |= FBSEC_STAT_KEY_OPERATOR;
    }
    fbsec_descriptor_build_status(FBSEC_STAT_COMMISSIONED, keys, &stat);
    highest = stat.highest_sub;
    sub_exists = ((data_id & 0xFFu) == 0u) && (sub <= highest);
    if (sub_exists && (payload_len == 0u)) {
      n = fbsec_status_serialize_sub(&stat, sub, buf, (uint16_t)sizeof(buf));
    }
  } else {
    fbsec_caps_t caps;
    uint8_t live_id_flags = 0u;
#if FBSEC_FEATURE_ASYM
    /* Sub 05h reports live identity state; feed it from the asym store so
       an LDevID export shows up in the same session. */
    if (fbsec_server_asym_idevid_present()) {
      live_id_flags |= FBSEC_DESC_ID_IDEVID;
    }
    if (fbsec_server_asym_ldevid_present()) {
      live_id_flags |= FBSEC_DESC_ID_LDEVID;
    }
#endif
    fbsec_descriptor_build_caps(live_id_flags, &caps);
    highest = caps.highest_sub;
    sub_exists = ((data_id & 0xFFu) == 0u) && (sub <= highest);
    if (sub_exists && (payload_len == 0u)) {
      n = fbsec_caps_serialize_sub(&caps, sub, buf, (uint16_t)sizeof(buf));
    }
  }

  /* MISRA-Dir-4.7 deviation: send_reply's TX status is discarded; the
     variant logs any transmit failure itself (see fbsec_send_reply_fn_t). */
  if (n != 0u) {
    (void)send_reply(user, src_dev, data_id, FBSEC_ABORT_NONE, buf, n);
    fbsec_server_trace_request(src_dev, dst_dev, data_id, verb,
                               FBSEC_ABORT_NONE,
                               payload, payload_len, buf, (size_t)n);
  } else {
    fbsec_abort_t abort_code = sub_exists ? FBSEC_ABORT_READ_ONLY
                                          : FBSEC_ABORT_NO_SUBINDEX;
    (void)send_reply(user, src_dev, data_id, abort_code, NULL, 0u);
    fbsec_server_trace_request(src_dev, dst_dev, data_id, verb, abort_code,
                               payload, payload_len, NULL, 0u);
  }
  return true;
}

/**
 * @brief Serve a read of a constant, unsecured OD entry (object 1018h and
 *        other manufacturer / application constants loaded from --od-file).
 *
 * @return true if @p data_id matches a loaded const entry and a reply was
 *         sent; false to let later dispatch tiers run.
 */
static bool try_serve_const_od(uint16_t src_dev, uint32_t data_id,
                               const uint8_t *payload, uint16_t payload_len,
                               fbsec_send_reply_fn_t send_reply, void *user) {
  uint16_t index = (uint16_t)(data_id >> 16);
  uint8_t  sub   = (uint8_t)((data_id >> 8) & 0xFFu);
  uint16_t len   = 0u;
  const uint8_t *val;
  uint16_t dst_dev = fbsec_sod_port_get_device_id();

  if ((data_id & 0xFFu) != 0u) {
    return false;
  }
  val = fbsec_const_od_get(index, sub, &len);
  if (val == NULL) {
    return false;                          /* not a const entry */
  }

  /* MISRA-Dir-4.7 deviation: send_reply's TX status is discarded; the
     variant logs any transmit failure itself. */
  if (payload_len != 0u) {                 /* const entries are read-only */
    (void)send_reply(user, src_dev, data_id, FBSEC_ABORT_READ_ONLY, NULL, 0u);
    fbsec_server_trace_request(src_dev, dst_dev, data_id, "CRD",
                               FBSEC_ABORT_READ_ONLY,
                               payload, payload_len, NULL, 0u);
  } else {
    (void)send_reply(user, src_dev, data_id, FBSEC_ABORT_NONE, val, len);
    fbsec_server_trace_request(src_dev, dst_dev, data_id, "CRD",
                               FBSEC_ABORT_NONE,
                               payload, payload_len, val, (size_t)len);
  }
  return true;
}

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
  uint16_t      reply_len  = 0u;
  fbsec_abort_t abort_code = FBSEC_ABORT_NONE;

  /* C000h / C001h descriptors are read-only and unauthenticated; serve
     them before the secure dispatch (CiA 720 base parameters). */
  if (try_serve_descriptor(src_dev, data_id, payload, payload_len,
                           send_reply, user)) {
    return;
  }

  /* Constant, unsecured OD entries (object 1018h and other --od-file
     constants). */
  if (try_serve_const_od(src_dev, data_id, payload, payload_len,
                         send_reply, user)) {
    return;
  }

  /* CiA 720 AEAD-block security objects handled outside the registry
     (C010h session salt, C011h key ids, C01Fh key set). */
  if (fbsec_server_security_try(src_dev, data_id, payload, payload_len,
                                send_reply, user)) {
    return;
  }

#if FBSEC_FEATURE_ASYM
  /* Handover objects: signed identity read (C028h), ownership control
     (C020h voucher/epoch/LDevID), provisioning install (C02Fh). */
  if (fbsec_server_handover_try(src_dev, data_id, payload, payload_len,
                                send_reply, user)) {
    return;
  }

  /* RPK secure objects: public keys (C021h/C022h), signed generic access
     (C042h) and signed function command (C049h). */
  if (fbsec_server_rpk_try(src_dev, data_id, payload, payload_len,
                           send_reply, user)) {
    return;
  }
#endif

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
      (void)send_reply(user, src_dev, data_id, FBSEC_ABORT_NONE,
                       reply_buf, reply_len);
      fbsec_server_trace_request(src_dev, dst_dev, data_id, verb,
                                 FBSEC_ABORT_NONE,
                                 payload, payload_len,
                                 reply_buf, (size_t)reply_len);
    } else if (srv == FBSEC_SOD_DEFER) {
      (void)send_reply(user, src_dev, data_id, FBSEC_ABORT_NONE, NULL, 0u);
      fbsec_server_trace_request(src_dev, dst_dev, data_id, verb,
                                 FBSEC_ABORT_NONE,
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
  (void)send_reply(user, src_dev, data_id, FBSEC_ABORT_NO_OBJECT, NULL, 0u);
  fbsec_server_trace_request(src_dev, dst_dev, data_id, verb,
                             FBSEC_ABORT_NO_OBJECT,
                             payload, payload_len,
                             NULL, 0u);
}

/* EOF */
