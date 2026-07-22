/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    server_common_handover.c
 * @brief   SOFA server_common, device-side handover object handler.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.1 of 20-JUL-2026
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#include "server_common_handover.h"

#if FBSEC_FEATURE_ASYM

#include <string.h>

#include "server_common_asym.h"
#include "server_common_trace.h"
#include "fbsec_asym.h"
#include "fbsec_secure_od.h"

/* Largest handover reply is the identity read (168 bytes). */
#define HANDOVER_REPLY_MAX  FBSEC_HO_IDENTITY_REPLY_LEN

/* Emit one reply + trace and return handled=true. */
static bool emit(uint16_t client_dev, uint32_t data_id, const char *verb,
                 fbsec_abort_t status, const uint8_t *data, uint16_t len,
                 const uint8_t *req, uint16_t req_len,
                 fbsec_send_reply_fn_t send_reply, void *user) {
  uint16_t dst_dev = fbsec_sod_port_get_device_id();
  /* MISRA-Dir-4.7 deviation: TX status discarded; the variant logs failures. */
  (void)send_reply(user, client_dev, data_id, status, data, len);
  fbsec_server_trace_request(client_dev, dst_dev, data_id, verb, status,
                             req, req_len, data, (size_t)len);
  return true;
}

/* Sign @p body under @p role with the device IDevID into @p sig. */
static bool sign_idevid(uint8_t role, const uint8_t *body, uint16_t body_len,
                        uint8_t sig[FBSEC_ASYM_SIG_SIZE]) {
  uint8_t  transcript[FBSEC_ASYM_TRANSCRIPT_OVERHEAD + FBSEC_HO_IDENTITY_REPLY_LEN];
  uint16_t tlen = fbsec_asym_transcript(role, body, body_len,
                                        transcript, (uint16_t)sizeof transcript);
  if (tlen == 0u) { return false; }
  return fbsec_asym_sign(fbsec_server_asym_idevid(), transcript, tlen, sig);
}

/* Identity read: req = rT[16]; reply = blob[40] || cert[64] || SIG(blob||rT)[64]. */
static bool handle_identity(uint16_t client_dev, const uint8_t *req, uint16_t req_len,
                            fbsec_send_reply_fn_t send_reply, void *user) {
  uint8_t reply[HANDOVER_REPLY_MAX];
  uint8_t signed_body[FBSEC_ASYM_IDENTITY_BLOB_LEN + FBSEC_HO_RT_LEN];
  uint16_t o = 0u;

  if (req_len != FBSEC_HO_RT_LEN) {
    return emit(client_dev, FBSEC_HO_IDENTITY_ID, "HOID",
                (req_len > FBSEC_HO_RT_LEN) ? FBSEC_ABORT_LEN_TOO_HIGH
                                            : FBSEC_ABORT_LEN_TOO_LOW,
                NULL, 0u, req, req_len, send_reply, user);
  }
  /* blob = serial || IDevID pub. */
  memcpy(&reply[o], fbsec_server_asym_serial(), FBSEC_ASYM_SERIAL_LEN);
  o = (uint16_t)(o + FBSEC_ASYM_SERIAL_LEN);
  memcpy(&reply[o], fbsec_server_asym_idevid()->pub, FBSEC_ASYM_PUBKEY_SIZE);
  o = (uint16_t)(o + FBSEC_ASYM_PUBKEY_SIZE);
  /* mfg certificate over the blob. */
  memcpy(&reply[o], fbsec_server_asym_idevid_cert(), FBSEC_ASYM_SIG_SIZE);
  o = (uint16_t)(o + FBSEC_ASYM_SIG_SIZE);
  /* SIG_DEV over (blob || rT) proves possession of the IDevID private key. */
  memcpy(signed_body, reply, FBSEC_ASYM_IDENTITY_BLOB_LEN);
  memcpy(&signed_body[FBSEC_ASYM_IDENTITY_BLOB_LEN], req, FBSEC_HO_RT_LEN);
  if (!sign_idevid(FBSEC_ASYM_RD_IDENTITY_READ, signed_body,
                   (uint16_t)sizeof signed_body, &reply[o])) {
    /* Signature GENERATION failed: an internal fault, not a bad signature. */
    return emit(client_dev, FBSEC_HO_IDENTITY_ID, "HOID", FBSEC_ABORT_INTERNAL,
                NULL, 0u, req, req_len, send_reply, user);
  }
  o = (uint16_t)(o + FBSEC_ASYM_SIG_SIZE);
  return emit(client_dev, FBSEC_HO_IDENTITY_ID, "HOID", FBSEC_ABORT_NONE, reply, o,
              req, req_len, send_reply, user);
}

/* LDevID export: req = trigger[1]; reply = ldevid_pub[32] || SIG(pub)[64]. */
static bool handle_ldevid(uint16_t client_dev, const uint8_t *req, uint16_t req_len,
                          fbsec_send_reply_fn_t send_reply, void *user) {
  uint8_t reply[FBSEC_HO_LDEVID_REPLY_LEN];
  fbsec_pubkey_t pub;

  if (req_len < 1u) {
    return emit(client_dev, FBSEC_HO_LDEVID_ID, "HOLD", FBSEC_ABORT_LEN_TOO_LOW,
                NULL, 0u, req, req_len, send_reply, user);
  }
  if (!fbsec_server_asym_generate_ldevid(&pub)) {
    return emit(client_dev, FBSEC_HO_LDEVID_ID, "HOLD", FBSEC_ABORT_INTERNAL,
                NULL, 0u, req, req_len, send_reply, user);
  }
  memcpy(&reply[0], pub.pub, FBSEC_ASYM_PUBKEY_SIZE);
  if (!sign_idevid(FBSEC_ASYM_RD_LDEVID_EXPORT, pub.pub, FBSEC_ASYM_PUBKEY_SIZE,
                   &reply[FBSEC_ASYM_PUBKEY_SIZE])) {
    return emit(client_dev, FBSEC_HO_LDEVID_ID, "HOLD", FBSEC_ABORT_INTERNAL,
                NULL, 0u, req, req_len, send_reply, user);
  }
  return emit(client_dev, FBSEC_HO_LDEVID_ID, "HOLD", FBSEC_ABORT_NONE,
              reply, (uint16_t)sizeof reply, req, req_len, send_reply, user);
}

/* Provisioning-Key install: req = key[16] || SIG[64]; reply = ACK / abort. */
static bool handle_provision(uint16_t client_dev, const uint8_t *req, uint16_t req_len,
                             fbsec_send_reply_fn_t send_reply, void *user) {
  bool ok = fbsec_server_asym_install_provisioning(req, req_len);
  return emit(client_dev, FBSEC_HO_PROVISION_ID, "HOPK",
              ok ? FBSEC_ABORT_NONE : FBSEC_ABORT_SIG_VERIFY, NULL, 0u,
              req, req_len, send_reply, user);
}

#if FBSEC_HANDOVER_AUTHORIZED
/* Ownership voucher claim: req = voucher[108]; reply = ACK / abort. */
static bool handle_voucher(uint16_t client_dev, const uint8_t *req, uint16_t req_len,
                           fbsec_send_reply_fn_t send_reply, void *user) {
  bool ok = fbsec_server_asym_claim(req, req_len);
  return emit(client_dev, FBSEC_HO_VOUCHER_ID, "HOVC",
              ok ? FBSEC_ABORT_NONE : FBSEC_ABORT_VOUCHER, NULL, 0u,
              req, req_len, send_reply, user);
}

/* Owner epoch read: req empty; reply = epoch[4 LE]. */
static bool handle_epoch(uint16_t client_dev, const uint8_t *req, uint16_t req_len,
                         fbsec_send_reply_fn_t send_reply, void *user) {
  uint32_t epoch = fbsec_server_asym_owner_epoch();
  uint8_t  reply[4];
  reply[0] = (uint8_t)(epoch & 0xFFu);
  reply[1] = (uint8_t)((epoch >> 8) & 0xFFu);
  reply[2] = (uint8_t)((epoch >> 16) & 0xFFu);
  reply[3] = (uint8_t)((epoch >> 24) & 0xFFu);
  return emit(client_dev, FBSEC_HO_EPOCH_ID, "HOEP", FBSEC_ABORT_NONE, reply, 4u,
              req, req_len, send_reply, user);
}
#endif /* FBSEC_HANDOVER_AUTHORIZED */

bool fbsec_server_handover_try(uint16_t client_dev, uint32_t data_id,
                               const uint8_t *req, uint16_t req_len,
                               fbsec_send_reply_fn_t send_reply, void *user) {
  switch (data_id) {
    case FBSEC_HO_IDENTITY_ID:
      return handle_identity(client_dev, req, req_len, send_reply, user);
    case FBSEC_HO_LDEVID_ID:
      return handle_ldevid(client_dev, req, req_len, send_reply, user);
    case FBSEC_HO_PROVISION_ID:
      return handle_provision(client_dev, req, req_len, send_reply, user);
#if FBSEC_HANDOVER_AUTHORIZED
    case FBSEC_HO_VOUCHER_ID:
      return handle_voucher(client_dev, req, req_len, send_reply, user);
    case FBSEC_HO_EPOCH_ID:
      return handle_epoch(client_dev, req, req_len, send_reply, user);
#endif
    default:
      return false;
  }
}

#endif /* FBSEC_FEATURE_ASYM */

/* EOF */
