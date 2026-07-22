/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    client_common_commission.c
 * @brief   SOFA client_common, commissioning-tool handover driver.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.1 of 20-JUL-2026
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#include "client_common_commission.h"

#if FBSEC_FEATURE_ASYM

#include <string.h>

#include "client_common_asym.h"
#include "fbsec_asym_demo.h"

/* Fixed demo Provisioning Key the tool installs (public demo material). */
static const uint8_t DEMO_PROVISIONING_KEY[FBSEC_AEAD_KEY_SIZE] = {
  0x00u,0x11u,0x22u,0x33u,0x44u,0x55u,0x66u,0x77u,
  0x88u,0x99u,0xAAu,0xBBu,0xCCu,0xDDu,0xEEu,0xFFu
};

/* Demo ownership epoch (must advance past the device's starting epoch). */
#define DEMO_VOUCHER_EPOCH  2u

int fbsec_commission_verify_genuineness(const fbsec_secure_transport_t *transport,
                                        uint16_t target, uint32_t timeout_ms) {
  uint8_t  rt[FBSEC_HO_RT_LEN];
  uint8_t  reply[FBSEC_HO_IDENTITY_REPLY_LEN];
  uint32_t      len  = 0u;
  fbsec_abort_t abrt = FBSEC_ABORT_NONE;
  const uint8_t *blob;
  const uint8_t *cert;
  const uint8_t *sig_rt;
  uint8_t  ct[FBSEC_ASYM_TRANSCRIPT_OVERHEAD + FBSEC_ASYM_IDENTITY_BLOB_LEN];
  uint8_t  st[FBSEC_ASYM_TRANSCRIPT_OVERHEAD + FBSEC_ASYM_IDENTITY_BLOB_LEN + FBSEC_HO_RT_LEN];
  uint8_t  body[FBSEC_ASYM_IDENTITY_BLOB_LEN + FBSEC_HO_RT_LEN];
  fbsec_pubkey_t idevid_pub;
  fbsec_pubkey_t anchor;
  uint16_t n;

  if (transport == NULL || transport->read == NULL) { return 1; }
  if (!fbsec_secure_port_random(rt, FBSEC_HO_RT_LEN)) { return 1; }

  if (transport->read(transport->ctx, target, FBSEC_HO_IDENTITY_ID, rt, FBSEC_HO_RT_LEN,
                      reply, (uint32_t)sizeof reply, timeout_ms, &len, &abrt) != FBSEC_SECP_OK) {
    return 2;
  }
  if (len != FBSEC_HO_IDENTITY_REPLY_LEN) { return 3; }
  blob   = &reply[0];
  cert   = &reply[FBSEC_ASYM_IDENTITY_BLOB_LEN];
  sig_rt = &reply[FBSEC_ASYM_IDENTITY_BLOB_LEN + FBSEC_ASYM_SIG_SIZE];

  /* 1. The manufacturer certified this IDevID: verify the cert (over the
        blob) against the manufacturer anchor (its public key). */
  memcpy(anchor.pub, fbsec_client_asym_manufacturer()->pub, FBSEC_ASYM_PUBKEY_SIZE);
  n = fbsec_asym_transcript(FBSEC_ASYM_RD_IDEVID_CERT, blob,
                            FBSEC_ASYM_IDENTITY_BLOB_LEN, ct, (uint16_t)sizeof ct);
  if ((n == 0u) || !fbsec_asym_verify(&anchor, ct, n, cert)) {
    return 4;
  }
  /* 2. The device holds the IDevID private key: verify SIG(blob||rT)
        against the certified IDevID public key (bytes 8..39 of the blob). */
  memcpy(idevid_pub.pub, &blob[FBSEC_ASYM_SERIAL_LEN], FBSEC_ASYM_PUBKEY_SIZE);
  memcpy(body, blob, FBSEC_ASYM_IDENTITY_BLOB_LEN);
  memcpy(&body[FBSEC_ASYM_IDENTITY_BLOB_LEN], rt, FBSEC_HO_RT_LEN);
  n = fbsec_asym_transcript(FBSEC_ASYM_RD_IDENTITY_READ, body,
                            (uint16_t)sizeof body, st, (uint16_t)sizeof st);
  if ((n == 0u) || !fbsec_asym_verify(&idevid_pub, st, n, sig_rt)) {
    return 5;
  }
  return 0;
}

#if FBSEC_HANDOVER_AUTHORIZED
int fbsec_commission_present_voucher(const fbsec_secure_transport_t *transport,
                                     uint16_t target, uint32_t timeout_ms) {
  static const uint8_t serial[FBSEC_ASYM_SERIAL_LEN] = FBSEC_DEMO_DEVICE_SERIAL_BYTES;
  uint8_t  voucher[FBSEC_HO_VOUCHER_LEN];
  uint8_t  body[FBSEC_ASYM_SERIAL_LEN + FBSEC_ASYM_PUBKEY_SIZE + 4u];
  uint8_t  transcript[FBSEC_ASYM_TRANSCRIPT_OVERHEAD + sizeof body];
  uint16_t o = 0u;
  uint16_t tn;
  fbsec_abort_t abrt = FBSEC_ABORT_NONE;

  if (transport == NULL || transport->write == NULL) { return 1; }

  /* body = serial || integrator_pub || epoch(LE) */
  memcpy(&body[o], serial, FBSEC_ASYM_SERIAL_LEN); o = (uint16_t)(o + FBSEC_ASYM_SERIAL_LEN);
  memcpy(&body[o], fbsec_client_asym_integrator()->pub, FBSEC_ASYM_PUBKEY_SIZE);
  o = (uint16_t)(o + FBSEC_ASYM_PUBKEY_SIZE);
  body[o++] = (uint8_t)(DEMO_VOUCHER_EPOCH & 0xFFu);
  body[o++] = 0u; body[o++] = 0u; body[o++] = 0u;

  memcpy(voucher, body, o);
  tn = fbsec_asym_transcript(FBSEC_ASYM_RD_VOUCHER, body, o,
                             transcript, (uint16_t)sizeof transcript);
  if ((tn == 0u) ||
      !fbsec_asym_sign(fbsec_client_asym_manufacturer(), transcript, tn, &voucher[o])) {
    return 6;
  }
  if (transport->write(transport->ctx, target, FBSEC_HO_VOUCHER_ID,
                       voucher, FBSEC_HO_VOUCHER_LEN, timeout_ms, &abrt) != FBSEC_SECP_OK) {
    return 2;
  }
  return 0;
}
#endif /* FBSEC_HANDOVER_AUTHORIZED */

int fbsec_commission_install_provisioning(const fbsec_secure_transport_t *transport,
                                          uint16_t target, uint32_t timeout_ms) {
  uint8_t  payload[FBSEC_HO_PROVISION_LEN];
  uint8_t  transcript[FBSEC_ASYM_TRANSCRIPT_OVERHEAD + FBSEC_AEAD_KEY_SIZE];
  uint16_t tn;
  fbsec_abort_t abrt = FBSEC_ABORT_NONE;

  if (transport == NULL || transport->write == NULL) { return 1; }

  memcpy(payload, DEMO_PROVISIONING_KEY, FBSEC_AEAD_KEY_SIZE);
  tn = fbsec_asym_transcript(FBSEC_ASYM_RD_PKINSTALL_ACK, DEMO_PROVISIONING_KEY,
                             (uint16_t)FBSEC_AEAD_KEY_SIZE, transcript,
                             (uint16_t)sizeof transcript);
  if ((tn == 0u) ||
      !fbsec_asym_sign(fbsec_client_asym_integrator(), transcript, tn,
                       &payload[FBSEC_AEAD_KEY_SIZE])) {
    return 6;
  }
  if (transport->write(transport->ctx, target, FBSEC_HO_PROVISION_ID,
                       payload, FBSEC_HO_PROVISION_LEN, timeout_ms, &abrt) != FBSEC_SECP_OK) {
    return 2;
  }
  return 0;
}

int fbsec_commission_generate_ldevid(const fbsec_secure_transport_t *transport,
                                     uint16_t target, uint32_t timeout_ms,
                                     fbsec_pubkey_t *out_ldevid) {
  uint8_t  trigger[1] = { 0x01u };
  uint8_t  reply[FBSEC_HO_LDEVID_REPLY_LEN];
  uint32_t      len  = 0u;
  fbsec_abort_t abrt = FBSEC_ABORT_NONE;
  uint8_t  transcript[FBSEC_ASYM_TRANSCRIPT_OVERHEAD + FBSEC_ASYM_PUBKEY_SIZE];
  uint16_t n;

  if (transport == NULL || transport->read == NULL) { return 1; }

  if (transport->read(transport->ctx, target, FBSEC_HO_LDEVID_ID, trigger, 1u,
                      reply, (uint32_t)sizeof reply, timeout_ms, &len, &abrt) != FBSEC_SECP_OK) {
    return 2;
  }
  if (len != FBSEC_HO_LDEVID_REPLY_LEN) { return 3; }

  /* The IDevID signs the new LDevID public key; verify against the server's
     factory identity. */
  n = fbsec_asym_transcript(FBSEC_ASYM_RD_LDEVID_EXPORT, reply,
                            FBSEC_ASYM_PUBKEY_SIZE, transcript, (uint16_t)sizeof transcript);
  if ((n == 0u) ||
      !fbsec_asym_verify(fbsec_client_asym_server_idevid(), transcript, n,
                         &reply[FBSEC_ASYM_PUBKEY_SIZE])) {
    return 5;
  }
  if (out_ldevid != NULL) {
    memcpy(out_ldevid->pub, reply, FBSEC_ASYM_PUBKEY_SIZE);
  }
  return 0;
}

#endif /* FBSEC_FEATURE_ASYM */

/* EOF */
