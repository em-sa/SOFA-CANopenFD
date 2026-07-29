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
#include <stdio.h>

#include "client_common_asym.h"
#include "client_common_cli.h"
#include "client_common_keys.h"
#include "client_common_verbs.h"
#include "fbsec_asym_demo.h"

/* Fixed demo Provisioning Key the tool installs (public demo material). */
static const uint8_t DEMO_PROVISIONING_KEY[FBSEC_AEAD_KEY_SIZE] = {
  0x00u,0x11u,0x22u,0x33u,0x44u,0x55u,0x66u,0x77u,
  0x88u,0x99u,0xAAu,0xBBu,0xCCu,0xDDu,0xEEu,0xFFu
};

/* Demo Device Claim Token (public demo material; mirrors the server-side
   FBSEC_DEMO_CLAIM_TOKEN in server_common_keys.c). 32 bytes so both AES-128
   and AES-256 builds match the device; FBSEC_AEAD_KEY_SIZE bytes are used.
   --claim-token overrides it via fbsec_commission_set_claim_token_hex. */
static const uint8_t DEMO_CLAIM_TOKEN[32] = {
  0x01u,0x23u,0x45u,0x67u,0x89u,0xABu,0xCDu,0xEFu,
  0xFEu,0xDCu,0xBAu,0x98u,0x76u,0x54u,0x32u,0x10u,
  0x01u,0x23u,0x45u,0x67u,0x89u,0xABu,0xCDu,0xEFu,
  0xFEu,0xDCu,0xBAu,0x98u,0x76u,0x54u,0x32u,0x10u
};
static uint8_t g_claim_token[FBSEC_AEAD_KEY_SIZE];
static bool    g_claim_token_set = false;

/* Demo ownership epoch (must advance past the device's starting epoch). */
#define DEMO_VOUCHER_EPOCH  2u

const uint8_t *fbsec_commission_claim_token(void) {
  return g_claim_token_set ? g_claim_token : DEMO_CLAIM_TOKEN;
}

int fbsec_commission_set_claim_token_hex(const char *hex) {
  size_t n = 0u;
  if (fbsec_client_cli_parse_hex(hex, g_claim_token, sizeof g_claim_token, &n) != 0
      || n != (size_t)FBSEC_AEAD_KEY_SIZE) {
    return 1;
  }
  g_claim_token_set = true;
  return 0;
}

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

/* A voucher relayed from a file, if one was loaded; otherwise the demo
   voucher is built and signed on the spot (client holds the demo mfg key). */
static uint8_t g_voucher[FBSEC_HO_VOUCHER_LEN];
static bool    g_voucher_loaded = false;

int fbsec_commission_build_voucher(uint8_t *out, uint16_t out_size, uint16_t *out_len) {
  static const uint8_t serial[FBSEC_ASYM_SERIAL_LEN] = FBSEC_DEMO_DEVICE_SERIAL_BYTES;
  uint8_t  body[FBSEC_ASYM_SERIAL_LEN + FBSEC_ASYM_PUBKEY_SIZE + 4u];
  uint8_t  transcript[FBSEC_ASYM_TRANSCRIPT_OVERHEAD + sizeof body];
  uint16_t o = 0u;
  uint16_t tn;

  if ((out == NULL) || (out_size < (uint16_t)FBSEC_HO_VOUCHER_LEN)) { return 1; }

  /* body = serial || integrator_pub || epoch(LE) */
  memcpy(&body[o], serial, FBSEC_ASYM_SERIAL_LEN); o = (uint16_t)(o + FBSEC_ASYM_SERIAL_LEN);
  memcpy(&body[o], fbsec_client_asym_integrator()->pub, FBSEC_ASYM_PUBKEY_SIZE);
  o = (uint16_t)(o + FBSEC_ASYM_PUBKEY_SIZE);
  body[o++] = (uint8_t)(DEMO_VOUCHER_EPOCH & 0xFFu);
  body[o++] = 0u; body[o++] = 0u; body[o++] = 0u;

  memcpy(out, body, o);
  tn = fbsec_asym_transcript(FBSEC_ASYM_RD_VOUCHER, body, o,
                             transcript, (uint16_t)sizeof transcript);
  if ((tn == 0u) ||
      !fbsec_asym_sign(fbsec_client_asym_manufacturer(), transcript, tn, &out[o])) {
    return 6;
  }
  if (out_len != NULL) { *out_len = (uint16_t)FBSEC_HO_VOUCHER_LEN; }
  return 0;
}

int fbsec_commission_present_voucher_bytes(const fbsec_secure_transport_t *transport,
                                           uint16_t target, uint32_t timeout_ms,
                                           const uint8_t *voucher, uint16_t len) {
  fbsec_abort_t abrt = FBSEC_ABORT_NONE;
  if ((transport == NULL) || (transport->write == NULL) || (voucher == NULL)) { return 1; }
  if (len != (uint16_t)FBSEC_HO_VOUCHER_LEN) { return 7; }
  if (transport->write(transport->ctx, target, FBSEC_HO_VOUCHER_ID,
                       voucher, len, timeout_ms, &abrt) != FBSEC_SECP_OK) {
    return 2;
  }
  return 0;
}

int fbsec_commission_present_voucher(const fbsec_secure_transport_t *transport,
                                     uint16_t target, uint32_t timeout_ms) {
  uint8_t  voucher[FBSEC_HO_VOUCHER_LEN];
  uint16_t n = 0u;
  int      rc;

  if (g_voucher_loaded) {
    return fbsec_commission_present_voucher_bytes(transport, target, timeout_ms,
                                                  g_voucher, (uint16_t)FBSEC_HO_VOUCHER_LEN);
  }
  rc = fbsec_commission_build_voucher(voucher, (uint16_t)sizeof voucher, &n);
  if (rc != 0) { return rc; }
  return fbsec_commission_present_voucher_bytes(transport, target, timeout_ms, voucher, n);
}

int fbsec_commission_get_voucher(uint8_t *out, uint16_t out_size, uint16_t *out_len) {
  if ((out == NULL) || (out_size < (uint16_t)FBSEC_HO_VOUCHER_LEN)) { return 1; }
  if (g_voucher_loaded) {
    memcpy(out, g_voucher, FBSEC_HO_VOUCHER_LEN);
    if (out_len != NULL) { *out_len = (uint16_t)FBSEC_HO_VOUCHER_LEN; }
    return 0;
  }
  return fbsec_commission_build_voucher(out, out_size, out_len);
}

/* Read @p path, dropping '#'-to-end-of-line comments, into @p out (a NUL-
   terminated hex string). Returns 0 on success. */
static int slurp_hex_text(const char *path, char *out, size_t out_size) {
  FILE  *f;
  size_t w = 0u;
  int    c;
  bool   in_comment = false;

  if ((path == NULL) || (out == NULL) || (out_size == 0u)) { return 1; }
  f = fopen(path, "rb");
  if (f == NULL) { return 1; }
  while ((c = fgetc(f)) != EOF) {
    if (c == '#') { in_comment = true; continue; }
    if (c == '\n') { in_comment = false; continue; }
    if (in_comment) { continue; }
    if (w < (out_size - 1u)) { out[w++] = (char)c; }
    else { fclose(f); return 1; }   /* overflow */
  }
  fclose(f);
  out[w] = '\0';
  return 0;
}

int fbsec_commission_load_voucher_file(const char *path) {
  char    text[512];
  uint8_t buf[FBSEC_HO_VOUCHER_LEN];
  size_t  n = 0u;

  if (slurp_hex_text(path, text, sizeof text) != 0) { return 1; }
  if (fbsec_client_cli_parse_hex(text, buf, sizeof buf, &n) != 0) { return 2; }
  if (n != (size_t)FBSEC_HO_VOUCHER_LEN) { return 3; }
  memcpy(g_voucher, buf, FBSEC_HO_VOUCHER_LEN);
  g_voucher_loaded = true;
  return 0;
}

int fbsec_commission_emit_voucher_file(const char *path) {
  uint8_t  voucher[FBSEC_HO_VOUCHER_LEN];
  uint16_t n = 0u;
  FILE    *f;
  uint16_t i;
  int      rc;

  rc = fbsec_commission_build_voucher(voucher, (uint16_t)sizeof voucher, &n);
  if (rc != 0) { return rc; }
  f = fopen(path, "wb");
  if (f == NULL) { return 10; }
  (void)fprintf(f, "# SOFA demo ownership voucher (offline MASA artifact).\n");
  (void)fprintf(f, "# serial || integrator_pub || epoch(LE) || SIG_mfg; %u bytes hex.\n",
                (unsigned)n);
  for (i = 0u; i < n; ++i) {
    (void)fprintf(f, "%02X%s", voucher[i], (((i + 1u) % 16u) == 0u) ? "\n" : " ");
  }
  (void)fprintf(f, "\n");
  (void)fclose(f);
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

/* Install one C01Fh key-set rung: send the client's own @p target_slot key,
   the write AEAD-authorized under @p auth_slot's key. Both slots must already
   hold key material. Body = selector[1] || keyid[4 LE] || key[KEY_SIZE], with
   the non-secret C011h id following the demo convention 0x1000 + slot. */
static int install_key_rung(const fbsec_secure_transport_t *transport,
                            uint16_t target, uint32_t timeout_ms,
                            uint8_t target_slot, uint8_t auth_slot) {
  uint8_t  body[FBSEC_HO_KEY_SET_BODY_LEN];
  uint32_t keyid_val = 0x1000u + (uint32_t)target_slot;

  /* The value to install is the client's own session key for target_slot. */
  fbsec_client_keys_set_keyid(target_slot);
  if (!fbsec_client_keys_session_set()) { return 20; }   /* target key missing */
  body[0] = target_slot;
  body[1] = (uint8_t)(keyid_val & 0xFFu);
  body[2] = (uint8_t)((keyid_val >> 8) & 0xFFu);
  body[3] = (uint8_t)((keyid_val >> 16) & 0xFFu);
  body[4] = (uint8_t)((keyid_val >> 24) & 0xFFu);
  memcpy(&body[5], fbsec_client_keys_session(), FBSEC_AEAD_KEY_SIZE);

  /* Authorize the write under the tier below (the rolling key). */
  fbsec_client_keys_set_keyid(auth_slot);
  if (!fbsec_client_keys_session_set()) { return 21; }   /* auth key missing */
  return fbsec_client_run_secure_write(transport, target, FBSEC_HO_KEY_SET_ID,
                                       body, (uint16_t)FBSEC_HO_KEY_SET_BODY_LEN,
                                       timeout_ms);
}

int fbsec_commission_install_provisioning_by_token(
    const fbsec_secure_transport_t *transport,
    uint16_t target, uint32_t timeout_ms) {
  uint8_t saved_keyid = fbsec_client_keys_keyid();  /* restore the user's choice */
  int     rc;

  /* Seat the Device Claim Token in its slot so it can authorize the write. */
  fbsec_client_keys_set_keyid(FBSEC_CLIENT_KEYID_CLAIM_TOKEN);
  if (!fbsec_client_keys_set_session(fbsec_commission_claim_token())) {
    fbsec_client_keys_set_keyid(saved_keyid);
    return 22;
  }
  rc = install_key_rung(transport, target, timeout_ms,
                        FBSEC_CLIENT_KEYID_PROVISIONING,
                        FBSEC_CLIENT_KEYID_CLAIM_TOKEN);
  fbsec_client_keys_set_keyid(saved_keyid);
  return rc;
}

int fbsec_commission_install_ladder(const fbsec_secure_transport_t *transport,
                                    uint16_t target, uint32_t timeout_ms) {
  uint8_t saved_keyid = fbsec_client_keys_keyid();  /* restore the user's choice */
  int     rc = install_key_rung(transport, target, timeout_ms,
                                FBSEC_CLIENT_KEYID_INTEGRATOR,
                                FBSEC_CLIENT_KEYID_PROVISIONING);
  if (rc == 0) {
    rc = install_key_rung(transport, target, timeout_ms,
                          FBSEC_CLIENT_KEYID_OPERATOR,
                          FBSEC_CLIENT_KEYID_INTEGRATOR);
  }
  fbsec_client_keys_set_keyid(saved_keyid);
  return rc;
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
