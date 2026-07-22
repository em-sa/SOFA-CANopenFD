/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    client_common_rpk.c
 * @brief   SOFA client_common, RPK signed secure-access driver, impl.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 22-JUL-2026
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#include "client_common_rpk.h"

#if FBSEC_FEATURE_ASYM

#include <string.h>

#include "client_common_asym.h"
#include "fbsec_asym.h"

#define RPK_BODY_MAX        64u
#define RPK_TRANSCRIPT_MAX  (RPK_BODY_MAX + FBSEC_ASYM_TRANSCRIPT_OVERHEAD)

static uint16_t put_u16le(uint8_t *p, uint16_t v) {
  p[0] = (uint8_t)(v & 0xFFu);
  p[1] = (uint8_t)((v >> 8) & 0xFFu);
  return 2u;
}

static uint16_t put_u32le(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v & 0xFFu);
  p[1] = (uint8_t)((v >> 8) & 0xFFu);
  p[2] = (uint8_t)((v >> 16) & 0xFFu);
  p[3] = (uint8_t)((v >> 24) & 0xFFu);
  return 4u;
}

int fbsec_rpk_signed_read(const fbsec_secure_transport_t *transport,
                          uint16_t target, uint16_t target_index,
                          uint8_t target_sub, uint8_t *buf, uint32_t buf_size,
                          uint32_t *len_out, uint32_t timeout_ms) {
  uint8_t  req[FBSEC_RPK_READ_REQ_LEN];
  uint8_t  reply[FBSEC_RPK_VALUE_MAX + FBSEC_ASYM_SIG_SIZE];
  uint8_t  body[RPK_BODY_MAX];
  uint8_t  transcript[RPK_TRANSCRIPT_MAX];
  uint32_t      rlen = 0u;
  fbsec_abort_t abrt = FBSEC_ABORT_NONE;
  uint32_t target_id;
  uint16_t vlen;
  uint16_t o = 0u;
  uint16_t tn;

  if (transport == NULL || transport->read == NULL || buf == NULL) { return 1; }

  (void)put_u16le(&req[0], target_index);
  req[2] = target_sub;
  if (!fbsec_secure_port_random(&req[3], FBSEC_RPK_NONCE_LEN)) { return 1; }

  if (transport->read(transport->ctx, target, FBSEC_RPK_GENERIC_READ_ID,
                      req, (uint16_t)sizeof req, reply, (uint32_t)sizeof reply,
                      timeout_ms, &rlen, &abrt) != FBSEC_SECP_OK) {
    return 2;
  }
  if (rlen < FBSEC_ASYM_SIG_SIZE) { return 3; }
  vlen = (uint16_t)(rlen - FBSEC_ASYM_SIG_SIZE);
  if (vlen > FBSEC_RPK_VALUE_MAX || (uint32_t)vlen > buf_size) { return 3; }

  target_id = ((uint32_t)target_index << 16) | ((uint32_t)target_sub << 8);
  o = (uint16_t)(o + put_u32le(&body[o], target_id));
  o = (uint16_t)(o + put_u16le(&body[o], target));
  o = (uint16_t)(o + put_u16le(&body[o], fbsec_secure_port_get_client_id()));
  memcpy(&body[o], &req[3], FBSEC_RPK_NONCE_LEN);
  o = (uint16_t)(o + FBSEC_RPK_NONCE_LEN);
  memcpy(&body[o], reply, vlen);
  o = (uint16_t)(o + vlen);

  tn = fbsec_asym_transcript(FBSEC_ASYM_RD_GENERIC_READ, body, o,
                             transcript, (uint16_t)sizeof transcript);
  if ((tn == 0u) ||
      !fbsec_asym_verify(fbsec_client_asym_server_idevid(), transcript, tn,
                         &reply[vlen])) {
    return 5;
  }
  memcpy(buf, reply, vlen);
  if (len_out != NULL) { *len_out = vlen; }
  return 0;
}

/* Fetch a server challenge for @p data_id into @p server_nonce. */
static int fetch_challenge(const fbsec_secure_transport_t *transport,
                           uint16_t target, uint32_t data_id,
                           const uint8_t *req, uint16_t req_len,
                           uint8_t server_nonce[FBSEC_RPK_NONCE_LEN],
                           uint32_t timeout_ms) {
  uint8_t  reply[FBSEC_RPK_NONCE_LEN];
  uint32_t      rlen = 0u;
  fbsec_abort_t abrt = FBSEC_ABORT_NONE;

  if (transport->read(transport->ctx, target, data_id, req, req_len,
                      reply, (uint32_t)sizeof reply, timeout_ms,
                      &rlen, &abrt) != FBSEC_SECP_OK) {
    return 2;
  }
  if (rlen != FBSEC_RPK_NONCE_LEN) { return 3; }
  memcpy(server_nonce, reply, FBSEC_RPK_NONCE_LEN);
  return 0;
}

int fbsec_rpk_signed_write(const fbsec_secure_transport_t *transport,
                           uint16_t target, uint16_t target_index,
                           uint8_t target_sub, const uint8_t *value,
                           uint16_t value_len, uint32_t timeout_ms) {
  uint8_t  hdr[3];
  uint8_t  server_nonce[FBSEC_RPK_NONCE_LEN];
  uint8_t  client_nonce[FBSEC_RPK_NONCE_LEN];
  uint8_t  body[RPK_BODY_MAX];
  uint8_t  transcript[RPK_TRANSCRIPT_MAX];
  uint8_t  payload[FBSEC_RPK_WRITE_HDR_LEN + FBSEC_RPK_VALUE_MAX + FBSEC_ASYM_SIG_SIZE];
  uint32_t target_id;
  uint16_t o = 0u;
  uint16_t p = 0u;
  uint16_t tn;
  int rc;
  fbsec_abort_t abrt = FBSEC_ABORT_NONE;

  if (transport == NULL || transport->read == NULL || transport->write == NULL) {
    return 1;
  }
  if (value == NULL || value_len > FBSEC_RPK_VALUE_MAX) { return 1; }

  /* Pass 1: request a server challenge with the bare target header. */
  (void)put_u16le(&hdr[0], target_index);
  hdr[2] = target_sub;
  rc = fetch_challenge(transport, target, FBSEC_RPK_GENERIC_WRITE_ID,
                       hdr, (uint16_t)sizeof hdr, server_nonce, timeout_ms);
  if (rc != 0) { return rc; }

  if (!fbsec_secure_port_random(client_nonce, FBSEC_RPK_NONCE_LEN)) { return 1; }

  /* Pass 2 transcript body = target_id[4] || server[2] || client[2] ||
     server_nonce[16] || client_nonce[16] || value. */
  target_id = ((uint32_t)target_index << 16) | ((uint32_t)target_sub << 8);
  o = (uint16_t)(o + put_u32le(&body[o], target_id));
  o = (uint16_t)(o + put_u16le(&body[o], target));
  o = (uint16_t)(o + put_u16le(&body[o], fbsec_secure_port_get_client_id()));
  memcpy(&body[o], server_nonce, FBSEC_RPK_NONCE_LEN);
  o = (uint16_t)(o + FBSEC_RPK_NONCE_LEN);
  memcpy(&body[o], client_nonce, FBSEC_RPK_NONCE_LEN);
  o = (uint16_t)(o + FBSEC_RPK_NONCE_LEN);
  memcpy(&body[o], value, value_len);
  o = (uint16_t)(o + value_len);

  /* Pass 2 payload = header || client_nonce || value || signature. */
  (void)put_u16le(&payload[p], target_index); p = (uint16_t)(p + 2u);
  payload[p++] = target_sub;
  memcpy(&payload[p], client_nonce, FBSEC_RPK_NONCE_LEN);
  p = (uint16_t)(p + FBSEC_RPK_NONCE_LEN);
  memcpy(&payload[p], value, value_len);
  p = (uint16_t)(p + value_len);

  tn = fbsec_asym_transcript(FBSEC_ASYM_RD_GENERIC_WRITE, body, o,
                             transcript, (uint16_t)sizeof transcript);
  if ((tn == 0u) ||
      !fbsec_asym_sign(fbsec_client_asym_integrator(), transcript, tn,
                       &payload[p])) {
    return 6;
  }
  p = (uint16_t)(p + FBSEC_ASYM_SIG_SIZE);

  if (transport->write(transport->ctx, target, FBSEC_RPK_GENERIC_WRITE_ID,
                       payload, p, timeout_ms, &abrt) != FBSEC_SECP_OK) {
    return 2;
  }
  return 0;
}

int fbsec_rpk_command(const fbsec_secure_transport_t *transport,
                      uint16_t target, uint32_t code, uint32_t timeout_ms) {
  uint8_t  server_nonce[FBSEC_RPK_NONCE_LEN];
  uint8_t  client_nonce[FBSEC_RPK_NONCE_LEN];
  uint8_t  code_bytes[FBSEC_RPK_CMD_LEN];
  uint8_t  body[RPK_BODY_MAX];
  uint8_t  transcript[RPK_TRANSCRIPT_MAX];
  uint8_t  payload[FBSEC_RPK_NONCE_LEN + FBSEC_RPK_CMD_LEN + FBSEC_ASYM_SIG_SIZE];
  uint16_t o = 0u;
  uint16_t p = 0u;
  uint16_t tn;
  int rc;
  fbsec_abort_t abrt = FBSEC_ABORT_NONE;

  if (transport == NULL || transport->read == NULL || transport->write == NULL) {
    return 1;
  }

  /* Pass 1: empty request -> server challenge. */
  rc = fetch_challenge(transport, target, FBSEC_RPK_FUNCCMD_ID, NULL, 0u,
                       server_nonce, timeout_ms);
  if (rc != 0) { return rc; }

  if (!fbsec_secure_port_random(client_nonce, FBSEC_RPK_NONCE_LEN)) { return 1; }
  (void)put_u32le(code_bytes, code);

  /* body = data_id[4] || server[2] || client[2] || server_nonce ||
     client_nonce || code. */
  o = (uint16_t)(o + put_u32le(&body[o], FBSEC_RPK_FUNCCMD_ID));
  o = (uint16_t)(o + put_u16le(&body[o], target));
  o = (uint16_t)(o + put_u16le(&body[o], fbsec_secure_port_get_client_id()));
  memcpy(&body[o], server_nonce, FBSEC_RPK_NONCE_LEN);
  o = (uint16_t)(o + FBSEC_RPK_NONCE_LEN);
  memcpy(&body[o], client_nonce, FBSEC_RPK_NONCE_LEN);
  o = (uint16_t)(o + FBSEC_RPK_NONCE_LEN);
  memcpy(&body[o], code_bytes, FBSEC_RPK_CMD_LEN);
  o = (uint16_t)(o + FBSEC_RPK_CMD_LEN);

  memcpy(&payload[p], client_nonce, FBSEC_RPK_NONCE_LEN);
  p = (uint16_t)(p + FBSEC_RPK_NONCE_LEN);
  memcpy(&payload[p], code_bytes, FBSEC_RPK_CMD_LEN);
  p = (uint16_t)(p + FBSEC_RPK_CMD_LEN);

  tn = fbsec_asym_transcript(FBSEC_ASYM_RD_FUNCTION_CMD, body, o,
                             transcript, (uint16_t)sizeof transcript);
  if ((tn == 0u) ||
      !fbsec_asym_sign(fbsec_client_asym_integrator(), transcript, tn,
                       &payload[p])) {
    return 6;
  }
  p = (uint16_t)(p + FBSEC_ASYM_SIG_SIZE);

  if (transport->write(transport->ctx, target, FBSEC_RPK_FUNCCMD_ID,
                       payload, p, timeout_ms, &abrt) != FBSEC_SECP_OK) {
    return 2;
  }
  return 0;
}

#endif /* FBSEC_FEATURE_ASYM */

/* EOF */
