/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    fbsec_secure_proto.c
 * @brief   SOFA client-side secure-tunnel protocol, implementation.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.2 of 20-JUL-2026
 *
 * Two flows, each two round-trips through the transport vtable:
 *
 *   Both single-shot flows now contribute fresh randomness from BOTH
 *   peers: client_random and server_random are each
 *   FBSEC_AEAD_RAND_SIZE bytes (default 12). The GCM nonce is
 *   nonce = client_random[0..NS-1] XOR server_random[0..NS-1] where
 *   NS = FBSEC_AEAD_NONCE_SIZE. Nonce uniqueness survives a single
 *   weak-RNG peer. Both randoms are bound into the AAD tail of the
 *   data-bearing direction (READ_RESPONSE / WRITE_REQUEST), so any
 *   in-flight tamper of either contribution fails AEAD verification.
 *
 *   The wire keyid byte is carried only on CLIENT REQUESTS, never on
 *   server responses, and where it appears it is the FIRST byte of
 *   the payload. The server learns the keyid from the client's request
 *   and never echoes it back; AAD-binding still ensures any in-flight
 *   tamper of the keyid fails the tag verify.
 *
 *   secure read:
 *     1. transport.write(key_id[1] || client_random[R])
 *     2. transport.read() -> server_random[R] || data || tag[8]
 *     3. nonce = XOR; AAD direction = READ_RESPONSE with tail =
 *        client_random[R] || server_random[R]
 *        (|| plaintext if encryption=0).
 *
 *   secure write (mirror of secure read):
 *     1. transport.read(req empty) -> server_random[R]
 *        (server has no key context yet, no tag possible.)
 *     2. transport.write(key_id[1] || client_random[R] || ciphertext[N]
 *                        || tag[8])
 *        (nonce = XOR; AAD direction = WRITE_REQUEST with tail =
 *         client_random[R] || server_random[R] (|| plaintext if
 *         encryption=0).)
 *
 * The transport never sees a key, never builds an AAD, never touches
 * AES. Authentication-only mode means the wire payload of the secure
 * read response is plaintext + tag (no encryption); confidentiality is
 * deliberately not in scope for this protocol level.
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#include "fbsec_secure_proto.h"

#include <string.h>

/* On-wire sizes. */
#define CHALLENGE_LEN_RD     ((uint16_t)(1u + FBSEC_AEAD_RAND_SIZE))    /* 1 + R */
#define CHALLENGE_LEN_WR     ((uint16_t)FBSEC_AEAD_RAND_SIZE)           /* R */
/* Worst-case secure-read Pass-2 reply: server_random + data + tag.
   The keyid is no longer echoed (client knows what it sent). */
#define RESPONSE_BUF_LEN     ((uint16_t)(FBSEC_AEAD_RAND_SIZE \
                                        + FBSEC_AEAD_MAX_PROTECTED \
                                        + FBSEC_AEAD_TAG_SIZE))

/* Worst-case secure-write Pass-2 framed payload: keyid + client_random
   + data + tag. */
#define FRAMED_BUF_LEN       ((uint16_t)(1u + FBSEC_AEAD_RAND_SIZE \
                                        + FBSEC_AEAD_MAX_PROTECTED \
                                        + FBSEC_AEAD_TAG_SIZE))

/* ---- Salt callback ---------------------------------------------------- */

static fbsec_secure_salt_cb_t  g_salt_cb     = NULL;
static void                 *g_salt_cb_ctx = NULL;

void fbsec_secure_set_salt_callback(fbsec_secure_salt_cb_t cb, void *ctx) {
  g_salt_cb     = cb;
  g_salt_cb_ctx = ctx;
}

static void notify_salt(const uint8_t *salt, uint16_t len) {
  if (g_salt_cb != NULL) {
    g_salt_cb(salt, len, g_salt_cb_ctx);
  }
}

#if FBSEC_FEATURE_READ
/* ---- Secure read ------------------------------------------------------ */

fbsec_secure_status_t fbsec_secure_read(
  const fbsec_secure_transport_t *transport,
  uint16_t device_id,
  uint32_t data_id,
  const uint8_t key[FBSEC_AEAD_KEY_SIZE],
  uint8_t       key_id,
  uint8_t      *buf,
  uint32_t      buf_size,
  uint32_t      timeout_ms,
  uint32_t     *len_out,
  fbsec_abort_t *abort_out)
{
  if (transport == NULL || transport->read == NULL || transport->write == NULL
      || key == NULL || buf == NULL) {
    return FBSEC_SECP_PROTOCOL;
  }
  if (FBSEC_AEAD_KEYID_RESERVED(key_id) != 0u
      || FBSEC_AEAD_KEYID_BASE(key_id) == 0u
      || FBSEC_AEAD_KEYID_BASE(key_id) > FBSEC_AEAD_KEYID_MAX) {
    return FBSEC_SECP_PROTOCOL;
  }

  uint8_t challenge[CHALLENGE_LEN_RD];
  uint8_t client_random[FBSEC_AEAD_RAND_SIZE];

  if (!fbsec_secure_port_random(client_random, FBSEC_AEAD_RAND_SIZE)) {
    return FBSEC_SECP_RANDOM;
  }
  notify_salt(client_random, FBSEC_AEAD_RAND_SIZE);

  /* Pass 1 wire shape: key_id[1] || client_random[R].
     The keyid is the first byte of every client request that carries
     it; the server never echoes it back. */
  challenge[0] = key_id;
  memcpy(&challenge[1], client_random, FBSEC_AEAD_RAND_SIZE);

  /* Pass 1: write the challenge. */
  fbsec_secure_status_t rc = transport->write(transport->ctx,
                                            device_id, data_id,
                                            challenge, CHALLENGE_LEN_RD,
                                            timeout_ms, abort_out);
  if (rc != FBSEC_SECP_OK) {
    return rc;
  }

  /* Pass 2: read the response. Wire shape:
       server_random[R] || ciphertext[N] || tag[T]
     The keyid is not on the wire; the client already knows it and
     the AAD-binding (prefix offset 3) authenticates it via the tag. */
  uint8_t  response[RESPONSE_BUF_LEN];
  uint32_t resp_len = 0u;
  rc = transport->read(transport->ctx,
                       device_id, data_id,
                       NULL, 0u,
                       response, sizeof response,
                       timeout_ms,
                       &resp_len, abort_out);
  if (rc != FBSEC_SECP_OK) {
    return rc;
  }
  const uint16_t header_len = (uint16_t)FBSEC_AEAD_RAND_SIZE;
  if (resp_len < (uint32_t)(header_len + FBSEC_AEAD_TAG_SIZE)) {
    return FBSEC_SECP_PROTOCOL;
  }
  const uint8_t *server_random = &response[0];
  uint16_t data_len = (uint16_t)(resp_len - header_len - FBSEC_AEAD_TAG_SIZE);
  if (data_len > FBSEC_AEAD_MAX_PROTECTED) {
    return FBSEC_SECP_PROTOCOL;
  }
  if (data_len > buf_size) {
    return FBSEC_SECP_BUFSIZE;
  }

  /* nonce = client_random[0..11] XOR server_random[0..11]; AAD tail
     binds BOTH randoms (and the keyid via the prefix at offset 3). */
  uint8_t nonce[FBSEC_AEAD_NONCE_SIZE];
  fbsec_aead_xor_nonce(client_random, server_random, nonce);

  if (!fbsec_aead_open(key, nonce,
                     FBSEC_AEAD_DIR_READ_RESPONSE, key_id,
                     device_id, fbsec_secure_port_get_client_id(),
                     data_id,
                     client_random, server_random,
                     &response[header_len], data_len,
                     &response[header_len + data_len],
                     buf)) {
    return FBSEC_SECP_TAG;
  }

  if (len_out != NULL) {
    *len_out = data_len;
  }
  return FBSEC_SECP_OK;
}
#endif /* FBSEC_FEATURE_READ */

#if FBSEC_FEATURE_WRITE
/* ---- Secure write ----------------------------------------------------- */

fbsec_secure_status_t fbsec_secure_write(
  const fbsec_secure_transport_t *transport,
  uint16_t device_id,
  uint32_t data_id,
  const uint8_t key[FBSEC_AEAD_KEY_SIZE],
  uint8_t       key_id,
  const uint8_t *buf,
  uint32_t       len,
  uint32_t       timeout_ms,
  fbsec_abort_t *abort_out)
{
  if (transport == NULL || transport->read == NULL || transport->write == NULL
      || key == NULL || buf == NULL) {
    return FBSEC_SECP_PROTOCOL;
  }
  if (FBSEC_AEAD_KEYID_RESERVED(key_id) != 0u
      || FBSEC_AEAD_KEYID_BASE(key_id) == 0u
      || FBSEC_AEAD_KEYID_BASE(key_id) > FBSEC_AEAD_KEYID_MAX) {
    return FBSEC_SECP_PROTOCOL;
  }
  if (len == 0u || len > FBSEC_AEAD_MAX_PROTECTED) {
    return FBSEC_SECP_BUFSIZE;
  }

  /* Pass 1: ask the server for a fresh server_random with an empty
     request body. Server has no key context yet; the wire reply is
     the bare server_random[R]. Mirrors the read flow's pass-1
     challenge, turned around. */
  uint8_t  server_random[FBSEC_AEAD_RAND_SIZE];
  uint32_t server_random_len = 0u;
  fbsec_secure_status_t rc = transport->read(transport->ctx,
                                           device_id, data_id,
                                           NULL, 0u,
                                           server_random, sizeof server_random,
                                           timeout_ms,
                                           &server_random_len, abort_out);
  if (rc != FBSEC_SECP_OK) {
    return rc;
  }
  if (server_random_len != CHALLENGE_LEN_WR) {
    return FBSEC_SECP_PROTOCOL;
  }
  notify_salt(server_random, FBSEC_AEAD_RAND_SIZE);

  /* Generate the client's contribution and derive the per-frame nonce
     by XORing the two randoms. As long as either side's RNG is sound
     the nonce is unique. */
  uint8_t client_random[FBSEC_AEAD_RAND_SIZE];
  if (!fbsec_secure_port_random(client_random, FBSEC_AEAD_RAND_SIZE)) {
    return FBSEC_SECP_RANDOM;
  }
  uint8_t nonce[FBSEC_AEAD_NONCE_SIZE];
  fbsec_aead_xor_nonce(client_random, server_random, nonce);

  /* Pass 2: keyid[1] || client_random[R] || ciphertext[N] || tag[8].
     AAD direction = WRITE_REQUEST; AAD tail authenticates BOTH
     randoms (client first, then server) plus, in auth-only mode, the
     plaintext. The leading keyid byte tells the server which key to
     use; it is also the verbatim byte at AAD prefix offset 3. */
  uint8_t  framed[FRAMED_BUF_LEN];
  framed[0] = key_id;
  memcpy(&framed[1], client_random, FBSEC_AEAD_RAND_SIZE);
  uint8_t *write_cipher = &framed[1u + FBSEC_AEAD_RAND_SIZE];
  uint8_t *write_tag    = &framed[1u + FBSEC_AEAD_RAND_SIZE + len];
  if (!fbsec_aead_seal(key, nonce,
                     FBSEC_AEAD_DIR_WRITE_REQUEST, key_id,
                     device_id, fbsec_secure_port_get_client_id(),
                     data_id,
                     client_random, server_random,
                     buf, (uint16_t)len,
                     write_cipher,
                     write_tag)) {
    return FBSEC_SECP_TAG;
  }

  return transport->write(transport->ctx,
                          device_id, data_id,
                          framed,
                          1u + FBSEC_AEAD_RAND_SIZE + len + FBSEC_AEAD_TAG_SIZE,
                          timeout_ms, abort_out);
}
#endif /* FBSEC_FEATURE_WRITE */

#if FBSEC_FEATURE_CYCLIC
/* ---- Cyclic-mode helpers ----------------------------------------- */

/* Per-frame poll nonce: nonce_base XOR (0^64 || counter_be32). The
   nonce_base is the XOR of the two arm-time randoms (see spec
   section 11.1 and EmSA-WP-105 section 4.2.6). */
static void session_build_nonce(
  const fbsec_secure_session_t *sess,
  uint32_t                    counter_for_frame,
  uint8_t                     nonce_out[FBSEC_AEAD_NONCE_SIZE])
{
  memcpy(nonce_out, sess->nonce_base, FBSEC_AEAD_NONCE_SIZE);
  nonce_out[8]  ^= (uint8_t)((counter_for_frame >> 24) & 0xFFu);
  nonce_out[9]  ^= (uint8_t)((counter_for_frame >> 16) & 0xFFu);
  nonce_out[10] ^= (uint8_t)((counter_for_frame >>  8) & 0xFFu);
  nonce_out[11] ^= (uint8_t)( counter_for_frame        & 0xFFu);
}

/* ---- Cyclic-capable single read / write ------------------------- */

#if FBSEC_FEATURE_READ
fbsec_secure_status_t fbsec_secure_read_armed(
  const fbsec_secure_transport_t *transport,
  uint16_t      device_id,
  uint32_t      data_id,
  const uint8_t key[FBSEC_AEAD_KEY_SIZE],
  uint8_t       key_id,
  uint8_t      *buf,
  uint32_t      buf_size,
  uint32_t      timeout_ms,
  uint32_t     *len_out,
  fbsec_abort_t *abort_out,
  fbsec_secure_session_t *out_sess)
{
  if (transport == NULL || transport->read == NULL || transport->write == NULL
      || key == NULL || buf == NULL || out_sess == NULL) {
    return FBSEC_SECP_PROTOCOL;
  }
  if (FBSEC_AEAD_KEYID_RESERVED(key_id) != 0u
      || FBSEC_AEAD_KEYID_BASE(key_id) == 0u
      || FBSEC_AEAD_KEYID_BASE(key_id) > FBSEC_AEAD_KEYID_MAX) {
    return FBSEC_SECP_PROTOCOL;
  }
  /* Force bit 6 on; preserve bit 7 (encryption) and bits 3..0 (base id). */
  uint8_t arm_kid = (uint8_t)(key_id | 0x40u);

  uint8_t challenge[CHALLENGE_LEN_RD];
  uint8_t client_random[FBSEC_AEAD_RAND_SIZE];

  if (!fbsec_secure_port_random(client_random, FBSEC_AEAD_RAND_SIZE)) {
    return FBSEC_SECP_RANDOM;
  }
  notify_salt(client_random, FBSEC_AEAD_RAND_SIZE);

  /* Pass 1: arm_kid[1] || client_random[R]. Same as plain single SRD
     except bit-6 set in the keyid byte. */
  challenge[0] = arm_kid;
  memcpy(&challenge[1], client_random, FBSEC_AEAD_RAND_SIZE);

  fbsec_secure_status_t rc = transport->write(transport->ctx,
                                            device_id, data_id,
                                            challenge, CHALLENGE_LEN_RD,
                                            timeout_ms, abort_out);
  if (rc != FBSEC_SECP_OK) return rc;

  /* Pass 2: server_random[R] || cipher[N] || tag[T] - byte-identical
     to the single-shot reply (no session_id on the wire). */
  uint8_t  response[RESPONSE_BUF_LEN];
  uint32_t resp_len = 0u;
  rc = transport->read(transport->ctx,
                       device_id, data_id,
                       NULL, 0u,
                       response, sizeof response,
                       timeout_ms,
                       &resp_len, abort_out);
  if (rc != FBSEC_SECP_OK) return rc;
  const uint16_t header_len = (uint16_t)FBSEC_AEAD_RAND_SIZE;
  if (resp_len < (uint32_t)(header_len + FBSEC_AEAD_TAG_SIZE)) {
    return FBSEC_SECP_PROTOCOL;
  }
  uint16_t data_len = (uint16_t)(resp_len - header_len - FBSEC_AEAD_TAG_SIZE);
  if (data_len > FBSEC_AEAD_MAX_PROTECTED) return FBSEC_SECP_PROTOCOL;
  if (data_len > buf_size) return FBSEC_SECP_BUFSIZE;

  const uint8_t *server_random = &response[0];
  uint8_t nonce[FBSEC_AEAD_NONCE_SIZE];
  fbsec_aead_xor_nonce(client_random, server_random, nonce);

  if (!fbsec_aead_open(key, nonce,
                     FBSEC_AEAD_DIR_READ_RESPONSE, arm_kid,
                     device_id, fbsec_secure_port_get_client_id(),
                     data_id,
                     client_random, server_random,
                     &response[header_len], data_len,
                     &response[header_len + data_len],
                     buf)) {
    return FBSEC_SECP_TAG;
  }

  /* Cyclic session state: nonce_base persists as the per-frame nonce
     prefix; counter starts at 0 and increments on each poll. */
  out_sess->in_use     = true;
  out_sess->data_id    = data_id;
  out_sess->key_id     = arm_kid;
  fbsec_aead_xor_nonce(client_random, server_random, out_sess->nonce_base);
  out_sess->counter    = 0u;

  if (len_out != NULL) *len_out = data_len;
  return FBSEC_SECP_OK;
}
#endif /* FBSEC_FEATURE_READ */

#if FBSEC_FEATURE_WRITE
fbsec_secure_status_t fbsec_secure_write_armed(
  const fbsec_secure_transport_t *transport,
  uint16_t      device_id,
  uint32_t      data_id,
  const uint8_t key[FBSEC_AEAD_KEY_SIZE],
  uint8_t       key_id,
  const uint8_t *buf,
  uint32_t       len,
  uint32_t       timeout_ms,
  fbsec_abort_t *abort_out,
  fbsec_secure_session_t *out_sess)
{
  if (transport == NULL || transport->read == NULL || transport->write == NULL
      || key == NULL || buf == NULL || out_sess == NULL) {
    return FBSEC_SECP_PROTOCOL;
  }
  if (FBSEC_AEAD_KEYID_RESERVED(key_id) != 0u
      || FBSEC_AEAD_KEYID_BASE(key_id) == 0u
      || FBSEC_AEAD_KEYID_BASE(key_id) > FBSEC_AEAD_KEYID_MAX) {
    return FBSEC_SECP_PROTOCOL;
  }
  if (len == 0u || len > FBSEC_AEAD_MAX_PROTECTED) {
    return FBSEC_SECP_BUFSIZE;
  }
  uint8_t arm_kid = (uint8_t)(key_id | 0x40u);

  /* Pass 1: empty body -> server_random[R]. Same as single-shot SWR. */
  uint8_t  server_random[FBSEC_AEAD_RAND_SIZE];
  uint32_t server_random_len = 0u;
  fbsec_secure_status_t rc = transport->read(transport->ctx,
                                           device_id, data_id,
                                           NULL, 0u,
                                           server_random, sizeof server_random,
                                           timeout_ms,
                                           &server_random_len, abort_out);
  if (rc != FBSEC_SECP_OK) return rc;
  if (server_random_len != CHALLENGE_LEN_WR) return FBSEC_SECP_PROTOCOL;
  notify_salt(server_random, FBSEC_AEAD_RAND_SIZE);

  uint8_t client_random[FBSEC_AEAD_RAND_SIZE];
  if (!fbsec_secure_port_random(client_random, FBSEC_AEAD_RAND_SIZE)) {
    return FBSEC_SECP_RANDOM;
  }
  uint8_t nonce[FBSEC_AEAD_NONCE_SIZE];
  fbsec_aead_xor_nonce(client_random, server_random, nonce);

  /* Pass 2: arm_kid[1] || client_random[R] || cipher[N] || tag[T].
     Same as single-shot SWR Pass 2 except bit-6 set in the keyid. */
  uint8_t  framed[FRAMED_BUF_LEN];
  framed[0] = arm_kid;
  memcpy(&framed[1], client_random, FBSEC_AEAD_RAND_SIZE);
  uint8_t *write_cipher = &framed[1u + FBSEC_AEAD_RAND_SIZE];
  uint8_t *write_tag    = &framed[1u + FBSEC_AEAD_RAND_SIZE + len];
  if (!fbsec_aead_seal(key, nonce,
                     FBSEC_AEAD_DIR_WRITE_REQUEST, arm_kid,
                     device_id, fbsec_secure_port_get_client_id(),
                     data_id,
                     client_random, server_random,
                     buf, (uint16_t)len,
                     write_cipher, write_tag)) {
    return FBSEC_SECP_TAG;
  }

  /* Pass 2 ACK is empty (byte-identical to single-shot SWR ACK); the
     server's cyclic state is established under the same key + arm
     randoms, and the client tracks it locally via nonce_base. */
  rc = transport->write(transport->ctx,
                        device_id, data_id,
                        framed,
                        1u + FBSEC_AEAD_RAND_SIZE + len + FBSEC_AEAD_TAG_SIZE,
                        timeout_ms, abort_out);
  if (rc != FBSEC_SECP_OK) return rc;

  out_sess->in_use     = true;
  out_sess->data_id    = data_id;
  out_sess->key_id     = arm_kid;
  fbsec_aead_xor_nonce(client_random, server_random, out_sess->nonce_base);
  out_sess->counter    = 0u;
  return FBSEC_SECP_OK;
}
#endif /* FBSEC_FEATURE_WRITE */

/* ---- Cyclic-mode polls ------------------------------------------ */

#if FBSEC_FEATURE_READ
fbsec_secure_status_t fbsec_secure_poll_read(
  const fbsec_secure_transport_t *transport,
  uint16_t                      device_id,
  const uint8_t                 key[FBSEC_AEAD_KEY_SIZE],
  uint32_t                      timeout_ms,
  fbsec_abort_t                *abort_out,
  fbsec_secure_session_t         *sess,
  uint8_t                      *plain,
  uint16_t                      plain_max,
  uint16_t                     *plain_len_out,
  uint8_t                      *tag_out)
{
  if (transport == NULL || transport->read == NULL || key == NULL
      || sess == NULL || !sess->in_use || plain == NULL) {
    return FBSEC_SECP_PROTOCOL;
  }
  if (sess->counter >= FBSEC_AEAD_KEY_USE_LIMIT) {
    return FBSEC_SECP_PROTOCOL;     /* key-use limit reached; caller must re-arm */
  }
  uint32_t next_counter = sess->counter + 1u;
  uint8_t  body         = (uint8_t)(next_counter & 0xFFu);

  uint8_t  reply[1u + FBSEC_AEAD_MAX_PROTECTED + FBSEC_AEAD_TAG_SIZE];
  uint32_t reply_len = 0u;
  fbsec_secure_status_t rc = transport->read(transport->ctx,
                                           device_id, sess->data_id,
                                           &body, 1u,
                                           reply, sizeof reply,
                                           timeout_ms,
                                           &reply_len, abort_out);
  if (rc != FBSEC_SECP_OK) return rc;
  if (reply_len < (uint32_t)(1u + FBSEC_AEAD_TAG_SIZE)) return FBSEC_SECP_PROTOCOL;
  if (reply[0] != body) return FBSEC_SECP_PROTOCOL;     /* desync detected */

  uint16_t cipher_len = (uint16_t)(reply_len - 1u - FBSEC_AEAD_TAG_SIZE);
  if (cipher_len > FBSEC_AEAD_MAX_PROTECTED) return FBSEC_SECP_PROTOCOL;
  if (cipher_len > plain_max)              return FBSEC_SECP_BUFSIZE;

  uint8_t nonce[FBSEC_AEAD_NONCE_SIZE];
  session_build_nonce(sess, next_counter, nonce);

  if (!fbsec_aead_open(key, nonce,
                     FBSEC_AEAD_DIR_READ_POLL_RESPONSE, sess->key_id,
                     device_id, fbsec_secure_port_get_client_id(),
                     sess->data_id,
                     NULL, NULL,            /* no challenge randoms on polls */
                     &reply[1], cipher_len,
                     &reply[1u + cipher_len],
                     plain)) {
    return FBSEC_SECP_TAG;
  }

  sess->counter = next_counter;
  if (plain_len_out != NULL) *plain_len_out = cipher_len;
  if (tag_out != NULL) {
    memcpy(tag_out, &reply[1u + cipher_len], FBSEC_AEAD_TAG_SIZE);
  }
  return FBSEC_SECP_OK;
}
#endif /* FBSEC_FEATURE_READ */

#if FBSEC_FEATURE_WRITE
fbsec_secure_status_t fbsec_secure_poll_write(
  const fbsec_secure_transport_t *transport,
  uint16_t                      device_id,
  const uint8_t                 key[FBSEC_AEAD_KEY_SIZE],
  uint32_t                      timeout_ms,
  fbsec_abort_t                *abort_out,
  fbsec_secure_session_t         *sess,
  const uint8_t                *plain,
  uint16_t                      plain_len,
  uint8_t                      *tag_out)
{
  if (transport == NULL || transport->write == NULL || key == NULL
      || sess == NULL || !sess->in_use || plain == NULL) {
    return FBSEC_SECP_PROTOCOL;
  }
  if (plain_len == 0u || plain_len > FBSEC_AEAD_MAX_PROTECTED) {
    return FBSEC_SECP_BUFSIZE;
  }
  if (sess->counter >= FBSEC_AEAD_KEY_USE_LIMIT) {
    return FBSEC_SECP_PROTOCOL;     /* key-use limit reached; caller must re-arm */
  }
  uint32_t next_counter = sess->counter + 1u;

  uint8_t nonce[FBSEC_AEAD_NONCE_SIZE];
  session_build_nonce(sess, next_counter, nonce);

  uint8_t  framed[1u + FBSEC_AEAD_MAX_PROTECTED + FBSEC_AEAD_TAG_SIZE];
  framed[0] = (uint8_t)(next_counter & 0xFFu);
  uint8_t *out_cipher = &framed[1];
  uint8_t *out_tag    = &framed[1u + plain_len];

  if (!fbsec_aead_seal(key, nonce,
                     FBSEC_AEAD_DIR_WRITE_POLL_REQUEST, sess->key_id,
                     device_id, fbsec_secure_port_get_client_id(),
                     sess->data_id,
                     NULL, NULL,            /* no challenge randoms on polls */
                     plain, plain_len,
                     out_cipher,
                     out_tag)) {
    return FBSEC_SECP_TAG;
  }

  fbsec_secure_status_t rc = transport->write(
    transport->ctx,
    device_id, sess->data_id,
    framed, (uint32_t)(1u + plain_len + FBSEC_AEAD_TAG_SIZE),
    timeout_ms, abort_out);
  if (rc != FBSEC_SECP_OK) return rc;

  sess->counter = next_counter;
  if (tag_out != NULL) {
    memcpy(tag_out, out_tag, FBSEC_AEAD_TAG_SIZE);
  }
  return FBSEC_SECP_OK;
}
#endif /* FBSEC_FEATURE_WRITE */
#endif /* FBSEC_FEATURE_CYCLIC */

/* EOF */
