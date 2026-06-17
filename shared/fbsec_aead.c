/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    fbsec_aead.c
 * @brief   SOFA AEAD primitives, implementation.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 03-MAY-2026
 *
 * Three GCM modes plumbed; selection is per-call, driven by bit 7 of
 * the key_id argument (the encryption flag in the wire mechanism byte).
 *
 *   gcm_mac_only(): zero-length plaintext, all data in AAD, returns
 *                   truncated tag. Used for compute_tag/verify_tag, and
 *                   for seal/open when bit 7 of key_id is 0 (auth-only).
 *
 *   gcm_seal():     non-zero plaintext, GCM encrypt-and-tag. Used for
 *                   fbsec_aead_seal when bit 7 of key_id is 1.
 *
 *   gcm_open():     mbedtls_gcm_auth_decrypt with truncated tag. Used
 *                   for fbsec_aead_open when bit 7 of key_id is 1.
 *
 * In auth-only mode (key_id high bit clear), seal/open delegate to
 * gcm_mac_only with the data appended to the AAD, and copy plaintext
 * <-> "ciphertext_out" / "plaintext_out" verbatim. In both modes the
 * AAD's mechanism byte is FBSEC_AEAD_MECHANISM_FOR(key_id) so both peers
 * compute the same AAD when they see the same wire keyid byte.
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#include "fbsec_aead.h"

#include <string.h>

#include "mbedtls/gcm.h"

/* Maximum AAD: 12-byte prefix + the largest possible per-direction tail
   (two FBSEC_AEAD_RAND_SIZE-byte randoms for READ_RESPONSE / WRITE_REQUEST;
   the 6-byte session tail of poll directions is smaller, so the same
   buffer covers it) + up to FBSEC_AEAD_MAX_PROTECTED bytes of data
   (auth-only mode only). */
#define FBSEC_AEAD_AAD_MAX  (FBSEC_AEAD_AAD_PREFIX_SIZE \
                           + 2u * FBSEC_AEAD_RAND_SIZE \
                           + FBSEC_AEAD_MAX_PROTECTED)

/* ---- AAD construction ------------------------------------------------- */

/**
 * @brief Build the AAD into @p aad_out and return the length.
 *
 * If @p include_data is true, @p data is appended after any direction-
 * specific tail (this is the auth-only path where the data is
 * authenticated as part of the AAD). If false, no data is appended
 * (encryption path: data goes through GCM instead).
 *
 * READ_RESPONSE / WRITE_REQUEST place both randoms in the tail. Poll
 * directions have no AAD tail beyond the optional plaintext; the per-
 * frame counter is bound via the GCM nonce (nonce_base XOR counter)
 * and so does not need separate AAD coverage.
 */
static bool dir_takes_dual_randoms(uint8_t direction) {
  return direction == FBSEC_AEAD_DIR_READ_RESPONSE
      || direction == FBSEC_AEAD_DIR_WRITE_REQUEST;
}

static uint16_t aad_build(
  uint8_t  direction,
  uint8_t  key_id,
  uint16_t server_device_id,
  uint16_t client_device_id,
  uint32_t data_id,
  const uint8_t *client_random_rd,
  const uint8_t *server_random_rd,
  bool     include_data,
  const uint8_t *data,
  uint16_t       data_len,
  uint8_t       *aad_out)
{
  uint8_t *p = aad_out;

  /* Variant-sized prefix. The mechanism byte's high bit mirrors the
     key_id's high bit, so bit 7 of key_id end-to-end controls
     encrypt-vs-MAC for this single AAD computation. The remaining
     key_id bits (cyclic-arm at bit 6, reserved at bits 5..4, base id
     at bits 3..0) are covered by baking the full key_id byte into
     the prefix at offset 3. server_device_id then client_device_id
     each occupy FBSEC_AEAD_DEV_ID_SIZE bytes (1 on CANopen FD - the
     current default; 2 on the future 2-byte device_id variants). See
     doc/fieldbus_sim_secure_tunnel_spec.txt section 4.1. */
  *p++ = FBSEC_AEAD_PROTOCOL_VERSION;
  *p++ = FBSEC_AEAD_MECHANISM_FOR(key_id);
  *p++ = direction;
  *p++ = key_id;
  *p++ = (uint8_t)( server_device_id        & 0xFFu);
#if FBSEC_AEAD_DEV_ID_SIZE == 2
  *p++ = (uint8_t)((server_device_id >>  8) & 0xFFu);
#endif
  *p++ = (uint8_t)( client_device_id        & 0xFFu);
#if FBSEC_AEAD_DEV_ID_SIZE == 2
  *p++ = (uint8_t)((client_device_id >>  8) & 0xFFu);
#endif
  *p++ = (uint8_t)( data_id          & 0xFFu);
  *p++ = (uint8_t)((data_id   >>  8) & 0xFFu);
  *p++ = (uint8_t)((data_id   >> 16) & 0xFFu);
  *p++ = (uint8_t)((data_id   >> 24) & 0xFFu);
  *p++ = (uint8_t)( data_len         & 0xFFu);
  *p++ = (uint8_t)((data_len  >>  8) & 0xFFu);

  /* Tail. READ_RESPONSE / WRITE_REQUEST pin BOTH randoms into the AAD
     in the same order on both peers (client first, then server) so the
     AAD is identical regardless of which side computes it. The XOR
     nonce ensures uniqueness; the AAD-binding ensures integrity of the
     individual contributions. */
  if (dir_takes_dual_randoms(direction)
      && client_random_rd != NULL && server_random_rd != NULL) {
    memcpy(p, client_random_rd, FBSEC_AEAD_RAND_SIZE);
    p += FBSEC_AEAD_RAND_SIZE;
    memcpy(p, server_random_rd, FBSEC_AEAD_RAND_SIZE);
    p += FBSEC_AEAD_RAND_SIZE;
  }
  /* Poll directions intentionally have no session-metadata tail; the
     per-frame counter is bound via the GCM nonce. */
  if (include_data && data != NULL && data_len > 0u) {
    memcpy(p, data, data_len);
    p += data_len;
  }
  return (uint16_t)(p - aad_out);
}

/* ---- GCM helpers ------------------------------------------------------ */

/**
 * @brief Compute a truncated GCM tag with empty plaintext (MAC mode).
 */
static bool gcm_mac_only(
  const uint8_t  key[FBSEC_AEAD_KEY_SIZE],
  const uint8_t  nonce[FBSEC_AEAD_NONCE_SIZE],
  const uint8_t *aad,
  uint16_t       aad_len,
  uint8_t        tag_out[FBSEC_AEAD_TAG_SIZE])
{
  mbedtls_gcm_context gcm;
  uint8_t  full_tag[16];
  bool     ok = false;

  mbedtls_gcm_init(&gcm);
  if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES,
                         key, FBSEC_AEAD_KEY_SIZE * 8u) != 0) {
    goto done;
  }
  if (mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT,
                                0u,
                                nonce, FBSEC_AEAD_NONCE_SIZE,
                                aad, aad_len,
                                NULL, NULL,
                                sizeof full_tag, full_tag) != 0) {
    goto done;
  }
  memcpy(tag_out, full_tag, FBSEC_AEAD_TAG_SIZE);
  ok = true;

done:
  mbedtls_gcm_free(&gcm);
  return ok;
}

/**
 * @brief GCM encrypt-and-tag with plaintext input.
 */
static bool gcm_seal(
  const uint8_t  key[FBSEC_AEAD_KEY_SIZE],
  const uint8_t  nonce[FBSEC_AEAD_NONCE_SIZE],
  const uint8_t *aad,
  uint16_t       aad_len,
  const uint8_t *plaintext,
  uint16_t       pt_len,
  uint8_t       *ciphertext_out,
  uint8_t        tag_out[FBSEC_AEAD_TAG_SIZE])
{
  mbedtls_gcm_context gcm;
  uint8_t  full_tag[16];
  bool     ok = false;

  mbedtls_gcm_init(&gcm);
  if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES,
                         key, FBSEC_AEAD_KEY_SIZE * 8u) != 0) {
    goto done;
  }
  if (mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT,
                                pt_len,
                                nonce, FBSEC_AEAD_NONCE_SIZE,
                                aad, aad_len,
                                plaintext, ciphertext_out,
                                sizeof full_tag, full_tag) != 0) {
    goto done;
  }
  memcpy(tag_out, full_tag, FBSEC_AEAD_TAG_SIZE);
  ok = true;

done:
  mbedtls_gcm_free(&gcm);
  return ok;
}

/**
 * @brief GCM auth-decrypt; mbedtls accepts a truncated tag via tag_len.
 */
static bool gcm_open(
  const uint8_t  key[FBSEC_AEAD_KEY_SIZE],
  const uint8_t  nonce[FBSEC_AEAD_NONCE_SIZE],
  const uint8_t *aad,
  uint16_t       aad_len,
  const uint8_t *ciphertext,
  uint16_t       ct_len,
  const uint8_t  tag_in[FBSEC_AEAD_TAG_SIZE],
  uint8_t       *plaintext_out)
{
  mbedtls_gcm_context gcm;
  bool ok = false;

  mbedtls_gcm_init(&gcm);
  if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES,
                         key, FBSEC_AEAD_KEY_SIZE * 8u) != 0) {
    goto done;
  }
  if (mbedtls_gcm_auth_decrypt(&gcm, ct_len,
                               nonce, FBSEC_AEAD_NONCE_SIZE,
                               aad, aad_len,
                               tag_in, FBSEC_AEAD_TAG_SIZE,
                               ciphertext, plaintext_out) != 0) {
    goto done;
  }
  ok = true;

done:
  mbedtls_gcm_free(&gcm);
  return ok;
}

/* ---- Constant-time compare ------------------------------------------- */

static int const_time_diff(const uint8_t *a, const uint8_t *b, uint16_t n) {
  uint8_t  diff = 0u;
  for (uint16_t i = 0u; i < n; ++i) {
    diff |= (uint8_t)(a[i] ^ b[i]);
  }
  return (int)diff;
}

/* ---- Public API: nonce helper --------------------------------------- */

void fbsec_aead_xor_nonce(
  const uint8_t client_random_rd[FBSEC_AEAD_RAND_SIZE],
  const uint8_t server_random_rd[FBSEC_AEAD_RAND_SIZE],
  uint8_t       nonce_out[FBSEC_AEAD_NONCE_SIZE])
{
  for (uint16_t i = 0u; i < FBSEC_AEAD_NONCE_SIZE; ++i) {
    nonce_out[i] = (uint8_t)(client_random_rd[i] ^ server_random_rd[i]);
  }
}

/* ---- Public API: MAC-only ------------------------------------------- */

bool fbsec_aead_compute_tag(
  const uint8_t  key[FBSEC_AEAD_KEY_SIZE],
  const uint8_t  nonce[FBSEC_AEAD_NONCE_SIZE],
  uint8_t        direction,
  uint8_t        key_id,
  uint16_t       server_device_id,
  uint16_t       client_device_id,
  uint32_t       data_id,
  const uint8_t *client_random_rd,
  const uint8_t *server_random_rd,
  const uint8_t *data,
  uint16_t       data_len,
  uint8_t        tag_out[FBSEC_AEAD_TAG_SIZE])
{
  if (key == NULL || nonce == NULL || tag_out == NULL) return false;
  if (data_len > FBSEC_AEAD_MAX_PROTECTED)               return false;

  uint8_t  aad[FBSEC_AEAD_AAD_MAX];
  uint16_t aad_len = aad_build(direction, key_id,
                               server_device_id, client_device_id, data_id,
                               client_random_rd, server_random_rd,
                               true, data, data_len, aad);
  return gcm_mac_only(key, nonce, aad, aad_len, tag_out);
}

bool fbsec_aead_verify_tag(
  const uint8_t  key[FBSEC_AEAD_KEY_SIZE],
  const uint8_t  nonce[FBSEC_AEAD_NONCE_SIZE],
  uint8_t        direction,
  uint8_t        key_id,
  uint16_t       server_device_id,
  uint16_t       client_device_id,
  uint32_t       data_id,
  const uint8_t *client_random_rd,
  const uint8_t *server_random_rd,
  const uint8_t *data,
  uint16_t       data_len,
  const uint8_t  tag_in[FBSEC_AEAD_TAG_SIZE])
{
  uint8_t expected[FBSEC_AEAD_TAG_SIZE];
  if (tag_in == NULL) return false;
  if (!fbsec_aead_compute_tag(key, nonce, direction, key_id,
                            server_device_id, client_device_id, data_id,
                            client_random_rd, server_random_rd,
                            data, data_len, expected)) {
    return false;
  }
  return const_time_diff(expected, tag_in, FBSEC_AEAD_TAG_SIZE) == 0;
}

/* ---- Public API: AEAD seal / open ----------------------------------- */

bool fbsec_aead_seal(
  const uint8_t  key[FBSEC_AEAD_KEY_SIZE],
  const uint8_t  nonce[FBSEC_AEAD_NONCE_SIZE],
  uint8_t        direction,
  uint8_t        key_id,
  uint16_t       server_device_id,
  uint16_t       client_device_id,
  uint32_t       data_id,
  const uint8_t *client_random_rd,
  const uint8_t *server_random_rd,
  const uint8_t *plaintext,
  uint16_t       pt_len,
  uint8_t       *ciphertext_out,
  uint8_t        tag_out[FBSEC_AEAD_TAG_SIZE])
{
  if (key == NULL || nonce == NULL || tag_out == NULL)   return false;
  if (pt_len > FBSEC_AEAD_MAX_PROTECTED)                   return false;
  if (pt_len > 0u && (plaintext == NULL || ciphertext_out == NULL)) return false;

  uint8_t aad[FBSEC_AEAD_AAD_MAX];

  if (FBSEC_AEAD_KEYID_ENCRYPT(key_id)) {
    /* Real AEAD: data lives in GCM, NOT in the AAD tail. */
    uint16_t aad_len = aad_build(direction, key_id,
                                 server_device_id, client_device_id, data_id,
                                 client_random_rd, server_random_rd,
                                 false, NULL, 0u, aad);
    return gcm_seal(key, nonce, aad, aad_len,
                    plaintext, pt_len,
                    ciphertext_out, tag_out);
  }
  /* Auth-only: data goes into AAD; ciphertext_out is a verbatim copy. */
  uint16_t aad_len = aad_build(direction, key_id,
                               server_device_id, client_device_id, data_id,
                               client_random_rd, server_random_rd,
                               true, plaintext, pt_len, aad);
  if (!gcm_mac_only(key, nonce, aad, aad_len, tag_out)) return false;
  if (pt_len > 0u) memcpy(ciphertext_out, plaintext, pt_len);
  return true;
}

bool fbsec_aead_open(
  const uint8_t  key[FBSEC_AEAD_KEY_SIZE],
  const uint8_t  nonce[FBSEC_AEAD_NONCE_SIZE],
  uint8_t        direction,
  uint8_t        key_id,
  uint16_t       server_device_id,
  uint16_t       client_device_id,
  uint32_t       data_id,
  const uint8_t *client_random_rd,
  const uint8_t *server_random_rd,
  const uint8_t *ciphertext,
  uint16_t       ct_len,
  const uint8_t  tag_in[FBSEC_AEAD_TAG_SIZE],
  uint8_t       *plaintext_out)
{
  if (key == NULL || nonce == NULL || tag_in == NULL)    return false;
  if (ct_len > FBSEC_AEAD_MAX_PROTECTED)                   return false;
  if (ct_len > 0u && (ciphertext == NULL || plaintext_out == NULL)) return false;

  uint8_t aad[FBSEC_AEAD_AAD_MAX];

  if (FBSEC_AEAD_KEYID_ENCRYPT(key_id)) {
    uint16_t aad_len = aad_build(direction, key_id,
                                 server_device_id, client_device_id, data_id,
                                 client_random_rd, server_random_rd,
                                 false, NULL, 0u, aad);
    return gcm_open(key, nonce, aad, aad_len,
                    ciphertext, ct_len, tag_in, plaintext_out);
  }
  /* Auth-only: re-derive expected tag from AAD-with-data, compare. */
  uint8_t  expected[FBSEC_AEAD_TAG_SIZE];
  uint16_t aad_len = aad_build(direction, key_id,
                               server_device_id, client_device_id, data_id,
                               client_random_rd, server_random_rd,
                               true, ciphertext, ct_len, aad);
  if (!gcm_mac_only(key, nonce, aad, aad_len, expected)) return false;
  if (const_time_diff(expected, tag_in, FBSEC_AEAD_TAG_SIZE) != 0) return false;
  if (ct_len > 0u) memcpy(plaintext_out, ciphertext, ct_len);
  return true;
}

/* EOF */
