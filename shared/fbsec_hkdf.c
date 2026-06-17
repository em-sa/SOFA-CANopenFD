/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    fbsec_hkdf.c
 * @brief   SOFA HKDF-SHA256 (RFC 5869), implementation.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 03-MAY-2026
 *
 * HMAC-SHA256 + HKDF Extract / Expand on top of mbedtls/sha256.h. No
 * dynamic allocation; one stack-resident mbedtls_sha256_context per
 * inner SHA call.
 *
 * Port of MCOPSecureAccess/MCO_CiA401__User_Secure/sod_hkdf.c (already
 * Apache 2.0 licensed, reused here verbatim except for the function
 * name namespace rename `sod_hkdf_*` -> `fbsec_hkdf_*`).
 *
 * RFC 5869 references:
 *   2.2 Step 1 (Extract): PRK = HMAC-Hash(salt, IKM)
 *   2.3 Step 2 (Expand): T(0) = empty;
 *                        T(i) = HMAC-Hash(PRK, T(i-1) | info | i)
 *                        OKM  = T(1) | T(2) | ... | T(N)
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#include "fbsec_hkdf.h"

#include <string.h>

#include "mbedtls/sha256.h"

#define FBSEC_HKDF_BLOCK_LEN  64u   /* SHA-256 internal block size */

/**
 * @brief One-shot SHA-256 over a single contiguous buffer.
 */
static bool fbsec_sha256(
  const uint8_t *data,
  size_t         len,
  uint8_t        out[FBSEC_HKDF_HASH_LEN])
{
  mbedtls_sha256_context ctx;
  int rc;

  mbedtls_sha256_init(&ctx);
  rc = mbedtls_sha256_starts(&ctx, 0);                /* 0 = SHA-256, not SHA-224 */
  if (rc == 0 && data != NULL && len > 0u) {
    rc = mbedtls_sha256_update(&ctx, data, len);
  }
  if (rc == 0) {
    rc = mbedtls_sha256_finish(&ctx, out);
  }
  mbedtls_sha256_free(&ctx);
  return rc == 0;
}

/**
 * @brief HMAC-SHA256, two-pass plain implementation (FIPS 198-1).
 *
 * Three message segments are accepted so the Expand step can feed
 * (T(i-1), info, [i]) without copying into a single buffer.
 */
static bool fbsec_hmac_sha256(
  const uint8_t *key,   size_t key_len,
  const uint8_t *msg_a, size_t msg_a_len,
  const uint8_t *msg_b, size_t msg_b_len,
  const uint8_t *msg_c, size_t msg_c_len,
  uint8_t        mac[FBSEC_HKDF_HASH_LEN])
{
  uint8_t  k0[FBSEC_HKDF_BLOCK_LEN];
  uint8_t  ipad[FBSEC_HKDF_BLOCK_LEN];
  uint8_t  opad[FBSEC_HKDF_BLOCK_LEN];
  uint8_t  inner[FBSEC_HKDF_HASH_LEN];
  uint8_t  outer_concat[FBSEC_HKDF_BLOCK_LEN + FBSEC_HKDF_HASH_LEN];
  mbedtls_sha256_context ctx;
  int      rc;

  /* Step 1: derive K0 (block-sized HMAC key). */
  memset(k0, 0, sizeof k0);
  if (key_len > FBSEC_HKDF_BLOCK_LEN) {
    if (!fbsec_sha256(key, key_len, k0)) return false;
  } else if (key_len > 0u) {
    memcpy(k0, key, key_len);
  }

  /* Step 2: ipad / opad. */
  for (size_t i = 0u; i < FBSEC_HKDF_BLOCK_LEN; ++i) {
    ipad[i] = (uint8_t)(k0[i] ^ 0x36u);
    opad[i] = (uint8_t)(k0[i] ^ 0x5Cu);
  }

  /* Step 3: inner = H(ipad || msg). Streamed to avoid allocating a
     concatenated buffer. */
  mbedtls_sha256_init(&ctx);
  rc = mbedtls_sha256_starts(&ctx, 0);
  if (rc == 0) rc = mbedtls_sha256_update(&ctx, ipad, FBSEC_HKDF_BLOCK_LEN);
  if (rc == 0 && msg_a != NULL && msg_a_len > 0u) {
    rc = mbedtls_sha256_update(&ctx, msg_a, msg_a_len);
  }
  if (rc == 0 && msg_b != NULL && msg_b_len > 0u) {
    rc = mbedtls_sha256_update(&ctx, msg_b, msg_b_len);
  }
  if (rc == 0 && msg_c != NULL && msg_c_len > 0u) {
    rc = mbedtls_sha256_update(&ctx, msg_c, msg_c_len);
  }
  if (rc == 0) rc = mbedtls_sha256_finish(&ctx, inner);
  mbedtls_sha256_free(&ctx);
  if (rc != 0) return false;

  /* Step 4: outer = H(opad || inner). */
  memcpy(&outer_concat[0],                  opad,  FBSEC_HKDF_BLOCK_LEN);
  memcpy(&outer_concat[FBSEC_HKDF_BLOCK_LEN], inner, FBSEC_HKDF_HASH_LEN);
  if (!fbsec_sha256(outer_concat, sizeof outer_concat, mac)) return false;

  /* Wipe transient material. */
  memset(k0,           0, sizeof k0);
  memset(ipad,         0, sizeof ipad);
  memset(opad,         0, sizeof opad);
  memset(inner,        0, sizeof inner);
  memset(outer_concat, 0, sizeof outer_concat);
  return true;
}

bool fbsec_hkdf_sha256(
  const uint8_t *ikm,  size_t ikm_len,
  const uint8_t *salt, size_t salt_len,
  const uint8_t *info, size_t info_len,
  uint8_t       *okm,  size_t okm_len)
{
  uint8_t  prk[FBSEC_HKDF_HASH_LEN];
  uint8_t  zero_salt[FBSEC_HKDF_HASH_LEN];
  uint8_t  t[FBSEC_HKDF_HASH_LEN];
  size_t   produced = 0u;
  uint8_t  counter  = 0u;
  bool     ok       = true;
  size_t   t_len    = 0u;       /* T(0) is empty */

  if (ikm == NULL || ikm_len == 0u)              return false;
  if (okm == NULL || okm_len == 0u)              return false;
  if (okm_len > (255u * FBSEC_HKDF_HASH_LEN))      return false;
  if (info == NULL && info_len > 0u)             return false;

  /* RFC 5869 2.2: a zero-length salt is treated as HashLen zero bytes. */
  if (salt == NULL || salt_len == 0u) {
    memset(zero_salt, 0, sizeof zero_salt);
    salt     = zero_salt;
    salt_len = sizeof zero_salt;
  }

  /* Extract: PRK = HMAC-SHA256(salt, IKM). */
  if (!fbsec_hmac_sha256(salt, salt_len,
                       ikm,  ikm_len,
                       NULL, 0u,
                       NULL, 0u,
                       prk)) {
    ok = false;
    goto wipe;
  }

  /* Expand: T(i) = HMAC-SHA256(PRK, T(i-1) || info || i). */
  while (produced < okm_len) {
    counter = (uint8_t)(counter + 1u);
    if (!fbsec_hmac_sha256(prk, sizeof prk,
                         t,        t_len,
                         info,     info_len,
                         &counter, 1u,
                         t)) {
      ok = false;
      goto wipe;
    }
    size_t take = okm_len - produced;
    if (take > FBSEC_HKDF_HASH_LEN) take = FBSEC_HKDF_HASH_LEN;
    memcpy(&okm[produced], t, take);
    produced += take;
    t_len = FBSEC_HKDF_HASH_LEN;
  }

wipe:
  memset(prk,       0, sizeof prk);
  memset(t,         0, sizeof t);
  memset(zero_salt, 0, sizeof zero_salt);
  return ok;
}

/* EOF */
