/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    fbsec_asym.c
 * @brief   SOFA optional Ed25519 identity primitive (RFC 8032).
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 19-JUL-2026
 *
 * Implementation of shared/fbsec_asym.h on top of vendored Monocypher.
 * The Monocypher headers are included ONLY here so the rest of SOFA sees
 * a stable, primitive-neutral API.
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#include "fbsec_asym.h"

#if FBSEC_FEATURE_ASYM

#include <string.h>

#include "monocypher.h"
#include "monocypher-ed25519.h"

bool fbsec_asym_keygen(const uint8_t seed[FBSEC_ASYM_SEED_SIZE],
                       fbsec_keypair_t *out)
{
  uint8_t seed_copy[FBSEC_ASYM_SEED_SIZE];

  if ((seed == NULL) || (out == NULL))
  {
    return false;
  }

  /* crypto_ed25519_key_pair() wipes its seed argument in place, so it
   * must be given a mutable copy - the caller's seed stays intact. */
  memcpy(seed_copy, seed, FBSEC_ASYM_SEED_SIZE);
  crypto_ed25519_key_pair(out->priv, out->pub, seed_copy);
  crypto_wipe(seed_copy, sizeof(seed_copy));

  return true;
}

bool fbsec_asym_sign(const fbsec_keypair_t *kp,
                     const uint8_t *msg, uint16_t msg_len,
                     uint8_t sig_out[FBSEC_ASYM_SIG_SIZE])
{
  if ((kp == NULL) || (sig_out == NULL) || ((msg == NULL) && (msg_len != 0u)))
  {
    return false;
  }

  crypto_ed25519_sign(sig_out, kp->priv, msg, (size_t)msg_len);
  return true;
}

bool fbsec_asym_verify(const fbsec_pubkey_t *pk,
                       const uint8_t *msg, uint16_t msg_len,
                       const uint8_t sig[FBSEC_ASYM_SIG_SIZE])
{
  if ((pk == NULL) || (sig == NULL) || ((msg == NULL) && (msg_len != 0u)))
  {
    return false;
  }

  /* crypto_ed25519_check returns 0 on a valid signature, non-zero otherwise. */
  return (crypto_ed25519_check(sig, pk->pub, msg, (size_t)msg_len) == 0);
}

uint16_t fbsec_asym_transcript(uint8_t role_dir,
                               const uint8_t *body, uint16_t body_len,
                               uint8_t *out, uint16_t out_max)
{
  uint16_t total;

  if ((out == NULL) || ((body == NULL) && (body_len != 0u)))
  {
    return 0u;
  }

  total = (uint16_t)(FBSEC_ASYM_TRANSCRIPT_OVERHEAD + body_len);
  if (out_max < total)
  {
    return 0u;
  }

  out[0] = FBSEC_ASYM_TRANSCRIPT_VERSION;
  out[1] = role_dir;
  if (body_len != 0u)
  {
    memcpy(&out[FBSEC_ASYM_TRANSCRIPT_OVERHEAD], body, body_len);
  }

  return total;
}

#endif /* FBSEC_FEATURE_ASYM */

/* EOF */
