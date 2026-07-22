/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    fbsec_descriptor.c
 * @brief   SOFA CiA 720 capability + status descriptor, implementation.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V2.0 of 22-JUL-2026
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#include "fbsec_descriptor.h"

/* Compile-time AEAD primitive bitmap. */
static uint8_t desc_aead_bitmap(void)
{
  uint8_t b = 0u;
#if FBSEC_AEAD_AES128_GCM
  b |= FBSEC_DESC_AEAD_AES128_GCM;
#endif
#if FBSEC_AEAD_AES256_GCM
  b |= FBSEC_DESC_AEAD_AES256_GCM;
#endif
#if FBSEC_AEAD_ASCON_128
  b |= FBSEC_DESC_AEAD_ASCON128;
#endif
#if FBSEC_AEAD_CHACHA20_POLY1305
  b |= FBSEC_DESC_AEAD_CHACHA20;
#endif
  return b;
}

/* Little-endian U32 store / load helpers. */
static void put_u32le(uint8_t *p, uint32_t v)
{
  p[0] = (uint8_t)(v & 0xFFu);
  p[1] = (uint8_t)((v >> 8) & 0xFFu);
  p[2] = (uint8_t)((v >> 16) & 0xFFu);
  p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

static uint32_t get_u32le(const uint8_t *p)
{
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
         ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* ---- C000h capabilities ---------------------------------------------- */

void fbsec_descriptor_build_caps(fbsec_caps_t *out)
{
  if (out == NULL)
  {
    return;
  }

  out->highest_sub = FBSEC_DESC_CAP_SUB_MAX;

  /* Pass 1 is AEAD-only: profile 00h Custom, capability level 0,
   * restore depth 0, mechanisms bitmap = AEAD only, suite generation 0.
   * RPK and X509 are never advertised this pass, even in an asym build. */
  out->type_word = FBSEC_TYPEWORD(FBSEC_PROFILE_CUSTOM, 0u, 0u,
                                  FBSEC_MECH_AEAD, 0u);

  /* Sub 02h: session protocols. FBsec only this pass. */
  out->session_proto = FBSEC_DESC_PROTO_FBSEC;

  /* Sub 03h: AEAD bitmap (byte 0) + tag length (byte 1). */
  out->aead_and_tag = (uint32_t)desc_aead_bitmap() |
                      (((uint32_t)(FBSEC_AEAD_TAG_LEN_BYTES) & 0xFFu) << 8);

  /* Sub 04h..06h: no RPK, no identity artifacts, TOFU handover.
   * The demo ships with keys already loaded and runs as if a
   * claim-on-first-use handover happened in the past. */
  out->rpk_alg        = FBSEC_DESC_RPK_NONE;
  out->id_flags       = 0u;
  out->handover_model = FBSEC_DESC_HANDOVER_TOFU;

  /* Sub 07h: manufacturer-specific capabilities. */
  out->mfg_caps = 0u;
}

uint16_t fbsec_caps_serialize_sub(const fbsec_caps_t *c, uint8_t sub,
                                  uint8_t *out, uint16_t out_max)
{
  if ((c == NULL) || (out == NULL))
  {
    return 0u;
  }

  switch (sub)
  {
    case 0x00u:
      if (out_max < 1u) { return 0u; }
      out[0] = c->highest_sub;
      return 1u;
    case 0x01u:
      if (out_max < 4u) { return 0u; }
      put_u32le(out, c->type_word);
      return 4u;
    case 0x02u:
      if (out_max < 4u) { return 0u; }
      put_u32le(out, c->session_proto);
      return 4u;
    case 0x03u:
      if (out_max < 4u) { return 0u; }
      put_u32le(out, c->aead_and_tag);
      return 4u;
    case 0x04u:
      if (out_max < 1u) { return 0u; }
      out[0] = c->rpk_alg;
      return 1u;
    case 0x05u:
      if (out_max < 1u) { return 0u; }
      out[0] = c->id_flags;
      return 1u;
    case 0x06u:
      if (out_max < 1u) { return 0u; }
      out[0] = c->handover_model;
      return 1u;
    case 0x07u:
      if (out_max < 4u) { return 0u; }
      put_u32le(out, c->mfg_caps);
      return 4u;
    default:
      return 0u;
  }
}

bool fbsec_caps_deserialize_sub(fbsec_caps_t *c, uint8_t sub,
                                const uint8_t *in, uint16_t len)
{
  if ((c == NULL) || (in == NULL))
  {
    return false;
  }

  switch (sub)
  {
    case 0x00u:
      if (len != 1u) { return false; }
      c->highest_sub = in[0];
      return true;
    case 0x01u:
      if (len != 4u) { return false; }
      c->type_word = get_u32le(in);
      return true;
    case 0x02u:
      if (len != 4u) { return false; }
      c->session_proto = get_u32le(in);
      return true;
    case 0x03u:
      if (len != 4u) { return false; }
      c->aead_and_tag = get_u32le(in);
      return true;
    case 0x04u:
      if (len != 1u) { return false; }
      c->rpk_alg = in[0];
      return true;
    case 0x05u:
      if (len != 1u) { return false; }
      c->id_flags = in[0];
      return true;
    case 0x06u:
      if (len != 1u) { return false; }
      c->handover_model = in[0];
      return true;
    case 0x07u:
      if (len != 4u) { return false; }
      c->mfg_caps = get_u32le(in);
      return true;
    default:
      return false;
  }
}

/* ---- C001h status ---------------------------------------------------- */

void fbsec_descriptor_build_status(uint8_t commissioning,
                                   uint8_t keys_installed,
                                   fbsec_status_t *out)
{
  if (out == NULL)
  {
    return;
  }
  out->highest_sub    = FBSEC_DESC_STAT_SUB_MAX;
  out->commissioning  = commissioning;
  out->keys_installed = keys_installed;
}

uint16_t fbsec_status_serialize_sub(const fbsec_status_t *s, uint8_t sub,
                                    uint8_t *out, uint16_t out_max)
{
  if ((s == NULL) || (out == NULL) || (out_max < 1u))
  {
    return 0u;
  }

  switch (sub)
  {
    case 0x00u:
      out[0] = s->highest_sub;
      return 1u;
    case 0x01u:
      out[0] = s->commissioning;
      return 1u;
    case 0x02u:
      out[0] = s->keys_installed;
      return 1u;
    default:
      return 0u;
  }
}

bool fbsec_status_deserialize_sub(fbsec_status_t *s, uint8_t sub,
                                  const uint8_t *in, uint16_t len)
{
  if ((s == NULL) || (in == NULL) || (len != 1u))
  {
    return false;
  }

  switch (sub)
  {
    case 0x00u:
      s->highest_sub = in[0];
      return true;
    case 0x01u:
      s->commissioning = in[0];
      return true;
    case 0x02u:
      s->keys_installed = in[0];
      return true;
    default:
      return false;
  }
}

/* ---- Client-side predicates ------------------------------------------ */

bool fbsec_caps_supports_signed_fbsec(const fbsec_caps_t *c)
{
  return (c != NULL) &&
         ((c->session_proto & FBSEC_DESC_PROTO_SIGNED_FBSEC) != 0u) &&
         ((c->id_flags & FBSEC_DESC_ID_SIGNED_FBSEC) != 0u);
}

bool fbsec_caps_supports_voucher_handover(const fbsec_caps_t *c)
{
  return (c != NULL) &&
         ((c->handover_model & FBSEC_DESC_HANDOVER_VOUCHER) != 0u);
}

bool fbsec_caps_has_ed25519(const fbsec_caps_t *c)
{
  return (c != NULL) && (c->rpk_alg == FBSEC_DESC_RPK_ED25519);
}

/* EOF */
