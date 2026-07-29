/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    fbsec_descriptor.c
 * @brief   SOFA CiA 720 capability + status descriptor, implementation.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V2.1 of 29-JUL-2026
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

static void put_u16le(uint8_t *p, uint16_t v)
{
  p[0] = (uint8_t)(v & 0xFFu);
  p[1] = (uint8_t)((v >> 8) & 0xFFu);
}

static uint16_t get_u16le(const uint8_t *p)
{
  return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

/* ---- C000h capabilities ---------------------------------------------- */

void fbsec_descriptor_build_caps(uint8_t live_id_flags, fbsec_caps_t *out)
{
  if (out == NULL)
  {
    return;
  }

  out->highest_sub = FBSEC_DESC_CAP_SUB_MAX;

  /* Profile 00h Custom in every build: the device is deliberately partial
   * (no X509, no AEAD generic access, no function-command AEAD twin), so it
   * makes no numbered-profile conformance claim. Capability level 0; the
   * concrete level advertisement is a separate item. */
  out->type_word = FBSEC_TYPEWORD(FBSEC_PROFILE_CUSTOM, 0u);

#if FBSEC_FEATURE_ASYM
  /* Asymmetric build: advertise AEAD | RPK, the Ed25519 signature
   * algorithm, and the voucher gate when the authorized model is compiled. */
  out->sig_alg     = FBSEC_DESC_SIG_ED25519;
  out->mechanisms  = (uint16_t)(FBSEC_MECH_AEAD | FBSEC_MECH_RPK);
  /* Sub 06h reports live identity state (b0 IDevID, b1 LDevID); the caller
   * supplies it from the asym store so an LDevID export shows up at once. */
  out->id_flags       = live_id_flags;
  out->handover_model = FBSEC_DESC_HANDOVER_TOFU
                      | FBSEC_DESC_HANDOVER_TOKEN
#if FBSEC_HANDOVER_AUTHORIZED
                      | FBSEC_DESC_HANDOVER_VOUCHER
#endif
                      ;
#else
  /* AEAD-only build: mechanisms bitmap = AEAD only, no RPK, no identity
   * artifacts, TOFU gate. The demo ships with keys already loaded and runs
   * as if a claim-on-first-use handover happened in the past. */
  (void)live_id_flags;
  out->sig_alg        = 0u;
  out->mechanisms     = (uint16_t)FBSEC_MECH_AEAD;
  out->id_flags       = 0u;
  out->handover_model = FBSEC_DESC_HANDOVER_TOFU;
#endif

  /* Sub 02h: AEAD bitmap (byte 0) + tag length (byte 1). */
  out->aead_and_tag = (uint32_t)desc_aead_bitmap() |
                      (((uint32_t)(FBSEC_AEAD_TAG_LEN_BYTES) & 0xFFu) << 8);

  /* Sub 03h: key derivation functions. HKDF-SHA-256 in every build. */
  out->kdf = FBSEC_DESC_KDF_HKDF_SHA256;

  /* Sub 05h: symmetric key levels this device supports. */
  out->sym_levels = (uint8_t)(FBSEC_DESC_SYMLVL_PROVISIONING
                            | FBSEC_DESC_SYMLVL_INTEGRATOR
                            | FBSEC_DESC_SYMLVL_OPERATOR);
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
      put_u32le(out, c->aead_and_tag);
      return 4u;
    case 0x03u:
      if (out_max < 2u) { return 0u; }
      put_u16le(out, c->kdf);
      return 2u;
    case 0x04u:
      if (out_max < 2u) { return 0u; }
      put_u16le(out, c->sig_alg);
      return 2u;
    case 0x05u:
      if (out_max < 1u) { return 0u; }
      out[0] = c->sym_levels;
      return 1u;
    case 0x06u:
      if (out_max < 1u) { return 0u; }
      out[0] = c->id_flags;
      return 1u;
    case 0x07u:
      if (out_max < 1u) { return 0u; }
      out[0] = c->handover_model;
      return 1u;
    case 0x08u:
      if (out_max < 2u) { return 0u; }
      put_u16le(out, c->mechanisms);
      return 2u;
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
      c->aead_and_tag = get_u32le(in);
      return true;
    case 0x03u:
      if (len != 2u) { return false; }
      c->kdf = get_u16le(in);
      return true;
    case 0x04u:
      if (len != 2u) { return false; }
      c->sig_alg = get_u16le(in);
      return true;
    case 0x05u:
      if (len != 1u) { return false; }
      c->sym_levels = in[0];
      return true;
    case 0x06u:
      if (len != 1u) { return false; }
      c->id_flags = in[0];
      return true;
    case 0x07u:
      if (len != 1u) { return false; }
      c->handover_model = in[0];
      return true;
    case 0x08u:
      if (len != 2u) { return false; }
      c->mechanisms = get_u16le(in);
      return true;
    default:
      return false;
  }
}

/* ---- C001h status ---------------------------------------------------- */

/* The one claim gate active on this build. Exactly one gate is active at a
 * time; the authorized asymmetric build uses the voucher gate, an
 * asymmetric build without it the token gate, an AEAD-only build TOFU. */
static uint8_t desc_active_gate(void)
{
#if FBSEC_FEATURE_ASYM
#if FBSEC_HANDOVER_AUTHORIZED
  return FBSEC_DESC_HANDOVER_VOUCHER;
#else
  return FBSEC_DESC_HANDOVER_TOKEN;
#endif
#else
  return FBSEC_DESC_HANDOVER_TOFU;
#endif
}

void fbsec_descriptor_build_status(uint8_t commissioning,
                                   uint8_t keys_installed,
                                   uint8_t identities,
                                   fbsec_status_t *out)
{
  if (out == NULL)
  {
    return;
  }
  out->highest_sub    = FBSEC_DESC_STAT_SUB_MAX;
  out->commissioning  = commissioning;
  out->active_gate    = desc_active_gate();
  out->keys_installed = keys_installed;
  /* Active AEAD algorithm and tag length, same encoding as C000h sub 02h. */
  out->active_aead    = (uint32_t)desc_aead_bitmap() |
                        (((uint32_t)(FBSEC_AEAD_TAG_LEN_BYTES) & 0xFFu) << 8);
  out->identities     = identities;
}

uint16_t fbsec_status_serialize_sub(const fbsec_status_t *s, uint8_t sub,
                                    uint8_t *out, uint16_t out_max)
{
  if ((s == NULL) || (out == NULL))
  {
    return 0u;
  }

  switch (sub)
  {
    case 0x00u:
      if (out_max < 1u) { return 0u; }
      out[0] = s->highest_sub;
      return 1u;
    case 0x01u:
      if (out_max < 1u) { return 0u; }
      out[0] = s->commissioning;
      return 1u;
    case 0x02u:
      if (out_max < 1u) { return 0u; }
      out[0] = s->active_gate;
      return 1u;
    case 0x03u:
      if (out_max < 1u) { return 0u; }
      out[0] = s->keys_installed;
      return 1u;
    case 0x04u:
      if (out_max < 4u) { return 0u; }
      put_u32le(out, s->active_aead);
      return 4u;
    case 0x05u:
      if (out_max < 1u) { return 0u; }
      out[0] = s->identities;
      return 1u;
    default:
      return 0u;
  }
}

bool fbsec_status_deserialize_sub(fbsec_status_t *s, uint8_t sub,
                                  const uint8_t *in, uint16_t len)
{
  if ((s == NULL) || (in == NULL))
  {
    return false;
  }

  switch (sub)
  {
    case 0x00u:
      if (len != 1u) { return false; }
      s->highest_sub = in[0];
      return true;
    case 0x01u:
      if (len != 1u) { return false; }
      s->commissioning = in[0];
      return true;
    case 0x02u:
      if (len != 1u) { return false; }
      s->active_gate = in[0];
      return true;
    case 0x03u:
      if (len != 1u) { return false; }
      s->keys_installed = in[0];
      return true;
    case 0x04u:
      if (len != 4u) { return false; }
      s->active_aead = get_u32le(in);
      return true;
    case 0x05u:
      if (len != 1u) { return false; }
      s->identities = in[0];
      return true;
    default:
      return false;
  }
}

/* ---- Client-side predicates ------------------------------------------ */

bool fbsec_caps_supports_voucher_handover(const fbsec_caps_t *c)
{
  return (c != NULL) &&
         ((c->handover_model & FBSEC_DESC_HANDOVER_VOUCHER) != 0u);
}

bool fbsec_caps_has_ed25519(const fbsec_caps_t *c)
{
  return (c != NULL) && ((c->sig_alg & FBSEC_DESC_SIG_ED25519) != 0u);
}

/* EOF */
