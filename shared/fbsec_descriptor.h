/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    fbsec_descriptor.h
 * @brief   SOFA CiA 720 capability + status descriptor (read-only, unauth).
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V2.1 of 29-JUL-2026
 *
 * Builds and (de)serializes the two base descriptors of the CiA 720
 * security object dictionary:
 *
 *   - C000h Security profile and capabilities (what the build CAN do).
 *   - C001h Security status (what is CURRENTLY true).
 *
 * Both are READ-ONLY and UNAUTHENTICATED: a client reads them cold,
 * before any key or identity exists, then fails closed on features the
 * peer does not advertise. As of the CiA 720 migration the two
 * records no longer share a shape: C000h carries a security type word and
 * a set of capability bitmaps; C001h reports the active configuration.
 * They therefore have separate build / serialize / deserialize entry
 * points.
 *
 * This module is ALWAYS compiled. An AEAD-only build (FBSEC_FEATURE_ASYM
 * == 0) advertises the AEAD mechanism alone; an FBSEC_FEATURE_ASYM build
 * additionally advertises RPK (Ed25519 identity, signed secure objects at
 * C020h/C021h/C022h/C028h/C02Fh/C042h/C049h). X509 is never advertised yet.
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#ifndef FBSEC_DESCRIPTOR_H
#define FBSEC_DESCRIPTOR_H

#include "fbsec_config.h"

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- OD record indices / sub-index ranges ---------------------------- */

#define FBSEC_DESC_CAP_INDEX     0xC000u  /* capability record            */
#define FBSEC_DESC_STAT_INDEX    0xC001u  /* status record                */
#define FBSEC_DESC_CAP_SUB_MAX   0x08u    /* highest C000h sub-index       */
#define FBSEC_DESC_STAT_SUB_MAX  0x05u    /* highest C001h sub-index        */

/* ---- C000h sub 01h: security type word (U32), mirrors CiA 1301 1000h -- */
/* bits 11:0  security profile number (0 = no standard profile)
 * bits 15:12 capability level (0..3 => C0..C3)
 * bits 31:16 additional information, defined by the reported profile.
 * Per the "Capability levels and profiles" section of CiA 720-1 and the
 * "Object C000h" section of CiA 720-2.                                     */

#define FBSEC_PROFILE_CUSTOM        0x00u
#define FBSEC_PROFILE_OPEN          0x01u
#define FBSEC_PROFILE_CLAIMED       0x02u
#define FBSEC_PROFILE_AUTHORIZED    0x03u
#define FBSEC_PROFILE_IDENTIFIED    0x04u
#define FBSEC_PROFILE_CONFIDENTIAL  0x05u

#define FBSEC_TYPEWORD(profile, level)                            \
  (  ((uint32_t)(profile) & 0x0FFFu)                              \
   | (((uint32_t)(level)   & 0x0Fu) << 12) )

#define FBSEC_TYPEWORD_PROFILE(tw)  ((uint16_t)((tw) & 0x0FFFu))
#define FBSEC_TYPEWORD_LEVEL(tw)    ((uint8_t)(((tw) >> 12) & 0x0Fu))

/* ---- C000h sub 02h: AEAD algorithms (low byte) + tag length (byte 1) - */
/* One bit per AEAD algorithm of the CiA 720-1 Table 5 registry
 * (01h AES-128-GCM, 02h AES-256-GCM). Byte 1 carries the tag length.       */
#define FBSEC_DESC_AEAD_AES128_GCM     0x01u
#define FBSEC_DESC_AEAD_AES256_GCM     0x02u
#define FBSEC_DESC_AEAD_ASCON128       0x04u
#define FBSEC_DESC_AEAD_CHACHA20       0x08u

/* ---- C000h sub 03h: key derivation functions (U16 bitmap) ------------ */
#define FBSEC_DESC_KDF_HKDF_SHA256     0x0001u  /* registry id 10h */

/* ---- C000h sub 04h: signature algorithms (U16 bitmap) ---------------- */
#define FBSEC_DESC_SIG_ED25519         0x0001u  /* registry id 30h */

/* ---- C000h sub 05h: symmetric key levels supported (U8 bitmap) ------- */
#define FBSEC_DESC_SYMLVL_PROVISIONING 0x01u
#define FBSEC_DESC_SYMLVL_INTEGRATOR   0x02u
#define FBSEC_DESC_SYMLVL_OPERATOR     0x04u

/* ---- C000h sub 06h: asymmetric key presence (U8 bitmap) -------------- */
#define FBSEC_DESC_ID_IDEVID           0x01u
#define FBSEC_DESC_ID_LDEVID           0x02u
#define FBSEC_DESC_ID_X509             0x08u

/* ---- C000h sub 07h: claim gates supported (U8 bitmap) ---------------- */
#define FBSEC_DESC_HANDOVER_TOFU       0x01u  /* b0 claim on first use     */
#define FBSEC_DESC_HANDOVER_TOKEN      0x02u  /* b1 device claim token      */
#define FBSEC_DESC_HANDOVER_VOUCHER    0x04u  /* b2 ownership voucher       */

/* ---- C000h sub 08h: mechanisms implemented (U16 bitmap) -------------- */
#define FBSEC_MECH_AEAD  0x01u
#define FBSEC_MECH_RPK   0x02u
#define FBSEC_MECH_X509  0x04u

/* ---- C001h sub 01h: commissioning state ------------------------------ */
#define FBSEC_STAT_UNCOMMISSIONED      0x00u
#define FBSEC_STAT_COMMISSIONED        0x01u

/* ---- C001h keys-installed bitmap ------------------------------------- */
#define FBSEC_STAT_KEY_PROVISIONING    0x01u
#define FBSEC_STAT_KEY_INTEGRATOR      0x02u
#define FBSEC_STAT_KEY_OPERATOR        0x04u

/* ---- Decoded C000h record -------------------------------------------- */

typedef struct
{
  uint8_t  highest_sub;    /* sub 00h */
  uint32_t type_word;      /* sub 01h: profile 11:0, level 15:12 */
  uint32_t aead_and_tag;   /* sub 02h: low = AEAD bitmap, byte1 = tag len */
  uint16_t kdf;            /* sub 03h: KDF bitmap */
  uint16_t sig_alg;        /* sub 04h: signature-algorithm bitmap */
  uint8_t  sym_levels;     /* sub 05h: symmetric key levels bitmap */
  uint8_t  id_flags;       /* sub 06h: asymmetric key presence */
  uint8_t  handover_model; /* sub 07h: claim gates supported */
  uint16_t mechanisms;     /* sub 08h: mechanisms implemented */
} fbsec_caps_t;

/* ---- Decoded C001h record -------------------------------------------- */

typedef struct
{
  uint8_t  highest_sub;    /* sub 00h */
  uint8_t  commissioning;  /* sub 01h: FBSEC_STAT_UNCOMMISSIONED / _COMMISSIONED */
  uint8_t  active_gate;    /* sub 02h: the one active claim gate (FBSEC_DESC_HANDOVER_*) */
  uint8_t  keys_installed; /* sub 03h: FBSEC_STAT_KEY_* bitmap */
  uint32_t active_aead;    /* sub 04h: active AEAD algorithm (low) + tag length (byte 1) */
  uint8_t  identities;     /* sub 05h: device identities present (FBSEC_DESC_ID_*) */
} fbsec_status_t;

/* ---- C000h capabilities: build / serialize / deserialize ------------- */

/**
 * @brief Build the C000h capability record for this build.
 *
 * In an FBSEC_FEATURE_ASYM build this advertises AEAD | RPK; otherwise
 * AEAD only. Subindex 05h (identity flags) reports live state, so the
 * caller passes the current bitmap (b0 IDevID present, b1 LDevID present);
 * it is ignored in an AEAD-only build.
 *
 * @param live_id_flags  FBSEC_DESC_ID_* bitmap of the identity artifacts
 *                       currently loaded (0 in an AEAD-only build).
 * @param out            record to fill.
 */
void fbsec_descriptor_build_caps(uint8_t live_id_flags, fbsec_caps_t *out);

/**
 * @brief Serialize one C000h sub-index onto the wire (U8 or U32 LE).
 * @return bytes written (1 or 4), or 0 on bad sub-index / small buffer.
 */
uint16_t fbsec_caps_serialize_sub(const fbsec_caps_t *c, uint8_t sub,
                                  uint8_t *out, uint16_t out_max);

/**
 * @brief Decode one C000h sub-index read from the wire.
 * @return true if @p sub is valid and @p len matches its width.
 */
bool fbsec_caps_deserialize_sub(fbsec_caps_t *c, uint8_t sub,
                                const uint8_t *in, uint16_t len);

/* ---- C001h status: build / serialize / deserialize ------------------- */

/**
 * @brief Build the C001h status record from live device state.
 *
 * The active claim gate and the active AEAD algorithm are build-derived;
 * the caller supplies the live commissioning state, the populated key
 * slots and the identity artifacts present.
 *
 * @param commissioning   FBSEC_STAT_UNCOMMISSIONED / _COMMISSIONED.
 * @param keys_installed  FBSEC_STAT_KEY_* bitmap of populated key slots.
 * @param identities      FBSEC_DESC_ID_* bitmap of identity artifacts present.
 * @param out             record to fill.
 */
void fbsec_descriptor_build_status(uint8_t commissioning,
                                   uint8_t keys_installed,
                                   uint8_t identities,
                                   fbsec_status_t *out);

/**
 * @brief Serialize one C001h sub-index onto the wire (U8).
 * @return bytes written (1), or 0 on bad sub-index / small buffer.
 */
uint16_t fbsec_status_serialize_sub(const fbsec_status_t *s, uint8_t sub,
                                    uint8_t *out, uint16_t out_max);

/**
 * @brief Decode one C001h sub-index read from the wire.
 */
bool fbsec_status_deserialize_sub(fbsec_status_t *s, uint8_t sub,
                                  const uint8_t *in, uint16_t len);

/* ---- Client-side predicates (fail-closed checks) --------------------- */

/** @return true if the peer advertises the manufacturer-voucher handover. */
bool fbsec_caps_supports_voucher_handover(const fbsec_caps_t *c);

/** @return true if the peer advertises an Ed25519 RPK identity. */
bool fbsec_caps_has_ed25519(const fbsec_caps_t *c);

#ifdef __cplusplus
}
#endif

#endif /* FBSEC_DESCRIPTOR_H */
/* EOF */
