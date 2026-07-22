/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    fbsec_descriptor.h
 * @brief   SOFA CiA 720 capability + status descriptor (read-only, unauth).
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V2.0 of 22-JUL-2026
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
 * a manufacturer-capabilities word (subs 00h..07h); C001h is a minimal
 * status array (subs 00h..02h). They therefore have separate build /
 * serialize / deserialize entry points.
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
#define FBSEC_DESC_CAP_SUB_MAX   0x07u    /* highest C000h sub-index       */
#define FBSEC_DESC_STAT_SUB_MAX  0x02u    /* highest C001h sub-index (mand)*/

/* ---- C000h sub 01h: security type word (U32) ------------------------- */
/* bits  7:0  security profile number
 * bits 11:8  capability level (0..3 => C0..C3)
 * bits 15:12 restore capability (highest restore depth, 0..4)
 * bits 18:16 mechanisms supported (b16 AEAD, b17 RPK, b18 X509)
 * bits 22:19 algorithm-suite generation
 * bits 31:23 reserved, profile-defined                                    */

#define FBSEC_PROFILE_CUSTOM        0x00u
#define FBSEC_PROFILE_OPEN          0x01u
#define FBSEC_PROFILE_CLAIMED       0x02u
#define FBSEC_PROFILE_AUTHORIZED    0x03u
#define FBSEC_PROFILE_IDENTIFIED    0x04u
#define FBSEC_PROFILE_CONFIDENTIAL  0x05u

#define FBSEC_MECH_AEAD  0x01u  /* type-word b16 */
#define FBSEC_MECH_RPK   0x02u  /* type-word b17 */
#define FBSEC_MECH_X509  0x04u  /* type-word b18 */

#define FBSEC_TYPEWORD(profile, level, restore, mech, suite)      \
  (  ((uint32_t)(profile) & 0xFFu)                                \
   | (((uint32_t)(level)   & 0x0Fu) << 8)                         \
   | (((uint32_t)(restore) & 0x0Fu) << 12)                        \
   | (((uint32_t)(mech)    & 0x07u) << 16)                        \
   | (((uint32_t)(suite)   & 0x0Fu) << 19) )

#define FBSEC_TYPEWORD_PROFILE(tw)  ((uint8_t)((tw) & 0xFFu))
#define FBSEC_TYPEWORD_LEVEL(tw)    ((uint8_t)(((tw) >> 8)  & 0x0Fu))
#define FBSEC_TYPEWORD_RESTORE(tw)  ((uint8_t)(((tw) >> 12) & 0x0Fu))
#define FBSEC_TYPEWORD_MECH(tw)     ((uint8_t)(((tw) >> 16) & 0x07u))
#define FBSEC_TYPEWORD_SUITE(tw)    ((uint8_t)(((tw) >> 19) & 0x0Fu))

/* ---- C000h sub 02h: session-protocol bitmap (U32) -------------------- */
#define FBSEC_DESC_PROTO_FBSEC         0x0001u
#define FBSEC_DESC_PROTO_TLS_PSK       0x0002u
#define FBSEC_DESC_PROTO_CTLS          0x0004u
#define FBSEC_DESC_PROTO_TLS13         0x0008u

/* ---- C000h sub 03h low byte: AEAD primitive bitmap ------------------- */
#define FBSEC_DESC_AEAD_AES128_GCM     0x01u
#define FBSEC_DESC_AEAD_AES256_GCM     0x02u
#define FBSEC_DESC_AEAD_ASCON128       0x04u
#define FBSEC_DESC_AEAD_CHACHA20       0x08u

/* ---- C000h sub 04h: RPK algorithm id --------------------------------- */
#define FBSEC_DESC_RPK_NONE            0x00u
#define FBSEC_DESC_RPK_ED25519         0x01u

/* ---- C000h sub 05h: identity / certificate flags --------------------- */
#define FBSEC_DESC_ID_IDEVID           0x01u
#define FBSEC_DESC_ID_LDEVID           0x02u
#define FBSEC_DESC_ID_X509             0x08u

/* ---- C000h sub 06h: handover-model bitmap (WP-104 claim gates) ------- */
#define FBSEC_DESC_HANDOVER_TOFU       0x01u  /* b0 claim on first use     */
#define FBSEC_DESC_HANDOVER_TOKEN      0x02u  /* b1 printed one-time token  */
#define FBSEC_DESC_HANDOVER_VOUCHER    0x04u  /* b2 manufacturer voucher    */

/* ---- C001h sub 01h: commissioning state ------------------------------ */
#define FBSEC_STAT_UNCOMMISSIONED      0x00u
#define FBSEC_STAT_COMMISSIONED        0x01u

/* ---- C001h sub 02h: keys-installed bitmap ---------------------------- */
#define FBSEC_STAT_KEY_PROVISIONING    0x01u
#define FBSEC_STAT_KEY_INTEGRATOR      0x02u
#define FBSEC_STAT_KEY_OPERATOR        0x04u

/* ---- Decoded C000h record -------------------------------------------- */

typedef struct
{
  uint8_t  highest_sub;    /* sub 00h */
  uint32_t type_word;      /* sub 01h */
  uint32_t session_proto;  /* sub 02h */
  uint32_t aead_and_tag;   /* sub 03h: low = AEAD bitmap, byte1 = tag len */
  uint8_t  rpk_alg;        /* sub 04h */
  uint8_t  id_flags;       /* sub 05h */
  uint8_t  handover_model; /* sub 06h */
  uint32_t mfg_caps;       /* sub 07h */
} fbsec_caps_t;

/* ---- Decoded C001h record -------------------------------------------- */

typedef struct
{
  uint8_t highest_sub;    /* sub 00h */
  uint8_t commissioning;  /* sub 01h: FBSEC_STAT_UNCOMMISSIONED / _COMMISSIONED */
  uint8_t keys_installed; /* sub 02h: FBSEC_STAT_KEY_* bitmap */
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
 * @param commissioning   FBSEC_STAT_UNCOMMISSIONED / _COMMISSIONED.
 * @param keys_installed  FBSEC_STAT_KEY_* bitmap of populated key slots.
 * @param out             record to fill.
 */
void fbsec_descriptor_build_status(uint8_t commissioning,
                                   uint8_t keys_installed,
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
