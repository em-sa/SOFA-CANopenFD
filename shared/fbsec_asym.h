/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    fbsec_asym.h
 * @brief   SOFA optional Ed25519 identity primitive (RFC 8032), public API.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 19-JUL-2026
 *
 * Thin wrapper over the vendored Monocypher Ed25519 (EdDSA with
 * Curve25519 + SHA-512) primitive. This is the ONLY module the rest of
 * SOFA calls for asymmetric identity work; the Monocypher headers are an
 * implementation detail confined to fbsec_asym.c.
 *
 * Compiled only when FBSEC_FEATURE_ASYM == 1 (see shared/fbsec_config.h
 * and doc/fieldbus_sim_secure_tunnel_spec.txt sections 11.5-11.6).
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#ifndef FBSEC_ASYM_H
#define FBSEC_ASYM_H

#include "fbsec_config.h"

#if FBSEC_FEATURE_ASYM

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "fbsec_aead.h"   /* FBSEC_AEAD_KEY_SIZE (provisioning-install len) */

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Sizes (Ed25519 / RFC 8032) -------------------------------------- */

/** Ed25519 public key size in bytes. */
#define FBSEC_ASYM_PUBKEY_SIZE   32u
/** Ed25519 private-key material size in bytes (seed || public key). */
#define FBSEC_ASYM_PRIVKEY_SIZE  64u
/** Ed25519 detached signature size in bytes. */
#define FBSEC_ASYM_SIG_SIZE      64u
/** Ed25519 keygen seed size in bytes. */
#define FBSEC_ASYM_SEED_SIZE     32u

/** Asymmetric algorithm id published in the capability descriptor. */
#define FBSEC_ASYM_ALG_ED25519   0x01u

/* ---- Signature transcript domain separation (spec 11.6.4) ------------ */

/** Transcript version byte, prepended before role_dir and body. */
#define FBSEC_ASYM_TRANSCRIPT_VERSION   0x01u

/** role_dir values: one per signed exchange, so a signature minted for
 *  one role can never verify in another. See spec section 11.6.4. */
#define FBSEC_ASYM_RD_IDENTITY_READ     0x01u /* genuineness proof (IDevID)   */
#define FBSEC_ASYM_RD_PKINSTALL_ACK     0x02u /* provisioning-key install ack */
#define FBSEC_ASYM_RD_LDEVID_EXPORT     0x03u /* IDevID signs new LDevID pub  */
/* 0x04, 0x05 reserved (were signed-FBsec c2s/s2c, removed). */
#define FBSEC_ASYM_RD_VOUCHER           0x06u /* ownership voucher (mfg anchor)*/
#define FBSEC_ASYM_RD_IDEVID_CERT       0x07u /* manufacturer cert over IDevID */
#define FBSEC_ASYM_RD_GENERIC_READ      0x08u /* C042h signed read (dev signs) */
#define FBSEC_ASYM_RD_GENERIC_WRITE     0x09u /* C042h signed write (cli signs)*/
#define FBSEC_ASYM_RD_FUNCTION_CMD      0x0Au /* C049h signed command (cli)    */

/** Fixed transcript overhead (version byte + role_dir byte). */
#define FBSEC_ASYM_TRANSCRIPT_OVERHEAD  2u

/* ---- SOFA identity-blob layout (handover identity read) -------------- */

/** Device serial length carried in the identity blob. */
#define FBSEC_ASYM_SERIAL_LEN         8u
/** Identity blob = serial[8] || IDevID public key[32]; the manufacturer
 *  certificate (role FBSEC_ASYM_RD_IDEVID_CERT) signs this blob. */
#define FBSEC_ASYM_IDENTITY_BLOB_LEN  (FBSEC_ASYM_SERIAL_LEN + FBSEC_ASYM_PUBKEY_SIZE)

/* ---- Handover object data_ids and payload sizes (CiA 720 RPK block) --- */
/* data_id = (index << 16) | (sub << 8). The three ownership operations are
 * subindices of C020h; the signed identity read and provisioning install
 * are their own indices. */

#define FBSEC_HO_IDENTITY_ID   0xC0280000u  /* C028h:00 signed identity read  */
#define FBSEC_HO_VOUCHER_ID    0xC0200100u  /* C020h:01 ownership voucher      */
#define FBSEC_HO_EPOCH_ID      0xC0200200u  /* C020h:02 owner epoch RO U32     */
#define FBSEC_HO_PROVISION_ID  0xC02F0000u  /* C02Fh:00 provisioning install   */
#define FBSEC_HO_LDEVID_ID     0xC0200300u  /* C020h:03 LDevID generate/export */

/** Freshness nonce the tool sends on an identity read. */
#define FBSEC_HO_RT_LEN        16u

/** Identity read reply: blob[40] || mfg_cert[64] || SIG_DEV(blob||rT)[64]. */
#define FBSEC_HO_IDENTITY_REPLY_LEN \
  ((uint16_t)(FBSEC_ASYM_IDENTITY_BLOB_LEN + FBSEC_ASYM_SIG_SIZE + FBSEC_ASYM_SIG_SIZE))

/** Ownership voucher: serial[8] || integrator_pub[32] || epoch[4] || SIG_MFG[64]. */
#define FBSEC_HO_VOUCHER_LEN \
  ((uint16_t)(FBSEC_ASYM_SERIAL_LEN + FBSEC_ASYM_PUBKEY_SIZE + 4u + FBSEC_ASYM_SIG_SIZE))

/** Provisioning-Key install: key[FBSEC_AEAD_KEY_SIZE] || SIG_integrator[64]. */
#define FBSEC_HO_PROVISION_LEN \
  ((uint16_t)(FBSEC_AEAD_KEY_SIZE + FBSEC_ASYM_SIG_SIZE))

/** LDevID export reply: ldevid_pub[32] || SIG_DEV(pub)[64]. */
#define FBSEC_HO_LDEVID_REPLY_LEN \
  ((uint16_t)(FBSEC_ASYM_PUBKEY_SIZE + FBSEC_ASYM_SIG_SIZE))

/* ---- RPK secure objects (CiA 720 C021h/C022h/C042h/C049h) ------------ */
/* Unauthenticated public-key reads plus the signed generic-access and
 * function-command verbs. C042h/C049h use the replacement model: an
 * Ed25519 signature protects the access instead of an AEAD tag, and a
 * two-pass challenge supplies the freshness that the signature covers. */

#define FBSEC_RPK_PUBKEYS_INDEX     0xC021u      /* public keys (none)         */
#define FBSEC_RPK_PKTYPES_INDEX     0xC022u      /* public key types (none)    */
#define FBSEC_RPK_PUBKEY_HIGHEST_SUB 0x02u       /* 01h mfg, 02h integrator    */

#define FBSEC_RPK_GENERIC_READ_ID   0xC0420100u  /* C042h:01 signed read       */
#define FBSEC_RPK_GENERIC_WRITE_ID  0xC0420200u  /* C042h:02 signed write      */
#define FBSEC_RPK_FUNCCMD_ID        0xC0490000u  /* C049h:00 signed command    */

/** Challenge nonce each side contributes for signed-access freshness. */
#define FBSEC_RPK_NONCE_LEN         16u
/** Largest demo value carried through a C042h access (the 2017h twin). */
#define FBSEC_RPK_VALUE_MAX         16u

/** C042h:01 signed-read request: target_index[2 LE] + sub[1] + client_nonce[16]. */
#define FBSEC_RPK_READ_REQ_LEN      ((uint16_t)(3u + FBSEC_RPK_NONCE_LEN))
/** C042h:02 / C049h signed-write Pass-2 body =
 *  target_index[2 LE] + sub[1] + client_nonce[16] + value[N] + SIG[64].
 *  For C049h the value is the 4-byte command code. */
#define FBSEC_RPK_WRITE_HDR_LEN     ((uint16_t)(3u + FBSEC_RPK_NONCE_LEN))
/** Function-command code width. */
#define FBSEC_RPK_CMD_LEN           4u

/* ---- Key types ------------------------------------------------------- */

/** A bare Ed25519 public key (peer identity, trust anchor, owner key). */
typedef struct
{
  uint8_t pub[FBSEC_ASYM_PUBKEY_SIZE];
} fbsec_pubkey_t;

/** An Ed25519 keypair. @c priv holds the Monocypher secret-key form
 *  (seed || public key); @c pub is the public half, duplicated for
 *  convenient distribution. */
typedef struct
{
  uint8_t priv[FBSEC_ASYM_PRIVKEY_SIZE];
  uint8_t pub[FBSEC_ASYM_PUBKEY_SIZE];
} fbsec_keypair_t;

/* ---- API ------------------------------------------------------------- */

/**
 * @brief Derive an Ed25519 keypair deterministically from a 32-byte seed.
 *
 * The seed is the caller's secret entropy (from a port RNG hook, or a
 * fixed demo seed). A given seed always yields the same keypair.
 *
 * @param seed  32 bytes of seed material (not modified by this wrapper).
 * @param out   destination keypair; both @c priv and @c pub are filled.
 * @retval true  keypair derived.
 * @retval false @p seed or @p out was NULL.
 */
bool fbsec_asym_keygen(const uint8_t seed[FBSEC_ASYM_SEED_SIZE],
                       fbsec_keypair_t *out);

/**
 * @brief Produce a detached Ed25519 signature over @p msg.
 *
 * @param kp       signing keypair.
 * @param msg      message bytes (typically a domain-separated transcript
 *                 built with fbsec_asym_transcript()).
 * @param msg_len  message length in bytes.
 * @param sig_out  destination for the 64-byte signature.
 * @retval true    signature written to @p sig_out.
 * @retval false   a required pointer was NULL.
 */
bool fbsec_asym_sign(const fbsec_keypair_t *kp,
                     const uint8_t *msg, uint16_t msg_len,
                     uint8_t sig_out[FBSEC_ASYM_SIG_SIZE]);

/**
 * @brief Verify a detached Ed25519 signature against a public key.
 *
 * @param pk       verifying public key.
 * @param msg      message bytes that were signed.
 * @param msg_len  message length in bytes.
 * @param sig      the 64-byte signature to check.
 * @retval true    signature is valid for (@p pk, @p msg).
 * @retval false   signature invalid, or a required pointer was NULL.
 */
bool fbsec_asym_verify(const fbsec_pubkey_t *pk,
                       const uint8_t *msg, uint16_t msg_len,
                       const uint8_t sig[FBSEC_ASYM_SIG_SIZE]);

/**
 * @brief Build a domain-separated transcript to be signed / verified.
 *
 * Output = FBSEC_ASYM_TRANSCRIPT_VERSION || role_dir || body. Every
 * signature in the asymmetric layer is computed over such a transcript,
 * never over a raw message, so cross-protocol signature reuse is
 * impossible (spec section 11.6.4).
 *
 * @param role_dir  one of FBSEC_ASYM_RD_*.
 * @param body      context bytes to bind (may be NULL when @p body_len 0).
 * @param body_len  length of @p body in bytes.
 * @param out       destination buffer.
 * @param out_max   capacity of @p out in bytes.
 * @return the transcript length written (body_len + 2), or 0 if @p out is
 *         NULL, @p out_max is too small, or @p body is NULL with a
 *         non-zero @p body_len.
 */
uint16_t fbsec_asym_transcript(uint8_t role_dir,
                               const uint8_t *body, uint16_t body_len,
                               uint8_t *out, uint16_t out_max);

#ifdef __cplusplus
}
#endif

#endif /* FBSEC_FEATURE_ASYM */

#endif /* FBSEC_ASYM_H */
/* EOF */
