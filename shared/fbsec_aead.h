/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    fbsec_aead.h
 * @brief   SOFA AEAD primitives, public API and configuration-derived sizes.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 03-MAY-2026
 *
 * Two API surfaces:
 *
 *   fbsec_aead_seal / fbsec_aead_open
 *       Used for READ_RESPONSE, WRITE_REQUEST, READ_POLL_RESPONSE and
 *       WRITE_POLL_REQUEST. In encryption mode (bit 7 of key_id set)
 *       data goes through GCM as plaintext->ciphertext; in auth-only
 *       mode they collapse to MAC compute/verify with data authenticated
 *       via AAD inclusion.
 *
 *   fbsec_aead_compute_tag / fbsec_aead_verify_tag
 *       Used for any explicit MAC-only verification. WRITE_CHALLENGE
 *       no longer constructs an AAD (the responder has no key context
 *       at that leg under the current flow), so this entry point is
 *       presently unused but stays available for future directions.
 *
 * AAD layout depends on direction AND encryption mode (full byte-by-byte
 * spec in doc/fieldbus_sim_secure_tunnel_spec.txt section 4.1).
 *
 *   Prefix carries a server (responder) and a client (requester)
 *   identifier in two variant-sized fields. FBSEC_AEAD_DEV_ID_SIZE
 *   (fbsec_config.h) is 1 by default (CANopen FD, uint8 node_id
 *   1..127) since CANopen FD is the only variant currently built.
 *   Setting it to 2 produces a uint16 device_id layout, reserved for
 *   the future generic / CANopen CC / EtherCAT variants. The data_id
 *   and data_len fields shift by 2 bytes between the two layouts;
 *   key_id stays at offset 3 on both.
 *
 *   In CiA 720 terms the key_id byte is the key selector, and the data_id
 *   is the object multiplexor (CiA 301 index and sub-index). The readable,
 *   non-secret key identifier is a separate value, reported by C011h.
 *
 *   CANopen FD variant (DEV_ID_SIZE = 1, prefix length 12, current default):
 *     0    protocol version          (FBSEC_AEAD_PROTOCOL_VERSION = 0x01)
 *     1    mechanism                  (FBSEC_AEAD_MECHANISM = (encrypt<<7)|prim)
 *     2    direction                  (FBSEC_AEAD_DIR_*)
 *     3    key_id                     (full wire byte: bit 7 = encrypt,
 *                                     bit 6 = cyclic-arm, bits 5..4 = reserved
 *                                     (must be 0), bits 3..0 = base id 1..15)
 *     4    server_node_id             (uint8; responder, 1..127)
 *     5    client_node_id             (uint8; requester, 1..127)
 *     6-9  data_id                    (uint32 LE)
 *     10-11 data_len                  (uint16 LE)
 *
 *   2-byte device_id variant (DEV_ID_SIZE = 2, prefix length 14, future):
 *     0    protocol version          (0x01)
 *     1    mechanism
 *     2    direction
 *     3    key_id
 *     4-5  server_device_id           (uint16 LE; responder's id)
 *     6-7  client_device_id           (uint16 LE; requester's id)
 *     8-11 data_id                    (uint32 LE)
 *     12-13 data_len                  (uint16 LE; plaintext byte count)
 *
 *   Tail:
 *     READ_CHALLENGE:        (no AAD constructed)
 *     READ_RESPONSE:         client_random[R] || server_random[R]
 *                            || plaintext[N]   (only if encryption == 0)
 *     WRITE_CHALLENGE:       (no AAD constructed)
 *     WRITE_REQUEST:         client_random[R] || server_random[R]
 *                            || plaintext[N]   (only if encryption == 0)
 *     READ_POLL_REQUEST:     (no AAD tail)
 *     READ_POLL_RESPONSE:    plaintext[N]      (only if encryption == 0)
 *     WRITE_POLL_REQUEST:    plaintext[N]      (only if encryption == 0)
 *
 *   R = FBSEC_AEAD_RANDOM_SIZE (default 12). Both randoms feed the GCM
 *   nonce_base via XOR (see fbsec_aead_xor_nonce). Cyclic-mode polls
 *   reuse nonce_base from the arming step and XOR the per-frame
 *   counter into its low 32 bits; the counter is therefore nonce-
 *   bound, which is why the poll-direction AAD tails carry no
 *   session metadata.
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#ifndef FBSEC_AEAD_H
#define FBSEC_AEAD_H

#include <stdint.h>
#include <stdbool.h>

#include "fbsec_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Primitive parameters derived from config ------------------------- */

#if FBSEC_AEAD_AES128_GCM
#  define FBSEC_AEAD_KEY_SIZE          16u
#  define FBSEC_AEAD_NONCE_SIZE        12u
#  define FBSEC_AEAD_PRIMITIVE_ID      0x01u   /* AES-128-GCM */
#elif FBSEC_AEAD_AES256_GCM
#  define FBSEC_AEAD_KEY_SIZE          32u
#  define FBSEC_AEAD_NONCE_SIZE        12u
#  define FBSEC_AEAD_PRIMITIVE_ID      0x02u   /* AES-256-GCM */
#endif

#define FBSEC_AEAD_TAG_SIZE            ((uint16_t)(FBSEC_AEAD_TAG_LEN_BYTES))

/* Mechanism byte = (encryption << 7) | primitive_id.
 *   bit 7    : encryption mode (0 = auth-only, 1 = encrypt-and-authenticate)
 *   bits 0-6 : primitive id (0..127)
 *
 * Per-call: the encryption flag is carried as bit 7 of the key_id
 * argument, so the AEAD mode can change frame by frame. The macro derives
 * the mechanism byte at call sites that need it. The compile-time
 * FBSEC_AEAD_ENCRYPTION knob in fbsec_config.h survives only as the default
 * the client prompts with at startup; runtime always honours the keyid
 * bit. The bare 4-bit identity (0x01..0x0F) is recovered with
 * FBSEC_AEAD_KEYID_BASE().
 *
 * Wire key_id byte layout:
 *   bit 7    : encryption flag
 *   bit 6    : cyclic-arm flag (meaningful only on READ_CHALLENGE
 *              and WRITE_CHALLENGE; ignored on poll directions)
 *   bits 5-4 : reserved, must be 0; verifier rejects non-zero with
 *              FBSEC_ABORT_KEY_ID (C4h) so future bit assignments do
 *              not silently collide with old peers
 *   bits 3-0 : base key selector (1..15)
 *
 * The whole key_id byte is part of the AAD prefix at offset 3, so a
 * downgrade attempt (flipping bit 7 / bit 6, repurposing a reserved
 * bit, or swapping the base id) fails AEAD verification. */
#define FBSEC_AEAD_MECHANISM_FOR(kid) \
    ((uint8_t)(((uint8_t)(kid) & 0x80u) | FBSEC_AEAD_PRIMITIVE_ID))
#define FBSEC_AEAD_KEYID_ENCRYPT(kid)       (((uint8_t)(kid) & 0x80u) != 0u)
#define FBSEC_AEAD_KEYID_IS_CYCLIC(kid)     (((uint8_t)(kid) & 0x40u) != 0u)
#define FBSEC_AEAD_KEYID_RESERVED(kid)      ((uint8_t)(((uint8_t)(kid) >> 4) & 0x03u))
#define FBSEC_AEAD_KEYID_BASE(kid)          ((uint8_t)((uint8_t)(kid) & 0x0Fu))
#define FBSEC_AEAD_KEYID_MAX                15u

/* ---- Other AAD-related sizes ----------------------------------------- */

/* Per-peer challenge size (client_random AND server_random, both
 * contribute to the GCM nonce via XOR; see fbsec_config.h). */
#define FBSEC_AEAD_RAND_SIZE           ((uint16_t)(FBSEC_AEAD_RANDOM_SIZE))
#define FBSEC_AEAD_MAX_PROTECTED       32u    /* max plaintext per transfer    */
/* Prefix = 4 fixed bytes (proto, mech, dir, key_id) +
 *          2 * FBSEC_AEAD_DEV_ID_SIZE (server_id, client_id) +
 *          4 bytes data_id + 2 bytes data_len.
 * Evaluates to 12 on the CANopen FD variant (current default) and to
 * 14 on the future 2-byte device_id variants; see
 * doc/fieldbus_sim_secure_tunnel_spec.txt section 4.1. */
#define FBSEC_AEAD_AAD_PREFIX_SIZE \
        ((uint16_t)(4u + 2u * (FBSEC_AEAD_DEV_ID_SIZE) + 4u + 2u))

/* ---- AAD direction byte values --------------------------------------- */

#define FBSEC_AEAD_DIR_READ_CHALLENGE      0x01u
#define FBSEC_AEAD_DIR_READ_RESPONSE       0x02u
#define FBSEC_AEAD_DIR_WRITE_CHALLENGE     0x03u
#define FBSEC_AEAD_DIR_WRITE_REQUEST       0x04u

/* Cyclic-mode follow-up frames (after a bit-6 arming challenge). The
 * per-frame counter is XOR'd into the low 32 bits of nonce_base (which
 * itself is the arm-time mutual-random XOR base) to form the GCM nonce
 * for each poll, so the counter is already nonce-bound and the poll-
 * direction AAD tails carry no session metadata. The low byte of the
 * counter still rides on the wire as a desync cross-check (not part of
 * the AAD). See spec section 11.1. */
#define FBSEC_AEAD_DIR_READ_POLL_REQUEST   0x05u
#define FBSEC_AEAD_DIR_READ_POLL_RESPONSE  0x06u
#define FBSEC_AEAD_DIR_WRITE_POLL_REQUEST  0x07u
/* 0x08..0xFF available */

/* ---- AAD prefix versioning ------------------------------------------- */

#define FBSEC_AEAD_PROTOCOL_VERSION        0x01u
/* Single in-the-field protocol revision. The protocol-version byte is
 * baked into the AAD prefix so a peer running a future version that
 * bumps the byte will fail-closed against this one; that is the right
 * outcome until a co-ordinated upgrade lands. */

/* ====================================================================== */
/*                                Public API                              */
/* ====================================================================== */

/**
 * @brief Build the per-frame GCM nonce by XORing the first
 *        FBSEC_AEAD_NONCE_SIZE bytes of two FBSEC_AEAD_RAND_SIZE-byte
 *        randoms.
 *
 * Used by single-shot READ_RESPONSE and WRITE_REQUEST. The resulting
 * nonce is unique whenever **either** input random is unique, so the
 * scheme survives a single weak peer RNG.
 *
 * @param client_random_rd   FBSEC_AEAD_RAND_SIZE bytes.
 * @param server_random_rd   FBSEC_AEAD_RAND_SIZE bytes.
 * @param nonce_out          FBSEC_AEAD_NONCE_SIZE bytes; XOR result.
 */
void fbsec_aead_xor_nonce(
  const uint8_t client_random_rd[FBSEC_AEAD_RAND_SIZE],
  const uint8_t server_random_rd[FBSEC_AEAD_RAND_SIZE],
  uint8_t       nonce_out[FBSEC_AEAD_NONCE_SIZE]);

/**
 * @brief Compute the truncated AEAD tag for a MAC-only direction.
 *
 * Used for READ_RESPONSE / WRITE_REQUEST / poll directions when the
 * key_id's encryption bit is clear, and available for any future
 * direction that needs a metadata-only MAC.
 *
 * @param key                FBSEC_AEAD_KEY_SIZE-byte session key.
 * @param nonce              FBSEC_AEAD_NONCE_SIZE-byte GCM nonce.
 * @param direction          FBSEC_AEAD_DIR_*.
 * @param key_id             Full wire byte (incl. encrypt + cyclic bits).
 * @param server_device_id   Responder identifier (AAD); width set
 *                           by FBSEC_AEAD_DEV_ID_SIZE.
 * @param client_device_id   Requester identifier (AAD); same width.
 * @param data_id            Object multiplexor (AAD): CiA 301 index and sub-index.
 * @param client_random_rd   FBSEC_AEAD_RAND_SIZE bytes for
 *                           READ_RESPONSE / WRITE_REQUEST; ignored on
 *                           poll directions (pass NULL).
 * @param server_random_rd   FBSEC_AEAD_RAND_SIZE bytes for
 *                           READ_RESPONSE / WRITE_REQUEST; ignored on
 *                           poll directions (pass NULL).
 * @param data               Bytes appended to the AAD as the data tail.
 * @param data_len           Length of @p data (also encoded in AAD).
 * @param tag_out            Receives FBSEC_AEAD_TAG_SIZE bytes.
 * @retval true              Success.
 * @retval false             Backend error or invalid parameters.
 */
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
  uint8_t        tag_out[FBSEC_AEAD_TAG_SIZE]);

/**
 * @brief Verify a MAC-only tag (constant-time compare).
 *
 * Same parameter shape as @ref fbsec_aead_compute_tag plus the @p tag_in
 * to verify against. Returns true iff the tag matches.
 */
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
  const uint8_t  tag_in[FBSEC_AEAD_TAG_SIZE]);

/**
 * @brief Outgoing AEAD: protect plaintext, emit (ciphertext, tag).
 *
 * Direction must be READ_RESPONSE, WRITE_REQUEST, READ_POLL_RESPONSE, or
 * WRITE_POLL_REQUEST. In encryption mode the plaintext goes through GCM
 * as input and @p ciphertext_out receives the ciphertext. In auth-only
 * mode the function collapses to a MAC over the AAD (with plaintext in
 * the tail) and @p ciphertext_out receives a copy of the plaintext.
 *
 * @param key                Session key.
 * @param nonce              GCM nonce. For poll directions this is
 *                           session_random[6] || session_id_be16[2]
 *                           || counter_be32[4] (12 bytes total).
 * @param direction          FBSEC_AEAD_DIR_READ_RESPONSE, _WRITE_REQUEST,
 *                           _READ_POLL_RESPONSE, or _WRITE_POLL_REQUEST.
 * @param key_id, server_device_id, client_device_id, data_id
 *                           AAD prefix fields. The two identifier fields
 *                           are each FBSEC_AEAD_DEV_ID_SIZE bytes wide.
 * @param client_random_rd   FBSEC_AEAD_RAND_SIZE bytes for
 *                           READ_RESPONSE / WRITE_REQUEST (NULL on
 *                           poll directions).
 * @param server_random_rd   FBSEC_AEAD_RAND_SIZE bytes for
 *                           READ_RESPONSE / WRITE_REQUEST (NULL on
 *                           poll directions).
 * @param session            Non-NULL for poll directions; NULL otherwise.
 * @param plaintext          Plaintext bytes (max FBSEC_AEAD_MAX_PROTECTED).
 * @param pt_len             Plaintext length.
 * @param ciphertext_out     pt_len-byte buffer; receives ciphertext or
 *                           plaintext-copy depending on mode.
 * @param tag_out            FBSEC_AEAD_TAG_SIZE-byte tag buffer.
 * @retval true / false      Backend success / failure.
 */
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
  uint8_t        tag_out[FBSEC_AEAD_TAG_SIZE]);

/**
 * @brief Incoming AEAD: verify tag and recover plaintext.
 *
 * Mirror of @ref fbsec_aead_seal. In encryption mode runs GCM auth-decrypt;
 * in auth-only mode re-derives the expected tag from the AAD (with the
 * received ciphertext-as-plaintext appended) and constant-time-compares
 * to @p tag_in.
 *
 * @retval true   Tag valid; plaintext recovered into @p plaintext_out.
 * @retval false  Tag mismatch or backend error.
 */
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
  uint8_t       *plaintext_out);

#ifdef __cplusplus
}
#endif

#endif /* FBSEC_AEAD_H */
/* EOF */
