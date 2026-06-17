/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    fbsec_secure_proto.h
 * @brief   SOFA client-side secure-tunnel protocol, public API.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.1 of 06-MAY-2026
 *
 * Network-independent secure-read / secure-write orchestration on top of
 * a transport vtable. Implements the two flows described in
 * doc/fieldbus_sim_secure_tunnel_spec.txt.
 *
 * Wire-keyid byte rule: the keyid is carried only on CLIENT REQUESTS,
 * never on server responses, and where it appears it is the FIRST byte
 * of the payload. The server never echoes it back.
 *
 *   secure read:  write key_id[1] || client_random[R]
 *                 -> read server_random[R] || cipher[N] || tag[T]
 *   secure write: read empty -> server_random[R]
 *                 then write key_id[1] || client_random[R]
 *                                       || cipher[N] || tag[T]
 *
 * The protocol authenticates over a variant-sized AAD prefix that
 * includes server / client peer ids and the 4-byte data_id (12 bytes
 * on CANopen FD, 14 bytes on future uint16 device_id variants); see
 * fbsec_aead.h.
 *
 * This is a port of MCOPSecureAccess/Utils/secure_client/secure_protocol.{c,h}
 * with the addressing widened from (uint8 nid, uint16 idx, uint8 sub) to
 * (uint16 device_id, uint32 data_id) and the AEAD wrapper switched to
 * the new fbsec_aead module. Public API names changed to fbsec_secure_* for
 * namespace consistency.
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#ifndef FBSEC_SECURE_PROTO_H
#define FBSEC_SECURE_PROTO_H

#include <stdint.h>
#include <stdbool.h>

#include "fbsec_aead.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Status codes ----------------------------------------------------- */

typedef enum fbsec_secure_status_t {
  FBSEC_SECP_OK       = 0,
  FBSEC_SECP_TIMEOUT  = 1,
  FBSEC_SECP_TX       = 2,
  FBSEC_SECP_PROTOCOL = 3,
  FBSEC_SECP_BUFSIZE  = 4,
  FBSEC_SECP_ABORT    = 5,
  FBSEC_SECP_TAG      = 6,
  FBSEC_SECP_RANDOM   = 7
} fbsec_secure_status_t;

/* ---- Transport vtable ------------------------------------------------- */

/**
 * @brief Read raw bytes from a target peer at (device_id, data_id).
 *
 * The transport is responsible for serializing the request, demuxing the
 * response on the bus, parsing the demo response envelope (status[4 LE]
 * || data), and surfacing application aborts via @p abort_out.
 *
 * @p req_body / @p req_len carry an optional Pass-1 request payload --
 * used by secure_arm_write (cyclic) to ship the client's wire keyid
 * byte (bit 6 set, bit 7 = encryption flag) before the server picks
 * server_random. Single-shot secure_write Pass 1 has no request body.
 * Pass NULL/0 for a body-less read challenge.
 *
 * @retval FBSEC_SECP_OK         data placed in @p buf, length in @p *len_out.
 * @retval FBSEC_SECP_TIMEOUT    no response within @p timeout_ms.
 * @retval FBSEC_SECP_TX         transmit / socket error.
 * @retval FBSEC_SECP_PROTOCOL   malformed response.
 * @retval FBSEC_SECP_BUFSIZE    response too big for @p buf_size.
 * @retval FBSEC_SECP_ABORT      server returned non-zero envelope status;
 *                             code in @p *abort_out.
 */
typedef fbsec_secure_status_t (*fbsec_secure_transport_read_fn)(
  void    *ctx,
  uint16_t device_id,
  uint32_t data_id,
  const uint8_t *req_body,
  uint16_t       req_len,
  uint8_t *buf,
  uint32_t buf_size,
  uint32_t timeout_ms,
  uint32_t *len_out,
  uint32_t *abort_out);

/**
 * @brief Write raw bytes to a target peer at (device_id, data_id).
 *
 * Same envelope rules as @ref fbsec_secure_transport_read_fn.
 *
 * @retval FBSEC_SECP_OK         server acknowledged with status == 0.
 * @retval FBSEC_SECP_TIMEOUT, FBSEC_SECP_TX, FBSEC_SECP_PROTOCOL, FBSEC_SECP_ABORT
 *                              as above.
 */
typedef fbsec_secure_status_t (*fbsec_secure_transport_write_fn)(
  void    *ctx,
  uint16_t device_id,
  uint32_t data_id,
  const uint8_t *buf,
  uint32_t len,
  uint32_t timeout_ms,
  uint32_t *abort_out);

typedef struct fbsec_secure_transport_t {
  fbsec_secure_transport_read_fn   read;
  fbsec_secure_transport_write_fn  write;
  void                          *ctx;
} fbsec_secure_transport_t;

/* ---- Salt callback (optional) ----------------------------------------- */

/**
 * @brief Salt-observation callback. Receives the R-byte client_random
 *        before a secure read, or the R-byte server_random after a
 *        secure write Pass-1 (R = FBSEC_AEAD_RAND_SIZE).
 *
 * Useful for `--verbose` mode in the CLI. Set NULL to clear.
 */
typedef void (*fbsec_secure_salt_cb_t)(const uint8_t *salt, uint16_t len, void *ctx);

void fbsec_secure_set_salt_callback(fbsec_secure_salt_cb_t cb, void *ctx);

/* ---- Random-byte port hook (host-supplied) ---------------------------- */

/**
 * @brief Fill @p buf with @p len cryptographically-strong random bytes.
 *
 * Implemented by the host (e.g. via Win32 BCryptGenRandom or
 * CryptGenRandom). Required; protocol returns FBSEC_SECP_RANDOM if this
 * returns false.
 */
bool fbsec_secure_port_random(uint8_t *buf, uint16_t len);

/**
 * @brief Return this client's own peer identifier for the AAD prefix
 *        client_device_id field.
 *
 * Required port hook. The CANopen FD variant returns the local
 * node_id (1..127) promoted to uint16; only the low byte is consumed
 * because FBSEC_AEAD_DEV_ID_SIZE = 1 there. Future 2-byte device_id
 * variants will return the full uint16 device_id.
 *
 * Mirrors the server-side fbsec_sod_port_get_device_id() hook in
 * shared/fbsec_secure_od.h.
 */
uint16_t fbsec_secure_port_get_client_id(void);

/* ---- Public secure-flow entry points ---------------------------------- */

#if FBSEC_FEATURE_READ
/**
 * @brief Secure-read of a SECURE_RO entry.
 *
 * @param transport   Transport vtable bound to a connected hub.
 * @param device_id   Target peer's device_id.
 * @param data_id     Application data_id.
 * @param key         32-byte AES-256 session key.
 * @param key_id      1..15 key role identifier.
 * @param buf         Receives the decrypted plaintext.
 * @param buf_size    Capacity of @p buf.
 * @param timeout_ms  Per-round-trip timeout (the flow has two
 *                    round-trips; each gets its own deadline).
 * @param len_out     Receives the plaintext length on success.
 *                    May be NULL.
 * @param abort_out   On FBSEC_SECP_ABORT, receives the server's abort
 *                    code. May be NULL.
 */
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
  uint32_t     *abort_out);
#endif /* FBSEC_FEATURE_READ */

#if FBSEC_FEATURE_WRITE
/**
 * @brief Secure-write of a SECURE_WO entry.
 *
 * @param transport, device_id, data_id, key, key_id, timeout_ms,
 *                    abort_out   - as for fbsec_secure_read.
 * @param buf, len    Plaintext to write (max FBSEC_AEAD_MAX_PROTECTED).
 */
fbsec_secure_status_t fbsec_secure_write(
  const fbsec_secure_transport_t *transport,
  uint16_t device_id,
  uint32_t data_id,
  const uint8_t key[FBSEC_AEAD_KEY_SIZE],
  uint8_t       key_id,
  const uint8_t *buf,
  uint32_t       len,
  uint32_t       timeout_ms,
  uint32_t      *abort_out);
#endif /* FBSEC_FEATURE_WRITE */

#if FBSEC_FEATURE_CYCLIC
/* ---- Cyclic-mode session API ------------------------------------- */

/**
 * @brief Client-side cyclic-mode session context.
 *
 * Owned by the caller (typically a small static array indexed by
 * data_id). Populated by fbsec_secure_read_armed / fbsec_secure_write_armed,
 * mutated on each fbsec_secure_poll_*. Treat fields as opaque.
 */
typedef struct fbsec_secure_session_t {
  bool      in_use;
  uint32_t  data_id;
  uint8_t   key_id;             /* full wire byte (incl. encrypt + cont bits) */
  uint8_t   nonce_base[FBSEC_AEAD_NONCE_SIZE];  /* XOR of arm-time randoms */
  uint32_t  counter;            /* last-used counter; next frame uses +1 */
} fbsec_secure_session_t;

#if FBSEC_FEATURE_READ
/**
 * @brief Cyclic-capable single secure-read.
 *
 * Wire-byte-identical to @ref fbsec_secure_read EXCEPT bit 6 of the
 * keyid is forced on, signalling to the server "keep a session for
 * this entry alive after the data return". The Pass-2 response is
 * byte-identical to the plain single-shot's
 * `server_random[R] || cipher[N] || tag[T]`; no session_id on the
 * wire. This function decrypts the data into @p buf, computes
 * nonce_base = XOR(client_random, server_random), and populates
 * @p out_sess so the caller can hand it straight to
 * @ref fbsec_secure_poll_read for follow-up polls.
 *
 * @param key_id  Wire keyid: bits 3..0 = base id (1..15), bits 5..4
 *                reserved (must be 0), bit 7 may be set for
 *                encryption, bit 6 will be forced on inside this
 *                function.
 */
fbsec_secure_status_t fbsec_secure_read_armed(
  const fbsec_secure_transport_t *transport,
  uint16_t                      device_id,
  uint32_t                      data_id,
  const uint8_t                 key[FBSEC_AEAD_KEY_SIZE],
  uint8_t                       key_id,
  uint8_t                      *buf,
  uint32_t                      buf_size,
  uint32_t                      timeout_ms,
  uint32_t                     *len_out,
  uint32_t                     *abort_out,
  fbsec_secure_session_t         *out_sess);

/**
 * @brief Issue one cyclic-read poll on an armed session.
 *
 * Sends READ_POLL_REQUEST with the next counter's low byte. Receives
 * READ_POLL_RESPONSE, verifies the wire counter byte matches, runs
 * fbsec_aead_open with the derived nonce, and copies the plaintext into
 * @p plain. Advances @p sess->counter on success only.
 *
 * @param tag_out  If non-NULL, receives the FBSEC_AEAD_TAG_SIZE-byte
 *                 wire tag from the response on success (lets demos
 *                 render it without re-parsing the wire frame).
 */
fbsec_secure_status_t fbsec_secure_poll_read(
  const fbsec_secure_transport_t *transport,
  uint16_t                      device_id,
  const uint8_t                 key[FBSEC_AEAD_KEY_SIZE],
  uint32_t                      timeout_ms,
  uint32_t                     *abort_out,
  fbsec_secure_session_t         *sess,
  uint8_t                      *plain,
  uint16_t                      plain_max,
  uint16_t                     *plain_len_out,
  uint8_t                      *tag_out);
#endif /* FBSEC_FEATURE_READ */

#if FBSEC_FEATURE_WRITE
/**
 * @brief Cyclic-capable single secure-write.
 *
 * Wire-byte-identical to @ref fbsec_secure_write EXCEPT bit 6 of the
 * Pass-2 keyid is forced on, signalling to the server "keep a session
 * for this entry alive after the commit". The Pass-2 ACK is empty
 * (same as single-shot). This function computes
 * nonce_base = XOR(client_random, server_random) and populates
 * @p out_sess so the caller can hand it straight to
 * @ref fbsec_secure_poll_write for follow-up polls.
 */
fbsec_secure_status_t fbsec_secure_write_armed(
  const fbsec_secure_transport_t *transport,
  uint16_t                      device_id,
  uint32_t                      data_id,
  const uint8_t                 key[FBSEC_AEAD_KEY_SIZE],
  uint8_t                       key_id,
  const uint8_t                *buf,
  uint32_t                      len,
  uint32_t                      timeout_ms,
  uint32_t                     *abort_out,
  fbsec_secure_session_t         *out_sess);

/**
 * @brief Issue one cyclic-write poll on an armed session.
 *
 * Builds counter_low[1] || ciphertext[len] || tag[8], increments the
 * stored counter, and sends. Server reply is just an envelope status
 * (no authenticated body).
 *
 * @param tag_out  If non-NULL, receives the FBSEC_AEAD_TAG_SIZE-byte
 *                 wire tag the client just sent (lets demos render
 *                 the same bytes that went onto the wire).
 */
fbsec_secure_status_t fbsec_secure_poll_write(
  const fbsec_secure_transport_t *transport,
  uint16_t                      device_id,
  const uint8_t                 key[FBSEC_AEAD_KEY_SIZE],
  uint32_t                      timeout_ms,
  uint32_t                     *abort_out,
  fbsec_secure_session_t         *sess,
  const uint8_t                *plain,
  uint16_t                      plain_len,
  uint8_t                      *tag_out);
#endif /* FBSEC_FEATURE_WRITE */

#endif /* FBSEC_FEATURE_CYCLIC */

#ifdef __cplusplus
}
#endif

#endif /* FBSEC_SECURE_PROTO_H */
/* EOF */
