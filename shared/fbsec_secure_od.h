/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    fbsec_secure_od.h
 * @brief   SOFA server-side secure object dictionary, public API.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.2 of 22-JUL-2026
 *
 * Server-side counterpart to fbsec_secure_proto: a tiny registry of
 * (data_id) -> (access flags, key_id, data_len) records, plus the
 * dispatch state machine that fields incoming secure read challenges
 * and write requests, runs the AEAD wrap / unwrap, and surfaces the
 * three application hooks (access_allowed, read_before, write_after)
 * to the host.
 *
 * Direct port of MCOPSecureAccess/MCO_CiA401__User_Secure/secure_od.h
 * with the addressing widened to (uint16 device_id, uint32 data_id) and
 * the AEAD calls switched to fbsec_aead. Renamed to fbsec_secure_od for
 * namespace consistency. Greenfield implementation under Apache 2.0.
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#ifndef FBSEC_SECURE_OD_H
#define FBSEC_SECURE_OD_H

#include <stdint.h>
#include <stdbool.h>

#include "fbsec_abort.h"
#include "fbsec_aead.h"
#if FBSEC_FEATURE_ASYM
#include "fbsec_asym.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Sizing ---------------------------------------------------------- */

#define FBSEC_SOD_MAX_ENTRIES            8u     /* MVP: small registry        */
#define FBSEC_SOD_KEY_SLOTS              4u     /* hard-coded slots: 0..3     */
#define FBSEC_SOD_CHALLENGE_TIMEOUT_MS   5000u  /* single-shot arm staleness  */
#define FBSEC_SOD_SESSION_IDLE_TIMEOUT_MS 60000u /* cyclic-mode idle gap      */

/* ---- Access flags ---------------------------------------------------- */

#define FBSEC_SOD_ACCESS_NONE         0x00u
#define FBSEC_SOD_ACCESS_SECURE_RO    0x01u
#define FBSEC_SOD_ACCESS_SECURE_WO    0x02u
/* Marks an entry whose read data is confidential, not merely integrity-
   protected. Authenticate-only builds (FBSEC_AEAD_ENCRYPTION == 0) carry the
   payload in clear, so a confidential entry cannot be honored there;
   fbsec_sod_register_entry refuses such an entry at build/startup rather than
   silently exposing it. Combine with FBSEC_SOD_ACCESS_SECURE_RO. */
#define FBSEC_SOD_ACCESS_CONFIDENTIAL 0x04u

/* ---- Key role sentinel ----------------------------------------------- */

#define FBSEC_SOD_KEY_NONE            0x00u   /* not bound; for SECURE_RO "any" */

/* ---- Operation enum --------------------------------------------------- */

typedef enum fbsec_sod_op_t {
  FBSEC_SOD_OP_READ  = 0,
  FBSEC_SOD_OP_WRITE = 1
} fbsec_sod_op_t;

/* ---- Value-type tag (for trace rendering) ---------------------------- */

#define FBSEC_SOD_TYPE_BIN     0x00u   /* opaque bytes; render as hex          */
#define FBSEC_SOD_TYPE_STRING  0x01u   /* ASCII; trace renders as quoted text  */

/* ---- Status enum (returned to host dispatch glue) -------------------- */

typedef enum fbsec_sod_status_t {
  FBSEC_SOD_OK          = 0,    /* request handled, response is ready    */
  FBSEC_SOD_NOT_HANDLED = 1,    /* not a registered secure entry         */
  FBSEC_SOD_ABORT       = 2,    /* request denied; out_abort holds code  */
  FBSEC_SOD_DEFER       = 3     /* read-challenge armed; reply with ACK  */
} fbsec_sod_status_t;

/* ---- Entry record ---------------------------------------------------- */

typedef struct fbsec_sod_entry_t {
  uint32_t data_id;
  uint8_t  key_id;          /* 1..15 (or FBSEC_SOD_KEY_NONE = "any") */
  uint8_t  access_flags;
  uint8_t  value_type;      /* FBSEC_SOD_TYPE_*; 0 = BIN by default   */
  uint16_t data_len;
} fbsec_sod_entry_t;

/* ---- Abort codes ------------------------------------------------------ */
/* Single-byte CiA 1301 Table 31 codes plus the SOFA C0h..CFh block; see
   fbsec_abort.h. The former 32-bit FBSEC_SOD_ABORT_* set (classical CiA
   301 SDO abort codes) is gone - it was never valid on a USDO bus. */

/* ---- Public API ------------------------------------------------------- */

/**
 * @brief Initialize / reset the registry, key slots, and challenge state.
 */
void fbsec_sod_init(void);

/**
 * @brief Register a secure OD entry.
 *
 * @retval true  registered (or replaced existing entry with same data_id).
 * @retval false registry full or invalid entry.
 */
bool fbsec_sod_register_entry(const fbsec_sod_entry_t *entry);

/**
 * @brief Look up a registered entry by data_id.
 *
 * @return Pointer into the registry, or NULL.
 */
const fbsec_sod_entry_t *fbsec_sod_find_entry(uint32_t data_id);

/**
 * @brief Test support: age every armed slot past its freshness window.
 *
 * Not used in production. Moves the arming timestamp of each read and write
 * slot far enough back that both the single-shot and the cyclic freshness
 * checks treat it as stale, so tests can exercise the stale-slot paths without
 * waiting out the real timeout. Only timestamps change; no key, entry or
 * armed-payload state is touched.
 */
void fbsec_sod_test_expire_arming(void);

/**
 * @brief Install a session key in slot @p key_id (1..FBSEC_SOD_KEY_SLOTS).
 *
 * The non-secret key id / version reported by C011h defaults to the slot
 * number. Use @ref fbsec_sod_set_key_ex to set it explicitly.
 *
 * @retval true  key installed.
 * @retval false invalid key_id, NULL key, or slot already populated.
 */
bool fbsec_sod_set_key(uint8_t key_id, const uint8_t key[FBSEC_AEAD_KEY_SIZE]);

/**
 * @brief Install a session key with an explicit non-secret id / version.
 *
 * As @ref fbsec_sod_set_key, but records @p id_value as the key id
 * reported by C011h, independent of the slot's role number.
 *
 * @retval true  key installed.
 * @retval false invalid key_id, NULL key, or slot already populated.
 */
bool fbsec_sod_set_key_ex(uint8_t key_id, const uint8_t key[FBSEC_AEAD_KEY_SIZE],
                          uint32_t id_value);

/**
 * @brief Check whether a key slot has been populated.
 */
bool fbsec_sod_has_key(uint8_t key_id);

/**
 * @brief Non-secret key id / version of a slot, for C011h.
 *
 * @return the id set at install (or the slot number by default), or 0 if
 *         the slot is empty or @p key_id is out of range.
 */
uint32_t fbsec_sod_get_key_id_value(uint8_t key_id);

/* ---- Dispatch entry points ------------------------------------------- */

/**
 * @brief Handle an inbound request frame from a peer.
 *
 * Looks up @p data_id in the registry and runs the matching dispatch.
 * Caller (the server's main loop) provides the request payload and a
 * buffer for the reply payload; this function fills the reply payload
 * and returns its length plus a status that tells the caller what to
 * send back inside the demo response envelope.
 *
 * The variant wraps the outcome in its own envelope:
 * - On FBSEC_SOD_OK:    normal response carrying @p reply.
 * - On FBSEC_SOD_ABORT: an abort carrying the one-byte @p out_abort
 *                       code, no payload.
 * - On FBSEC_SOD_DEFER: empty positive ACK (challenge accepted,
 *                       response pending).
 * - On FBSEC_SOD_NOT_HANDLED: caller falls back to plain dispatch.
 *
 * @param client_dev    Source device_id of the request.
 * @param data_id       Application data_id.
 * @param req           Request bytes (the transport frame's payload).
 * @param req_len       Request length.
 * @param reply         Buffer for the reply payload; the variant adds
 *                      its own envelope around it.
 * @param reply_max     Capacity of @p reply.
 * @param reply_len     Receives the reply payload length on OK / DEFER.
 * @param out_abort     Receives the CiA 1301 abort code on ABORT.
 */
fbsec_sod_status_t fbsec_sod_dispatch(
  uint16_t       client_dev,
  uint32_t       data_id,
  const uint8_t *req,
  uint16_t       req_len,
  uint8_t       *reply,
  uint16_t       reply_max,
  uint16_t      *reply_len,
  fbsec_abort_t *out_abort);

/* ---- Host port hooks ------------------------------------------------- */

/**
 * @brief Returns this server's device_id (used in the AAD prefix).
 */
uint16_t fbsec_sod_port_get_device_id(void);

/**
 * @brief Returns a free-running millisecond counter for challenge
 *        freshness checks. Wraps at 16 bits; core handles single wrap.
 */
uint16_t fbsec_sod_port_get_time_ms(void);

/**
 * @brief Fill @p buf with @p len cryptographically-strong random bytes.
 *
 * Used to generate R_B for write challenges.
 */
bool fbsec_sod_port_random(uint8_t *buf, uint16_t len);

/**
 * @brief Pre-execution access gate. Called before any read or write.
 *
 * Device-state question: "is this op allowed at all right now?" (lock
 * state, region map, factory mode, etc.). The keyid is not part of
 * this decision; for per-key role policy use @ref
 * fbsec_sod_port_role_allowed. Returns false -> abort with
 * FBSEC_ABORT_DEVICE_STATE (62h).
 */
bool fbsec_sod_port_access_allowed(fbsec_sod_op_t op, uint32_t data_id);

/**
 * @brief Per-role access gate. Called once the requesting keyid is
 *        known and before any AEAD work that would commit state.
 *
 * Role question: "is this key allowed to perform this op against this
 * entry?" The dispatcher passes the bare 4-bit identity (1..15); bits
 * 7/6 (encryption / cyclic-arm) are stripped so the policy is over the
 * role, not the wire flags. The hook is called at every point the
 * keyid is known: read challenge arm, cyclic write arm, single-shot
 * write Pass 2 (before AEAD verify), and on each cyclic poll. Returns
 * false -> abort with FBSEC_ABORT_ROLE_DENIED (C3h).
 *
 * Default policy in the reference server: Provisioning Session Key
 * (1) and Integrator Session Key (2) can read and write; Operator
 * Session Key (3) can read but not write. Hosts override this hook
 * to install their own role mapping.
 */
bool fbsec_sod_port_role_allowed(fbsec_sod_op_t op,
                                 uint8_t key_id_base,
                                 uint32_t data_id);

/**
 * @brief Materialize plaintext for a SECURE_RO read.
 *
 * @param data_id  Entry being read.
 * @param dst      Destination buffer (entry->data_len bytes).
 * @param len      In: max size (= entry->data_len). Out: actual.
 * @return         FBSEC_ABORT_NONE on success, or an abort code on
 *                 application refusal.
 */
fbsec_abort_t fbsec_sod_port_read_before(uint32_t data_id,
                                         uint8_t *dst,
                                         uint16_t *len);

/**
 * @brief Apply a verified SECURE_WO plaintext.
 *
 * @return FBSEC_ABORT_NONE on commit success, or an abort code.
 */
fbsec_abort_t fbsec_sod_port_write_after(uint32_t data_id,
                                         const uint8_t *src,
                                         uint16_t len);

#ifdef __cplusplus
}
#endif

#endif /* FBSEC_SECURE_OD_H */
/* EOF */
