/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    fbsec_secure_od.h
 * @brief   SOFA server-side secure object dictionary, public API.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 03-MAY-2026
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

#include "fbsec_aead.h"

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

/* ---- Standard demo abort codes (CiA-301 derived, application-defined) - */

#define FBSEC_SOD_ABORT_TYPEMISMATCH  0x06070010uL
#define FBSEC_SOD_ABORT_UNSUPPORTED   0x06010000uL
#define FBSEC_SOD_ABORT_LOCKED        0x08000022uL
#define FBSEC_SOD_ABORT_TRANSFER      0x08000020uL
#define FBSEC_SOD_ABORT_TAGFAIL       0x05030000uL
#define FBSEC_SOD_ABORT_GENERAL       0x08000000uL

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
 * @brief Install a session key in slot @p key_id (1..FBSEC_SOD_KEY_SLOTS).
 *
 * @retval true  key installed.
 * @retval false invalid key_id, NULL key, or slot already populated.
 */
bool fbsec_sod_set_key(uint8_t key_id, const uint8_t key[FBSEC_AEAD_KEY_SIZE]);

/**
 * @brief Check whether a key slot has been populated.
 */
bool fbsec_sod_has_key(uint8_t key_id);

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
 * Reply envelope: 4-byte LE status header + reply payload bytes.
 * - On FBSEC_SOD_OK:    status = 0, payload = (filled by this fn).
 * - On FBSEC_SOD_ABORT: status = (out_abort), payload empty.
 * - On FBSEC_SOD_DEFER: status = 0, payload empty (challenge accepted,
 *                                            response pending).
 * - On FBSEC_SOD_NOT_HANDLED: caller falls back to plain dispatch.
 *
 * @param client_dev    Source device_id of the request.
 * @param data_id       Application data_id.
 * @param req           Request bytes (the transport frame's payload).
 * @param req_len       Request length.
 * @param reply         Buffer for reply payload (excludes the 4-byte
 *                      status header, caller prepends that).
 * @param reply_max     Capacity of @p reply.
 * @param reply_len     Receives the reply payload length on OK / DEFER.
 * @param out_abort     Receives the abort code on ABORT.
 */
fbsec_sod_status_t fbsec_sod_dispatch(
  uint16_t       client_dev,
  uint32_t       data_id,
  const uint8_t *req,
  uint16_t       req_len,
  uint8_t       *reply,
  uint16_t       reply_max,
  uint16_t      *reply_len,
  uint32_t      *out_abort);

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
 * FBSEC_SOD_ABORT_LOCKED.
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
 * false -> abort with FBSEC_SOD_ABORT_UNSUPPORTED.
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
 * @return         0 on success or an abort code on application refusal.
 */
uint32_t fbsec_sod_port_read_before(uint32_t data_id,
                                  uint8_t *dst,
                                  uint16_t *len);

/**
 * @brief Apply a verified SECURE_WO plaintext.
 *
 * @return 0 on commit success or an abort code.
 */
uint32_t fbsec_sod_port_write_after(uint32_t data_id,
                                  const uint8_t *src,
                                  uint16_t len);

#ifdef __cplusplus
}
#endif

#endif /* FBSEC_SECURE_OD_H */
/* EOF */
