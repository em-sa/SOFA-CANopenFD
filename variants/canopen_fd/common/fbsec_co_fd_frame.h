/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    fbsec_co_fd_frame.h
 * @brief   SOFA CANopen FD, CAN FD frame struct and (de)serialization.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 06-MAY-2026
 *
 * In-memory representation of a CAN FD frame plus codecs against the
 * 6-byte-header carrier wire format defined by
 * `doc/fieldbus_sim_canopen_fd_spec.txt §3`:
 *
 *     offset  size  field            notes
 *     ------  ----  ---------------  -----------------------------------
 *     0       4     can_id           uint32 LE; bit 31=IDE, 30=RTR,
 *                                              29=ERR, 28..0 id value
 *     4       1     flags            bit 0=BRS, bit 1=ESI, others reserved
 *     5       1     len              payload length, 0..64 (carrier-exact)
 *     6       N     payload          len bytes
 *
 * Pure CAN FD plumbing: no SOFA / USDO semantics live here. The
 * USDO codec sits on top in `fbsec_co_fd_usdo.{c,h}`.
 *
 * No socket headers, no malloc, no globals. Thread-safe.
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#ifndef FBSEC_CO_FD_FRAME_H
#define FBSEC_CO_FD_FRAME_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum CAN FD payload, in bytes. */
#define FBSEC_CO_FD_PAYLOAD_MAX 64u

/** Carrier header size (bytes preceding the variable-length payload). */
#define FBSEC_CO_FD_HEADER_SIZE 6u

/** Maximum on-wire size of a single carrier message (header + max payload). */
#define FBSEC_CO_FD_WIRE_MAX (FBSEC_CO_FD_HEADER_SIZE + FBSEC_CO_FD_PAYLOAD_MAX)

/* ---- can_id flag bits (top byte of the 32-bit can_id word) -------------- */

#define FBSEC_CO_FD_CAN_ID_FLAG_IDE (1u << 31)  /**< 1 = 29-bit extended ID */
#define FBSEC_CO_FD_CAN_ID_FLAG_RTR (1u << 30)  /**< must be 0 (CAN FD)     */
#define FBSEC_CO_FD_CAN_ID_FLAG_ERR (1u << 29)  /**< must be 0              */
#define FBSEC_CO_FD_CAN_ID_FLAGS    0xE0000000u
#define FBSEC_CO_FD_CAN_ID_VALUE    0x1FFFFFFFu /**< bits 28..0             */

#define FBSEC_CO_FD_STD_ID_MAX 0x000007FFu      /**< 11-bit max             */
#define FBSEC_CO_FD_EXT_ID_MAX 0x1FFFFFFFu      /**< 29-bit max             */

/* ---- frame.flags bits --------------------------------------------------- */

#define FBSEC_CO_FD_FLAG_BRS (1u << 0)  /**< bit-rate switch (informational) */
#define FBSEC_CO_FD_FLAG_ESI (1u << 1)  /**< error state indicator           */
#define FBSEC_CO_FD_FLAG_ALL (FBSEC_CO_FD_FLAG_BRS | FBSEC_CO_FD_FLAG_ESI)

/**
 * @brief In-memory CAN FD frame.
 *
 * @c can_id carries the identifier together with the IDE / RTR / ERR
 * flags in its top byte (see the FBSEC_CO_FD_CAN_ID_FLAG_* macros).
 * @c flags carries the BRS / ESI flags (see FBSEC_CO_FD_FLAG_*).
 * @c len gives the payload byte count, 0..64. @c payload is filled
 * up to @c len; bytes beyond are uninspected.
 */
typedef struct fbsec_co_fd_frame_t {
  uint32_t can_id;
  uint8_t  flags;
  uint8_t  len;
  uint8_t  payload[FBSEC_CO_FD_PAYLOAD_MAX];
} fbsec_co_fd_frame_t;

/* ---- Construction helpers ---------------------------------------------- */

/**
 * @brief Initialize @p f to a zeroed frame with the given CAN ID and
 *        IDE bit, leaving payload empty.
 *
 * Convenience for callers that build frames programmatically.
 *
 * @param f          frame to initialize. Must not be NULL.
 * @param can_id     identifier value (without the FLAG bits in bits
 *                   28..0).
 * @param extended   true to set the IDE flag (29-bit ID), false for
 *                   11-bit.
 */
void fbsec_co_fd_frame_init(fbsec_co_fd_frame_t *f,
                            uint32_t can_id,
                            bool     extended);

/* ---- Validation -------------------------------------------------------- */

/** Validation result codes from @ref fbsec_co_fd_frame_validate. */
typedef enum {
  FBSEC_CO_FD_VALID_OK             = 0,
  FBSEC_CO_FD_VALID_RESERVED_CANID = 1, /**< RTR / ERR / 11-bit overflow   */
  FBSEC_CO_FD_VALID_RESERVED_FLAGS = 2, /**< unknown bit set in frame.flags*/
  FBSEC_CO_FD_VALID_LEN_TOO_BIG    = 3  /**< len > FBSEC_CO_FD_PAYLOAD_MAX */
} fbsec_co_fd_validity_t;

/**
 * @brief Check that a frame is well-formed enough to put on the wire.
 *
 * Useful both before serialization and after deserialization. The
 * carrier-level error codes that map onto these results are listed
 * in `doc/fieldbus_sim_canopen_fd_spec.txt §7.3`:
 *
 *   FBSEC_CO_FD_VALID_RESERVED_CANID  ->  SIM_FRAME_ERROR err 0x01
 *   FBSEC_CO_FD_VALID_RESERVED_FLAGS  ->  SIM_FRAME_ERROR err 0x02
 *   FBSEC_CO_FD_VALID_LEN_TOO_BIG     ->  SIM_FRAME_ERROR err 0x03
 *
 * @param f  frame to validate. Must not be NULL.
 */
fbsec_co_fd_validity_t fbsec_co_fd_frame_validate(const fbsec_co_fd_frame_t *f);

/* ---- Serialization ----------------------------------------------------- */

/**
 * @brief Serialize @p f into the 6-byte-header carrier wire format.
 *
 * Caller passes a buffer of at least @ref FBSEC_CO_FD_WIRE_MAX bytes;
 * the actual on-wire length (header + payload) is written into
 * @p out_len.
 *
 * @param f         frame to serialize. Must not be NULL. The caller
 *                  is expected to have validated @p f first; this
 *                  function does NOT re-validate.
 * @param buf       destination buffer. Must not be NULL.
 * @param buf_size  capacity of @p buf in bytes.
 * @param out_len   receives the written byte count on success.
 *                  Must not be NULL.
 *
 * @retval true   serialization succeeded.
 * @retval false  @p buf_size too small for header + f->len.
 */
bool fbsec_co_fd_frame_serialize(const fbsec_co_fd_frame_t *f,
                                 uint8_t                   *buf,
                                 size_t                     buf_size,
                                 size_t                    *out_len);

/* ---- Deserialization --------------------------------------------------- */

/** Parse-step results from @ref fbsec_co_fd_frame_parse_header. */
typedef enum {
  FBSEC_CO_FD_PARSE_OK              = 0, /**< header complete; payload follows */
  FBSEC_CO_FD_PARSE_NEED_MORE       = 1, /**< not enough bytes yet           */
  FBSEC_CO_FD_PARSE_LEN_TOO_BIG     = 2, /**< len byte > FBSEC_CO_FD_PAYLOAD_MAX */
  FBSEC_CO_FD_PARSE_RESERVED_CANID  = 3,
  FBSEC_CO_FD_PARSE_RESERVED_FLAGS  = 4
} fbsec_co_fd_parse_t;

/**
 * @brief Parse the 6-byte carrier header from @p buf into @p f.
 *
 * On success @p *expected_payload is set to the number of payload
 * bytes the caller still has to read from the wire to complete the
 * frame; the caller deposits those bytes directly at
 * `f->payload[0..*expected_payload-1]`. The header bytes themselves
 * are no longer needed in @p buf after this call returns.
 *
 * @param buf                input buffer holding at least
 *                           FBSEC_CO_FD_HEADER_SIZE bytes.
 * @param buf_len            number of valid bytes in @p buf.
 * @param f                  destination frame; can_id / flags / len
 *                           are populated, payload bytes are NOT
 *                           touched. Must not be NULL.
 * @param expected_payload   receives the number of payload bytes to
 *                           still read on success. Must not be NULL.
 *
 * @retval FBSEC_CO_FD_PARSE_OK             header parsed; read @p
 *                                           *expected_payload more
 *                                           bytes into f->payload.
 * @retval FBSEC_CO_FD_PARSE_NEED_MORE      buf_len < HEADER_SIZE.
 * @retval FBSEC_CO_FD_PARSE_LEN_TOO_BIG    declared len > 64.
 * @retval FBSEC_CO_FD_PARSE_RESERVED_CANID bit 30 / 29 set, or 11-bit
 *                                           with bits 28..11 nonzero.
 * @retval FBSEC_CO_FD_PARSE_RESERVED_FLAGS unknown bits set in flags.
 */
fbsec_co_fd_parse_t fbsec_co_fd_frame_parse_header(const uint8_t        *buf,
                                                   size_t                buf_len,
                                                   fbsec_co_fd_frame_t  *f,
                                                   size_t               *expected_payload);

/* ---- Convenience accessors --------------------------------------------- */

/** @return Identifier value (bits 28..0 of can_id). */
uint32_t fbsec_co_fd_frame_id_value(const fbsec_co_fd_frame_t *f);

/** @return true if the frame uses a 29-bit extended identifier. */
bool fbsec_co_fd_frame_is_extended(const fbsec_co_fd_frame_t *f);

#ifdef __cplusplus
}
#endif

#endif /* FBSEC_CO_FD_FRAME_H */
/* EOF */
