/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    fbsec_co_fd_frame.c
 * @brief   SOFA CANopen FD, CAN FD frame codec, implementation.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 06-MAY-2026
 *
 * Pure byte-shovelling: no SOFA semantics, no platform headers.
 * See header for the wire layout.
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#include "fbsec_co_fd_frame.h"

#include <string.h>

/* ---- Little-endian helpers (local; no other module needs them) ---------- */

static uint32_t read_u32le(const uint8_t *p) {
  return ((uint32_t)p[0])
       | ((uint32_t)p[1] <<  8)
       | ((uint32_t)p[2] << 16)
       | ((uint32_t)p[3] << 24);
}

static void write_u32le(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)( v        & 0xFFu);
  p[1] = (uint8_t)((v >>  8) & 0xFFu);
  p[2] = (uint8_t)((v >> 16) & 0xFFu);
  p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

/* ---- Construction ------------------------------------------------------ */

void fbsec_co_fd_frame_init(fbsec_co_fd_frame_t *f,
                            uint32_t can_id,
                            bool     extended) {
  memset(f, 0, sizeof(*f));
  f->can_id = can_id & FBSEC_CO_FD_CAN_ID_VALUE;
  if (extended) {
    f->can_id |= FBSEC_CO_FD_CAN_ID_FLAG_IDE;
  }
}

/* ---- Validation -------------------------------------------------------- */

fbsec_co_fd_validity_t fbsec_co_fd_frame_validate(const fbsec_co_fd_frame_t *f) {
  if ((f->can_id & FBSEC_CO_FD_CAN_ID_FLAG_RTR) != 0u) {
    return FBSEC_CO_FD_VALID_RESERVED_CANID;
  }
  if ((f->can_id & FBSEC_CO_FD_CAN_ID_FLAG_ERR) != 0u) {
    return FBSEC_CO_FD_VALID_RESERVED_CANID;
  }
  /* 11-bit frame: bits 28..11 of identifier value must be zero. */
  if ((f->can_id & FBSEC_CO_FD_CAN_ID_FLAG_IDE) == 0u) {
    if ((f->can_id & FBSEC_CO_FD_CAN_ID_VALUE) > FBSEC_CO_FD_STD_ID_MAX) {
      return FBSEC_CO_FD_VALID_RESERVED_CANID;
    }
  }
  if ((f->flags & ~FBSEC_CO_FD_FLAG_ALL) != 0u) {
    return FBSEC_CO_FD_VALID_RESERVED_FLAGS;
  }
  if (f->len > FBSEC_CO_FD_PAYLOAD_MAX) {
    return FBSEC_CO_FD_VALID_LEN_TOO_BIG;
  }
  return FBSEC_CO_FD_VALID_OK;
}

/* ---- Serialization ----------------------------------------------------- */

bool fbsec_co_fd_frame_serialize(const fbsec_co_fd_frame_t *f,
                                 uint8_t                   *buf,
                                 size_t                     buf_size,
                                 size_t                    *out_len) {
  size_t total = (size_t)FBSEC_CO_FD_HEADER_SIZE + (size_t)f->len;
  if (buf_size < total) {
    return false;
  }
  write_u32le(buf, f->can_id);
  buf[4] = f->flags;
  buf[5] = f->len;
  if (f->len > 0u) {
    memcpy(buf + FBSEC_CO_FD_HEADER_SIZE, f->payload, f->len);
  }
  *out_len = total;
  return true;
}

/* ---- Deserialization --------------------------------------------------- */

fbsec_co_fd_parse_t fbsec_co_fd_frame_parse_header(const uint8_t        *buf,
                                                   size_t                buf_len,
                                                   fbsec_co_fd_frame_t  *f,
                                                   size_t               *expected_payload) {
  if (buf_len < FBSEC_CO_FD_HEADER_SIZE) {
    return FBSEC_CO_FD_PARSE_NEED_MORE;
  }

  uint32_t can_id = read_u32le(buf);
  uint8_t  flags  = buf[4];
  uint8_t  len    = buf[5];

  /* Reject before populating the frame so a caller that ignores the
     return value does not see a partially-populated object. */
  if ((can_id & FBSEC_CO_FD_CAN_ID_FLAG_RTR) != 0u ||
      (can_id & FBSEC_CO_FD_CAN_ID_FLAG_ERR) != 0u) {
    return FBSEC_CO_FD_PARSE_RESERVED_CANID;
  }
  if ((can_id & FBSEC_CO_FD_CAN_ID_FLAG_IDE) == 0u &&
      (can_id & FBSEC_CO_FD_CAN_ID_VALUE) > FBSEC_CO_FD_STD_ID_MAX) {
    return FBSEC_CO_FD_PARSE_RESERVED_CANID;
  }
  if ((flags & ~FBSEC_CO_FD_FLAG_ALL) != 0u) {
    return FBSEC_CO_FD_PARSE_RESERVED_FLAGS;
  }
  if (len > FBSEC_CO_FD_PAYLOAD_MAX) {
    return FBSEC_CO_FD_PARSE_LEN_TOO_BIG;
  }

  f->can_id        = can_id;
  f->flags         = flags;
  f->len           = len;
  /* payload bytes are filled by the caller after this call */
  *expected_payload = (size_t)len;
  return FBSEC_CO_FD_PARSE_OK;
}

/* ---- Convenience accessors --------------------------------------------- */

uint32_t fbsec_co_fd_frame_id_value(const fbsec_co_fd_frame_t *f) {
  return f->can_id & FBSEC_CO_FD_CAN_ID_VALUE;
}

bool fbsec_co_fd_frame_is_extended(const fbsec_co_fd_frame_t *f) {
  return (f->can_id & FBSEC_CO_FD_CAN_ID_FLAG_IDE) != 0u;
}

/* EOF */
