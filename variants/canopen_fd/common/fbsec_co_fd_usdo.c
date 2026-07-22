/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    fbsec_co_fd_usdo.c
 * @brief   SOFA CANopen FD, USDO expedited + segmented PDU codec,
 *          implementation.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V3.1 of 20-JUL-2026
 *
 * Pure byte-shovelling on top of fbsec_co_fd_frame_t. See header for
 * the wire layout and the spec references.
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#include "fbsec_co_fd_usdo.h"

#include <string.h>

/* ---- CAN ID helpers --------------------------------------------------- */

uint32_t fbsec_co_fd_usdo_can_id(uint8_t sender_node_id, bool to_server) {
  if (sender_node_id == 0u || sender_node_id > FBSEC_CO_FD_NODE_ID_MAX) {
    return 0u;
  }
  uint32_t base = to_server ? FBSEC_CO_FD_USDO_REQ_BASE
                            : FBSEC_CO_FD_USDO_RSP_BASE;
  return base | (uint32_t)sender_node_id;
}

bool fbsec_co_fd_usdo_can_id_split(uint32_t                 can_id,
                                   uint8_t                 *sender_out,
                                   fbsec_co_fd_usdo_kind_t *kind_out) {
  uint8_t                 sender = (uint8_t)(can_id & FBSEC_CO_FD_USDO_NID_MASK);
  fbsec_co_fd_usdo_kind_t kind   = FBSEC_CO_FD_USDO_KIND_NONE;
  if (sender != 0u && sender <= FBSEC_CO_FD_NODE_ID_MAX) {
    if      ((can_id & FBSEC_CO_FD_USDO_BASE_MASK) == FBSEC_CO_FD_USDO_REQ_BASE) {
      kind = FBSEC_CO_FD_USDO_KIND_REQUEST;
    } else if ((can_id & FBSEC_CO_FD_USDO_BASE_MASK) == FBSEC_CO_FD_USDO_RSP_BASE) {
      kind = FBSEC_CO_FD_USDO_KIND_RESPONSE;
    }
  }
  if (sender_out != NULL) *sender_out = sender;
  if (kind_out   != NULL) *kind_out   = kind;
  return kind != FBSEC_CO_FD_USDO_KIND_NONE;
}

/* ---- cmd classification ----------------------------------------------- */

static bool cmd_is_known(uint8_t cmd) {
  switch (cmd) {
    case FBSEC_CO_FD_USDO_CMD_DOWNLOAD_REQ:
    case FBSEC_CO_FD_USDO_CMD_DOWNLOAD_RESP:
    case FBSEC_CO_FD_USDO_CMD_UPLOAD_REQ:
    case FBSEC_CO_FD_USDO_CMD_UPLOAD_RESP:
    case FBSEC_CO_FD_USDO_CMD_ABORT:
    case FBSEC_CO_FD_USDO_CMD_DOWNLOAD_INIT_REQ:
    case FBSEC_CO_FD_USDO_CMD_DOWNLOAD_SEG_REQ:
    case FBSEC_CO_FD_USDO_CMD_DOWNLOAD_END_REQ:
    case FBSEC_CO_FD_USDO_CMD_UPLOAD_SEG_REQ:
    case FBSEC_CO_FD_USDO_CMD_DOWNLOAD_INIT_RESP:
    case FBSEC_CO_FD_USDO_CMD_DOWNLOAD_SEG_RESP:
    case FBSEC_CO_FD_USDO_CMD_DOWNLOAD_END_RESP:
    case FBSEC_CO_FD_USDO_CMD_UPLOAD_INIT_RESP:
    case FBSEC_CO_FD_USDO_CMD_UPLOAD_SEG_RESP:
    case FBSEC_CO_FD_USDO_CMD_UPLOAD_END_RESP:
      return true;
    default:
      return false;
  }
}

/* True for the command specifiers that travel client -> server (they ride
   the 0x600 CAN ID base); everything else rides the 0x580 base. */
static bool cmd_is_request(uint8_t cmd) {
  switch (cmd) {
    case FBSEC_CO_FD_USDO_CMD_DOWNLOAD_REQ:
    case FBSEC_CO_FD_USDO_CMD_UPLOAD_REQ:
    case FBSEC_CO_FD_USDO_CMD_DOWNLOAD_INIT_REQ:
    case FBSEC_CO_FD_USDO_CMD_DOWNLOAD_SEG_REQ:
    case FBSEC_CO_FD_USDO_CMD_DOWNLOAD_END_REQ:
    case FBSEC_CO_FD_USDO_CMD_UPLOAD_SEG_REQ:
      return true;
    default:
      return false;
  }
}

/* True for cmd values that MUST carry a (data_type, data_length, data)
   block in the PDU regardless of @p data_len. For download_resp the
   data block is OPTIONAL: present iff @p data_len > 0 (the 2-byte
   session_id appended on the cyclic-capable single SWR commit ACK
   uses this; ordinary single-shot acks stay 6 bytes total). */
static bool cmd_must_have_data(uint8_t cmd) {
  return (cmd == FBSEC_CO_FD_USDO_CMD_DOWNLOAD_REQ)
      || (cmd == FBSEC_CO_FD_USDO_CMD_UPLOAD_RESP);
}

static bool cmd_emits_data(uint8_t cmd, uint16_t data_len) {
  if (cmd_must_have_data(cmd)) return true;
  if (cmd == FBSEC_CO_FD_USDO_CMD_DOWNLOAD_RESP && data_len > 0u) return true;
  return false;
}

/* ---- Encode shared core ----------------------------------------------- */

static bool encode_common(fbsec_co_fd_frame_t *out_frame,
                          uint8_t              src_node_id,
                          uint8_t              dst_node_id,
                          uint8_t              cmd,
                          uint8_t              session,
                          uint16_t             index,
                          uint8_t              subindex,
                          uint8_t              data_type,
                          const uint8_t       *data,
                          uint16_t             data_len) {
  if (out_frame == NULL) return false;
  if (src_node_id == 0u || src_node_id > FBSEC_CO_FD_NODE_ID_MAX) return false;
  if (dst_node_id == 0u || dst_node_id > FBSEC_CO_FD_NODE_ID_MAX) return false;
  if (session == 0u) return false;
  if (index < 0x1000u) return false;
  if (data_len > FBSEC_CO_FD_USDO_DATA_MAX) return false;
  if (data_len > 0u && data == NULL) return false;

  uint32_t can_id = fbsec_co_fd_usdo_can_id(src_node_id, cmd_is_request(cmd));
  if (can_id == 0u) return false;

  fbsec_co_fd_frame_init(out_frame, can_id, /*extended=*/false);
  out_frame->flags = FBSEC_CO_FD_FLAG_BRS;

  out_frame->payload[0] = dst_node_id;
  out_frame->payload[1] = cmd;
  out_frame->payload[2] = session;
  out_frame->payload[3] = subindex;
  out_frame->payload[4] = (uint8_t)( index        & 0xFFu);
  out_frame->payload[5] = (uint8_t)((index >> 8)  & 0xFFu);

  uint16_t total = FBSEC_CO_FD_USDO_HEADER_SIZE;
  if (cmd_emits_data(cmd, data_len)) {
    out_frame->payload[6] = data_type;
    out_frame->payload[7] = (uint8_t)data_len;
    if (data_len > 0u) {
      memcpy(&out_frame->payload[8], data, data_len);
    }
    total = (uint16_t)(FBSEC_CO_FD_USDO_HEADER_SIZE
                       + FBSEC_CO_FD_USDO_DATA_PREFIX_SIZE + data_len);
  }
  out_frame->len = (uint8_t)total;
  return true;
}

/* ---- Encode entry points ---------------------------------------------- */

bool fbsec_co_fd_usdo_encode_download_req(fbsec_co_fd_frame_t *out_frame,
                                          uint8_t              src_node_id,
                                          uint8_t              dst_node_id,
                                          uint8_t              session,
                                          uint16_t             index,
                                          uint8_t              subindex,
                                          const uint8_t       *data,
                                          uint16_t             data_len) {
  return encode_common(out_frame, src_node_id, dst_node_id,
                       FBSEC_CO_FD_USDO_CMD_DOWNLOAD_REQ, session,
                       index, subindex,
                       FBSEC_CO_FD_USDO_TYPE_DOMAIN, data, data_len);
}

bool fbsec_co_fd_usdo_encode_download_resp(fbsec_co_fd_frame_t *out_frame,
                                           uint8_t              src_node_id,
                                           uint8_t              dst_node_id,
                                           uint8_t              session,
                                           uint16_t             index,
                                           uint8_t              subindex,
                                           const uint8_t       *data,
                                           uint16_t             data_len) {
  return encode_common(out_frame, src_node_id, dst_node_id,
                       FBSEC_CO_FD_USDO_CMD_DOWNLOAD_RESP, session,
                       index, subindex,
                       FBSEC_CO_FD_USDO_TYPE_DOMAIN, data, data_len);
}

bool fbsec_co_fd_usdo_encode_upload_req(fbsec_co_fd_frame_t *out_frame,
                                        uint8_t              src_node_id,
                                        uint8_t              dst_node_id,
                                        uint8_t              session,
                                        uint16_t             index,
                                        uint8_t              subindex,
                                        const uint8_t       *data,
                                        uint16_t             data_len) {
  /* Upload-request is a read trigger and per the wire format carries no
     data block. The cyclic-arm byte SOFA wants to send (1-byte payload
     for swr Pass 1) is shipped as a download-request body instead;
     callers using upload_req with data_len > 0 are misconfigured. */
  if (data_len > 0u || data != NULL) return false;
  return encode_common(out_frame, src_node_id, dst_node_id,
                       FBSEC_CO_FD_USDO_CMD_UPLOAD_REQ, session,
                       index, subindex,
                       0u, NULL, 0u);
}

bool fbsec_co_fd_usdo_encode_upload_resp(fbsec_co_fd_frame_t *out_frame,
                                         uint8_t              src_node_id,
                                         uint8_t              dst_node_id,
                                         uint8_t              session,
                                         uint16_t             index,
                                         uint8_t              subindex,
                                         const uint8_t       *data,
                                         uint16_t             data_len) {
  return encode_common(out_frame, src_node_id, dst_node_id,
                       FBSEC_CO_FD_USDO_CMD_UPLOAD_RESP, session,
                       index, subindex,
                       FBSEC_CO_FD_USDO_TYPE_DOMAIN, data, data_len);
}

/* ---- Segmented transfer encode ---------------------------------------- */

/* Shared prologue for every segmented frame: validate the peers and the
   session, stamp the CAN ID and PDU bytes 0..2. Byte 3 and beyond are the
   caller's business. Returns false on any invalid argument. */
static bool encode_seg_common(fbsec_co_fd_frame_t *out_frame,
                              uint8_t              src_node_id,
                              uint8_t              dst_node_id,
                              uint8_t              cmd,
                              uint8_t              session) {
  if (out_frame == NULL) return false;
  if (src_node_id == 0u || src_node_id > FBSEC_CO_FD_NODE_ID_MAX) return false;
  if (dst_node_id == 0u || dst_node_id > FBSEC_CO_FD_NODE_ID_MAX) return false;
  if (session == 0u) return false;

  uint32_t can_id = fbsec_co_fd_usdo_can_id(src_node_id, cmd_is_request(cmd));
  if (can_id == 0u) return false;

  fbsec_co_fd_frame_init(out_frame, can_id, /*extended=*/false);
  out_frame->flags = FBSEC_CO_FD_FLAG_BRS;
  out_frame->payload[0] = dst_node_id;
  out_frame->payload[1] = cmd;
  out_frame->payload[2] = session;
  return true;
}

/* Initiate frames (0x02 / 0x32) share the 12-byte layout: the expedited
   header, then data_type, a reserved zero, and the size as u32 LE. */
static bool encode_init_common(fbsec_co_fd_frame_t *out_frame,
                               uint8_t              src_node_id,
                               uint8_t              dst_node_id,
                               uint8_t              cmd,
                               uint8_t              session,
                               uint16_t             index,
                               uint8_t              subindex,
                               uint32_t             total_size) {
  if ((total_size == 0u) || (total_size > FBSEC_CO_FD_USDO_SEG_BODY_MAX)) {
    return false;
  }
  if (index < 0x1000u) return false;
  if (!encode_seg_common(out_frame, src_node_id, dst_node_id, cmd, session)) {
    return false;
  }
  out_frame->payload[3]  = subindex;
  out_frame->payload[4]  = (uint8_t)( index       & 0xFFu);
  out_frame->payload[5]  = (uint8_t)((index >> 8) & 0xFFu);
  out_frame->payload[6]  = FBSEC_CO_FD_USDO_TYPE_DOMAIN;
  out_frame->payload[7]  = 0u;   /* reserved */
  out_frame->payload[8]  = (uint8_t)( total_size        & 0xFFu);
  out_frame->payload[9]  = (uint8_t)((total_size >>  8) & 0xFFu);
  out_frame->payload[10] = (uint8_t)((total_size >> 16) & 0xFFu);
  out_frame->payload[11] = (uint8_t)((total_size >> 24) & 0xFFu);
  out_frame->len         = (uint8_t)FBSEC_CO_FD_USDO_INIT_SIZE;
  return true;
}

/* Full (intermediate) segment frames (0x03 / 0x33): counter plus exactly
   FBSEC_CO_FD_USDO_SEG_DATA_MAX data bytes. */
static bool encode_seg_data(fbsec_co_fd_frame_t *out_frame,
                            uint8_t              src_node_id,
                            uint8_t              dst_node_id,
                            uint8_t              cmd,
                            uint8_t              session,
                            uint8_t              counter,
                            const uint8_t       *data) {
  if (data == NULL) return false;
  if (!encode_seg_common(out_frame, src_node_id, dst_node_id, cmd, session)) {
    return false;
  }
  out_frame->payload[3] = counter;
  memcpy(&out_frame->payload[FBSEC_CO_FD_USDO_SEG_HEADER_SIZE], data,
         FBSEC_CO_FD_USDO_SEG_DATA_MAX);
  out_frame->len = (uint8_t)FBSEC_CO_FD_PAYLOAD_MAX;
  return true;
}

/* End frames (0x04 / 0x34): byte 3 holds the last-segment byte count. */
static bool encode_seg_end(fbsec_co_fd_frame_t *out_frame,
                           uint8_t              src_node_id,
                           uint8_t              dst_node_id,
                           uint8_t              cmd,
                           uint8_t              session,
                           const uint8_t       *data,
                           uint16_t             len) {
  if (len > FBSEC_CO_FD_USDO_SEG_DATA_MAX) return false;
  if ((len > 0u) && (data == NULL)) return false;
  if (!encode_seg_common(out_frame, src_node_id, dst_node_id, cmd, session)) {
    return false;
  }
  out_frame->payload[3] = (uint8_t)len;
  if (len > 0u) {
    memcpy(&out_frame->payload[FBSEC_CO_FD_USDO_SEG_HEADER_SIZE], data, len);
  }
  out_frame->len = (uint8_t)(FBSEC_CO_FD_USDO_SEG_HEADER_SIZE + len);
  return true;
}

bool fbsec_co_fd_usdo_encode_download_init_req(fbsec_co_fd_frame_t *out_frame,
                                               uint8_t              src_node_id,
                                               uint8_t              dst_node_id,
                                               uint8_t              session,
                                               uint16_t             index,
                                               uint8_t              subindex,
                                               uint32_t             total_size) {
  return encode_init_common(out_frame, src_node_id, dst_node_id,
                            FBSEC_CO_FD_USDO_CMD_DOWNLOAD_INIT_REQ, session,
                            index, subindex, total_size);
}

bool fbsec_co_fd_usdo_encode_download_init_resp(fbsec_co_fd_frame_t *out_frame,
                                                uint8_t              src_node_id,
                                                uint8_t              dst_node_id,
                                                uint8_t              session,
                                                uint16_t             index,
                                                uint8_t              subindex) {
  if (index < 0x1000u) return false;
  if (!encode_seg_common(out_frame, src_node_id, dst_node_id,
                         FBSEC_CO_FD_USDO_CMD_DOWNLOAD_INIT_RESP, session)) {
    return false;
  }
  out_frame->payload[3] = subindex;
  out_frame->payload[4] = (uint8_t)( index       & 0xFFu);
  out_frame->payload[5] = (uint8_t)((index >> 8) & 0xFFu);
  out_frame->len        = (uint8_t)FBSEC_CO_FD_USDO_HEADER_SIZE;
  return true;
}

bool fbsec_co_fd_usdo_encode_download_seg_req(fbsec_co_fd_frame_t *out_frame,
                                              uint8_t              src_node_id,
                                              uint8_t              dst_node_id,
                                              uint8_t              session,
                                              uint8_t              counter,
                                              const uint8_t       *data) {
  return encode_seg_data(out_frame, src_node_id, dst_node_id,
                         FBSEC_CO_FD_USDO_CMD_DOWNLOAD_SEG_REQ, session,
                         counter, data);
}

bool fbsec_co_fd_usdo_encode_download_seg_resp(fbsec_co_fd_frame_t *out_frame,
                                               uint8_t              src_node_id,
                                               uint8_t              dst_node_id,
                                               uint8_t              session,
                                               uint8_t              counter) {
  if (!encode_seg_common(out_frame, src_node_id, dst_node_id,
                         FBSEC_CO_FD_USDO_CMD_DOWNLOAD_SEG_RESP, session)) {
    return false;
  }
  out_frame->payload[3] = counter;
  out_frame->len        = (uint8_t)FBSEC_CO_FD_USDO_SEG_HEADER_SIZE;
  return true;
}

bool fbsec_co_fd_usdo_encode_download_end_req(fbsec_co_fd_frame_t *out_frame,
                                              uint8_t              src_node_id,
                                              uint8_t              dst_node_id,
                                              uint8_t              session,
                                              const uint8_t       *data,
                                              uint16_t             len) {
  if (len == 0u) return false;   /* a download always ends with payload */
  return encode_seg_end(out_frame, src_node_id, dst_node_id,
                        FBSEC_CO_FD_USDO_CMD_DOWNLOAD_END_REQ, session,
                        data, len);
}

bool fbsec_co_fd_usdo_encode_download_end_resp(fbsec_co_fd_frame_t *out_frame,
                                               uint8_t              src_node_id,
                                               uint8_t              dst_node_id,
                                               uint8_t              session) {
  if (!encode_seg_common(out_frame, src_node_id, dst_node_id,
                         FBSEC_CO_FD_USDO_CMD_DOWNLOAD_END_RESP, session)) {
    return false;
  }
  out_frame->len = (uint8_t)FBSEC_CO_FD_USDO_END_RESP_SIZE;
  return true;
}

bool fbsec_co_fd_usdo_encode_upload_init_resp(fbsec_co_fd_frame_t *out_frame,
                                              uint8_t              src_node_id,
                                              uint8_t              dst_node_id,
                                              uint8_t              session,
                                              uint16_t             index,
                                              uint8_t              subindex,
                                              uint32_t             total_size) {
  return encode_init_common(out_frame, src_node_id, dst_node_id,
                            FBSEC_CO_FD_USDO_CMD_UPLOAD_INIT_RESP, session,
                            index, subindex, total_size);
}

bool fbsec_co_fd_usdo_encode_upload_seg_req(fbsec_co_fd_frame_t *out_frame,
                                            uint8_t              src_node_id,
                                            uint8_t              dst_node_id,
                                            uint8_t              session,
                                            uint8_t              counter) {
  if (!encode_seg_common(out_frame, src_node_id, dst_node_id,
                         FBSEC_CO_FD_USDO_CMD_UPLOAD_SEG_REQ, session)) {
    return false;
  }
  out_frame->payload[3] = counter;
  out_frame->len        = (uint8_t)FBSEC_CO_FD_USDO_SEG_HEADER_SIZE;
  return true;
}

bool fbsec_co_fd_usdo_encode_upload_seg_resp(fbsec_co_fd_frame_t *out_frame,
                                             uint8_t              src_node_id,
                                             uint8_t              dst_node_id,
                                             uint8_t              session,
                                             uint8_t              counter,
                                             const uint8_t       *data) {
  return encode_seg_data(out_frame, src_node_id, dst_node_id,
                         FBSEC_CO_FD_USDO_CMD_UPLOAD_SEG_RESP, session,
                         counter, data);
}

bool fbsec_co_fd_usdo_encode_upload_end_resp(fbsec_co_fd_frame_t *out_frame,
                                             uint8_t              src_node_id,
                                             uint8_t              dst_node_id,
                                             uint8_t              session,
                                             const uint8_t       *data,
                                             uint16_t             len) {
  return encode_seg_end(out_frame, src_node_id, dst_node_id,
                        FBSEC_CO_FD_USDO_CMD_UPLOAD_END_RESP, session,
                        data, len);
}

bool fbsec_co_fd_usdo_encode_abort(fbsec_co_fd_frame_t *out_frame,
                                   uint8_t              src_node_id,
                                   uint8_t              dst_node_id,
                                   uint8_t              session,
                                   uint16_t             index,
                                   uint8_t              subindex,
                                   fbsec_abort_t        abort_code) {
  /* CiA 1301 Table 32: the abort frame carries no data_type /
     data_length prefix. It is exactly 7 bytes and ends with the
     single-byte abort code. */
  if (index < 0x1000u) return false;
  if (!encode_seg_common(out_frame, src_node_id, dst_node_id,
                         FBSEC_CO_FD_USDO_CMD_ABORT, session)) {
    return false;
  }
  out_frame->payload[3] = subindex;
  out_frame->payload[4] = (uint8_t)( index       & 0xFFu);
  out_frame->payload[5] = (uint8_t)((index >> 8) & 0xFFu);
  out_frame->payload[FBSEC_CO_FD_USDO_ABORT_AC_OFFSET] = abort_code;
  out_frame->len        = (uint8_t)FBSEC_CO_FD_USDO_ABORT_SIZE;
  return true;
}

/* ---- Decode ----------------------------------------------------------- */

fbsec_co_fd_usdo_decode_t fbsec_co_fd_usdo_decode(
    const fbsec_co_fd_frame_t *f,
    fbsec_co_fd_usdo_pdu_t    *pdu) {
  uint8_t                 sender = 0u;
  fbsec_co_fd_usdo_kind_t kind   = FBSEC_CO_FD_USDO_KIND_NONE;
  if (!fbsec_co_fd_usdo_can_id_split(fbsec_co_fd_frame_id_value(f),
                                     &sender, &kind)) {
    return FBSEC_CO_FD_USDO_DECODE_NOT_USDO;
  }
  /* Every USDO frame - expedited, segmented or abort - carries at least
     receiver, cmd and session. The download-end response stops there. */
  if (f->len < FBSEC_CO_FD_USDO_END_RESP_SIZE) {
    return FBSEC_CO_FD_USDO_DECODE_FRAME_TOO_SHORT;
  }

  uint8_t dst_node_id = f->payload[0];
  uint8_t cmd         = f->payload[1];
  uint8_t session     = f->payload[2];

  if (dst_node_id == 0u || dst_node_id > FBSEC_CO_FD_NODE_ID_MAX) {
    return FBSEC_CO_FD_USDO_DECODE_RESERVED_NODE;
  }
  if (!cmd_is_known(cmd)) {
    return FBSEC_CO_FD_USDO_DECODE_BAD_CMD;
  }

  pdu->src_node_id = sender;
  pdu->dst_node_id = dst_node_id;
  pdu->cmd         = cmd;
  pdu->session     = session;
  pdu->index       = 0u;
  pdu->subindex    = 0u;
  pdu->mux_valid   = false;
  pdu->counter     = 0u;
  pdu->total_size  = 0u;
  pdu->data_type   = 0u;
  pdu->abort_code  = FBSEC_ABORT_NONE;
  pdu->data_len    = 0u;
  pdu->data        = NULL;

  /* ---- Segmented frames: no multiplexor, byte 3 is counter / length --- */
  switch (cmd) {
    case FBSEC_CO_FD_USDO_CMD_DOWNLOAD_SEG_REQ:
    case FBSEC_CO_FD_USDO_CMD_UPLOAD_SEG_RESP:
      /* Intermediate segments are always full frames. */
      if (f->len < FBSEC_CO_FD_PAYLOAD_MAX) {
        return FBSEC_CO_FD_USDO_DECODE_BAD_SEGMENT;
      }
      pdu->counter  = f->payload[3];
      pdu->data_len = FBSEC_CO_FD_USDO_SEG_DATA_MAX;
      pdu->data     = &f->payload[FBSEC_CO_FD_USDO_SEG_HEADER_SIZE];
      return FBSEC_CO_FD_USDO_DECODE_OK;

    case FBSEC_CO_FD_USDO_CMD_DOWNLOAD_END_REQ:
    case FBSEC_CO_FD_USDO_CMD_UPLOAD_END_RESP:
      if (f->len < FBSEC_CO_FD_USDO_SEG_HEADER_SIZE) {
        return FBSEC_CO_FD_USDO_DECODE_FRAME_TOO_SHORT;
      }
      pdu->counter  = f->payload[3];
      pdu->data_len = (uint16_t)f->payload[3];
      if (pdu->data_len > FBSEC_CO_FD_USDO_SEG_DATA_MAX) {
        return FBSEC_CO_FD_USDO_DECODE_BAD_SEGMENT;
      }
      if (f->len < (uint16_t)(FBSEC_CO_FD_USDO_SEG_HEADER_SIZE + pdu->data_len)) {
        return FBSEC_CO_FD_USDO_DECODE_FRAME_TOO_SHORT;
      }
      pdu->data = (pdu->data_len > 0u)
                ? &f->payload[FBSEC_CO_FD_USDO_SEG_HEADER_SIZE] : NULL;
      return FBSEC_CO_FD_USDO_DECODE_OK;

    case FBSEC_CO_FD_USDO_CMD_DOWNLOAD_SEG_RESP:
    case FBSEC_CO_FD_USDO_CMD_UPLOAD_SEG_REQ:
      if (f->len < FBSEC_CO_FD_USDO_SEG_HEADER_SIZE) {
        return FBSEC_CO_FD_USDO_DECODE_FRAME_TOO_SHORT;
      }
      pdu->counter = f->payload[3];
      return FBSEC_CO_FD_USDO_DECODE_OK;

    case FBSEC_CO_FD_USDO_CMD_DOWNLOAD_END_RESP:
      return FBSEC_CO_FD_USDO_DECODE_OK;

    case FBSEC_CO_FD_USDO_CMD_ABORT:
      /* CiA 1301 Table 32: 7 bytes, mux at 3..5, one-byte ac at 6. */
      if (f->len < FBSEC_CO_FD_USDO_ABORT_SIZE) {
        return FBSEC_CO_FD_USDO_DECODE_BAD_ABORT_LEN;
      }
      pdu->subindex   = f->payload[3];
      pdu->index      = (uint16_t)( (uint16_t)f->payload[4]
                                  | ((uint16_t)f->payload[5] << 8));
      pdu->mux_valid  = true;
      pdu->abort_code = f->payload[FBSEC_CO_FD_USDO_ABORT_AC_OFFSET];
      return FBSEC_CO_FD_USDO_DECODE_OK;

    default:
      break;   /* multiplexor-carrying frame; fall through below */
  }

  /* ---- Multiplexor-carrying frames ------------------------------------ */
  if (f->len < FBSEC_CO_FD_USDO_HEADER_SIZE) {
    return FBSEC_CO_FD_USDO_DECODE_FRAME_TOO_SHORT;
  }
  pdu->subindex  = f->payload[3];
  pdu->index     = (uint16_t)( (uint16_t)f->payload[4]
                             | ((uint16_t)f->payload[5] << 8));
  pdu->mux_valid = true;
  if (pdu->index < 0x1000u) {
    return FBSEC_CO_FD_USDO_DECODE_BAD_INDEX;
  }

  /* Initiate frames carry data_type, a reserved byte and the size u32. */
  if ((cmd == FBSEC_CO_FD_USDO_CMD_DOWNLOAD_INIT_REQ)
      || (cmd == FBSEC_CO_FD_USDO_CMD_UPLOAD_INIT_RESP)) {
    if (f->len < FBSEC_CO_FD_USDO_INIT_SIZE) {
      return FBSEC_CO_FD_USDO_DECODE_FRAME_TOO_SHORT;
    }
    pdu->data_type  = f->payload[6];
    pdu->total_size = (uint32_t)f->payload[8]
                    | ((uint32_t)f->payload[9]  <<  8)
                    | ((uint32_t)f->payload[10] << 16)
                    | ((uint32_t)f->payload[11] << 24);
    if ((pdu->total_size == 0u)
        || (pdu->total_size > FBSEC_CO_FD_USDO_SEG_BODY_MAX)) {
      return FBSEC_CO_FD_USDO_DECODE_BAD_SEGMENT;
    }
    return FBSEC_CO_FD_USDO_DECODE_OK;
  }

  if (cmd == FBSEC_CO_FD_USDO_CMD_DOWNLOAD_INIT_RESP) {
    return FBSEC_CO_FD_USDO_DECODE_OK;
  }

  /* Mandatory-data commands (download_req, upload_resp) always
     have a data prefix. download_resp has it only when the carrier
     `len` indicates a body beyond the 6-byte header. upload_req has
     no body. */
  bool has_data_block = cmd_must_have_data(cmd)
    || (cmd == FBSEC_CO_FD_USDO_CMD_DOWNLOAD_RESP
        && f->len > FBSEC_CO_FD_USDO_HEADER_SIZE);

  if (has_data_block) {
    if (f->len < FBSEC_CO_FD_USDO_HEADER_SIZE
                  + FBSEC_CO_FD_USDO_DATA_PREFIX_SIZE) {
      return FBSEC_CO_FD_USDO_DECODE_FRAME_TOO_SHORT;
    }
    pdu->data_type = f->payload[6];
    pdu->data_len  = (uint16_t)f->payload[7];
    if (pdu->data_len > FBSEC_CO_FD_USDO_DATA_MAX) {
      return FBSEC_CO_FD_USDO_DECODE_BAD_CMD;
    }
    /* The carrier `len` field may be padded up by the FD DLC mapping.
       We require *at least* enough bytes; trailing padding is OK. */
    uint16_t expected = (uint16_t)(FBSEC_CO_FD_USDO_HEADER_SIZE
                                   + FBSEC_CO_FD_USDO_DATA_PREFIX_SIZE
                                   + pdu->data_len);
    if (f->len < expected) {
      return FBSEC_CO_FD_USDO_DECODE_FRAME_TOO_SHORT;
    }
    pdu->data = (pdu->data_len > 0u) ? &f->payload[8] : NULL;
  }

  return FBSEC_CO_FD_USDO_DECODE_OK;
}

/* EOF */
