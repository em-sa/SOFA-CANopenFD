/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    fbsec_co_fd_usdo.c
 * @brief   SOFA CANopen FD, USDO expedited PDU codec, implementation.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V2.0 of 08-MAY-2026
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
      || (cmd == FBSEC_CO_FD_USDO_CMD_UPLOAD_RESP)
      || (cmd == FBSEC_CO_FD_USDO_CMD_ABORT);
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

  bool to_server = (cmd == FBSEC_CO_FD_USDO_CMD_DOWNLOAD_REQ)
                || (cmd == FBSEC_CO_FD_USDO_CMD_UPLOAD_REQ);
  uint32_t can_id = fbsec_co_fd_usdo_can_id(src_node_id, to_server);
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

bool fbsec_co_fd_usdo_encode_abort(fbsec_co_fd_frame_t *out_frame,
                                   uint8_t              src_node_id,
                                   uint8_t              dst_node_id,
                                   uint8_t              session,
                                   uint16_t             index,
                                   uint8_t              subindex,
                                   uint32_t             abort_code) {
  uint8_t buf[4];
  buf[0] = (uint8_t)( abort_code        & 0xFFu);
  buf[1] = (uint8_t)((abort_code >>  8) & 0xFFu);
  buf[2] = (uint8_t)((abort_code >> 16) & 0xFFu);
  buf[3] = (uint8_t)((abort_code >> 24) & 0xFFu);
  return encode_common(out_frame, src_node_id, dst_node_id,
                       FBSEC_CO_FD_USDO_CMD_ABORT, session,
                       index, subindex,
                       FBSEC_CO_FD_USDO_TYPE_DOMAIN, buf, sizeof buf);
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
  if (f->len < FBSEC_CO_FD_USDO_HEADER_SIZE) {
    return FBSEC_CO_FD_USDO_DECODE_FRAME_TOO_SHORT;
  }

  uint8_t  dst_node_id = f->payload[0];
  uint8_t  cmd         = f->payload[1];
  uint8_t  session     = f->payload[2];
  uint8_t  subindex    = f->payload[3];
  uint16_t index       = (uint16_t)( (uint16_t)f->payload[4]
                                   | ((uint16_t)f->payload[5] << 8));

  if (dst_node_id == 0u || dst_node_id > FBSEC_CO_FD_NODE_ID_MAX) {
    return FBSEC_CO_FD_USDO_DECODE_RESERVED_NODE;
  }
  if (!cmd_is_known(cmd)) {
    return FBSEC_CO_FD_USDO_DECODE_BAD_CMD;
  }
  if (index < 0x1000u) {
    return FBSEC_CO_FD_USDO_DECODE_BAD_INDEX;
  }

  uint8_t        data_type = 0u;
  uint16_t       data_len  = 0u;
  const uint8_t *data_ptr  = NULL;

  /* Mandatory-data commands (download_req, upload_resp, abort) always
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
    data_type = f->payload[6];
    data_len  = (uint16_t)f->payload[7];
    if (data_len > FBSEC_CO_FD_USDO_DATA_MAX) {
      return FBSEC_CO_FD_USDO_DECODE_BAD_CMD;
    }
    /* The carrier `len` field may be padded up by the FD DLC mapping.
       We require *at least* enough bytes; trailing padding is OK. */
    uint16_t expected = (uint16_t)(FBSEC_CO_FD_USDO_HEADER_SIZE
                                   + FBSEC_CO_FD_USDO_DATA_PREFIX_SIZE
                                   + data_len);
    if (f->len < expected) {
      return FBSEC_CO_FD_USDO_DECODE_FRAME_TOO_SHORT;
    }
    if (cmd == FBSEC_CO_FD_USDO_CMD_ABORT && data_len != 4u) {
      return FBSEC_CO_FD_USDO_DECODE_BAD_ABORT_LEN;
    }
    data_ptr = (data_len > 0u) ? &f->payload[8] : NULL;
  }

  pdu->src_node_id = sender;
  pdu->dst_node_id = dst_node_id;
  pdu->cmd         = cmd;
  pdu->session     = session;
  pdu->index       = index;
  pdu->subindex    = subindex;
  pdu->data_type   = data_type;
  pdu->data_len    = data_len;
  pdu->data        = data_ptr;
  return FBSEC_CO_FD_USDO_DECODE_OK;
}

/* EOF */
