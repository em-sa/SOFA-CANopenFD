/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    fbsec_co_fd_usdo.h
 * @brief   SOFA CANopen FD, USDO expedited + segmented PDU codec.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V3.1 of 20-JUL-2026
 *
 * Byte-correct CANopen FD USDO expedited transfer codec, replacing the
 * earlier simplified single-CAN-ID demo encoding. Frames now use the
 * standard 11-bit USDO CAN ID family observed on real CANopen FD buses
 * via CANopen Magic Ultimate:
 *
 *     CAN ID = 0x600 + sender_node_id   for client-to-server requests
 *     CAN ID = 0x580 + sender_node_id   for server-to-client responses
 *                                       (and aborts)
 *
 * Both directions encode the **sender** in bits 6..0; the addressee
 * lives in PDU byte 0. The 0x600 / 0x580 prefixes match classical
 * CANopen SDO, but with the sender (not the server) in the lower bits
 * so that multiple clients and concurrent sessions coexist on one bus.
 *
 *     offset  size  field
 *     ------  ----  ----------------
 *     0       1     receiver_node_id  (the addressee)
 *     1       1     cmd_specifier     (see cmd table)
 *     2       1     session           (1..255; client-allocated)
 *     3       1     subindex          (OD subindex 0..255)
 *     4       2     index (LE)        (OD index 0x0000..0xFFFF)
 *     6       1     data_type         (CiA 301 type code; only when
 *                                      frame carries data)
 *     7       1     data_length       (byte count of @c data)
 *     8       N     data              (expedited bytes)
 *
 * Header without data is 6 bytes (used for empty requests / acks);
 * header with data is 8 + N bytes. Real CAN FD wire DLC is rounded up
 * to {0..8, 12, 16, 20, 24, 32, 48, 64} by the carrier driver.
 *
 * The abort frame is its own shape (CiA 1301 Table 32): 7 bytes, no
 * data_type / data_length prefix, with the single-byte abort code `ac`
 * at offset 6:
 *
 *     offset  size  field
 *     ------  ----  ----------------
 *     0       1     receiver_node_id  (sda / cda)
 *     1       1     cmd_specifier     (7Fh, ccs and scs alike)
 *     2       1     session           (sid)
 *     3       1     subindex
 *     4       2     index (LE)
 *     6       1     abort code (ac)   (CiA 1301 Table 31)
 *
 * Payloads larger than one expedited data block use the CiA 1301 USDO
 * SEGMENTED transfer protocol (SOFA carried these over a bespoke
 * fragmentation layer up to V2.x; that layer is gone). Segmented
 * frames reuse bytes 0..2 (receiver, cmd, session) and repurpose
 * byte 3 as the sequence counter / last-segment length:
 *
 *   download initiate req  (0x02) len 12: [6]=data_type, [7]=0,
 *                                         [8..11]=total size u32 LE
 *   download initiate resp (0x22) len  6: mux echoed
 *   download segment  req  (0x03) len 64: [3]=counter, [4..63]=60 data
 *   download segment  resp (0x23) len  4: [3]=counter echoed
 *   download end      req  (0x04) len 4+n: [3]=n (1..60), [4..]=data
 *   download end      resp (0x24) len  3
 *   upload            req  (0x11) len  6: (same request as expedited)
 *   upload initiate   resp (0x32) len 12: [6]=data_type, [7]=0,
 *                                         [8..11]=total size u32 LE
 *   upload segment    req  (0x13) len  4: [3]=counter
 *   upload segment    resp (0x33) len 64: [3]=counter, [4..63]=60 data
 *   upload end        resp (0x34) len 4+n: [3]=n (0..60), [4..]=data
 *
 * Counters start at 0 and increment per segment; there is no toggle
 * bit (that is classical CANopen SDO, not USDO). Only the segment and
 * end frames omit index/subindex - the initiate frames carry the full
 * multiplexor, so a receiver binds the transfer to (index, subindex)
 * once and matches the follow-up frames on (peer, session).
 *
 * SOFA profile note: a request whose *response* body exceeds one
 * expedited data block is answered with the upload-initiate response
 * (0x32), after which the standard upload-segment exchange runs. That
 * lets a challenge-carrying download request (identity read, LDevID
 * export) return a large reply without inventing a new service.
 *
 * Also exports the SIM_* control-event CAN IDs and the SIM_PEER_ANNOUNCE /
 * LOSS / FRAME_ERROR helpers, which are simulator-only and stay 29-bit
 * extended (well above the USDO 11-bit range so there is no collision).
 *
 * No socket headers, no malloc, no globals. Thread-safe.
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#ifndef FBSEC_CO_FD_USDO_H
#define FBSEC_CO_FD_USDO_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "fbsec_abort.h"
#include "fbsec_co_fd_frame.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- USDO PDU header layout -------------------------------------------- */

/** Bytes of fixed USDO header preceding any expedited data block. */
#define FBSEC_CO_FD_USDO_HEADER_SIZE      6u
/** Bytes of the data-prefix (data_type[1] || data_length[1]). */
#define FBSEC_CO_FD_USDO_DATA_PREFIX_SIZE 2u

/** Maximum expedited data block (CAN FD payload max - header - data prefix). */
#define FBSEC_CO_FD_USDO_DATA_MAX \
        ((uint16_t)(FBSEC_CO_FD_PAYLOAD_MAX - FBSEC_CO_FD_USDO_HEADER_SIZE \
                    - FBSEC_CO_FD_USDO_DATA_PREFIX_SIZE))

/** Highest valid CANopen node id. */
#define FBSEC_CO_FD_NODE_ID_MAX 127u

/* ---- USDO segmented transfer layout ------------------------------------ */

/** Bytes of fixed header on a segment / segment-ack frame
 *  (receiver, cmd, session, counter). */
#define FBSEC_CO_FD_USDO_SEG_HEADER_SIZE 4u

/** Data bytes carried by one full (intermediate) segment frame. */
#define FBSEC_CO_FD_USDO_SEG_DATA_MAX \
        ((uint16_t)(FBSEC_CO_FD_PAYLOAD_MAX - FBSEC_CO_FD_USDO_SEG_HEADER_SIZE))

/** Length of an initiate frame (header + data_type + reserved + size u32). */
#define FBSEC_CO_FD_USDO_INIT_SIZE 12u

/** Length of a download-end response (receiver, cmd, session). */
#define FBSEC_CO_FD_USDO_END_RESP_SIZE 3u

/** Length of a USDO abort frame per CiA 1301 Table 32:
 *  sda[1] | ccs/scs[1] | sid[1] | sub-index[1] | index[2] | ac[1]. */
#define FBSEC_CO_FD_USDO_ABORT_SIZE 7u

/** Byte offset of the abort code (`ac`) inside the abort frame. */
#define FBSEC_CO_FD_USDO_ABORT_AC_OFFSET 6u

/** Largest body SOFA moves over a segmented transfer, in bytes. Covers
 *  every asymmetric-layer blob (identity reply 168, voucher 108,
 *  provisioning install 80, LDevID export 96) with headroom. */
#define FBSEC_CO_FD_USDO_SEG_BODY_MAX 256u

/* ---- USDO CAN ID family (11-bit standard) ------------------------------ */

/** Prefix added to sender node id for client-to-server USDO requests. */
#define FBSEC_CO_FD_USDO_REQ_BASE  0x600u
/** Prefix added to sender node id for server-to-client USDO responses
 *  and aborts (cmd byte distinguishes). */
#define FBSEC_CO_FD_USDO_RSP_BASE  0x580u
/** Mask covering the prefix (everything but the low 7 bits). */
#define FBSEC_CO_FD_USDO_BASE_MASK 0x780u
/** Mask covering the sender node id (low 7 bits). */
#define FBSEC_CO_FD_USDO_NID_MASK  0x07Fu

/* ---- SIM_* control CAN IDs (29-bit extended; unchanged) --------------- */

/** Simulator-only: peer announce on TCP connect. */
#define FBSEC_CO_FD_CAN_ID_SIM_PEER_ANNOUNCE 0x1FFFFFE0u
/** Simulator-only: synthesized peer loss on TCP disconnect. */
#define FBSEC_CO_FD_CAN_ID_SIM_PEER_LOSS     0x1FFFFFE1u
/** Simulator-only: synthesized frame error on protocol violation. */
#define FBSEC_CO_FD_CAN_ID_SIM_FRAME_ERROR   0x1FFFFFEFu

/* ---- USDO command specifiers (real CiA-aligned values) ---------------- */
/* Bit 5 (0x20) = response, bit 4 (0x10) = upload, bit 0 (0x01) = expedited.
   The abort service is not part of that bit scheme: CiA 1301 Table 22
   assigns it the fixed local code 7Fh (remote FFh), and Table 32 fixes
   both ccs and scs at 7Fh. */

#define FBSEC_CO_FD_USDO_CMD_DOWNLOAD_REQ   0x01u
#define FBSEC_CO_FD_USDO_CMD_DOWNLOAD_RESP  0x21u
#define FBSEC_CO_FD_USDO_CMD_UPLOAD_REQ     0x11u
#define FBSEC_CO_FD_USDO_CMD_UPLOAD_RESP    0x31u
#define FBSEC_CO_FD_USDO_CMD_ABORT          0x7Fu

/* Segmented transfer command specifiers (CiA 1301 USDO). */
#define FBSEC_CO_FD_USDO_CMD_DOWNLOAD_INIT_REQ  0x02u
#define FBSEC_CO_FD_USDO_CMD_DOWNLOAD_SEG_REQ   0x03u
#define FBSEC_CO_FD_USDO_CMD_DOWNLOAD_END_REQ   0x04u
#define FBSEC_CO_FD_USDO_CMD_UPLOAD_SEG_REQ     0x13u
#define FBSEC_CO_FD_USDO_CMD_DOWNLOAD_INIT_RESP 0x22u
#define FBSEC_CO_FD_USDO_CMD_DOWNLOAD_SEG_RESP  0x23u
#define FBSEC_CO_FD_USDO_CMD_DOWNLOAD_END_RESP  0x24u
#define FBSEC_CO_FD_USDO_CMD_UPLOAD_INIT_RESP   0x32u
#define FBSEC_CO_FD_USDO_CMD_UPLOAD_SEG_RESP    0x33u
#define FBSEC_CO_FD_USDO_CMD_UPLOAD_END_RESP    0x34u

/* ---- USDO data type codes (subset of CiA 301 used by SOFA) ------------ */
/* The secure tunnel ships opaque binary, so all four SOFA OD entries
   declare type Domain. Wider compatibility (Unsigned8/16/32, etc.) is
   left for callers that build USDO traffic outside SOFA. */
#define FBSEC_CO_FD_USDO_TYPE_DOMAIN        0x0Fu
/* Byte offset of data_type within the USDO PDU (data-bearing frames). */
#define FBSEC_CO_FD_USDO_DTYPE_OFFSET       6u

/* ---- SIM_PEER_ANNOUNCE / SIM_PEER_LOSS role byte (spec §7.1) ---------- */

#define FBSEC_CO_FD_SIM_ROLE_SERVER 0x01u
#define FBSEC_CO_FD_SIM_ROLE_CLIENT 0x02u

/* ---- SIM_FRAME_ERROR error codes (spec §7.3) -------------------------- */

#define FBSEC_CO_FD_SIM_ERR_RESERVED_CANID  0x01u
#define FBSEC_CO_FD_SIM_ERR_RESERVED_FLAGS  0x02u
#define FBSEC_CO_FD_SIM_ERR_LEN_TOO_BIG     0x03u
#define FBSEC_CO_FD_SIM_ERR_SHORT_READ      0x04u
#define FBSEC_CO_FD_SIM_ERR_UNKNOWN_CANID   0x05u
#define FBSEC_CO_FD_SIM_ERR_USDO_MALFORMED  0x06u
#define FBSEC_CO_FD_SIM_ERR_DUP_ANNOUNCE    0x07u

/* ---- USDO direction kind ---------------------------------------------- */

typedef enum {
  FBSEC_CO_FD_USDO_KIND_NONE     = 0,  /**< not a USDO CAN ID            */
  FBSEC_CO_FD_USDO_KIND_REQUEST  = 1,  /**< 0x600 + sender               */
  FBSEC_CO_FD_USDO_KIND_RESPONSE = 2,  /**< 0x580 + sender (cmd != 0x7F) */
  FBSEC_CO_FD_USDO_KIND_ABORT    = 3   /**< 0x580 + sender (cmd == 0x7F) */
} fbsec_co_fd_usdo_kind_t;

/**
 * @brief Build the 11-bit USDO CAN ID for a given direction.
 *
 * @param sender_node_id  1..127.
 * @param to_server       true: this is a request from a client to a
 *                        server (uses 0x600 base).
 *                        false: this is a response/abort from a server
 *                        to a client (uses 0x580 base).
 * @return 11-bit CAN ID, or 0 if @p sender_node_id is out of range.
 */
uint32_t fbsec_co_fd_usdo_can_id(uint8_t sender_node_id, bool to_server);

/**
 * @brief Decompose a CAN ID. Sets *kind to NONE for any non-USDO ID.
 *
 * @param can_id          11-bit ID value (top bits ignored).
 * @param sender_out      receives the low-7-bit sender node id when
 *                        @p *kind is REQUEST/RESPONSE/ABORT.
 * @param kind_out        REQUEST iff prefix is 0x600, RESPONSE iff
 *                        prefix is 0x580 (caller distinguishes ABORT
 *                        by inspecting cmd byte; this helper does
 *                        not consult the PDU). NONE otherwise.
 *
 * @return true iff the CAN ID is in a USDO range (kind != NONE).
 */
bool fbsec_co_fd_usdo_can_id_split(uint32_t                 can_id,
                                   uint8_t                 *sender_out,
                                   fbsec_co_fd_usdo_kind_t *kind_out);

/* ---- Decoded USDO PDU view -------------------------------------------- */

/**
 * @brief Parsed USDO PDU header (CAN-ID-derived sender + PDU-derived
 *        receiver and multiplex), with a pointer-into-frame to the
 *        expedited data block.
 *
 * The @c data pointer aliases bytes inside the source @ref
 * fbsec_co_fd_frame_t, so the lifetime of @c data is bounded by the
 * lifetime of that frame. Callers that want to keep the data must
 * memcpy it out.
 */
typedef struct fbsec_co_fd_usdo_pdu_t {
  uint8_t        src_node_id;   /**< from CAN ID low 7 bits          */
  uint8_t        dst_node_id;   /**< receiver, from PDU BUF[0]       */
  uint8_t        cmd;
  uint8_t        session;
  uint16_t       index;         /**< only when @c mux_valid          */
  uint8_t        subindex;      /**< only when @c mux_valid          */
  bool           mux_valid;     /**< false on segment / end frames,
                                     which carry no multiplexor      */
  uint8_t        counter;       /**< segment sequence counter; on the
                                     download/upload end frames this
                                     is the last-segment byte count  */
  uint32_t       total_size;    /**< declared transfer size; only on
                                     the initiate frames             */
  uint8_t        data_type;     /**< 0 if frame carries no data block */
  fbsec_abort_t  abort_code;    /**< `ac` byte; only on abort frames  */
  uint16_t       data_len;      /**< 0..FBSEC_CO_FD_USDO_SEG_DATA_MAX */
  const uint8_t *data;          /**< NULL when @c data_len == 0       */
} fbsec_co_fd_usdo_pdu_t;

/* ---- Decode results ---------------------------------------------------- */

typedef enum {
  FBSEC_CO_FD_USDO_DECODE_OK              = 0,
  FBSEC_CO_FD_USDO_DECODE_FRAME_TOO_SHORT = 1, /**< CAN FD len < 6 (or 8 for data-bearing) */
  FBSEC_CO_FD_USDO_DECODE_RESERVED_NODE   = 2, /**< dst_node_id 0/>127, or src out of range */
  FBSEC_CO_FD_USDO_DECODE_BAD_CMD         = 3, /**< unrecognized cmd       */
  FBSEC_CO_FD_USDO_DECODE_BAD_INDEX       = 4, /**< index < 0x1000         */
  FBSEC_CO_FD_USDO_DECODE_BAD_ABORT_LEN   = 5, /**< cmd==ABORT && frame < 7 bytes */
  FBSEC_CO_FD_USDO_DECODE_NOT_USDO        = 6, /**< CAN ID outside USDO family */
  FBSEC_CO_FD_USDO_DECODE_BAD_SEGMENT     = 7  /**< malformed segment frame  */
} fbsec_co_fd_usdo_decode_t;

/* ---- Decode ------------------------------------------------------------ */

/**
 * @brief Parse the USDO PDU carried by @p f into @p pdu.
 *
 * Reads the sender node id from the frame's CAN ID low 7 bits and
 * cross-checks the prefix (0x600 / 0x580); reads receiver / cmd /
 * session / index / sub from the PDU; reads optional data_type and
 * data_length when the cmd indicates a data-bearing frame.
 *
 * @param f    source CAN FD frame; must remain valid while @p pdu
 *             is in use (its data pointer aliases f->payload).
 *             Must not be NULL.
 * @param pdu  destination view. Must not be NULL.
 *
 * @return One of @ref fbsec_co_fd_usdo_decode_t. On any non-OK
 *         result @p pdu fields are unspecified and the caller should
 *         map onto @ref FBSEC_CO_FD_SIM_ERR_USDO_MALFORMED.
 */
fbsec_co_fd_usdo_decode_t fbsec_co_fd_usdo_decode(
  const fbsec_co_fd_frame_t *f,
  fbsec_co_fd_usdo_pdu_t    *pdu);

/* ---- Encode helpers ---------------------------------------------------- */

/**
 * @brief Build a USDO download-request frame (cmd 0x01).
 *
 * Used for srd Pass 1 (key_id || client_random) and swr Pass 2
 * (key_id || client_random || ciphertext || tag) per spec §6.1 / §6.2.
 *
 * @param out_frame      receives the populated frame, ready to
 *                       serialize via @ref fbsec_co_fd_frame_serialize.
 *                       Must not be NULL.
 * @param src_node_id    sender (the client's own announced node id).
 * @param dst_node_id    receiver (the target server's node id).
 * @param session        per-transfer session value, 1..255.
 * @param index          OD index >= 0x1000.
 * @param subindex       OD subindex (0..255).
 * @param data           expedited payload bytes (may be NULL when
 *                       data_len == 0).
 * @param data_len       0..FBSEC_CO_FD_USDO_DATA_MAX.
 *
 * @retval true   frame populated.
 * @retval false  invalid argument (src/dst out of range, index < 0x1000,
 *                data_len > FBSEC_CO_FD_USDO_DATA_MAX, or session==0).
 */
bool fbsec_co_fd_usdo_encode_download_req(fbsec_co_fd_frame_t *out_frame,
                                          uint8_t              src_node_id,
                                          uint8_t              dst_node_id,
                                          uint8_t              session,
                                          uint16_t             index,
                                          uint8_t              subindex,
                                          const uint8_t       *data,
                                          uint16_t             data_len);

/**
 * @brief Build a USDO download-confirmation frame (cmd 0x21).
 *
 * Optional expedited data; signals the server's success ACK after a
 * download request (srd Pass 1 DEFER ACK; swr Pass 2 commit ACK). The
 * cyclic-arming flow on swr Pass 2 returns a 2-byte session_id in the
 * data block; ordinary single-shot returns no data.
 *
 * @param src_node_id    server's own announced node id.
 * @param dst_node_id    requester's node id (the original client).
 * @param session        echo back the session from the request.
 * @param data           optional response data (NULL when @p data_len == 0).
 * @param data_len       0..FBSEC_CO_FD_USDO_DATA_MAX.
 */
bool fbsec_co_fd_usdo_encode_download_resp(fbsec_co_fd_frame_t *out_frame,
                                           uint8_t              src_node_id,
                                           uint8_t              dst_node_id,
                                           uint8_t              session,
                                           uint16_t             index,
                                           uint8_t              subindex,
                                           const uint8_t       *data,
                                           uint16_t             data_len);

/**
 * @brief Build a USDO upload-request frame (cmd 0x11).
 *
 * Used for srd Pass 2 (no body) and swr Pass 1 (single-shot:
 * empty body; cyclic-arm: 1-byte body with the wire keyid byte
 * carrying bit 6 = 1). The data argument lets the caller carry
 * the cyclic-arm byte; pass NULL/0 for a single-shot request.
 */
bool fbsec_co_fd_usdo_encode_upload_req(fbsec_co_fd_frame_t *out_frame,
                                        uint8_t              src_node_id,
                                        uint8_t              dst_node_id,
                                        uint8_t              session,
                                        uint16_t             index,
                                        uint8_t              subindex,
                                        const uint8_t       *data,
                                        uint16_t             data_len);

/**
 * @brief Build a USDO upload-response frame (cmd 0x31).
 *
 * Used for srd Pass 2 (server_random || ciphertext || tag) and swr
 * Pass 1 (server_random optionally followed by session_id_be[2]).
 */
bool fbsec_co_fd_usdo_encode_upload_resp(fbsec_co_fd_frame_t *out_frame,
                                         uint8_t              src_node_id,
                                         uint8_t              dst_node_id,
                                         uint8_t              session,
                                         uint16_t             index,
                                         uint8_t              subindex,
                                         const uint8_t       *data,
                                         uint16_t             data_len);

/* ---- Segmented transfer encode helpers -------------------------------- */

/**
 * @brief Build a USDO download-initiate request (cmd 0x02, 12 bytes).
 *
 * Opens a segmented download. @p total_size is the full body length the
 * following segment / end frames will deliver.
 *
 * @param out_frame    receives the populated frame. Must not be NULL.
 * @param src_node_id  sender (client) node id, 1..127.
 * @param dst_node_id  receiver (server) node id, 1..127.
 * @param session      per-transfer session value, 1..255.
 * @param index        OD index >= 0x1000.
 * @param subindex     OD subindex.
 * @param total_size   body length in bytes, 1..FBSEC_CO_FD_USDO_SEG_BODY_MAX.
 *
 * @retval true   frame populated.
 * @retval false  invalid argument.
 */
bool fbsec_co_fd_usdo_encode_download_init_req(fbsec_co_fd_frame_t *out_frame,
                                               uint8_t              src_node_id,
                                               uint8_t              dst_node_id,
                                               uint8_t              session,
                                               uint16_t             index,
                                               uint8_t              subindex,
                                               uint32_t             total_size);

/**
 * @brief Build a USDO download-initiate response (cmd 0x22, 6 bytes).
 *
 * @param out_frame    receives the populated frame. Must not be NULL.
 * @param src_node_id  sender (server) node id.
 * @param dst_node_id  receiver (client) node id.
 * @param session      session echoed from the request.
 * @param index        OD index echoed from the request.
 * @param subindex     OD subindex echoed from the request.
 * @return true on success, false on invalid argument.
 */
bool fbsec_co_fd_usdo_encode_download_init_resp(fbsec_co_fd_frame_t *out_frame,
                                                uint8_t              src_node_id,
                                                uint8_t              dst_node_id,
                                                uint8_t              session,
                                                uint16_t             index,
                                                uint8_t              subindex);

/**
 * @brief Build a USDO download-segment request (cmd 0x03, 64 bytes).
 *
 * Intermediate segments are always full: exactly
 * FBSEC_CO_FD_USDO_SEG_DATA_MAX data bytes.
 *
 * @param out_frame    receives the populated frame. Must not be NULL.
 * @param src_node_id  sender (client) node id.
 * @param dst_node_id  receiver (server) node id.
 * @param session      session of the open transfer.
 * @param counter      0-based segment counter.
 * @param data         FBSEC_CO_FD_USDO_SEG_DATA_MAX bytes. Must not be NULL.
 * @return true on success, false on invalid argument.
 */
bool fbsec_co_fd_usdo_encode_download_seg_req(fbsec_co_fd_frame_t *out_frame,
                                              uint8_t              src_node_id,
                                              uint8_t              dst_node_id,
                                              uint8_t              session,
                                              uint8_t              counter,
                                              const uint8_t       *data);

/**
 * @brief Build a USDO download-segment response (cmd 0x23, 4 bytes).
 *
 * @param out_frame    receives the populated frame. Must not be NULL.
 * @param src_node_id  sender (server) node id.
 * @param dst_node_id  receiver (client) node id.
 * @param session      session of the open transfer.
 * @param counter      segment counter echoed from the request.
 * @return true on success, false on invalid argument.
 */
bool fbsec_co_fd_usdo_encode_download_seg_resp(fbsec_co_fd_frame_t *out_frame,
                                               uint8_t              src_node_id,
                                               uint8_t              dst_node_id,
                                               uint8_t              session,
                                               uint8_t              counter);

/**
 * @brief Build a USDO download-end request (cmd 0x04, 4 + @p len bytes).
 *
 * @param out_frame    receives the populated frame. Must not be NULL.
 * @param src_node_id  sender (client) node id.
 * @param dst_node_id  receiver (server) node id.
 * @param session      session of the open transfer.
 * @param data         last-segment bytes. Must not be NULL.
 * @param len          1..FBSEC_CO_FD_USDO_SEG_DATA_MAX.
 * @return true on success, false on invalid argument.
 */
bool fbsec_co_fd_usdo_encode_download_end_req(fbsec_co_fd_frame_t *out_frame,
                                              uint8_t              src_node_id,
                                              uint8_t              dst_node_id,
                                              uint8_t              session,
                                              const uint8_t       *data,
                                              uint16_t             len);

/**
 * @brief Build a USDO download-end response (cmd 0x24, 3 bytes).
 *
 * @param out_frame    receives the populated frame. Must not be NULL.
 * @param src_node_id  sender (server) node id.
 * @param dst_node_id  receiver (client) node id.
 * @param session      session of the completed transfer.
 * @return true on success, false on invalid argument.
 */
bool fbsec_co_fd_usdo_encode_download_end_resp(fbsec_co_fd_frame_t *out_frame,
                                               uint8_t              src_node_id,
                                               uint8_t              dst_node_id,
                                               uint8_t              session);

/**
 * @brief Build a USDO upload-initiate response (cmd 0x32, 12 bytes).
 *
 * Answers an upload request (or, per the SOFA profile note in the file
 * banner, a challenge-carrying download request) whose result does not
 * fit one expedited data block.
 *
 * @param out_frame    receives the populated frame. Must not be NULL.
 * @param src_node_id  sender (server) node id.
 * @param dst_node_id  receiver (client) node id.
 * @param session      session echoed from the request.
 * @param index        OD index echoed from the request.
 * @param subindex     OD subindex echoed from the request.
 * @param total_size   result length, 1..FBSEC_CO_FD_USDO_SEG_BODY_MAX.
 * @return true on success, false on invalid argument.
 */
bool fbsec_co_fd_usdo_encode_upload_init_resp(fbsec_co_fd_frame_t *out_frame,
                                              uint8_t              src_node_id,
                                              uint8_t              dst_node_id,
                                              uint8_t              session,
                                              uint16_t             index,
                                              uint8_t              subindex,
                                              uint32_t             total_size);

/**
 * @brief Build a USDO upload-segment request (cmd 0x13, 4 bytes).
 *
 * @param out_frame    receives the populated frame. Must not be NULL.
 * @param src_node_id  sender (client) node id.
 * @param dst_node_id  receiver (server) node id.
 * @param session      session of the open transfer.
 * @param counter      0-based counter of the segment being requested.
 * @return true on success, false on invalid argument.
 */
bool fbsec_co_fd_usdo_encode_upload_seg_req(fbsec_co_fd_frame_t *out_frame,
                                            uint8_t              src_node_id,
                                            uint8_t              dst_node_id,
                                            uint8_t              session,
                                            uint8_t              counter);

/**
 * @brief Build a USDO upload-segment response (cmd 0x33, 64 bytes).
 *
 * @param out_frame    receives the populated frame. Must not be NULL.
 * @param src_node_id  sender (server) node id.
 * @param dst_node_id  receiver (client) node id.
 * @param session      session of the open transfer.
 * @param counter      counter echoed from the request.
 * @param data         FBSEC_CO_FD_USDO_SEG_DATA_MAX bytes. Must not be NULL.
 * @return true on success, false on invalid argument.
 */
bool fbsec_co_fd_usdo_encode_upload_seg_resp(fbsec_co_fd_frame_t *out_frame,
                                             uint8_t              src_node_id,
                                             uint8_t              dst_node_id,
                                             uint8_t              session,
                                             uint8_t              counter,
                                             const uint8_t       *data);

/**
 * @brief Build a USDO upload-end response (cmd 0x34, 4 + @p len bytes).
 *
 * @param out_frame    receives the populated frame. Must not be NULL.
 * @param src_node_id  sender (server) node id.
 * @param dst_node_id  receiver (client) node id.
 * @param session      session of the open transfer.
 * @param data         last-segment bytes (may be NULL when @p len == 0).
 * @param len          0..FBSEC_CO_FD_USDO_SEG_DATA_MAX.
 * @return true on success, false on invalid argument.
 */
bool fbsec_co_fd_usdo_encode_upload_end_resp(fbsec_co_fd_frame_t *out_frame,
                                             uint8_t              src_node_id,
                                             uint8_t              dst_node_id,
                                             uint8_t              session,
                                             const uint8_t       *data,
                                             uint16_t             len);

/**
 * @brief Build a USDO abort frame (cmd 7Fh) per CiA 1301 Table 32.
 *
 * The frame is exactly @ref FBSEC_CO_FD_USDO_ABORT_SIZE bytes:
 * sda | ccs/scs (7Fh) | sid | sub-index | index (LE) | ac. There is no
 * data_type / data_length prefix and no data block - `ac` is one
 * UNSIGNED8 drawn from CiA 1301 Table 31 (or the SOFA C0h..CFh block;
 * see `shared/fbsec_abort.h`).
 *
 * Aborts ride the response-direction CAN ID (0x580 + sender), since
 * in the SOFA demo the server is always the aborter. A future change
 * that lets clients abort would add a request-direction abort using
 * the request CAN ID prefix.
 *
 * @param out_frame    receives the populated frame. Must not be NULL.
 * @param src_node_id  sender (aborter) node id, 1..127.
 * @param dst_node_id  receiver node id, 1..127.
 * @param session      session of the aborted transfer, 1..255.
 * @param index        OD index of the aborted access (>= 0x1000).
 * @param subindex     OD sub-index of the aborted access.
 * @param abort_code   the `ac` byte.
 * @return true on success, false on invalid argument.
 */
bool fbsec_co_fd_usdo_encode_abort(fbsec_co_fd_frame_t *out_frame,
                                   uint8_t              src_node_id,
                                   uint8_t              dst_node_id,
                                   uint8_t              session,
                                   uint16_t             index,
                                   uint8_t              subindex,
                                   fbsec_abort_t        abort_code);

#ifdef __cplusplus
}
#endif

#endif /* FBSEC_CO_FD_USDO_H */
/* EOF */
