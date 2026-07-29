/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    server_common_rpk.c
 * @brief   SOFA server_common, CiA 720 RPK secure-object handler, impl.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 22-JUL-2026
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#include "server_common_rpk.h"

#if FBSEC_FEATURE_ASYM

#include <stdio.h>
#include <string.h>

#include "server_common_asym.h"
#include "server_common_handover.h"
#include "server_common_trace.h"
#include "fbsec_asym.h"
#include "fbsec_secure_od.h"

/* Peer slot holding the integrator public key that authorizes signed
   writes and commands (installed at startup for the demo). */
#define RPK_WRITE_PEER_SLOT   1u

/* Transcript work buffers: the largest body is a signed access,
   server[2] + client[2] + object_mux[4] + data_len[2] + client_nonce[16] +
   server_nonce[16] + value[16] = 58 bytes. */
#define RPK_BODY_MAX          64u
#define RPK_TRANSCRIPT_MAX    (RPK_BODY_MAX + FBSEC_ASYM_TRANSCRIPT_OVERHEAD)

/* ---- Single outstanding signed-access challenge ----------------------- */
/* One challenge may be armed at a time, across the signed read, write and
   command flows. A signed access costs an Ed25519 operation, so this single
   slot also rate-limits signed accesses: a peer cannot make the device spend
   a verification without first holding the one outstanding challenge. */

static struct {
  bool     armed;
  uint16_t client_dev;
  uint32_t data_id;                         /* C042h:01, C042h:02 or C049h:00 */
  uint8_t  server_nonce[FBSEC_RPK_NONCE_LEN];
} g_challenge;

/* ---- Little-endian store helpers ------------------------------------- */

static uint16_t put_u16le(uint8_t *p, uint16_t v) {
  p[0] = (uint8_t)(v & 0xFFu);
  p[1] = (uint8_t)((v >> 8) & 0xFFu);
  return 2u;
}

static uint16_t put_u32le(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v & 0xFFu);
  p[1] = (uint8_t)((v >> 8) & 0xFFu);
  p[2] = (uint8_t)((v >> 16) & 0xFFu);
  p[3] = (uint8_t)((v >> 24) & 0xFFu);
  return 4u;
}

/* Defined below; the read flow arms a challenge like the write and command. */
static bool arm_challenge(uint16_t client_dev, uint32_t data_id,
                          const char *verb, const uint8_t *req, uint16_t req_len,
                          fbsec_send_reply_fn_t send_reply, void *user);

/* Canonical signed-access transcript body (CiA 720-1 Table 6 body, CiA 720-4):
   responder || requester || object multiplexor || protected-data length ||
   requester random || responder random || protected data, little-endian. */
static uint16_t build_signed_body(uint8_t *body, uint16_t server_id,
                                  uint16_t client_id, uint32_t obj_mux,
                                  const uint8_t *client_nonce,
                                  const uint8_t *server_nonce,
                                  const uint8_t *value, uint16_t value_len) {
  uint16_t o = 0u;
  o = (uint16_t)(o + put_u16le(&body[o], server_id));
  o = (uint16_t)(o + put_u16le(&body[o], client_id));
  o = (uint16_t)(o + put_u32le(&body[o], obj_mux));
  o = (uint16_t)(o + put_u16le(&body[o], value_len));
  memcpy(&body[o], client_nonce, FBSEC_RPK_NONCE_LEN);
  o = (uint16_t)(o + FBSEC_RPK_NONCE_LEN);
  memcpy(&body[o], server_nonce, FBSEC_RPK_NONCE_LEN);
  o = (uint16_t)(o + FBSEC_RPK_NONCE_LEN);
  memcpy(&body[o], value, value_len);
  o = (uint16_t)(o + value_len);
  return o;
}

/* Emit one reply + trace and return handled = true. */
static bool emit(uint16_t client_dev, uint32_t data_id, const char *verb,
                 fbsec_abort_t status, const uint8_t *data, uint16_t len,
                 const uint8_t *req, uint16_t req_len,
                 fbsec_send_reply_fn_t send_reply, void *user) {
  uint16_t dst_dev = fbsec_sod_port_get_device_id();
  /* MISRA-Dir-4.7 deviation: TX status discarded; the variant logs failures. */
  (void)send_reply(user, client_dev, data_id, status, data, len);
  fbsec_server_trace_request(client_dev, dst_dev, data_id, verb, status,
                             req, req_len, data, (size_t)len);
  return true;
}

/* ---- C021h public keys ------------------------------------------------ */

static bool handle_pubkeys(uint16_t client_dev, uint32_t data_id, uint8_t sub,
                           const uint8_t *req, uint16_t req_len,
                           fbsec_send_reply_fn_t send_reply, void *user) {
  uint8_t buf[FBSEC_ASYM_PUBKEY_SIZE];

  if (req_len != 0u) {                       /* read-only object */
    return emit(client_dev, data_id, "C021", FBSEC_ABORT_READ_ONLY,
                NULL, 0u, req, req_len, send_reply, user);
  }
  switch (sub) {
    case 0x00u:
      buf[0] = FBSEC_RPK_PUBKEY_HIGHEST_SUB;
      return emit(client_dev, data_id, "C021", FBSEC_ABORT_NONE, buf, 1u,
                  req, req_len, send_reply, user);
    case 0x01u:
      memcpy(buf, fbsec_server_asym_anchor()->pub, FBSEC_ASYM_PUBKEY_SIZE);
      return emit(client_dev, data_id, "C021", FBSEC_ABORT_NONE, buf,
                  FBSEC_ASYM_PUBKEY_SIZE, req, req_len, send_reply, user);
    case 0x02u: {
      /* Integrator public key: the owner key installed at voucher claim.
         All-zero until a claim runs, so a tool sees "not yet owned". */
      const fbsec_pubkey_t *owner = fbsec_server_asym_owner();
      if (owner == NULL) {
        memset(buf, 0, FBSEC_ASYM_PUBKEY_SIZE);
      } else {
        memcpy(buf, owner->pub, FBSEC_ASYM_PUBKEY_SIZE);
      }
      return emit(client_dev, data_id, "C021", FBSEC_ABORT_NONE, buf,
                  FBSEC_ASYM_PUBKEY_SIZE, req, req_len, send_reply, user);
    }
    default:
      return emit(client_dev, data_id, "C021", FBSEC_ABORT_NO_SUBINDEX,
                  NULL, 0u, req, req_len, send_reply, user);
  }
}

/* ---- C022h public key types ------------------------------------------ */

static bool handle_pktypes(uint16_t client_dev, uint32_t data_id, uint8_t sub,
                           const uint8_t *req, uint16_t req_len,
                           fbsec_send_reply_fn_t send_reply, void *user) {
  uint8_t buf[4];

  if (req_len != 0u) {
    return emit(client_dev, data_id, "C022", FBSEC_ABORT_READ_ONLY,
                NULL, 0u, req, req_len, send_reply, user);
  }
  if (sub == 0x00u) {
    buf[0] = FBSEC_RPK_PUBKEY_HIGHEST_SUB;
    return emit(client_dev, data_id, "C022", FBSEC_ABORT_NONE, buf, 1u,
                req, req_len, send_reply, user);
  }
  if ((sub == 0x01u) || (sub == 0x02u)) {
    /* U32: byte 0 = algorithm id (01h Ed25519), byte 1 = length (20h). */
    (void)put_u32le(buf, (uint32_t)FBSEC_ASYM_ALG_ED25519
                       | ((uint32_t)FBSEC_ASYM_PUBKEY_SIZE << 8));
    return emit(client_dev, data_id, "C022", FBSEC_ABORT_NONE, buf, 4u,
                req, req_len, send_reply, user);
  }
  return emit(client_dev, data_id, "C022", FBSEC_ABORT_NO_SUBINDEX,
              NULL, 0u, req, req_len, send_reply, user);
}

/* ---- C042h:01 signed read --------------------------------------------- */

static bool handle_generic_read(uint16_t client_dev, const uint8_t *req,
                                uint16_t req_len,
                                fbsec_send_reply_fn_t send_reply, void *user) {
  const uint16_t hdr_len = 3u;                       /* index[2] + sub[1] */
  const uint16_t p2_len  = (uint16_t)(hdr_len + FBSEC_RPK_NONCE_LEN);
  uint16_t target_index;
  uint8_t  target_sub;
  uint32_t target_id;
  const uint8_t *client_nonce;
  uint8_t  val[FBSEC_RPK_VALUE_MAX];
  uint16_t vlen = 0u;
  fbsec_abort_t rd;
  uint8_t  body[RPK_BODY_MAX];
  uint8_t  transcript[RPK_TRANSCRIPT_MAX];
  uint8_t  reply[FBSEC_RPK_VALUE_MAX + FBSEC_ASYM_SIG_SIZE];
  uint16_t blen;
  uint16_t tn;

  /* Pass 1: bare target header (index[2] + sub[1]) -> issue a challenge. */
  if (req_len == hdr_len) {
    return arm_challenge(client_dev, FBSEC_RPK_GENERIC_READ_ID, "C42R",
                         req, req_len, send_reply, user);
  }
  /* Pass 2: index[2] + sub[1] + client_nonce[16]. */
  if (req_len != p2_len) {
    return emit(client_dev, FBSEC_RPK_GENERIC_READ_ID, "C42R",
                (req_len > p2_len) ? FBSEC_ABORT_LEN_TOO_HIGH
                                   : FBSEC_ABORT_LEN_TOO_LOW,
                NULL, 0u, req, req_len, send_reply, user);
  }
  if (!g_challenge.armed || (g_challenge.client_dev != client_dev) ||
      (g_challenge.data_id != FBSEC_RPK_GENERIC_READ_ID)) {
    return emit(client_dev, FBSEC_RPK_GENERIC_READ_ID, "C42R",
                FBSEC_ABORT_NO_SESSION, NULL, 0u, req, req_len, send_reply, user);
  }
  target_index = (uint16_t)((uint16_t)req[0] | ((uint16_t)req[1] << 8));
  target_sub   = req[2];
  target_id    = ((uint32_t)target_index << 16) | ((uint32_t)target_sub << 8);
  client_nonce = &req[hdr_len];

  rd = fbsec_sod_port_read_before(target_id, val, &vlen);
  if (rd != FBSEC_ABORT_NONE) {
    g_challenge.armed = false;
    return emit(client_dev, FBSEC_RPK_GENERIC_READ_ID, "C42R", rd,
                NULL, 0u, req, req_len, send_reply, user);
  }
  if (vlen > FBSEC_RPK_VALUE_MAX) {
    g_challenge.armed = false;
    return emit(client_dev, FBSEC_RPK_GENERIC_READ_ID, "C42R",
                FBSEC_ABORT_INTERNAL, NULL, 0u, req, req_len, send_reply, user);
  }

  blen = build_signed_body(body, fbsec_sod_port_get_device_id(), client_dev,
                           target_id, client_nonce, g_challenge.server_nonce,
                           val, vlen);
  tn = fbsec_asym_transcript(FBSEC_ASYM_RD_GENERIC_READ, body, blen,
                             transcript, (uint16_t)sizeof transcript);
  g_challenge.armed = false;                         /* one challenge, one response */
  memcpy(reply, val, vlen);
  if ((tn == 0u) ||
      !fbsec_asym_sign(fbsec_server_asym_idevid(), transcript, tn,
                       &reply[vlen])) {
    return emit(client_dev, FBSEC_RPK_GENERIC_READ_ID, "C42R",
                FBSEC_ABORT_INTERNAL, NULL, 0u, req, req_len, send_reply, user);
  }
  return emit(client_dev, FBSEC_RPK_GENERIC_READ_ID, "C42R", FBSEC_ABORT_NONE,
              reply, (uint16_t)(vlen + FBSEC_ASYM_SIG_SIZE),
              req, req_len, send_reply, user);
}

/* Arm a fresh challenge for @p data_id and reply with the server nonce. */
static bool arm_challenge(uint16_t client_dev, uint32_t data_id,
                          const char *verb, const uint8_t *req, uint16_t req_len,
                          fbsec_send_reply_fn_t send_reply, void *user) {
  if (!fbsec_sod_port_random(g_challenge.server_nonce, FBSEC_RPK_NONCE_LEN)) {
    return emit(client_dev, data_id, verb, FBSEC_ABORT_INTERNAL,
                NULL, 0u, req, req_len, send_reply, user);
  }
  g_challenge.armed      = true;
  g_challenge.client_dev = client_dev;
  g_challenge.data_id    = data_id;
  return emit(client_dev, data_id, verb, FBSEC_ABORT_NONE,
              g_challenge.server_nonce, FBSEC_RPK_NONCE_LEN,
              req, req_len, send_reply, user);
}

/* Verify a signed Pass-2 body against the outstanding challenge and the
   integrator peer key. @p challenge_id names the object the challenge was
   armed for (C042h:02 or C049h:00); @p bind_id is the object id bound into
   the signed transcript (the write target for C042h, the command object for
   C049h). Returns FBSEC_ABORT_NONE on success (and consumes the challenge),
   or an abort code. */
static fbsec_abort_t verify_signed(uint16_t client_dev, uint32_t challenge_id,
                                   uint32_t bind_id, uint8_t role,
                                   const uint8_t *client_nonce,
                                   const uint8_t *value, uint16_t value_len,
                                   const uint8_t *sig) {
  uint8_t  body[RPK_BODY_MAX];
  uint8_t  transcript[RPK_TRANSCRIPT_MAX];
  fbsec_pubkey_t peer;
  uint16_t o = 0u;
  uint16_t tn;

  if (!g_challenge.armed || (g_challenge.client_dev != client_dev) ||
      (g_challenge.data_id != challenge_id)) {
    return FBSEC_ABORT_NO_SESSION;
  }
  if (!fbsec_server_asym_get_peer(RPK_WRITE_PEER_SLOT, &peer)) {
    g_challenge.armed = false;
    return FBSEC_ABORT_SIG_VERIFY;           /* no authorizing key installed */
  }

  o = build_signed_body(body, fbsec_sod_port_get_device_id(), client_dev,
                        bind_id, client_nonce, g_challenge.server_nonce,
                        value, value_len);

  tn = fbsec_asym_transcript(role, body, o, transcript,
                             (uint16_t)sizeof transcript);
  g_challenge.armed = false;                 /* one challenge, one attempt */
  if ((tn == 0u) || !fbsec_asym_verify(&peer, transcript, tn, sig)) {
    return FBSEC_ABORT_SIG_VERIFY;
  }
  return FBSEC_ABORT_NONE;
}

/* ---- C042h:02 signed write -------------------------------------------- */

static bool handle_generic_write(uint16_t client_dev, const uint8_t *req,
                                 uint16_t req_len,
                                 fbsec_send_reply_fn_t send_reply, void *user) {
  const uint16_t min_p2 =
    (uint16_t)(FBSEC_RPK_WRITE_HDR_LEN + FBSEC_ASYM_SIG_SIZE);
  uint16_t target_index;
  uint8_t  target_sub;
  uint32_t target_id;
  const uint8_t *client_nonce;
  const uint8_t *value;
  uint16_t value_len;
  const uint8_t *sig;
  fbsec_abort_t st;

  /* Pass 1: bare target header (index[2] + sub[1]) -> issue a challenge. */
  if (req_len == FBSEC_RPK_WRITE_HDR_LEN - FBSEC_RPK_NONCE_LEN) {
    return arm_challenge(client_dev, FBSEC_RPK_GENERIC_WRITE_ID, "C42W",
                         req, req_len, send_reply, user);
  }
  /* Pass 2: index[2] + sub[1] + client_nonce[16] + value[N] + sig[64]. */
  if (req_len < min_p2) {
    return emit(client_dev, FBSEC_RPK_GENERIC_WRITE_ID, "C42W",
                FBSEC_ABORT_LEN_TOO_LOW, NULL, 0u, req, req_len,
                send_reply, user);
  }
  value_len = (uint16_t)(req_len - min_p2);
  if (value_len > FBSEC_RPK_VALUE_MAX) {
    return emit(client_dev, FBSEC_RPK_GENERIC_WRITE_ID, "C42W",
                FBSEC_ABORT_LEN_TOO_HIGH, NULL, 0u, req, req_len,
                send_reply, user);
  }
  target_index = (uint16_t)((uint16_t)req[0] | ((uint16_t)req[1] << 8));
  target_sub   = req[2];
  target_id    = ((uint32_t)target_index << 16) | ((uint32_t)target_sub << 8);
  client_nonce = &req[FBSEC_RPK_WRITE_HDR_LEN - FBSEC_RPK_NONCE_LEN];
  value        = &req[FBSEC_RPK_WRITE_HDR_LEN];
  sig          = &req[FBSEC_RPK_WRITE_HDR_LEN + value_len];

  st = verify_signed(client_dev, FBSEC_RPK_GENERIC_WRITE_ID, target_id,
                     FBSEC_ASYM_RD_GENERIC_WRITE, client_nonce, value,
                     value_len, sig);
  if (st != FBSEC_ABORT_NONE) {
    return emit(client_dev, FBSEC_RPK_GENERIC_WRITE_ID, "C42W", st,
                NULL, 0u, req, req_len, send_reply, user);
  }
  st = fbsec_sod_port_write_after(target_id, value, value_len);
  return emit(client_dev, FBSEC_RPK_GENERIC_WRITE_ID, "C42W", st,
              NULL, 0u, req, req_len, send_reply, user);
}

/* ---- C049h signed function command ------------------------------------ */

static bool handle_command(uint16_t client_dev, const uint8_t *req,
                           uint16_t req_len,
                           fbsec_send_reply_fn_t send_reply, void *user) {
  const uint16_t p2_len =
    (uint16_t)(FBSEC_RPK_NONCE_LEN + FBSEC_RPK_CMD_LEN + FBSEC_ASYM_SIG_SIZE);
  const uint8_t *client_nonce;
  const uint8_t *code_bytes;
  const uint8_t *sig;
  uint32_t code;
  fbsec_abort_t st;

  /* Pass 1: empty request -> issue a challenge. */
  if (req_len == 0u) {
    return arm_challenge(client_dev, FBSEC_RPK_FUNCCMD_ID, "C49C",
                         req, req_len, send_reply, user);
  }
  /* Pass 2: client_nonce[16] + code[4] + sig[64]. */
  if (req_len != p2_len) {
    return emit(client_dev, FBSEC_RPK_FUNCCMD_ID, "C49C",
                (req_len < p2_len) ? FBSEC_ABORT_LEN_TOO_LOW
                                   : FBSEC_ABORT_LEN_TOO_HIGH,
                NULL, 0u, req, req_len, send_reply, user);
  }
  client_nonce = &req[0];
  code_bytes   = &req[FBSEC_RPK_NONCE_LEN];
  sig          = &req[FBSEC_RPK_NONCE_LEN + FBSEC_RPK_CMD_LEN];

  st = verify_signed(client_dev, FBSEC_RPK_FUNCCMD_ID, FBSEC_RPK_FUNCCMD_ID,
                     FBSEC_ASYM_RD_FUNCTION_CMD, client_nonce, code_bytes,
                     FBSEC_RPK_CMD_LEN, sig);
  if (st != FBSEC_ABORT_NONE) {
    return emit(client_dev, FBSEC_RPK_FUNCCMD_ID, "C49C", st,
                NULL, 0u, req, req_len, send_reply, user);
  }
  code = (uint32_t)code_bytes[0] | ((uint32_t)code_bytes[1] << 8)
       | ((uint32_t)code_bytes[2] << 16) | ((uint32_t)code_bytes[3] << 24);
  if (code == FBSEC_HO_CMD_FACTORY_RESTORE) {
    /* Decommission: erase keys and ownership, return to Uncommissioned. The
       node stays online and can be commissioned again. */
    fbsec_server_handover_decommission();
    printf("  C049h manufacturer reset: device decommissioned (keys erased)\n");
  } else {
    /* Other codes only demonstrate that a signed command reached the
       application; a later pass gives them real effects. */
    printf("  C049h function command 0x%08lX received\n", (unsigned long)code);
  }
  return emit(client_dev, FBSEC_RPK_FUNCCMD_ID, "C49C", FBSEC_ABORT_NONE,
              NULL, 0u, req, req_len, send_reply, user);
}

/* ---- Dispatch --------------------------------------------------------- */

bool fbsec_server_rpk_try(uint16_t src_dev, uint32_t data_id,
                          const uint8_t *payload, uint16_t payload_len,
                          fbsec_send_reply_fn_t send_reply, void *user) {
  uint16_t index = (uint16_t)(data_id >> 16);
  uint8_t  sub   = (uint8_t)((data_id >> 8) & 0xFFu);

  if (index == FBSEC_RPK_PUBKEYS_INDEX) {
    return handle_pubkeys(src_dev, data_id, sub, payload, payload_len,
                          send_reply, user);
  }
  if (index == FBSEC_RPK_PKTYPES_INDEX) {
    return handle_pktypes(src_dev, data_id, sub, payload, payload_len,
                          send_reply, user);
  }
  if (data_id == FBSEC_RPK_GENERIC_READ_ID) {
    return handle_generic_read(src_dev, payload, payload_len, send_reply, user);
  }
  if (data_id == FBSEC_RPK_GENERIC_WRITE_ID) {
    return handle_generic_write(src_dev, payload, payload_len, send_reply, user);
  }
  if (data_id == FBSEC_RPK_FUNCCMD_ID) {
    return handle_command(src_dev, payload, payload_len, send_reply, user);
  }
  return false;
}

#endif /* FBSEC_FEATURE_ASYM */

/* EOF */
