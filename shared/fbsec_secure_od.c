/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    fbsec_secure_od.c
 * @brief   SOFA server-side secure object dictionary, implementation.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.3 of 22-JUL-2026
 *
 * Wire-keyid byte rule: the keyid is carried only on CLIENT REQUESTS,
 * never on server responses, and where it appears it is the FIRST byte
 * of the payload. The server consumes it from the first byte and
 * never echoes it back.
 *
 * Inbound dispatch for secure entries. Single-shot flows (existing):
 *
 *   data_id is SECURE_RO, payload_len == 1 + R (single-shot challenge):
 *     parse key_id[1] || client_random[R] (bit 6 of key_id clear);
 *     port_random() -> server_random[R];
 *     port_read_before() to fetch plaintext;
 *     nonce = client_random[0..11] XOR server_random[0..11];
 *     seal under READ_RESPONSE direction with AAD tail
 *       = client_random[R] || server_random[R] (|| plaintext if
 *         encryption=0);
 *     stash server_random[R] || cipher[N] || tag in the armed-read
 *     slot (no echoed keyid).
 *     -> DEFER (return ACK envelope; response held for the next read)
 *
 *   data_id is SECURE_RO, payload_len == 0, single-shot slot armed:
 *     -> OK with reply = stashed prepared bytes; clear slot
 *
 *   data_id is SECURE_WO, payload_len == 0 (single-shot challenge):
 *     port_random() -> server_random[R]
 *     stash random + deadline in armed-write slot (no keyid yet,
 *     learned on Pass 2)
 *     -> OK with reply = server_random[R]   (no tag: server cannot
 *        authenticate without a key bound to this leg)
 *
 *   data_id is SECURE_WO, payload_len == 1 + R + data_len + tag_len
 *                                       (single-shot write):
 *     parse keyid[1] || client_random[R] || cipher[N] || tag[T];
 *     nonce = client_random[0..11] XOR server_random[0..11];
 *     verify+apply (WRITE_REQUEST direction, AAD tail =
 *                   client_random[R] || server_random[R]).
 *     -> OK with empty reply; clear armed-write slot
 *
 * Cyclic-mode flows:
 *
 *   SECURE_RO challenge with bit 6 of key_id set (17 bytes):
 *     take client_random[0..5] as session_random; allocate session_id;
 *     mark slot cyclic, counter=0, store key_id+session info.
 *     -> OK with reply = session_id_be16[2] (2 bytes)
 *
 *   SECURE_RO with payload_len == 1 AND cyclic read slot armed:
 *     wire counter_low = req[0]; expected_counter = stored.counter + 1.
 *     If (counter_low == (expected_counter & 0xFF)) and slot is fresh:
 *       seal next plaintext with nonce =
 *         session_random[6] || session_id_be16[2] || counter_be32[4]
 *       and AAD tail = session_id || counter; advance stored.counter;
 *       refresh armed_at.
 *       -> OK with reply = counter_low[1] || ciphertext[N] || tag[8]
 *     If counter mismatch: drop (no state change), return abort
 *     FBSEC_ABORT_POLL_COUNTER without tearing down the slot.
 *     If counter reaches FBSEC_AEAD_KEY_USE_LIMIT: tear down, abort.
 *
 *   SECURE_WO challenge with bit 6 of key_id set (1 byte; the byte is
 *                                                 the wire keyid):
 *     port_random() -> server_random[16]; allocate session_id; stash
 *     random + sid + keyid in cyclic write slot, take server_random
 *     [0..5] as session_random, counter=0.
 *     -> OK with reply = server_random[16] || session_id_be16[2]
 *        (18 bytes)
 *
 *   SECURE_WO with payload_len == 1 + data_len + 8 AND cyclic write
 *   slot armed: wire counter_low = req[0]; ciphertext = req[1..1+
 *     data_len]; tag = req[1+data_len..]. Same counter-check as the
 *     read path. On success: open with the derived nonce,
 *     port_write_after(plaintext).
 *     -> OK with empty reply.
 *
 * MVP simplification: ONE armed slot per entry per direction (not
 * per-client). Cyclic-mode slots live up to FBSEC_SOD_SESSION_IDLE_-
 * TIMEOUT_MS without traffic; documented limitation that two clients
 * arming the same entry race-overwrite.
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#include "fbsec_secure_od.h"

#include <string.h>

/* On-wire challenge sizes. */
#define READ_CHALLENGE_LEN        ((uint16_t)(1u + FBSEC_AEAD_RAND_SIZE))       /* 13 */
#define WRITE_CHALLENGE_LEN       ((uint16_t)FBSEC_AEAD_RAND_SIZE)              /* 12 */
/* Ed25519 signature trailer appended to the establishment verb in
   signed-FBsec mode (spec 11.6.5); zero when the mode is not built. */
#if FBSEC_ASYM_SIGNED_FBSEC
#define SIGNED_TRAILER_LEN        ((uint16_t)FBSEC_ASYM_SIG_SIZE)
#else
#define SIGNED_TRAILER_LEN        0u
#endif

/* Pre-sealed single-shot read response shape: server_random[R] ||
   cipher[N] || tag[T] (|| SIG[64] in signed-FBsec mode). The cyclic-
   capable arm reply is byte-identical to the plain single-shot reply
   (no session_id on the wire); cyclic state lives in the slot and is
   keyed by (client_dev, data_id). */
#define READ_RESPONSE_MAX         ((uint16_t)(FBSEC_AEAD_RAND_SIZE \
                                              + FBSEC_AEAD_MAX_PROTECTED \
                                              + FBSEC_AEAD_TAG_SIZE \
                                              + SIGNED_TRAILER_LEN))

/* ---- Internal types --------------------------------------------------- */

#if FBSEC_FEATURE_READ
typedef struct read_state_t {
  bool      in_use;
  bool      cyclic;       /* true iff armed via bit-6 challenge */
  uint16_t  client_dev;       /* who armed this slot */
  uint16_t  armed_at;         /* port_get_time_ms() at arming or last poll */
  /* Single-shot only: pre-sealed response held until Pass-2 read. */
  uint16_t  prepared_len;
  uint8_t   prepared[READ_RESPONSE_MAX];
  /* Cyclic mode only: nonce_base = XOR of arm-time randoms; counter
     increments per poll and is XOR'd into nonce_base low 32 bits. */
  uint8_t   key_id;                                /* full wire byte */
  uint8_t   nonce_base[FBSEC_AEAD_NONCE_SIZE];
  uint32_t  counter;                               /* last accepted counter */
} read_state_t;
#endif /* FBSEC_FEATURE_READ */

#if FBSEC_FEATURE_WRITE
typedef struct write_state_t {
  bool      in_use;
  bool      cyclic;
  uint16_t  client_dev;
  uint16_t  armed_at;
  /* Set on Pass-2 verify_and_apply from the wire keyid byte (single-
     shot) or stashed at arming (cyclic). */
  uint8_t   key_id;
  /* Pass-1 server-side random; first FBSEC_AEAD_NONCE_SIZE bytes feed
     the single-shot GCM nonce and, on cyclic arming, feed nonce_base
     once Pass-2 brings the client's random. */
  uint8_t   server_random[FBSEC_AEAD_RAND_SIZE];
  /* Cyclic mode only: nonce_base = XOR of arm-time randoms; populated
     in verify_and_apply_write once the Pass-2 client_random arrives. */
  uint8_t   nonce_base[FBSEC_AEAD_NONCE_SIZE];
  uint32_t  counter;
} write_state_t;
#endif /* FBSEC_FEATURE_WRITE */

/* ---- Module state ----------------------------------------------------- */

static fbsec_sod_entry_t  g_registry[FBSEC_SOD_MAX_ENTRIES];
static uint8_t          g_registry_count = 0u;

/* Per-entry slots, indexed in lockstep with g_registry. */
#if FBSEC_FEATURE_READ
static read_state_t     g_read_slot[FBSEC_SOD_MAX_ENTRIES];
#endif
#if FBSEC_FEATURE_WRITE
static write_state_t    g_write_slot[FBSEC_SOD_MAX_ENTRIES];
#endif

/* Key slots 0..N-1; index 0 is the FBSEC_SOD_KEY_NONE sentinel and unused.
   key_id 1 -> g_keys[1], etc. g_key_id_val holds the non-secret U32 key
   id / version reported by C011h; it is independent of the slot's role
   number and defaults to the slot number when not set explicitly. */
static uint8_t          g_keys[FBSEC_SOD_KEY_SLOTS + 1u][FBSEC_AEAD_KEY_SIZE];
static bool             g_key_present[FBSEC_SOD_KEY_SLOTS + 1u];
static uint32_t         g_key_id_val[FBSEC_SOD_KEY_SLOTS + 1u];

/* ---- Lifecycle / registry -------------------------------------------- */

void fbsec_sod_init(void) {
  memset(g_registry,    0, sizeof g_registry);
#if FBSEC_FEATURE_READ
  memset(g_read_slot,   0, sizeof g_read_slot);
#endif
#if FBSEC_FEATURE_WRITE
  memset(g_write_slot,  0, sizeof g_write_slot);
#endif
  memset(g_keys,        0, sizeof g_keys);
  memset(g_key_present, 0, sizeof g_key_present);
  memset(g_key_id_val,  0, sizeof g_key_id_val);
  g_registry_count  = 0u;
}

static int find_index(uint32_t data_id) {
  for (uint8_t i = 0u; i < g_registry_count; ++i) {
    if (g_registry[i].data_id == data_id) return (int)i;
  }
  return -1;
}

bool fbsec_sod_register_entry(const fbsec_sod_entry_t *entry) {
  if (entry == NULL) return false;
  if (entry->data_len > FBSEC_AEAD_MAX_PROTECTED) return false;

  int idx = find_index(entry->data_id);
  if (idx >= 0) {
    g_registry[idx] = *entry;
    return true;
  }
  if (g_registry_count >= FBSEC_SOD_MAX_ENTRIES) return false;
  g_registry[g_registry_count] = *entry;
  ++g_registry_count;
  return true;
}

const fbsec_sod_entry_t *fbsec_sod_find_entry(uint32_t data_id) {
  int idx = find_index(data_id);
  return (idx >= 0) ? &g_registry[idx] : NULL;
}

/* ---- Key store ------------------------------------------------------- */

bool fbsec_sod_set_key_ex(uint8_t key_id, const uint8_t key[FBSEC_AEAD_KEY_SIZE],
                          uint32_t id_value) {
  if (key == NULL) return false;
  if (key_id < 1u || key_id > FBSEC_SOD_KEY_SLOTS) return false;
  if (g_key_present[key_id]) return false;     /* write-once */
  memcpy(g_keys[key_id], key, FBSEC_AEAD_KEY_SIZE);
  g_key_present[key_id] = true;
  g_key_id_val[key_id]  = id_value;
  return true;
}

bool fbsec_sod_set_key(uint8_t key_id, const uint8_t key[FBSEC_AEAD_KEY_SIZE]) {
  /* Back-compatible: the non-secret key id defaults to the slot number. */
  return fbsec_sod_set_key_ex(key_id, key, (uint32_t)key_id);
}

bool fbsec_sod_has_key(uint8_t key_id) {
  if (key_id < 1u || key_id > FBSEC_SOD_KEY_SLOTS) return false;
  return g_key_present[key_id];
}

uint32_t fbsec_sod_get_key_id_value(uint8_t key_id) {
  if (key_id < 1u || key_id > FBSEC_SOD_KEY_SLOTS) return 0u;
  return g_key_present[key_id] ? g_key_id_val[key_id] : 0u;
}

static const uint8_t *get_key(uint8_t key_id) {
  if (!fbsec_sod_has_key(key_id)) return NULL;
  return g_keys[key_id];
}

/* ---- Freshness check -------------------------------------------------- */

static bool slot_is_fresh_for(uint16_t armed_at, uint16_t timeout_ms) {
  uint16_t now = fbsec_sod_port_get_time_ms();
  /* 16-bit subtraction handles a single wrap. */
  uint16_t age = (uint16_t)(now - armed_at);
  return age <= timeout_ms;
}

static bool slot_is_fresh(uint16_t armed_at) {
  return slot_is_fresh_for(armed_at,
                           (uint16_t)FBSEC_SOD_CHALLENGE_TIMEOUT_MS);
}

#if FBSEC_FEATURE_WRITE || (FBSEC_FEATURE_CYCLIC && FBSEC_FEATURE_READ)
/* ---- Length-mismatch classification ---------------------------------- */

/**
 * @brief Pick the CiA 1301 Table 31 code for a wrong request length.
 *
 * Table 31 distinguishes "length of service parameter too high" (37h)
 * from "too low" (38h) wherever the receiver can tell; 36h is the
 * generic "data type / length does not match".
 *
 * @param got   received length in bytes.
 * @param want  expected length in bytes.
 * @return 37h, 38h, or 36h when the two are equal (never expected).
 */
static fbsec_abort_t length_abort(uint16_t got, uint16_t want) {
  if (got > want) { return FBSEC_ABORT_LEN_TOO_HIGH; }
  if (got < want) { return FBSEC_ABORT_LEN_TOO_LOW; }
  return FBSEC_ABORT_TYPE_MISMATCH;
}
#endif

#if FBSEC_FEATURE_CYCLIC
static bool session_is_fresh(uint16_t armed_at) {
  return slot_is_fresh_for(armed_at,
                           (uint16_t)FBSEC_SOD_SESSION_IDLE_TIMEOUT_MS);
}
#endif

#if FBSEC_FEATURE_CYCLIC
/* ---- Nonce assembly for cyclic-mode AEAD ------------------------- */

/* Per-frame poll nonce: nonce_base XOR (0^64 || counter_be32). The
   nonce_base is the arm-time XOR of the two randoms (see spec section
   11.1 and EmSA-WP-105 section 4.2.6). */
static void build_session_nonce(
  const uint8_t  nonce_base[FBSEC_AEAD_NONCE_SIZE],
  uint32_t       counter,
  uint8_t        nonce_out[FBSEC_AEAD_NONCE_SIZE])
{
  memcpy(nonce_out, nonce_base, FBSEC_AEAD_NONCE_SIZE);
  nonce_out[8]  ^= (uint8_t)((counter >> 24) & 0xFFu);
  nonce_out[9]  ^= (uint8_t)((counter >> 16) & 0xFFu);
  nonce_out[10] ^= (uint8_t)((counter >>  8) & 0xFFu);
  nonce_out[11] ^= (uint8_t)( counter        & 0xFFu);
}
#endif /* FBSEC_FEATURE_CYCLIC */

#if FBSEC_FEATURE_READ
/* ---- Read flow helpers ----------------------------------------------- */

static fbsec_sod_status_t arm_read_response(
  int                      slot_idx,
  const fbsec_sod_entry_t   *entry,
  uint16_t                 client_dev,
  const uint8_t           *challenge,    /* 1 + R bytes */
  uint8_t                 *reply,
  uint16_t                 reply_max,
  uint16_t                *reply_len,
  fbsec_abort_t           *out_abort)
{
  /* Wire shape: key_id[1] || client_random[R]. The keyid is the first
     byte of every client request that carries it. */
  uint8_t        key_id        = challenge[0];
  const uint8_t *client_random = &challenge[1];
  uint8_t        kid_base      = FBSEC_AEAD_KEYID_BASE(key_id);
#if FBSEC_FEATURE_CYCLIC
  bool           is_cyclic     = FBSEC_AEAD_KEYID_IS_CYCLIC(key_id);
#endif
  /* Pass-1 always returns DEFER with empty reply; the prepared bytes
     are delivered when Pass-2 (empty body) arrives. The reply / reply_max
     / reply_len params are present only for symmetry with other handlers. */
  (void)reply;
  (void)reply_max;
  (void)reply_len;

  /* Reserved bits (5..4) must be 0; reject anything else so future bit
     assignments do not silently collide with old peers. With cyclic
     stripped, bit 6 (cyclic-arm) joins the reserved set so a peer can
     never silently downgrade to single-shot when it expected cyclic. */
#if FBSEC_FEATURE_CYCLIC
  if (FBSEC_AEAD_KEYID_RESERVED(key_id) != 0u) {
    *out_abort = FBSEC_ABORT_KEY_ID;
    return FBSEC_SOD_ABORT;
  }
#else
  if (FBSEC_AEAD_KEYID_RESERVED(key_id) != 0u) {
    *out_abort = FBSEC_ABORT_KEY_ID;
    return FBSEC_SOD_ABORT;
  }
  if ((key_id & 0x40u) != 0u) {
    /* Cyclic-arm requested but the cyclic feature was stripped. */
    *out_abort = FBSEC_ABORT_NOT_BUILT;
    return FBSEC_SOD_ABORT;
  }
#endif

  /* Resolve key. SECURE_RO entries with key_id == FBSEC_SOD_KEY_NONE
     accept any provisioned key; otherwise the bound key is required.
     The full wire byte (bit 7 = encrypt, bit 6 = cyclic-arm,
     bits 5..4 = reserved (must be 0), bits 3..0 = base id) goes into
     AAD verbatim; the bare base id is the lookup key against
     entry->key_id. */
  if (entry->key_id != FBSEC_SOD_KEY_NONE && kid_base != entry->key_id) {
    *out_abort = FBSEC_ABORT_KEY_ID;
    return FBSEC_SOD_ABORT;
  }
  const uint8_t *key = get_key(kid_base);
  if (key == NULL) {
    *out_abort = FBSEC_ABORT_KEY_ID;
    return FBSEC_SOD_ABORT;
  }

  if (!fbsec_sod_port_access_allowed(FBSEC_SOD_OP_READ, entry->data_id)) {
    *out_abort = FBSEC_ABORT_DEVICE_STATE;
    return FBSEC_SOD_ABORT;
  }
  if (!fbsec_sod_port_role_allowed(FBSEC_SOD_OP_READ, kid_base, entry->data_id)) {
    *out_abort = FBSEC_ABORT_ROLE_DENIED;
    return FBSEC_SOD_ABORT;
  }

  read_state_t *slot = &g_read_slot[slot_idx];

  /* Single-shot data path runs whether or not bit-6 is set. When
     bit-6 IS set, we additionally allocate a session_id (appended to
     the prepared response) and keep the slot live across Pass 2 so
     subsequent READ_POLL_REQUESTs can reuse the established session.
     This is the "cyclic-capable single SRD" flow: byte-identical to
     a plain single SRD except for the keyid's bit-6 and the trailing
     session_id[2] in the Pass-2 response. */
  uint8_t  plaintext[FBSEC_AEAD_MAX_PROTECTED];
  uint16_t plain_len = entry->data_len;
  fbsec_abort_t hook_rc = fbsec_sod_port_read_before(entry->data_id,
                                              plaintext, &plain_len);
  if (hook_rc != FBSEC_ABORT_NONE) {
    *out_abort = hook_rc;
    return FBSEC_SOD_ABORT;
  }
  if (plain_len != entry->data_len) {
    *out_abort = FBSEC_ABORT_INTERNAL;
    return FBSEC_SOD_ABORT;
  }

  /* Generate the server's contribution to the nonce. Combined with the
     client's random via XOR, this yields a per-frame nonce that is
     unique whenever EITHER side has a sound RNG. */
  uint8_t server_random[FBSEC_AEAD_RAND_SIZE];
  if (!fbsec_sod_port_random(server_random, FBSEC_AEAD_RAND_SIZE)) {
    *out_abort = FBSEC_ABORT_INTERNAL;
    return FBSEC_SOD_ABORT;
  }
  uint8_t nonce[FBSEC_AEAD_NONCE_SIZE];
  fbsec_aead_xor_nonce(client_random, server_random, nonce);

  /* Pre-build the wire reply for Pass 2:
       server_random[R] || cipher[N] || tag[T]
     (no echoed keyid; the client already knows it and AAD-binding
     authenticates it via the tag.) AAD direction = READ_RESPONSE;
     tail authenticates BOTH randoms (and the keyid via the prefix at
     offset 3). */
  memset(slot, 0, sizeof *slot);
  memcpy(&slot->prepared[0], server_random, FBSEC_AEAD_RAND_SIZE);
  uint16_t cipher_off = (uint16_t)FBSEC_AEAD_RAND_SIZE;
  if (!fbsec_aead_seal(key, nonce,
                     FBSEC_AEAD_DIR_READ_RESPONSE, key_id,
                     fbsec_sod_port_get_device_id(), client_dev,
                     entry->data_id,
                     client_random, server_random,
                     plaintext, plain_len,
                     &slot->prepared[cipher_off],
                     &slot->prepared[cipher_off + plain_len])) {
    *out_abort = FBSEC_ABORT_INTERNAL;
    return FBSEC_SOD_ABORT;
  }
  slot->in_use       = true;
  slot->client_dev   = client_dev;
  slot->armed_at     = fbsec_sod_port_get_time_ms();
  slot->prepared_len = (uint16_t)(cipher_off + plain_len + FBSEC_AEAD_TAG_SIZE);

#if FBSEC_ASYM_SIGNED_FBSEC
  /* Signed-FBsec (spec 11.6.5): the server proves its runtime identity by
     appending an Ed25519 signature over the domain-separated transcript
     that binds both randoms and the addressing context. The AEAD tag is
     what a client verifies FIRST; this signature is the second factor. */
  if (FBSEC_AEAD_KEYID_SIGNED(key_id)) {
    uint8_t  ctx[FBSEC_ASYM_FBSEC_CTX_LEN];
    uint8_t  transcript[FBSEC_ASYM_TRANSCRIPT_OVERHEAD + FBSEC_ASYM_FBSEC_CTX_LEN];
    uint16_t clen = fbsec_asym_fbsec_context(entry->data_id,
                                             fbsec_sod_port_get_device_id(), client_dev,
                                             client_random, server_random,
                                             ctx, (uint16_t)sizeof ctx);
    uint16_t tlen = fbsec_asym_transcript(FBSEC_ASYM_RD_SIGNED_FBSEC_S2C, ctx, clen,
                                          transcript, (uint16_t)sizeof transcript);
    if ((clen == 0u) || (tlen == 0u) ||
        !fbsec_sod_port_sign(FBSEC_ASYM_RD_SIGNED_FBSEC_S2C, transcript, tlen,
                             &slot->prepared[slot->prepared_len])) {
      *out_abort = FBSEC_ABORT_INTERNAL;
      return FBSEC_SOD_ABORT;
    }
    slot->prepared_len = (uint16_t)(slot->prepared_len + FBSEC_ASYM_SIG_SIZE);
  }
#endif

#if FBSEC_FEATURE_CYCLIC
  /* Cyclic-capable single SRD: keep the prepared response byte-
     identical to plain single-shot (no session_id on the wire) but
     stash nonce_base + counter so the slot survives Pass 2 and
     subsequent READ_POLL_REQUESTs can reuse the established session. */
  slot->cyclic = is_cyclic;
  if (is_cyclic) {
    slot->key_id  = key_id;
    fbsec_aead_xor_nonce(client_random, server_random, slot->nonce_base);
    slot->counter = 0u;
  }
#else
  slot->cyclic = false;
#endif
  return FBSEC_SOD_DEFER;
}
#endif /* FBSEC_FEATURE_READ */

#if FBSEC_FEATURE_WRITE
/* ---- Write flow helpers ---------------------------------------------- */

/**
 * @brief Pass 1 of the secure-write flow. Single-shot is unauthenticated
 *        on this leg by design (server has no key context until the
 *        client's Pass 2 carries the keyid byte). Cyclic-arm reads the
 *        keyid from the 1-byte request body and stashes it; the keyid's
 *        cyclic-arm bit (6) drives the cyclic vs single-shot branch.
 *
 * @param wire_key_id  Single-shot: caller passes 0 (keyid arrives later
 *                     in the Pass-2 framed write). Cyclic-arm: the wire
 *                     keyid byte (bit 6 set, possibly bit 7 for encrypt).
 * @param have_kid     true iff @p wire_key_id is meaningful (cyclic arm).
 */
static fbsec_sod_status_t arm_write_challenge(
  int                      slot_idx,
  const fbsec_sod_entry_t   *entry,
  uint16_t                 client_dev,
  uint8_t                  wire_key_id,
  bool                     have_kid,
  uint8_t                 *reply,
  uint16_t                 reply_max,
  uint16_t                *reply_len,
  fbsec_abort_t           *out_abort)
{
  if (!fbsec_sod_port_access_allowed(FBSEC_SOD_OP_WRITE, entry->data_id)) {
    *out_abort = FBSEC_ABORT_DEVICE_STATE;
    return FBSEC_SOD_ABORT;
  }

#if FBSEC_FEATURE_CYCLIC
  bool is_cyclic = false;
#endif
  if (have_kid) {
#if FBSEC_FEATURE_CYCLIC
    /* Reserved bits (5..4) must be 0. */
    if (FBSEC_AEAD_KEYID_RESERVED(wire_key_id) != 0u) {
      *out_abort = FBSEC_ABORT_KEY_ID;
      return FBSEC_SOD_ABORT;
    }
    is_cyclic = FBSEC_AEAD_KEYID_IS_CYCLIC(wire_key_id);
    /* This entry-point is reached with have_kid=true only on cyclic
       arming under the new flow; reject single-shot keyids that
       arrive here (they belong on Pass 2). */
    if (!is_cyclic) {
      *out_abort = FBSEC_ABORT_KEY_ID;
      return FBSEC_SOD_ABORT;
    }
    uint8_t kid_base = FBSEC_AEAD_KEYID_BASE(wire_key_id);
    if (entry->key_id != FBSEC_SOD_KEY_NONE && kid_base != entry->key_id) {
      *out_abort = FBSEC_ABORT_KEY_ID;
      return FBSEC_SOD_ABORT;
    }
    if (get_key(kid_base) == NULL) {
      *out_abort = FBSEC_ABORT_KEY_ID;
      return FBSEC_SOD_ABORT;
    }
    if (!fbsec_sod_port_role_allowed(FBSEC_SOD_OP_WRITE, kid_base, entry->data_id)) {
      *out_abort = FBSEC_ABORT_ROLE_DENIED;
      return FBSEC_SOD_ABORT;
    }
#else
    /* Cyclic stripped: any have_kid arm request is invalid. With
       cyclic gone, bit 6 also joins the reserved set, so we don't even
       need to parse the wire byte. */
    (void)wire_key_id;
    *out_abort = FBSEC_ABORT_NOT_BUILT;
    return FBSEC_SOD_ABORT;
#endif
  }

  /* Pass-1 reply shape is the same for single-shot and cyclic arm:
     just server_random[R]. The cyclic vs single-shot distinction
     lives in the slot (bit 6 of the wire keyid drives is_cyclic). */
  if (reply_max < WRITE_CHALLENGE_LEN) {
    *out_abort = FBSEC_ABORT_INTERNAL;
    return FBSEC_SOD_ABORT;
  }

  uint8_t random_buf[FBSEC_AEAD_RAND_SIZE];
  if (!fbsec_sod_port_random(random_buf, FBSEC_AEAD_RAND_SIZE)) {
    *out_abort = FBSEC_ABORT_INTERNAL;
    return FBSEC_SOD_ABORT;
  }

  write_state_t *slot = &g_write_slot[slot_idx];
  memset(slot, 0, sizeof *slot);
  slot->in_use     = true;
#if FBSEC_FEATURE_CYCLIC
  slot->cyclic = is_cyclic;
#else
  slot->cyclic = false;
#endif
  slot->client_dev = client_dev;
  slot->armed_at   = fbsec_sod_port_get_time_ms();
  /* Single-shot: keyid not yet known; learned from Pass 2. Cyclic:
     stash now so polls do not need to carry the keyid byte. */
  slot->key_id     = have_kid ? wire_key_id : 0u;
  memcpy(slot->server_random, random_buf, FBSEC_AEAD_RAND_SIZE);
#if FBSEC_FEATURE_CYCLIC
  /* nonce_base is computed in verify_and_apply_write when the Pass-2
     client_random arrives; counter starts at 0. */
  slot->counter    = 0u;
#endif

  memcpy(&reply[0], random_buf, FBSEC_AEAD_RAND_SIZE);
  *reply_len = WRITE_CHALLENGE_LEN;
  return FBSEC_SOD_OK;
}

static fbsec_sod_status_t verify_and_apply_write(
  int                      slot_idx,
  const fbsec_sod_entry_t   *entry,
  const uint8_t           *req,
  uint16_t                 req_len,
  uint8_t                 *reply,
  uint16_t                 reply_max,
  uint16_t                *reply_len,
  fbsec_abort_t           *out_abort)
{
  write_state_t *slot = &g_write_slot[slot_idx];
  if (!slot->in_use) {
    *out_abort = FBSEC_ABORT_NO_SESSION;
    return FBSEC_SOD_ABORT;
  }
  if (!slot_is_fresh(slot->armed_at)) {
    slot->in_use = false;
    *out_abort = FBSEC_ABORT_NO_SESSION;
    return FBSEC_SOD_ABORT;
  }
  /* Pass-2 wire shape:
       keyid[1] || client_random[R] || ciphertext[N] || tag[T]
       (|| SIG[64] in signed-FBsec mode, flagged by keyid bit 5). */
  uint16_t expected = (uint16_t)(1u + FBSEC_AEAD_RAND_SIZE
                                 + entry->data_len + FBSEC_AEAD_TAG_SIZE);
#if FBSEC_ASYM_SIGNED_FBSEC
  bool     signed_req    = FBSEC_AEAD_KEYID_SIGNED(req[0]);
  uint16_t expected_full = signed_req
                         ? (uint16_t)(expected + FBSEC_ASYM_SIG_SIZE) : expected;
  if (req_len != expected_full) {
    slot->in_use = false;
    *out_abort = length_abort(req_len, expected_full);
    return FBSEC_SOD_ABORT;
  }
#else
  if (req_len != expected) {
    slot->in_use = false;
    *out_abort = length_abort(req_len, expected);
    return FBSEC_SOD_ABORT;
  }
#endif

  /* Pull the keyid from the wire. Reserved bits (5..4) must be 0; bit
     6 (cyclic-arm) is OPTIONAL on Pass 2; when set, the slot stays
     live for follow-up polls and the response carries a 2-byte
     session_id. Plain single-shot Pass 2 leaves bit 6 clear. The
     base id must match the entry's bound key. */
  uint8_t  wire_key_id = req[0];
  if (FBSEC_AEAD_KEYID_RESERVED(wire_key_id) != 0u) {
    slot->in_use = false;
    *out_abort = FBSEC_ABORT_KEY_ID;
    return FBSEC_SOD_ABORT;
  }
  uint8_t kid_base = FBSEC_AEAD_KEYID_BASE(wire_key_id);
  if (entry->key_id != FBSEC_SOD_KEY_NONE && kid_base != entry->key_id) {
    slot->in_use = false;
    *out_abort = FBSEC_ABORT_KEY_ID;
    return FBSEC_SOD_ABORT;
  }
  const uint8_t *client_random = &req[1];
  const uint8_t *ciphertext    = &req[1u + FBSEC_AEAD_RAND_SIZE];
  const uint8_t *tag           = &req[1u + FBSEC_AEAD_RAND_SIZE
                                         + entry->data_len];
  const uint8_t *key           = get_key(kid_base);
  if (key == NULL) {
    slot->in_use = false;
    *out_abort = FBSEC_ABORT_KEY_ID;
    return FBSEC_SOD_ABORT;
  }
  if (!fbsec_sod_port_role_allowed(FBSEC_SOD_OP_WRITE, kid_base, entry->data_id)) {
    slot->in_use = false;
    *out_abort = FBSEC_ABORT_ROLE_DENIED;
    return FBSEC_SOD_ABORT;
  }
  slot->key_id = wire_key_id;     /* now known; recorded for trace/AAD */

  /* nonce = client_random[0..11] XOR server_random[0..11]. AAD direction
     = WRITE_REQUEST; AAD tail authenticates BOTH randoms (and the keyid
     via the prefix at offset 3). */
  uint8_t nonce[FBSEC_AEAD_NONCE_SIZE];
  fbsec_aead_xor_nonce(client_random, slot->server_random, nonce);

  uint8_t plaintext[FBSEC_AEAD_MAX_PROTECTED];
  if (!fbsec_aead_open(key, nonce,
                     FBSEC_AEAD_DIR_WRITE_REQUEST, wire_key_id,
                     fbsec_sod_port_get_device_id(), slot->client_dev,
                     entry->data_id,
                     client_random, slot->server_random,
                     ciphertext, entry->data_len,
                     tag,
                     plaintext)) {
    slot->in_use = false;
    *out_abort = FBSEC_ABORT_TAG_VERIFY;
    return FBSEC_SOD_ABORT;
  }

#if FBSEC_ASYM_SIGNED_FBSEC
  /* Signed-FBsec (spec 11.6.5): the AEAD tag verified above; now verify
     the client's Ed25519 signature over the transcript before committing.
     Tag-first, signature-second preserves the DoS posture. */
  if (signed_req) {
    const uint8_t *sig = &req[expected];   /* trailer after keyid|R|cipher|tag */
    fbsec_pubkey_t pk;
    uint8_t  ctx[FBSEC_ASYM_FBSEC_CTX_LEN];
    uint8_t  transcript[FBSEC_ASYM_TRANSCRIPT_OVERHEAD + FBSEC_ASYM_FBSEC_CTX_LEN];
    uint16_t clen = fbsec_asym_fbsec_context(entry->data_id,
                                             fbsec_sod_port_get_device_id(), slot->client_dev,
                                             client_random, slot->server_random,
                                             ctx, (uint16_t)sizeof ctx);
    uint16_t tlen = fbsec_asym_transcript(FBSEC_ASYM_RD_SIGNED_FBSEC_C2S, ctx, clen,
                                          transcript, (uint16_t)sizeof transcript);
    if (!fbsec_sod_port_peer_pubkey(slot->client_dev, pk.pub) ||
        (clen == 0u) || (tlen == 0u) ||
        !fbsec_asym_verify(&pk, transcript, tlen, sig)) {
      slot->in_use = false;
      *out_abort = FBSEC_ABORT_SIG_VERIFY;
      return FBSEC_SOD_ABORT;
    }
  }
#endif

  fbsec_abort_t hook_rc = fbsec_sod_port_write_after(entry->data_id,
                                              plaintext, entry->data_len);
  if (hook_rc != FBSEC_ABORT_NONE) {
    slot->in_use = false;
    *out_abort = hook_rc;
    return FBSEC_SOD_ABORT;
  }

  (void)reply;
  (void)reply_max;
  (void)reply_len;
#if FBSEC_FEATURE_CYCLIC
  /* Cyclic-capable single SWR: the data was committed and the slot now
     transitions to "session ready for polls". nonce_base = the XOR of
     the two arm-time randoms, computed here because Pass 2 brought
     the client_random. Reply remains empty (byte-identical to plain
     single-shot SWR ACK). */
  bool is_cyclic = FBSEC_AEAD_KEYID_IS_CYCLIC(wire_key_id);
  if (is_cyclic) {
    slot->cyclic = true;
    slot->key_id = wire_key_id;
    fbsec_aead_xor_nonce(client_random, slot->server_random, slot->nonce_base);
    slot->counter    = 0u;
    slot->armed_at   = fbsec_sod_port_get_time_ms();
    /* slot->in_use stays true. */
    return FBSEC_SOD_OK;
  }
#endif

  slot->in_use = false;     /* single-shot consume */
  return FBSEC_SOD_OK;
}
#endif /* FBSEC_FEATURE_WRITE */

#if FBSEC_FEATURE_CYCLIC
/* ---- Cyclic-mode poll handlers ----------------------------------- */

/**
 * @brief Common counter check for the inbound side of a cyclic-mode
 *        frame. Returns the full 32-bit counter to use for AEAD on
 *        success; on failure populates @p out_abort.
 *
 * Strict equality on the wire low byte (matches the reliable-carrier
 * default; see fieldbus_sim_secure_tunnel_spec.txt §11.1). A mismatch
 * does NOT advance the counter and does NOT tear down the slot, so a
 * single spoofed frame cannot DoS the session. Reaching the per-key
 * use limit (FBSEC_AEAD_KEY_USE_LIMIT, fbsec_config.h) is fatal: the
 * slot is torn down and re-arming is required.
 */
static bool poll_check_counter(
  uint32_t  current_counter,
  uint8_t   wire_counter_low,
  uint32_t *expected_full_out,
  fbsec_abort_t *out_abort)
{
  if (current_counter >= FBSEC_AEAD_KEY_USE_LIMIT) {
    *out_abort = FBSEC_ABORT_KEY_BUDGET;
    return false;
  }
  uint32_t expected = current_counter + 1u;
  if (((uint8_t)(expected & 0xFFu)) != wire_counter_low) {
    *out_abort = FBSEC_ABORT_POLL_COUNTER;
    return false;
  }
  *expected_full_out = expected;
  return true;
}

#if FBSEC_FEATURE_READ
static fbsec_sod_status_t handle_read_poll(
  int                      slot_idx,
  const fbsec_sod_entry_t   *entry,
  uint16_t                 client_dev,
  const uint8_t           *req,           /* 1 byte: counter_low */
  uint16_t                 req_len,
  uint8_t                 *reply,
  uint16_t                 reply_max,
  uint16_t                *reply_len,
  fbsec_abort_t           *out_abort)
{
  read_state_t *slot = &g_read_slot[slot_idx];
  if (!slot->in_use || !slot->cyclic) {
    *out_abort = FBSEC_ABORT_NO_SESSION;
    return FBSEC_SOD_ABORT;
  }
  if (slot->client_dev != client_dev) {
    *out_abort = FBSEC_ABORT_NO_SESSION;
    return FBSEC_SOD_ABORT;
  }
  if (!session_is_fresh(slot->armed_at)) {
    slot->in_use = false;
    *out_abort = FBSEC_ABORT_NO_SESSION;
    return FBSEC_SOD_ABORT;
  }
  if (req_len != 1u) {
    *out_abort = length_abort(req_len, 1u);
    return FBSEC_SOD_ABORT;
  }
  uint16_t needed = (uint16_t)(1u + entry->data_len + FBSEC_AEAD_TAG_SIZE);
  if (reply_max < needed) {
    *out_abort = FBSEC_ABORT_INTERNAL;
    return FBSEC_SOD_ABORT;
  }

  uint32_t expected_counter = 0u;
  if (!poll_check_counter(slot->counter, req[0],
                          &expected_counter, out_abort)) {
    if (*out_abort == FBSEC_ABORT_KEY_BUDGET) {
      slot->in_use = false;     /* key-use limit reached: tear-down */
    }
    return FBSEC_SOD_ABORT;
  }

  if (!fbsec_sod_port_access_allowed(FBSEC_SOD_OP_READ, entry->data_id)) {
    *out_abort = FBSEC_ABORT_DEVICE_STATE;
    return FBSEC_SOD_ABORT;
  }
  if (!fbsec_sod_port_role_allowed(FBSEC_SOD_OP_READ,
                                   FBSEC_AEAD_KEYID_BASE(slot->key_id),
                                   entry->data_id)) {
    *out_abort = FBSEC_ABORT_ROLE_DENIED;
    return FBSEC_SOD_ABORT;
  }

  uint8_t  plaintext[FBSEC_AEAD_MAX_PROTECTED];
  uint16_t plain_len = entry->data_len;
  fbsec_abort_t hook_rc = fbsec_sod_port_read_before(entry->data_id,
                                              plaintext, &plain_len);
  if (hook_rc != FBSEC_ABORT_NONE) { *out_abort = hook_rc; return FBSEC_SOD_ABORT; }
  if (plain_len != entry->data_len) {
    *out_abort = FBSEC_ABORT_INTERNAL;
    return FBSEC_SOD_ABORT;
  }

  const uint8_t *key = get_key(FBSEC_AEAD_KEYID_BASE(slot->key_id));
  if (key == NULL) {
    *out_abort = FBSEC_ABORT_KEY_ID;
    return FBSEC_SOD_ABORT;
  }

  uint8_t nonce[FBSEC_AEAD_NONCE_SIZE];
  build_session_nonce(slot->nonce_base, expected_counter, nonce);

  uint8_t *out_counter = &reply[0];
  uint8_t *out_cipher  = &reply[1];
  uint8_t *out_tag     = &reply[1u + plain_len];
  if (!fbsec_aead_seal(key, nonce,
                     FBSEC_AEAD_DIR_READ_POLL_RESPONSE, slot->key_id,
                     fbsec_sod_port_get_device_id(), slot->client_dev,
                     entry->data_id,
                     NULL, NULL,            /* no challenge randoms on polls */
                     plaintext, plain_len,
                     out_cipher, out_tag)) {
    *out_abort = FBSEC_ABORT_INTERNAL;
    return FBSEC_SOD_ABORT;
  }
  *out_counter = (uint8_t)(expected_counter & 0xFFu);
  *reply_len   = needed;

  slot->counter  = expected_counter;
  slot->armed_at = fbsec_sod_port_get_time_ms();
  return FBSEC_SOD_OK;
}
#endif /* FBSEC_FEATURE_READ */

#if FBSEC_FEATURE_WRITE
static fbsec_sod_status_t handle_write_poll(
  int                      slot_idx,
  const fbsec_sod_entry_t   *entry,
  uint16_t                 client_dev,
  const uint8_t           *req,
  uint16_t                 req_len,
  fbsec_abort_t           *out_abort)
{
  write_state_t *slot = &g_write_slot[slot_idx];
  if (!slot->in_use || !slot->cyclic) {
    *out_abort = FBSEC_ABORT_NO_SESSION;
    return FBSEC_SOD_ABORT;
  }
  if (slot->client_dev != client_dev) {
    *out_abort = FBSEC_ABORT_NO_SESSION;
    return FBSEC_SOD_ABORT;
  }
  if (!session_is_fresh(slot->armed_at)) {
    slot->in_use = false;
    *out_abort = FBSEC_ABORT_NO_SESSION;
    return FBSEC_SOD_ABORT;
  }
  uint16_t expected_len = (uint16_t)(1u + entry->data_len + FBSEC_AEAD_TAG_SIZE);
  if (req_len != expected_len) {
    *out_abort = length_abort(req_len, expected_len);
    return FBSEC_SOD_ABORT;
  }

  uint32_t expected_counter = 0u;
  if (!poll_check_counter(slot->counter, req[0],
                          &expected_counter, out_abort)) {
    if (*out_abort == FBSEC_ABORT_KEY_BUDGET) {
      slot->in_use = false;     /* key-use limit reached: tear-down */
    }
    return FBSEC_SOD_ABORT;
  }

  if (!fbsec_sod_port_role_allowed(FBSEC_SOD_OP_WRITE,
                                   FBSEC_AEAD_KEYID_BASE(slot->key_id),
                                   entry->data_id)) {
    *out_abort = FBSEC_ABORT_ROLE_DENIED;
    return FBSEC_SOD_ABORT;
  }

  const uint8_t *ciphertext = &req[1];
  const uint8_t *tag        = &req[1u + entry->data_len];
  const uint8_t *key        = get_key(FBSEC_AEAD_KEYID_BASE(slot->key_id));
  if (key == NULL) {
    *out_abort = FBSEC_ABORT_KEY_ID;
    return FBSEC_SOD_ABORT;
  }

  uint8_t nonce[FBSEC_AEAD_NONCE_SIZE];
  build_session_nonce(slot->nonce_base, expected_counter, nonce);

  uint8_t plaintext[FBSEC_AEAD_MAX_PROTECTED];
  if (!fbsec_aead_open(key, nonce,
                     FBSEC_AEAD_DIR_WRITE_POLL_REQUEST, slot->key_id,
                     fbsec_sod_port_get_device_id(), slot->client_dev,
                     entry->data_id,
                     NULL, NULL,            /* no challenge randoms on polls */
                     ciphertext, entry->data_len,
                     tag,
                     plaintext)) {
    /* Bad tag: do NOT advance counter, do NOT tear down. The legitimate
       client's next poll with the (still-) expected counter must succeed. */
    *out_abort = FBSEC_ABORT_TAG_VERIFY;
    return FBSEC_SOD_ABORT;
  }

  fbsec_abort_t hook_rc = fbsec_sod_port_write_after(entry->data_id,
                                              plaintext, entry->data_len);
  if (hook_rc != FBSEC_ABORT_NONE) { *out_abort = hook_rc; return FBSEC_SOD_ABORT; }

  slot->counter  = expected_counter;
  slot->armed_at = fbsec_sod_port_get_time_ms();
  return FBSEC_SOD_OK;
}
#endif /* FBSEC_FEATURE_WRITE */
#endif /* FBSEC_FEATURE_CYCLIC */

/* ---- Public dispatch -------------------------------------------------- */

fbsec_sod_status_t fbsec_sod_dispatch(
  uint16_t       client_dev,
  uint32_t       data_id,
  const uint8_t *req,
  uint16_t       req_len,
  uint8_t       *reply,
  uint16_t       reply_max,
  uint16_t      *reply_len,
  fbsec_abort_t *out_abort)
{
  *reply_len = 0u;
  *out_abort = FBSEC_ABORT_NONE;

  int idx = find_index(data_id);
  if (idx < 0) {
    return FBSEC_SOD_NOT_HANDLED;
  }
  const fbsec_sod_entry_t *entry = &g_registry[idx];

#if FBSEC_FEATURE_READ
  bool has_ro = (entry->access_flags & FBSEC_SOD_ACCESS_SECURE_RO) != 0u;
#else
  bool has_ro = false;
#endif
#if FBSEC_FEATURE_WRITE
  bool has_wo = (entry->access_flags & FBSEC_SOD_ACCESS_SECURE_WO) != 0u;
#else
  bool has_wo = false;
#endif

  /* Cyclic-mode poll matchers run BEFORE the length-based dispatch.
     The 1-byte READ_POLL_REQUEST collides with the 1-byte cyclic-arm
     WRITE_CHALLENGE; slot state breaks that tie. The poll-write
     length is now distinct from single-shot WRITE_REQUEST (which
     carries an extra R bytes of client_random), so the write side is
     disambiguated by length alone, but checking slot.cyclic anyway
     keeps the two flows independent. */
#if FBSEC_FEATURE_CYCLIC && FBSEC_FEATURE_READ
  if (has_ro && req_len == 1u) {
    read_state_t *rslot = &g_read_slot[idx];
    if (rslot->in_use && rslot->cyclic) {
      return handle_read_poll(idx, entry, client_dev,
                              req, req_len,
                              reply, reply_max, reply_len, out_abort);
    }
  }
#endif
#if FBSEC_FEATURE_CYCLIC && FBSEC_FEATURE_WRITE
  if (has_wo) {
    uint16_t poll_len = (uint16_t)(1u + entry->data_len + FBSEC_AEAD_TAG_SIZE);
    if (req_len == poll_len) {
      write_state_t *wslot = &g_write_slot[idx];
      if (wslot->in_use && wslot->cyclic) {
        return handle_write_poll(idx, entry, client_dev,
                                 req, req_len, out_abort);
      }
    }
  }
#endif

  /* SECURE_RO branch (single-shot legacy paths). */
#if FBSEC_FEATURE_READ
  if (has_ro) {
    if (req_len == READ_CHALLENGE_LEN) {
      /* Pass 1: arm the read response. Single-shot returns DEFER with
         empty reply; cyclic returns OK with the 2-byte session_id. */
      return arm_read_response(idx, entry, client_dev, req,
                               reply, reply_max, reply_len, out_abort);
    }
    if (req_len == 0u) {
      /* Pass 2: deliver the prepared single-shot response. For
         cyclic-capable single (bit-6 set in Pass-1 keyid) the slot
         survives this delivery and transitions to "session ready for
         polls"; for plain single-shot the slot is torn down. */
      read_state_t *slot = &g_read_slot[idx];
      if (slot->in_use && slot->prepared_len > 0u && slot_is_fresh(slot->armed_at)) {
        if (slot->prepared_len > reply_max) {
          slot->in_use = false;
          *out_abort = FBSEC_ABORT_INTERNAL;
          return FBSEC_SOD_ABORT;
        }
        memcpy(reply, slot->prepared, slot->prepared_len);
        *reply_len = slot->prepared_len;
        if (slot->cyclic) {
          /* Keep the session live for poll_read; clear the prepared
             bytes since they've been consumed. counter / session_id /
             session_random / key_id stay populated. */
          slot->prepared_len = 0u;
          slot->armed_at     = fbsec_sod_port_get_time_ms();
        } else {
          slot->in_use = false;     /* single-shot consume */
        }
        return FBSEC_SOD_OK;
      }
      /* No armed single-shot read. If the entry is also SECURE_WO this
         empty-payload request begins a write challenge; otherwise it is a
         protocol violation. */
      if (!has_wo) {
        *out_abort = FBSEC_ABORT_NO_SESSION;
        return FBSEC_SOD_ABORT;
      }
      /* fall through to SECURE_WO empty-payload path */
    } else if (req_len == 1u && has_wo) {
      /* fall through to SECURE_WO Pass-1 with explicit keyid byte */
    } else if (!has_wo) {
      *out_abort = FBSEC_ABORT_TYPE_MISMATCH;
      return FBSEC_SOD_ABORT;
    }
  }
#endif /* FBSEC_FEATURE_READ */

  /* SECURE_WO branch (or fall-through from SECURE_RW).
     Pass-1 shapes:
       - 0 bytes: single-shot arm (no keyid yet; server replies with
                  R bytes of server_random).
       - 1 byte:  cyclic arm (the byte is the wire keyid with bit 6
                  set; reply = server_random[R] || sid[2]).
     Pass-2 shape (single-shot): 1 + R + data_len + tag_len (keyid +
     client_random + cipher + tag); leading byte is the keyid that
     drives key+AAD selection on the server. Distinct from the
     cyclic-poll length 1 + data_len + tag_len, so no slot-state
     disambiguation needed here; the cyclic-poll matcher above only
     triggers on its own length. */
#if FBSEC_FEATURE_WRITE
  if (has_wo) {
    if (req_len == 0u) {
      return arm_write_challenge(idx, entry, client_dev,
                                 0u, false,
                                 reply, reply_max, reply_len, out_abort);
    }
    if (req_len == 1u) {
      return arm_write_challenge(idx, entry, client_dev,
                                 req[0], true,
                                 reply, reply_max, reply_len, out_abort);
    }
    return verify_and_apply_write(idx, entry, req, req_len,
                                  reply, reply_max, reply_len, out_abort);
  }
#endif /* FBSEC_FEATURE_WRITE */

  /* Suppress unused-variable warnings on builds that strip a direction. */
  (void)has_ro;
  (void)has_wo;

  *out_abort = FBSEC_ABORT_NOT_BUILT;
  return FBSEC_SOD_ABORT;
}

/* EOF */
