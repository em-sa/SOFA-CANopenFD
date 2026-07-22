/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    server_common_trace.c
 * @brief   SOFA server_common, per-request trace formatter, impl.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.1 of 20-JUL-2026
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#include "server_common_trace.h"
#include "server_common_hooks.h"
#include "server_common_platform.h"

#include <stdio.h>
#include <string.h>

#include "fbsec_aead.h"
#include "fbsec_secure_od.h"

/* ---- ANSI SGR escapes ------------------------------------------------- */
/* Row-leading direction tint (blue = request received, magenta = response
   sent); per-segment hues take over after ANSI_RESET. Hub trace agrees on
   row direction. Red is reserved for abort tail. */
#define ANSI_RESET      "\x1b[0m"
#define ANSI_RED        "\x1b[31m"          /* abort                         */
#define ANSI_GREEN      "\x1b[32m"          /* auth tag                      */
#define ANSI_BLUE       "\x1b[94m"          /* RX side: request received     */
#define ANSI_MAGENTA    "\x1b[35m"          /* TX side: response sent        */
#define ANSI_WHITE      "\x1b[97m"          /* plaintext                     */
#define ANSI_LIGHT_GREY "\x1b[90m"          /* header / Key / counter / sid  */
#define ANSI_DARK_GREY  "\x1b[38;5;240m"    /* ciphertext                    */
#define ANSI_ORANGE     "\x1b[38;5;208m"    /* random / nonce                */

/* ---- File-static state ------------------------------------------------ */

static bool g_quiet     = false;
static bool g_use_color = false;

#define COL_REQ   (g_use_color ? ANSI_BLUE       : "")
#define COL_RSP   (g_use_color ? ANSI_MAGENTA    : "")
#define COL_END   (g_use_color ? ANSI_RESET      : "")
#define COL_HDR   (g_use_color ? ANSI_LIGHT_GREY : "")
#define COL_RAND  (g_use_color ? ANSI_ORANGE     : "")
#define COL_TAG   (g_use_color ? ANSI_GREEN      : "")
#define COL_CIPH  (g_use_color ? ANSI_DARK_GREY  : "")
#define COL_PLAIN (g_use_color ? ANSI_WHITE      : "")
#define COL_ABORT (g_use_color ? ANSI_RED        : "")

/* ---- Setters --------------------------------------------------------- */

void fbsec_server_trace_set_quiet(bool quiet)         { g_quiet     = quiet;     }
void fbsec_server_trace_set_use_color(bool use_color) { g_use_color = use_color; }

void fbsec_server_trace_print_legend(void) {
  if (!g_use_color) {
    return;
  }
  printf("Coloring: %sRequest%s, %sResponse%s, %sMeta%s, %sRandom%s, %sTag%s, %sData%s\n\n",
         COL_REQ,   COL_END,
         COL_RSP,   COL_END,
         COL_HDR,   COL_END,
         COL_RAND,  COL_END,
         COL_TAG,   COL_END,
         COL_PLAIN, COL_END);
}

/* ---- Segment helpers ------------------------------------------------- */

/**
 * @brief Print a coloured run of hex bytes, space-separated.
 *
 * @param col  ANSI colour prefix ("" for no colour).
 * @param p    byte buffer to render; at least @p n bytes must be readable.
 * @param n    number of bytes to print; no output when zero.
 */
static void print_hex_seg(const char *col, const uint8_t *p, uint16_t n) {
  if (n == 0u) {
    return;
  }
  printf(" %s", col);
  for (uint16_t i = 0u; i < n; ++i) {
    printf("%s%02X", (i == 0u) ? "" : " ", (unsigned)p[i]);
  }
  if (col[0] != '\0') {
    printf("%s", COL_END);
  }
}

/* ---- Inbound request slicer ----------------------------------------- */

/**
 * @brief Slice and colour an inbound request body by its wire layout.
 *
 * @param entry  matching secure-OD entry, or NULL to dump raw hex.
 * @param p      request payload bytes; at least @p n bytes readable.
 * @param n      payload length in bytes.
 */
static void log_rx_segments(const fbsec_sod_entry_t *entry,
                            const uint8_t *p, uint16_t n) {
  const uint16_t TAGN = (uint16_t)FBSEC_AEAD_TAG_SIZE;
  const uint16_t RAND = (uint16_t)FBSEC_AEAD_RAND_SIZE;
  if (entry == NULL) {
    print_hex_seg("", p, n);
    return;
  }
  bool has_ro = (entry->access_flags & FBSEC_SOD_ACCESS_SECURE_RO) != 0u;
  bool has_wo = (entry->access_flags & FBSEC_SOD_ACCESS_SECURE_WO) != 0u;
  if (has_ro && n == (uint16_t)(1u + RAND)) {
    /* READ_CHALLENGE: keyid[1] || client_random[R] (keyid is the first
       byte of every client request that carries it). */
    print_hex_seg(COL_HDR,  p,     1u);
    print_hex_seg(COL_RAND, &p[1], RAND);
    return;
  }
  if (has_ro && n == 1u) {
    /* READ_POLL_REQUEST: counter_low[1] */
    print_hex_seg(COL_HDR, p, 1u);
    return;
  }
  if (has_wo && n == 1u) {
    /* WRITE cyclic-arm: keyid[1]. Single-shot arm is an empty body
       and lands in the empty-payload branch above this function. */
    print_hex_seg(COL_HDR, p, 1u);
    return;
  }
  if (has_wo) {
    /* WRITE Pass-2 single-shot:
         keyid[1] || client_random[R] || cipher[data_len] || tag */
    uint16_t framed = (uint16_t)(1u + RAND + entry->data_len + TAGN);
    if (n == framed) {
      uint16_t cipher_off = (uint16_t)(1u + RAND);
      print_hex_seg(COL_HDR,   p,                          1u);
      print_hex_seg(COL_RAND,  &p[1],                      RAND);
      print_hex_seg(COL_PLAIN, &p[cipher_off],             entry->data_len);
      print_hex_seg(COL_TAG,   &p[cipher_off + entry->data_len], TAGN);
      return;
    }
    /* WRITE_POLL_REQUEST: counter_low[1] || cipher[data_len] || tag */
    uint16_t poll = (uint16_t)(1u + entry->data_len + TAGN);
    if (n == poll) {
      print_hex_seg(COL_HDR,   p,                            1u);
      print_hex_seg(COL_PLAIN, &p[1],                        entry->data_len);
      print_hex_seg(COL_TAG,   &p[1u + entry->data_len],     TAGN);
      return;
    }
  }
  print_hex_seg("", p, n);
}

/* ---- Outbound response slicer --------------------------------------- */

/**
 * @brief Slice and colour an outbound response body by its wire layout.
 *
 * @param entry  matching secure-OD entry, or NULL to dump raw hex.
 * @param p      response payload bytes; at least @p n bytes readable.
 * @param n      payload length in bytes.
 */
static void log_tx_segments(const fbsec_sod_entry_t *entry,
                            const uint8_t *p, uint16_t n) {
  const uint16_t TAGN = (uint16_t)FBSEC_AEAD_TAG_SIZE;
  const uint16_t RAND = (uint16_t)FBSEC_AEAD_RAND_SIZE;
  if (entry == NULL) {
    print_hex_seg("", p, n);
    return;
  }
  bool has_ro = (entry->access_flags & FBSEC_SOD_ACCESS_SECURE_RO) != 0u;
  bool has_wo = (entry->access_flags & FBSEC_SOD_ACCESS_SECURE_WO) != 0u;
  if (has_ro) {
    /* RDsec Pass-2 reply (single-shot):
         server_random[R] || cipher[data_len] || tag
       (no echoed keyid; the client already knows it.) */
    uint16_t single_shot = (uint16_t)(RAND + entry->data_len + TAGN);
    if (n == single_shot) {
      uint16_t cipher_off = RAND;
      print_hex_seg(COL_RAND,  p,                              RAND);
      print_hex_seg(COL_PLAIN, &p[cipher_off],                 entry->data_len);
      print_hex_seg(COL_TAG,   &p[cipher_off + entry->data_len], TAGN);
      return;
    }
    /* READ_POLL_RESPONSE: counter[1] || cipher[data_len] || tag */
    uint16_t poll_rsp = (uint16_t)(1u + entry->data_len + TAGN);
    if (n == poll_rsp) {
      print_hex_seg(COL_HDR,    p,                              1u);
      print_hex_seg(COL_PLAIN,  &p[1],                          entry->data_len);
      print_hex_seg(COL_TAG,    &p[1u + entry->data_len],       TAGN);
      return;
    }
  }
  if (has_wo) {
    if (n == RAND) {
      /* WRsec Pass-1 reply (single-shot or cyclic arming): server_
         random[R] (no tag; server has no key context bound to this
         leg until the client's Pass 2 carries the keyid). Cyclic
         arming reply is wire-identical. */
      print_hex_seg(COL_RAND, p, RAND);
      return;
    }
  }
  print_hex_seg("", p, n);
}

/* ---- Public entry point --------------------------------------------- */

void fbsec_server_trace_request(uint16_t       src_dev,
                                uint16_t       dst_dev,
                                uint32_t       data_id,
                                const char    *verb,
                                fbsec_abort_t  status,
                                const uint8_t *req_payload,
                                uint16_t       req_len,
                                const uint8_t *out_data,
                                size_t         out_len) {
  if (g_quiet) {
    return;
  }

  char ts[16];
  fbsec_server_format_timestamp(ts, sizeof ts);

  const fbsec_sod_entry_t *entry = fbsec_sod_find_entry(data_id);

  /* Plaintext annotation: only Pass-2 (data-bearing) frames carry
     application plaintext. SRD2 ships it on the TX response; SWR2
     receives it on the RX request. */
  const uint8_t *plain     = NULL;
  uint16_t       plain_len = 0u;
  bool           plain_on_rx = false;
  bool           plain_on_tx = false;
  if (strcmp(verb, "SRD2") == 0) {
    if      (data_id == FBSEC_SERVER_ENTRY_RD_DATA_ID)  {
      plain = fbsec_server_hooks_value();
      plain_len = FBSEC_SERVER_ENTRY_VALUE_LEN;
    } else if (data_id == FBSEC_SERVER_ENTRY_SRD_DATA_ID) {
      plain = fbsec_server_hooks_secure_ro();
      plain_len = FBSEC_SERVER_ENTRY_SECURE_LEN;
    }
    plain_on_tx = (plain != NULL && status == FBSEC_ABORT_NONE);
  } else if (strcmp(verb, "SWR2") == 0) {
    if      (data_id == FBSEC_SERVER_ENTRY_WR_DATA_ID)  {
      plain = fbsec_server_hooks_value();
      plain_len = FBSEC_SERVER_ENTRY_VALUE_LEN;
    } else if (data_id == FBSEC_SERVER_ENTRY_SWR_DATA_ID) {
      plain = fbsec_server_hooks_secure_wo();
      plain_len = FBSEC_SERVER_ENTRY_SECURE_LEN;
    }
    plain_on_rx = (plain != NULL && status == FBSEC_ABORT_NONE);
  }

  /* Compact 24-bit data_id render: index||subindex (the trailing reserved
     low byte is always zero; see doc/fieldbus_sim_canopen_fd_spec.txt §2). */
  unsigned id24 = (unsigned)((data_id >> 8) & 0xFFFFFFu);

  /* ---- RX (incoming request) ---- */
  printf("%s[%s] RX %-4s %02X->%02X [%06X]%s",
         COL_REQ, ts, verb,
         (unsigned)(src_dev & 0xFFu), (unsigned)(dst_dev & 0xFFu),
         id24, COL_END);
  if (req_len > 0u) {
    log_rx_segments(entry, req_payload, req_len);
  } else {
    /* Empty client request body; transport-level read fetch. */
    if      (verb[0] == 'S' && verb[1] == 'R' && verb[2] == 'D') {
      printf(" %sSRD REQ%s", COL_HDR, COL_END);
    } else if (verb[0] == 'S' && verb[1] == 'W' && verb[2] == 'R') {
      printf(" %sSWR REQ%s", COL_HDR, COL_END);
    }
  }
  if (plain_on_rx) {
    printf(" %sPlain:%s", COL_HDR, COL_END);
    print_hex_seg(COL_PLAIN, plain, plain_len);
  }
  printf("\n");

  /* ---- TX (outgoing response) ---- */
  printf("%s[%s] TX %-4s %02X->%02X [%06X]%s",
         COL_RSP, ts, verb,
         (unsigned)(dst_dev & 0xFFu), (unsigned)(src_dev & 0xFFu),
         id24, COL_END);
  if (status != FBSEC_ABORT_NONE) {
    printf(" %sabort 0x%02X%s", COL_ABORT, (unsigned)status, COL_END);
  } else if (out_data != NULL && out_len > 0) {
    log_tx_segments(entry, out_data, (uint16_t)out_len);
  } else {
    /* Empty positive response = ACK envelope. */
    printf(" %sACK%s", COL_HDR, COL_END);
  }
  if (plain_on_tx) {
    printf(" %sPlain:%s", COL_HDR, COL_END);
    print_hex_seg(COL_PLAIN, plain, plain_len);
  }
  printf("\n");
}

/* EOF */
