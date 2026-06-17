/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    client_common_trace.c
 * @brief   SOFA client_common, secure-frame trace formatter, impl.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 07-MAY-2026
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#include "client_common_trace.h"
#include "client_common_keys.h"
#include "client_common_platform.h"

#include <stdio.h>
#include <string.h>

#include "fbsec_aead.h"

/* ---- ANSI SGR escapes ------------------------------------------------- */
#define ANSI_RESET      "\x1b[0m"
#define ANSI_RED        "\x1b[31m"
#define ANSI_GREEN      "\x1b[32m"
#define ANSI_BLUE       "\x1b[94m"
#define ANSI_MAGENTA    "\x1b[35m"
#define ANSI_WHITE      "\x1b[97m"
#define ANSI_LIGHT_GREY "\x1b[90m"
#define ANSI_DARK_GREY  "\x1b[38;5;240m"
#define ANSI_ORANGE     "\x1b[38;5;208m"

/* ---- File-static state ------------------------------------------------ */

static bool        g_quiet         = false;
static bool        g_use_color     = false;
static bool        g_show_ts       = false;
static const char *g_current_verb  = "";
static uint8_t     g_secure_round  = 0u;
static bool        g_secure_rx_open = false;

#define COL_REQ   (g_use_color ? ANSI_BLUE       : "")
#define COL_RSP   (g_use_color ? ANSI_MAGENTA    : "")
#define COL_END   (g_use_color ? ANSI_RESET      : "")
#define COL_HDR   (g_use_color ? ANSI_LIGHT_GREY : "")
#define COL_RAND  (g_use_color ? ANSI_ORANGE     : "")
#define COL_TAG   (g_use_color ? ANSI_GREEN      : "")
#define COL_CIPH  (g_use_color ? ANSI_DARK_GREY  : "")
#define COL_PLAIN (g_use_color ? ANSI_WHITE      : "")
#define COL_ABORT (g_use_color ? ANSI_RED        : "")

/* ---- Setters / getters ---------------------------------------------- */

void fbsec_client_trace_set_quiet(bool q)         { g_quiet     = q; }
void fbsec_client_trace_set_use_color(bool c)     { g_use_color = c; }
void fbsec_client_trace_set_show_ts(bool t)       { g_show_ts   = t; }
bool fbsec_client_trace_get_quiet(void)           { return g_quiet; }
bool fbsec_client_trace_get_use_color(void)       { return g_use_color; }

void fbsec_client_trace_set_verb(const char *tag) { g_current_verb = (tag != NULL) ? tag : ""; }
void fbsec_client_trace_reset_round(void)         { g_secure_round = 0u; }
void fbsec_client_trace_inc_round(void)           { ++g_secure_round; }

const char *fbsec_client_trace_col_req(void)   { return COL_REQ;   }
const char *fbsec_client_trace_col_rsp(void)   { return COL_RSP;   }
const char *fbsec_client_trace_col_end(void)   { return COL_END;   }
const char *fbsec_client_trace_col_hdr(void)   { return COL_HDR;   }
const char *fbsec_client_trace_col_rand(void)  { return COL_RAND;  }
const char *fbsec_client_trace_col_tag(void)   { return COL_TAG;   }
const char *fbsec_client_trace_col_plain(void) { return COL_PLAIN; }
const char *fbsec_client_trace_col_abort(void) { return COL_ABORT; }

void fbsec_client_trace_print_legend(void) {
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

/* ---- Segment printers ----------------------------------------------- */

void fbsec_client_trace_print_hex_seg(const char *col, const uint8_t *p, uint16_t n) {
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

/* ---- Per-frame segment slicing (verb-aware) ------------------------- */

/**
 * @brief   Slice and colour-print one secure frame's payload by verb shape.
 * @param   is_tx   true for a transmitted frame, false for a received one.
 * @param   data_id Object data id (unused; reserved for future shaping).
 * @param   p       Pointer to the payload bytes.
 * @param   n       Payload length in bytes.
 */
static void log_secure_segments(bool is_tx, uint32_t data_id,
                                const uint8_t *p, uint16_t n) {
  (void)data_id;
  const char *v = g_current_verb;
  if (v[0] == '\0') {
    fbsec_client_trace_print_hex_seg("", p, n);
    return;
  }
  const uint16_t TAGN = (uint16_t)FBSEC_AEAD_TAG_SIZE;
  const uint16_t RAND = (uint16_t)FBSEC_AEAD_RAND_SIZE;
  const char *data_col = COL_PLAIN;

  /* srd / armrd TX: keyid[1] || client_random[R]. */
  if ((strcmp(v, "srd") == 0 || strcmp(v, "armrd") == 0)
      && is_tx && n == (uint16_t)(1u + RAND)) {
    fbsec_client_trace_print_hex_seg(COL_HDR,  p,        1u);
    fbsec_client_trace_print_hex_seg(COL_RAND, &p[1],    RAND);
    return;
  }
  /* srd / armrd RX: server_random[R] || ciphertext[N] || tag[T]
     (envelope status already stripped; cyclic-arming RX is wire-
     identical to plain single-shot). */
  if ((strcmp(v, "srd") == 0 || strcmp(v, "armrd") == 0)
      && !is_tx && n >= RAND + TAGN) {
    uint16_t cipher_off = RAND;
    uint16_t cipher     = (uint16_t)(n - cipher_off - TAGN);
    fbsec_client_trace_print_hex_seg(COL_RAND, p,                       RAND);
    fbsec_client_trace_print_hex_seg(data_col, &p[cipher_off],          cipher);
    fbsec_client_trace_print_hex_seg(COL_TAG,  &p[cipher_off + cipher], TAGN);
    return;
  }
  /* pollrd TX: counter_low[1] */
  if (strcmp(v, "pollrd") == 0 && is_tx && n == 1u) {
    fbsec_client_trace_print_hex_seg(COL_HDR, p, 1u);
    return;
  }
  /* pollrd RX: counter_low[1] || ciphertext[N] || tag[T] */
  if (strcmp(v, "pollrd") == 0 && !is_tx && n >= 1u + TAGN) {
    uint16_t cipher = (uint16_t)(n - 1u - TAGN);
    fbsec_client_trace_print_hex_seg(COL_HDR,  p,                1u);
    fbsec_client_trace_print_hex_seg(data_col, &p[1],            cipher);
    fbsec_client_trace_print_hex_seg(COL_TAG,  &p[1u + cipher],  TAGN);
    return;
  }
  /* swr TX Pass-2: keyid[1] || client_random[R] || ciphertext[N] || tag[T] */
  if (strcmp(v, "swr") == 0 && is_tx && n >= 1u + RAND + TAGN) {
    uint16_t cipher_off = (uint16_t)(1u + RAND);
    uint16_t cipher     = (uint16_t)(n - cipher_off - TAGN);
    fbsec_client_trace_print_hex_seg(COL_HDR,  p,                       1u);
    fbsec_client_trace_print_hex_seg(COL_RAND, &p[1],                   RAND);
    fbsec_client_trace_print_hex_seg(data_col, &p[cipher_off],          cipher);
    fbsec_client_trace_print_hex_seg(COL_TAG,  &p[cipher_off + cipher], TAGN);
    return;
  }
  /* swr RX Pass-1: server_random[R] (no tag; server has no key
     context at this leg). */
  if (strcmp(v, "swr") == 0 && !is_tx && n == RAND) {
    fbsec_client_trace_print_hex_seg(COL_RAND, p, RAND);
    return;
  }
  /* armwr TX: keyid[1] (matches swr Pass-1 with bit-6 set) */
  if (strcmp(v, "armwr") == 0 && is_tx && n == 1u) {
    fbsec_client_trace_print_hex_seg(COL_HDR, p, 1u);
    return;
  }
  /* armwr RX: server_random[R] - wire-identical to plain single-shot
     SWR Pass-1 reply. */
  if (strcmp(v, "armwr") == 0 && !is_tx && n == RAND) {
    fbsec_client_trace_print_hex_seg(COL_RAND, p, RAND);
    return;
  }
  /* pollwr TX: counter_low[1] || ciphertext[N] || tag[T] */
  if (strcmp(v, "pollwr") == 0 && is_tx && n >= 1u + TAGN) {
    uint16_t cipher = (uint16_t)(n - 1u - TAGN);
    fbsec_client_trace_print_hex_seg(COL_HDR,  p,                1u);
    fbsec_client_trace_print_hex_seg(data_col, &p[1],            cipher);
    fbsec_client_trace_print_hex_seg(COL_TAG,  &p[1u + cipher],  TAGN);
    return;
  }

  /* Default: anything we did not classify falls through to an
     uncoloured dump. */
  fbsec_client_trace_print_hex_seg("", p, n);
}

/* ---- Verb-tag -> SRD1/SRD2/SWR1/SWR2 label ------------------------- */

/**
 * @brief   Map the current verb tag to its SRD1/SRD2/SWR1/SWR2 row label.
 * @return  Static label string for the active verb / round.
 */
static const char *secure_verb_label(void) {
  const char *v = g_current_verb;
  if (v[0] == '\0') {
    return "--";
  }
  if (strcmp(v, "armrd")  == 0) {
    return "SRD1";
  }
  if (strcmp(v, "pollrd") == 0) {
    return "SRD2";
  }
  if (strcmp(v, "armwr")  == 0) {
    return "SWR1";
  }
  if (strcmp(v, "pollwr") == 0) {
    return "SWR2";
  }
  if (strcmp(v, "srd")    == 0) {
    return (g_secure_round >= 2u) ? "SRD2" : "SRD1";
  }
  if (strcmp(v, "swr")    == 0) {
    return (g_secure_round >= 2u) ? "SWR2" : "SWR1";
  }
  return v;
}

/* ---- Public entry points ------------------------------------------- */

void fbsec_client_trace_secure_frame(bool          is_tx,
                                     uint16_t      src,
                                     uint16_t      dst,
                                     uint32_t      data_id,
                                     const uint8_t *payload,
                                     uint32_t      plen,
                                     uint32_t      status) {
  if (g_quiet) {
    return;
  }

  /* Defensive: flush any prior deferred RX line before starting new one. */
  if (g_secure_rx_open) {
    printf("\n");
    g_secure_rx_open = false;
  }

  char ts[16];
  fbsec_client_format_timestamp(ts, sizeof ts);
  (void)g_show_ts;   /* trace ts is mandatory in this format; show_ts gates
                        the action_block emitter elsewhere */

  const char *label = secure_verb_label();
  /* Compact 24-bit data_id render: index||subindex (the trailing reserved
     low byte is always zero; see doc/fieldbus_sim_canopen_fd_spec.txt §2). */
  unsigned id24 = (unsigned)((data_id >> 8) & 0xFFFFFFu);
  printf("%s[%s] %s %-4s %02X->%02X [%06X]%s",
         is_tx ? COL_REQ : COL_RSP,
         ts, is_tx ? "TX" : "RX",
         label,
         (unsigned)(src & 0xFFu), (unsigned)(dst & 0xFFu), id24,
         COL_END);
  if (!is_tx && status != 0u) {
    printf(" %sabort 0x%08X%s\n", COL_ABORT, (unsigned)status, COL_END);
    return;
  }
  if (plen > 0u && payload != NULL) {
    log_secure_segments(is_tx, data_id, payload, (uint16_t)plen);
  } else if (!is_tx) {
    printf(" %sACK%s", COL_HDR, COL_END);
  } else {
    if      (label[0] == 'S' && label[1] == 'R' && label[2] == 'D') {
      printf(" %sSRD REQ%s", COL_HDR, COL_END);
    } else if (label[0] == 'S' && label[1] == 'W' && label[2] == 'R') {
      printf(" %sSWR REQ%s", COL_HDR, COL_END);
    }
  }

  /* Defer \n for srd / pollrd RX shapes so the runner can append
     " Plain:..." inline. All other rows close here. */
  const uint16_t TAGN = (uint16_t)FBSEC_AEAD_TAG_SIZE;
  bool defer = !is_tx && payload != NULL
            && ((strcmp(g_current_verb, "srd") == 0    && plen >= TAGN) ||
                (strcmp(g_current_verb, "pollrd") == 0 && plen >= 1u + (uint32_t)TAGN));
  if (defer) {
    g_secure_rx_open = true;
  } else {
    printf("\n");
  }
}

void fbsec_client_trace_close_with_plain(uint32_t data_id,
                                         const uint8_t *plain, uint16_t plen) {
  (void)data_id;
  if (!g_secure_rx_open) {
    return;
  }
  if (plain != NULL && plen > 0u) {
    printf(" %sPlain:%s", COL_HDR, COL_END);
    fbsec_client_trace_print_hex_seg(COL_PLAIN, plain, plen);
  }
  printf("\n");
  g_secure_rx_open = false;
}

void fbsec_client_trace_close_no_plain(void) {
  if (!g_secure_rx_open) {
    return;
  }
  printf("\n");
  g_secure_rx_open = false;
}

/* EOF */
