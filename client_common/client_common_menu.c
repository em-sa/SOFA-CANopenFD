/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    client_common_menu.c
 * @brief   SOFA client_common, interactive menu mode, implementation.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.2 of 22-JUL-2026
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#include "client_common_menu.h"
#include "client_common_keys.h"
#include "client_common_platform.h"
#include "client_common_trace.h"
#include "client_common_verbs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef _WIN32
#include <windows.h>
#endif

#include "fbsec_aead.h"
#include "fbsec_secure_proto.h"
#include "fbsec_descriptor.h"

/* ---- Menu constants -------------------------------------------------- */

#define MENU_POLL_COUNT     300u
#define MENU_POLL_DELAY_MS  200u
#define MENU_WR_DATA_ID     0x20100000u
#define MENU_RD_DATA_ID     0x20200000u
#define MENU_ID_DATA_ID     0xC0180000u
#define MENU_BIN_DATA_ID    0x20160000u
#define MENU_BIN_LEN        16u
/* 24-bit display form: drop the reserved low byte. */
#define MENU_DATA_ID24(d)   ((unsigned)(((d) >> 8) & 0xFFFFFFu))

/* ---- Local helpers --------------------------------------------------- */

/**
 * @brief  Trim leading and trailing whitespace from a string in place.
 * @param  s  String to trim (may be NULL).
 * @return Pointer to the first non-whitespace character of @p s, or @p s
 *         itself when it is NULL.
 */
static char *trim_inplace(char *s) {
  if (s == NULL) {
    return s;
  }
  while (*s == ' ' || *s == '\t') {
    ++s;
  }
  size_t n = strlen(s);
  while (n > 0 && (s[n-1] == ' ' || s[n-1] == '\t' ||
                   s[n-1] == '\r' || s[n-1] == '\n')) {
    s[--n] = '\0';
  }
  return s;
}

/**
 * @brief  Read one line from stdin into @p out and trim it in place.
 * @param  out       Destination buffer.
 * @param  out_size  Capacity of @p out in bytes.
 * @retval 1  A line was read.
 * @retval 0  End-of-file or read error.
 */
static int read_line(char *out, size_t out_size) {
  if (fgets(out, (int)out_size, stdin) == NULL) {
    return 0;
  }
  (void)trim_inplace(out);
  return 1;
}

/**
 * @brief  Parse a decimal or 0x-prefixed unsigned 32-bit value.
 * @param  s    NUL-terminated input string.
 * @param  out  Receives the parsed value on success.
 * @retval 0   Success.
 * @retval -1  NULL/empty input or trailing/invalid characters.
 */
static int parse_u32(const char *s, uint32_t *out) {
  if (s == NULL || *s == '\0') {
    return -1;
  }
  char *end = NULL;
  unsigned long v = strtoul(s, &end, 0);
  if (end == s || *end != '\0') {
    return -1;
  }
  *out = (uint32_t)v;
  return 0;
}

/**
 * @brief  Prompt the user for a target node id, validating the range.
 * @param  my_dev      Our own device id, rejected as a target to avoid a
 *                     self-collision.
 * @param  target_out  Receives the chosen target id on success.
 * @retval 1  A valid target was entered.
 * @retval 0  End-of-file on input.
 */
static int prompt_target(uint16_t my_dev, uint16_t *target_out) {
  char line[64];
  for (;;) {
    printf("Target node id (decimal or 0xHEX) [default 0x05]: ");
    fflush(stdout);
    if (read_line(line, sizeof line) == 0) {
      return 0;
    }
    const char *t = (line[0] == '\0') ? "0x05" : line;
    uint32_t v;
    if (parse_u32(t, &v) != 0 || v == 0u || v >= 0xFFFFu) {
      fprintf(stderr, "  invalid node id, expected 0x01..0x7F\n");
      continue;
    }
    if ((uint16_t)v == my_dev) {
      fprintf(stderr, "  target collides with our own id 0x%02X; pick another\n",
              (unsigned)(my_dev & 0xFFu));
      continue;
    }
    *target_out = (uint16_t)v;
    return 1;
  }
}

/**
 * @brief  Prompt the user to select one of the three demo session keys and
 *         set the active keyid accordingly.
 */
static void prompt_key(void) {
  char line[16];
  for (;;) {
    printf("Select key:\n"
           "  1) Provisioning Session Key (SRD & SWR access)\n"
           "  2) Integrator Session Key (SRD, SWR access)\n"
           "  3) Operator Session Key (SRD access only)\n"
           "[default %u]: ",
           (unsigned)((fbsec_client_keys_keyid() != 0u)
                      ? FBSEC_AEAD_KEYID_BASE(fbsec_client_keys_keyid())
                      : FBSEC_CLIENT_KEYID_INTEGRATOR));
    fflush(stdout);
    if (read_line(line, sizeof line) == 0) {
      return;
    }
    if (line[0] == '\0') {
      if (fbsec_client_keys_keyid() == 0u) {
        fbsec_client_keys_set_keyid(FBSEC_CLIENT_KEYID_INTEGRATOR);
      }
      return;
    }
    char c = line[0];
    if (c == '1') { fbsec_client_keys_set_keyid(FBSEC_CLIENT_KEYID_PROVISIONING); return; }
    if (c == '2') { fbsec_client_keys_set_keyid(FBSEC_CLIENT_KEYID_INTEGRATOR);   return; }
    if (c == '3') { fbsec_client_keys_set_keyid(FBSEC_CLIENT_KEYID_OPERATOR);     return; }
    fprintf(stderr, "  please answer 1, 2, or 3\n");
  }
}

/**
 * @brief  Prompt the user for our own node id and apply it via @p setter.
 * @param  my_dev_inout  In/out: current node id; updated on a valid entry.
 * @param  setter        Callback that pushes the new id to the variant; the
 *                       prompt is a no-op when NULL.
 */
static void prompt_node_id(uint16_t *my_dev_inout,
                           fbsec_client_menu_set_node_id_fn setter) {
  if (setter == NULL) {
    return;
  }
  char line[16];
  for (;;) {
    printf("Own node id (decimal or 0xHEX, 1..127) [default 0x%02X]: ",
           (unsigned)(*my_dev_inout & 0xFFu));
    fflush(stdout);
    if (read_line(line, sizeof line) == 0) {
      return;
    }
    if (line[0] == '\0') {
      return;
    }
    uint32_t v;
    if (parse_u32(line, &v) != 0 || v == 0u || v > 127u) {
      fprintf(stderr, "  invalid node id; expected 1..127\n");
      continue;
    }
    setter((uint8_t)v);
    *my_dev_inout = (uint16_t)v;
    return;
  }
}

/**
 * @brief  Prompt the user to enable or disable encryption and apply the
 *         choice to the key store.
 */
static void prompt_encryption(void) {
  char line[16];
  for (;;) {
    printf("Enable encryption? [y/n, default %s]: ",
           fbsec_client_keys_use_encryption() ? "y" : "n");
    fflush(stdout);
    if (read_line(line, sizeof line) == 0) {
      return;
    }
    if (line[0] == '\0') {
      return;
    }
    char c = line[0];
    if (c == 'y' || c == 'Y' || c == '1') { fbsec_client_keys_set_use_encryption(true);  return; }
    if (c == 'n' || c == 'N' || c == '0') { fbsec_client_keys_set_use_encryption(false); return; }
    fprintf(stderr, "  please answer y or n\n");
  }
}

/* ---- Cyclic-mode poll loops (manual, with per-shot CSV-style line) -- */

/**
 * @brief  Run the cyclic secure-read demo: one armed SRD followed by
 *         repeated poll-reads, printing a per-shot trace line and a summary.
 * @param  transport   Secure transport to use.
 * @param  target      Target node id.
 * @param  timeout_ms  Per-request timeout in milliseconds.
 * @retval 0  Always (failures are reported but not propagated).
 */
static int poll_read_loop(const fbsec_secure_transport_t *transport,
                          uint16_t target, uint32_t timeout_ms) {
  printf("\n--- polling srd 0x%02X:[0x%06X], %u reads, %u ms apart ---\n",
         (unsigned)(target & 0xFFu), MENU_DATA_ID24(MENU_RD_DATA_ID),
         (unsigned)MENU_POLL_COUNT, (unsigned)MENU_POLL_DELAY_MS);

  fbsec_secure_session_t sess;
  memset(&sess, 0, sizeof sess);

  /* Iteration 1: cyclic-capable single SRD. Full Pass-1 + Pass-2,
     prints the Plain: data exactly like menu option 3. The session is
     established as a side effect. */
  uint8_t  iter1_buf[FBSEC_AEAD_MAX_PROTECTED];
  uint32_t iter1_len = 0u;
  fbsec_abort_t abort_code = 0u;
  fbsec_client_keys_clear_observed_salt();
  fbsec_client_trace_set_verb("srd");
  fbsec_client_trace_reset_round();
  fbsec_secure_status_t rc = fbsec_secure_read_armed(transport,
                                               target, MENU_RD_DATA_ID,
                                               fbsec_client_keys_session(),
                                               fbsec_client_keys_effective_keyid(),
                                               iter1_buf, sizeof iter1_buf,
                                               timeout_ms,
                                               &iter1_len,
                                               &abort_code, &sess);
  fbsec_client_trace_set_verb("");
  if (rc != FBSEC_SECP_OK) {
    if (rc == FBSEC_SECP_ABORT) {
      printf("%sarmed-read FAIL%s %sabort 0x%02X (%s)%s\n",
             fbsec_client_trace_col_rsp(), fbsec_client_trace_col_end(),
             fbsec_client_trace_col_abort(), (unsigned)abort_code,
             fbsec_client_abort_name(abort_code),
             fbsec_client_trace_col_end());
    } else if (rc == FBSEC_SECP_TAG) {
      printf("%sarmed-read FAIL%s %stag verify failed%s\n",
             fbsec_client_trace_col_rsp(), fbsec_client_trace_col_end(),
             fbsec_client_trace_col_abort(), fbsec_client_trace_col_end());
    } else {
      printf("%sarmed-read FAIL%s %s%s%s\n",
             fbsec_client_trace_col_rsp(), fbsec_client_trace_col_end(),
             fbsec_client_trace_col_abort(), fbsec_client_secp_strerror(rc),
             fbsec_client_trace_col_end());
    }
    memset(&sess, 0, sizeof sess);
    return 0;
  }
  fbsec_client_trace_close_with_plain(MENU_RD_DATA_ID, iter1_buf, (uint16_t)iter1_len);
  printf("%sArmed cyclic read.%s\n",
         fbsec_client_trace_col_rsp(), fbsec_client_trace_col_end());

  const char *data_col = fbsec_client_trace_col_plain();
  bool prev_quiet;

  unsigned ok = 1, abort_n = 0, fail = 0;
  for (unsigned n = 2u; n <= MENU_POLL_COUNT; ++n) {
    char ts[16];
    fbsec_client_format_timestamp(ts, sizeof ts);

    uint8_t  buf[FBSEC_AEAD_MAX_PROTECTED];
    uint16_t got = 0u;
    abort_code = 0u;
    fbsec_client_keys_clear_observed_salt();
    prev_quiet = fbsec_client_trace_get_quiet();
    fbsec_client_trace_set_quiet(true);
    fbsec_client_trace_set_verb("pollrd");
    fbsec_client_trace_reset_round();
    uint8_t poll_tag[FBSEC_AEAD_TAG_SIZE];
    rc = fbsec_secure_poll_read(transport,
                              target, fbsec_client_keys_session(),
                              timeout_ms, &abort_code,
                              &sess, buf, sizeof buf, &got, poll_tag);
    fbsec_client_trace_set_verb("");
    fbsec_client_trace_set_quiet(prev_quiet);

    printf("%s[%s] poll %3u/%u%s",
           fbsec_client_trace_col_rsp(), ts, n, (unsigned)MENU_POLL_COUNT,
           fbsec_client_trace_col_end());
    uint8_t counter_byte = (uint8_t)(sess.counter & 0xFFu);
    fbsec_client_trace_print_hex_seg(fbsec_client_trace_col_hdr(), &counter_byte, 1u);

    if (rc == FBSEC_SECP_OK) {
      fbsec_client_trace_print_hex_seg(data_col, buf, got);
      fbsec_client_trace_print_hex_seg(fbsec_client_trace_col_tag(),
                                       poll_tag, (uint16_t)FBSEC_AEAD_TAG_SIZE);
      printf("\n");
      ++ok;
    } else if (rc == FBSEC_SECP_ABORT) {
      printf(" %sFAIL  abort 0x%02X (%s)%s\n",
             fbsec_client_trace_col_abort(), (unsigned)abort_code,
             fbsec_client_abort_name(abort_code),
             fbsec_client_trace_col_end());
      ++abort_n;
    } else {
      printf(" %sFAIL  %s%s\n",
             fbsec_client_trace_col_abort(), fbsec_client_secp_strerror(rc),
             fbsec_client_trace_col_end());
      ++fail;
    }

    if (n < MENU_POLL_COUNT) {
#ifdef _WIN32
      Sleep(MENU_POLL_DELAY_MS);
#endif
    }
  }

  printf("%spoll summary:%s %u/%u ok, %u abort, %u fail\n",
         fbsec_client_trace_col_rsp(), fbsec_client_trace_col_end(),
         ok, (unsigned)MENU_POLL_COUNT, abort_n, fail);
  memset(&sess, 0, sizeof sess);
  return 0;
}

/**
 * @brief  Run the cyclic secure-write demo: one armed SWR followed by
 *         repeated poll-writes, printing a per-shot trace line and a summary.
 * @param  transport   Secure transport to use.
 * @param  target      Target node id.
 * @param  timeout_ms  Per-request timeout in milliseconds.
 * @retval 0  Always (failures are reported but not propagated).
 */
static int poll_write_loop(const fbsec_secure_transport_t *transport,
                           uint16_t target, uint32_t timeout_ms) {
  printf("\n--- cyclic writing swr 0x%02X:[0x%06X], %u writes, %u ms apart ---\n",
         (unsigned)(target & 0xFFu), MENU_DATA_ID24(MENU_WR_DATA_ID),
         (unsigned)MENU_POLL_COUNT, (unsigned)MENU_POLL_DELAY_MS);

  fbsec_secure_session_t sess;
  memset(&sess, 0, sizeof sess);

  /* Iteration 1: cyclic-capable single SWR. Full Pass-1 + Pass-2,
     commits the first 4 bytes and establishes the session. */
  uint8_t  iter1_buf[4] = {
    (uint8_t)((1u >> 24) & 0xFFu),
    (uint8_t)((1u >> 16) & 0xFFu),
    (uint8_t)((1u >>  8) & 0xFFu),
    (uint8_t)( 1u        & 0xFFu),
  };
  fbsec_abort_t abort_code = 0u;
  fbsec_client_keys_clear_observed_salt();
  fbsec_client_trace_set_verb("swr");
  fbsec_client_trace_reset_round();
  fbsec_secure_status_t rc = fbsec_secure_write_armed(transport,
                                                target, MENU_WR_DATA_ID,
                                                fbsec_client_keys_session(),
                                                fbsec_client_keys_effective_keyid(),
                                                iter1_buf, (uint32_t)sizeof iter1_buf,
                                                timeout_ms,
                                                &abort_code, &sess);
  fbsec_client_trace_set_verb("");
  if (rc != FBSEC_SECP_OK) {
    if (rc == FBSEC_SECP_ABORT) {
      printf("%sarmed-write FAIL%s %sabort 0x%02X (%s)%s\n",
             fbsec_client_trace_col_rsp(), fbsec_client_trace_col_end(),
             fbsec_client_trace_col_abort(), (unsigned)abort_code,
             fbsec_client_abort_name(abort_code),
             fbsec_client_trace_col_end());
    } else if (rc == FBSEC_SECP_TAG) {
      printf("%sarmed-write FAIL%s %stag verify failed%s\n",
             fbsec_client_trace_col_rsp(), fbsec_client_trace_col_end(),
             fbsec_client_trace_col_abort(), fbsec_client_trace_col_end());
    } else {
      printf("%sarmed-write FAIL%s %s%s%s\n",
             fbsec_client_trace_col_rsp(), fbsec_client_trace_col_end(),
             fbsec_client_trace_col_abort(), fbsec_client_secp_strerror(rc),
             fbsec_client_trace_col_end());
    }
    memset(&sess, 0, sizeof sess);
    return 0;
  }
  printf("%sArmed cyclic write.%s\n",
         fbsec_client_trace_col_rsp(), fbsec_client_trace_col_end());

  bool prev_quiet;
  unsigned ok = 1, abort_n = 0, fail = 0;
  for (unsigned n = 2u; n <= MENU_POLL_COUNT; ++n) {
    char ts[16];
    fbsec_client_format_timestamp(ts, sizeof ts);

    uint8_t buf[4] = {
      (uint8_t)((n >> 24) & 0xFFu),
      (uint8_t)((n >> 16) & 0xFFu),
      (uint8_t)((n >>  8) & 0xFFu),
      (uint8_t)( n        & 0xFFu),
    };

    abort_code = 0u;
    fbsec_client_keys_clear_observed_salt();
    prev_quiet = fbsec_client_trace_get_quiet();
    fbsec_client_trace_set_quiet(true);
    fbsec_client_trace_set_verb("pollwr");
    fbsec_client_trace_reset_round();
    uint8_t poll_tag[FBSEC_AEAD_TAG_SIZE];
    rc = fbsec_secure_poll_write(transport,
                               target, fbsec_client_keys_session(),
                               timeout_ms, &abort_code,
                               &sess, buf, (uint16_t)sizeof buf, poll_tag);
    fbsec_client_trace_set_verb("");
    fbsec_client_trace_set_quiet(prev_quiet);

    printf("%s[%s] poll %3u/%u%s",
           fbsec_client_trace_col_rsp(), ts, n, (unsigned)MENU_POLL_COUNT,
           fbsec_client_trace_col_end());
    uint8_t counter_byte = (uint8_t)(sess.counter & 0xFFu);
    fbsec_client_trace_print_hex_seg(fbsec_client_trace_col_hdr(), &counter_byte, 1u);

    if (rc == FBSEC_SECP_OK) {
      fbsec_client_trace_print_hex_seg(fbsec_client_trace_col_plain(),
                                       buf, (uint16_t)sizeof buf);
      fbsec_client_trace_print_hex_seg(fbsec_client_trace_col_tag(),
                                       poll_tag, (uint16_t)FBSEC_AEAD_TAG_SIZE);
      printf("\n");
      ++ok;
    } else if (rc == FBSEC_SECP_ABORT) {
      printf(" %sFAIL  abort 0x%02X (%s)%s\n",
             fbsec_client_trace_col_abort(), (unsigned)abort_code,
             fbsec_client_abort_name(abort_code),
             fbsec_client_trace_col_end());
      ++abort_n;
    } else {
      printf(" %sFAIL  %s%s\n",
             fbsec_client_trace_col_abort(), fbsec_client_secp_strerror(rc),
             fbsec_client_trace_col_end());
      ++fail;
    }

    if (n < MENU_POLL_COUNT) {
#ifdef _WIN32
      Sleep(MENU_POLL_DELAY_MS);
#endif
    }
  }

  printf("%spoll summary:%s %u/%u ok, %u abort, %u fail\n",
         fbsec_client_trace_col_rsp(), fbsec_client_trace_col_end(),
         ok, (unsigned)MENU_POLL_COUNT, abort_n, fail);
  memset(&sess, 0, sizeof sess);
  return 0;
}

/* ---- Security-parameter scan (unsecured cold reads) ---------------- */

/* Little-endian U32 read (C000h/C001h/C011h are served little-endian). */
static uint32_t rd_u32le(const uint8_t *b, uint32_t len) {
  uint32_t v = 0u, i;
  for (i = 0u; (i < len) && (i < 4u); ++i) {
    v |= (uint32_t)b[i] << (8u * i);
  }
  return v;
}

/* Big-endian U32 read (object 1018h is served as authored, big-endian). */
static uint32_t rd_u32be(const uint8_t *b, uint32_t len) {
  uint32_t v = 0u, i;
  for (i = 0u; (i < len) && (i < 4u); ++i) {
    v = (v << 8u) | (uint32_t)b[i];
  }
  return v;
}

static const char *menu_profile_name(uint8_t p) {
  switch (p) {
    case FBSEC_PROFILE_CUSTOM:       return "Custom";
    case FBSEC_PROFILE_OPEN:         return "Open";
    case FBSEC_PROFILE_CLAIMED:      return "Claimed";
    case FBSEC_PROFILE_AUTHORIZED:   return "Authorized";
    case FBSEC_PROFILE_IDENTIFIED:   return "Identified";
    case FBSEC_PROFILE_CONFIDENTIAL: return "Confidential";
    default:                         return "unknown";
  }
}

static const char *menu_aead_name(uint8_t bitmap) {
  if ((bitmap & FBSEC_DESC_AEAD_AES128_GCM) != 0u) return "AES-128-GCM";
  if ((bitmap & FBSEC_DESC_AEAD_AES256_GCM) != 0u) return "AES-256-GCM";
  if ((bitmap & FBSEC_DESC_AEAD_ASCON128)   != 0u) return "Ascon-128";
  if ((bitmap & FBSEC_DESC_AEAD_CHACHA20)   != 0u) return "ChaCha20-Poly1305";
  return "unknown";
}

/**
 * @brief  Render the symbolic meaning of one scanned sub-index.
 *
 * @return true if @p out was filled with an interpretation, false if the
 *         (index, sub) pair has no known decoding.
 */
static bool interpret_sub(uint16_t index, uint8_t sub,
                          const uint8_t *b, uint32_t len,
                          char *out, size_t outsz) {
  uint32_t v = rd_u32le(b, len);

  switch (index) {
    case 0xC000u:
      switch (sub) {
        case 0x01u: {
          uint8_t m = FBSEC_TYPEWORD_MECH(v);
          (void)snprintf(out, outsz,
            "type word: profile %s, level C%u, restore %u, mechanisms%s%s%s, suite gen %u",
            menu_profile_name(FBSEC_TYPEWORD_PROFILE(v)),
            (unsigned)FBSEC_TYPEWORD_LEVEL(v),
            (unsigned)FBSEC_TYPEWORD_RESTORE(v),
            ((m & FBSEC_MECH_AEAD) != 0u) ? " AEAD" : "",
            ((m & FBSEC_MECH_RPK)  != 0u) ? " RPK"  : "",
            ((m & FBSEC_MECH_X509) != 0u) ? " X509" : "",
            (unsigned)FBSEC_TYPEWORD_SUITE(v));
          return true;
        }
        case 0x02u:
          (void)snprintf(out, outsz, "session protocols:%s%s%s%s%s",
            ((v & FBSEC_DESC_PROTO_FBSEC) != 0u)        ? " FBsec" : "",
            ((v & FBSEC_DESC_PROTO_TLS_PSK) != 0u)      ? " TLS-PSK" : "",
            ((v & FBSEC_DESC_PROTO_CTLS) != 0u)         ? " cTLS" : "",
            ((v & FBSEC_DESC_PROTO_TLS13) != 0u)        ? " TLS1.3" : "",
            ((v & FBSEC_DESC_PROTO_SIGNED_FBSEC) != 0u) ? " signed-FBsec" : "");
          return true;
        case 0x03u:
          (void)snprintf(out, outsz, "%s, tag %u bytes",
            menu_aead_name((uint8_t)(v & 0xFFu)),
            (unsigned)((v >> 8) & 0xFFu));
          return true;
        case 0x04u:
          (void)snprintf(out, outsz, "RPK algorithm: %s",
            (b[0] == FBSEC_DESC_RPK_ED25519) ? "Ed25519" :
            (b[0] == FBSEC_DESC_RPK_NONE)    ? "none" : "reserved");
          return true;
        case 0x05u:
          if (v == 0u) {
            (void)snprintf(out, outsz, "identity flags: none");
          } else {
            (void)snprintf(out, outsz, "identity flags:%s%s%s%s",
              ((v & FBSEC_DESC_ID_IDEVID) != 0u)       ? " IDevID" : "",
              ((v & FBSEC_DESC_ID_LDEVID) != 0u)       ? " LDevID" : "",
              ((v & FBSEC_DESC_ID_SIGNED_FBSEC) != 0u) ? " signed-FBsec" : "",
              ((v & FBSEC_DESC_ID_X509) != 0u)         ? " X509" : "");
          }
          return true;
        case 0x06u:
          if (v == 0u) {
            (void)snprintf(out, outsz, "handover: none");
          } else {
            (void)snprintf(out, outsz, "handover:%s%s%s",
              ((v & FBSEC_DESC_HANDOVER_TOFU) != 0u)    ? " TOFU" : "",
              ((v & FBSEC_DESC_HANDOVER_TOKEN) != 0u)   ? " printed-token" : "",
              ((v & FBSEC_DESC_HANDOVER_VOUCHER) != 0u) ? " voucher" : "");
          }
          return true;
        case 0x07u:
          (void)snprintf(out, outsz, "manufacturer-specific capabilities");
          return true;
        default:
          return false;
      }
    case 0xC001u:
      switch (sub) {
        case 0x01u:
          (void)snprintf(out, outsz, "commissioning: %s",
            (b[0] == FBSEC_STAT_COMMISSIONED) ? "commissioned/owned"
                                              : "uncommissioned");
          return true;
        case 0x02u:
          if (v == 0u) {
            (void)snprintf(out, outsz, "keys installed: none");
          } else {
            (void)snprintf(out, outsz, "keys installed:%s%s%s",
              ((v & FBSEC_STAT_KEY_PROVISIONING) != 0u) ? " Provisioning" : "",
              ((v & FBSEC_STAT_KEY_INTEGRATOR) != 0u)   ? " Integrator" : "",
              ((v & FBSEC_STAT_KEY_OPERATOR) != 0u)     ? " Operator" : "");
          }
          return true;
        default:
          return false;
      }
    case 0xC011u: {
      const char *role = (sub == 0x01u) ? "Provisioning"
                       : (sub == 0x02u) ? "Integrator"
                       : (sub == 0x03u) ? "Operator" : "Application";
      if (v == 0u) {
        (void)snprintf(out, outsz, "%s key: empty slot", role);
      } else {
        (void)snprintf(out, outsz, "%s key id = 0x%08lX",
                       role, (unsigned long)v);
      }
      return true;
    }
    case 0x1018u: {
      uint32_t be = rd_u32be(b, len);   /* 1018h is authored big-endian */
      switch (sub) {
        case 0x01u:
          (void)snprintf(out, outsz, "Vendor ID = 0x%08lX", (unsigned long)be);
          return true;
        case 0x02u: {
          char asc[5];
          int  printable = 1;
          uint32_t i;
          for (i = 0u; (i < 4u) && (i < len); ++i) {
            unsigned char ch = b[i];
            asc[i] = ((ch >= 0x20u) && (ch < 0x7Fu)) ? (char)ch : '.';
            if (!((ch >= 0x20u) && (ch < 0x7Fu))) { printable = 0; }
          }
          asc[i] = '\0';
          if (printable != 0) {
            (void)snprintf(out, outsz, "Product code = 0x%08lX (\"%s\")",
                           (unsigned long)be, asc);
          } else {
            (void)snprintf(out, outsz, "Product code = 0x%08lX",
                           (unsigned long)be);
          }
          return true;
        }
        case 0x03u:
          (void)snprintf(out, outsz, "Revision = 0x%08lX", (unsigned long)be);
          return true;
        case 0x04u:
          (void)snprintf(out, outsz, "Serial number = 0x%08lX",
                         (unsigned long)be);
          return true;
        default:
          return false;
      }
    }
    default:
      return false;
  }
}

/**
 * @brief  Read and print every sub-index of one constant, unsecured
 *         security-parameter object.
 *
 * Sub 0x00 carries the highest sub-index, so it bounds the loop. Reads use
 * the plain (body-less) transport read path; no key is required.
 *
 * @param  transport   Secure transport (its read fn is used unsecured).
 * @param  target      Target node id.
 * @param  timeout_ms  Per-read timeout.
 * @param  index       Object index to scan.
 * @param  name        Human-readable object name for the heading.
 */
static void scan_one_object(const fbsec_secure_transport_t *transport,
                            uint16_t target, uint32_t timeout_ms,
                            uint16_t index, const char *name) {
  uint8_t       buf[64];
  uint32_t      len  = 0u;
  fbsec_abort_t abrt = FBSEC_ABORT_NONE;
  fbsec_secure_status_t rc;
  unsigned      sub;
  unsigned      highest;
  char          note[192];

  /* Object heading (no trace row is open here). */
  printf("  %04Xh %s:\n", (unsigned)index, name);

  /* Sub 0x00 -> highest sub-index. The interpretation is appended inline to
     the RX trace line the transport read produced (no duplicate data). */
  rc = transport->read(transport->ctx, target, ((uint32_t)index << 16),
                       NULL, 0u, buf, (uint32_t)sizeof buf, timeout_ms,
                       &len, &abrt);
  if ((rc != FBSEC_SECP_OK) || (len < 1u)) {
    /* On an abort the RX row already carries "abort 0x.. (name)"; otherwise
       close any open row and note the transport failure. */
    if (rc != FBSEC_SECP_ABORT) {
      (void)snprintf(note, sizeof note, "read failed (%s)",
                     fbsec_client_secp_strerror(rc));
      fbsec_client_trace_close_with_note(note);
    } else {
      fbsec_client_trace_close_no_plain();
    }
    return;
  }
  highest = buf[0];
  (void)snprintf(note, sizeof note, "highest sub-index 0x%02X", highest);
  fbsec_client_trace_close_with_note(note);

  for (sub = 1u; sub <= highest; ++sub) {
    uint32_t data_id = ((uint32_t)index << 16) | ((uint32_t)sub << 8);
    len  = 0u;
    abrt = FBSEC_ABORT_NONE;
    rc = transport->read(transport->ctx, target, data_id, NULL, 0u,
                         buf, (uint32_t)sizeof buf, timeout_ms, &len, &abrt);
    if ((rc == FBSEC_SECP_OK) &&
        interpret_sub(index, (uint8_t)sub, buf, len, note, sizeof note)) {
      fbsec_client_trace_close_with_note(note);
    } else {
      /* OK-but-unknown: close plainly; abort: row already closed. */
      fbsec_client_trace_close_no_plain();
    }
  }
}

/**
 * @brief  Scan the constant, unsecured security-parameter objects and dump
 *         their contents: C000h capabilities, C001h status, C011h key ids,
 *         and object 1018h identity. No key is required. Each value's
 *         symbolic meaning is appended inline to its RX trace line.
 */
static void scan_security_params(const fbsec_secure_transport_t *transport,
                                 uint16_t target, uint32_t timeout_ms) {
  static const struct { uint16_t index; const char *name; } objs[] = {
    { 0xC000u, "capabilities" },
    { 0xC001u, "status" },
    { 0xC011u, "AEAD key ids" },
    { 0x1018u, "identity" },
  };
  size_t i;
  bool   prev_quiet = fbsec_client_trace_get_quiet();

  printf("--- security parameter scan (target 0x%02X, no key) ---\n",
         (unsigned)(target & 0xFFu));
  /* The scan is trace-driven: keep trace on and force RX rows to stay open
     so the interpretation is appended inline. */
  fbsec_client_trace_set_quiet(false);
  fbsec_client_trace_set_force_defer(true);
  for (i = 0u; i < (sizeof objs / sizeof objs[0]); ++i) {
    scan_one_object(transport, target, timeout_ms,
                    objs[i].index, objs[i].name);
  }
  fbsec_client_trace_set_force_defer(false);
  fbsec_client_trace_set_quiet(prev_quiet);
}

/* ---- REPL ---------------------------------------------------------- */

int fbsec_client_run_menu(const fbsec_secure_transport_t *transport,
                          const fbsec_client_menu_cfg_t  *cfg) {
  /* Prompt order: own node id -> target node id -> encryption ->
     key selection. The key prompt is skipped when a key was supplied
     via --key / --main-key on the command line.
     my_dev is a local mutable copy so the menu's prompt_node_id can
     update it (and propagate to the variant via cfg->set_node_id) without
     mutating the caller's cfg struct. */
  uint16_t my_dev = cfg->my_dev;
  prompt_node_id(&my_dev, cfg->set_node_id);

  uint16_t target = 0x0005u;
  if (prompt_target(my_dev, &target) == 0) {
    return 0;
  }

  prompt_encryption();

  if (!fbsec_client_keys_session_set() && !fbsec_client_keys_main_set()) {
    prompt_key();
  }

  uint16_t wr_counter  = 0u;
  uint32_t bin_counter = 1u;
  char     line[32];
  for (;;) {
    printf("\n");
    printf("=== fbsec client menu  (target 0x%02X  bus %s  %s) ===\n",
           (unsigned)(target & 0xFFu), cfg->bus_label,
           fbsec_client_keys_use_encryption() ? "encrypt+auth" : "auth-only (MAC)");
    printf("  A) %-24s  reads C000/C001/C011/1018 (no key)\n",
           "Scan security parameters");
    printf("  1) %-24s  SRD 0x%06X\n",
           "Single 16-byte read",
           MENU_DATA_ID24(MENU_ID_DATA_ID));
    printf("  2) %-24s  SWR 0x%06X   (counter %08X || CC*12)\n",
           "Single 16-byte write",
           MENU_DATA_ID24(MENU_BIN_DATA_ID), (unsigned)bin_counter);
    printf("  3) %-24s  SRD 0x%06X\n",
           "Single 4-byte read",
           MENU_DATA_ID24(MENU_RD_DATA_ID));
    printf("  4) %-24s  SWR 0x%06X   (start: 0x1234%04X)\n",
           "Single 4-byte write",
           MENU_DATA_ID24(MENU_WR_DATA_ID), (unsigned)wr_counter);
    char cyc_label[32];
    (void)snprintf(cyc_label, sizeof cyc_label, "%u cyclic reads",
             (unsigned)MENU_POLL_COUNT);
    printf("  5) %-24s  SRD 0x%06X   (%ux, %u ms apart)\n",
           cyc_label,
           MENU_DATA_ID24(MENU_RD_DATA_ID),
           (unsigned)MENU_POLL_COUNT, (unsigned)MENU_POLL_DELAY_MS);
    (void)snprintf(cyc_label, sizeof cyc_label, "%u cyclic writes",
             (unsigned)MENU_POLL_COUNT);
    printf("  6) %-24s  SWR 0x%06X   (%ux, %u ms apart)\n",
           cyc_label,
           MENU_DATA_ID24(MENU_WR_DATA_ID),
           (unsigned)MENU_POLL_COUNT, (unsigned)MENU_POLL_DELAY_MS);
    printf("  Q) Quit\n");
    printf("Choice: ");
    fflush(stdout);

    if (read_line(line, sizeof line) == 0) {
      printf("\n");
      break;
    }
    if (line[0] == '\0') {
      continue;
    }
    char c = line[0];
    if (c == 'q' || c == 'Q') {
      break;
    }

    printf("\n");
    if (c == 'a' || c == 'A') {
      scan_security_params(transport, target, cfg->timeout_ms);
      continue;
    }
    fbsec_client_trace_print_legend();
    if (strcmp(line, "1") == 0) {
      uint8_t buf[FBSEC_AEAD_MAX_PROTECTED];
      (void)fbsec_client_run_secure_read(transport, target, MENU_ID_DATA_ID,
                                         cfg->timeout_ms, buf, sizeof buf, NULL);
    } else if (strcmp(line, "2") == 0) {
      uint8_t buf[MENU_BIN_LEN];
      buf[0] = (uint8_t)((bin_counter >> 24) & 0xFFu);
      buf[1] = (uint8_t)((bin_counter >> 16) & 0xFFu);
      buf[2] = (uint8_t)((bin_counter >>  8) & 0xFFu);
      buf[3] = (uint8_t)( bin_counter        & 0xFFu);
      memset(&buf[4], 0xCCu, MENU_BIN_LEN - 4u);
      (void)fbsec_client_run_secure_write(transport, target, MENU_BIN_DATA_ID,
                                          buf, MENU_BIN_LEN, cfg->timeout_ms);
      ++bin_counter;
    } else if (strcmp(line, "3") == 0) {
      uint8_t buf[FBSEC_AEAD_MAX_PROTECTED];
      (void)fbsec_client_run_secure_read(transport, target, MENU_RD_DATA_ID,
                                         cfg->timeout_ms, buf, sizeof buf, NULL);
    } else if (strcmp(line, "4") == 0) {
      uint8_t buf[4];
      buf[0] = 0x12u;
      buf[1] = 0x34u;
      buf[2] = (uint8_t)((wr_counter >> 8) & 0xFFu);
      buf[3] = (uint8_t)( wr_counter       & 0xFFu);
      (void)fbsec_client_run_secure_write(transport, target, MENU_WR_DATA_ID,
                                          buf, 4u, cfg->timeout_ms);
      wr_counter = (uint16_t)((wr_counter + 1u) & 0xFFFFu);
    } else if (strcmp(line, "5") == 0) {
      (void)poll_read_loop(transport, target, cfg->timeout_ms);
    } else if (strcmp(line, "6") == 0) {
      (void)poll_write_loop(transport, target, cfg->timeout_ms);
    } else {
      printf("?? unrecognised choice: %s\n", line);
    }
  }

  return 0;
}

/* EOF */
