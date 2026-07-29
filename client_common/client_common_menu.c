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

#if FBSEC_FEATURE_ASYM
#include "fbsec_asym.h"
#include "client_common_rpk.h"
#include "client_common_commission.h"
#endif

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

/* Select a session key lazily: an AEAD operation needs one, but on an
   uncommissioned device no key exists until the handover (L) has run, so the
   choice is deferred out of startup to the first keyed operation. A keyid
   already fixed on the command line (--keyid / --key) or a --main-key
   derivation path is left untouched. */
static void ensure_key_selected(void) {
  if (fbsec_client_keys_keyid() == 0u && !fbsec_client_keys_main_set()) {
    prompt_key();
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
        case 0x01u:
          (void)snprintf(out, outsz,
            "type word: profile %s, level C%u",
            menu_profile_name((uint8_t)FBSEC_TYPEWORD_PROFILE(v)),
            (unsigned)FBSEC_TYPEWORD_LEVEL(v));
          return true;
        case 0x02u:
          (void)snprintf(out, outsz, "%s, tag %u bytes",
            menu_aead_name((uint8_t)(v & 0xFFu)),
            (unsigned)((v >> 8) & 0xFFu));
          return true;
        case 0x03u:
          (void)snprintf(out, outsz, "KDF:%s",
            ((v & FBSEC_DESC_KDF_HKDF_SHA256) != 0u) ? " HKDF-SHA-256" : " none");
          return true;
        case 0x04u:
          (void)snprintf(out, outsz, "signature:%s",
            ((v & FBSEC_DESC_SIG_ED25519) != 0u) ? " Ed25519" : " none");
          return true;
        case 0x05u:
          if (v == 0u) {
            (void)snprintf(out, outsz, "symmetric key levels: none");
          } else {
            (void)snprintf(out, outsz, "symmetric key levels:%s%s%s",
              ((v & FBSEC_DESC_SYMLVL_PROVISIONING) != 0u) ? " Provisioning" : "",
              ((v & FBSEC_DESC_SYMLVL_INTEGRATOR) != 0u)   ? " Integrator" : "",
              ((v & FBSEC_DESC_SYMLVL_OPERATOR) != 0u)     ? " Operator" : "");
          }
          return true;
        case 0x06u:
          if (v == 0u) {
            (void)snprintf(out, outsz, "asymmetric key presence: none");
          } else {
            (void)snprintf(out, outsz, "asymmetric key presence:%s%s%s",
              ((v & FBSEC_DESC_ID_IDEVID) != 0u)       ? " IDevID" : "",
              ((v & FBSEC_DESC_ID_LDEVID) != 0u)       ? " LDevID" : "",
              ((v & FBSEC_DESC_ID_X509) != 0u)         ? " X509" : "");
          }
          return true;
        case 0x07u:
          if (v == 0u) {
            (void)snprintf(out, outsz, "claim gates: none");
          } else {
            (void)snprintf(out, outsz, "claim gates:%s%s%s",
              ((v & FBSEC_DESC_HANDOVER_TOFU) != 0u)    ? " TOFU" : "",
              ((v & FBSEC_DESC_HANDOVER_TOKEN) != 0u)   ? " token" : "",
              ((v & FBSEC_DESC_HANDOVER_VOUCHER) != 0u) ? " voucher" : "");
          }
          return true;
        case 0x08u:
          if (v == 0u) {
            (void)snprintf(out, outsz, "mechanisms: none");
          } else {
            (void)snprintf(out, outsz, "mechanisms:%s%s%s",
              ((v & FBSEC_MECH_AEAD) != 0u) ? " AEAD" : "",
              ((v & FBSEC_MECH_RPK)  != 0u) ? " RPK"  : "",
              ((v & FBSEC_MECH_X509) != 0u) ? " X509" : "");
          }
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
            (void)snprintf(out, outsz, "active claim gate: none");
          } else {
            (void)snprintf(out, outsz, "active claim gate:%s%s%s",
              ((v & FBSEC_DESC_HANDOVER_TOFU) != 0u)    ? " TOFU" : "",
              ((v & FBSEC_DESC_HANDOVER_TOKEN) != 0u)   ? " token" : "",
              ((v & FBSEC_DESC_HANDOVER_VOUCHER) != 0u) ? " voucher" : "");
          }
          return true;
        case 0x03u:
          if (v == 0u) {
            (void)snprintf(out, outsz, "keys installed: none");
          } else {
            (void)snprintf(out, outsz, "keys installed:%s%s%s",
              ((v & FBSEC_STAT_KEY_PROVISIONING) != 0u) ? " Provisioning" : "",
              ((v & FBSEC_STAT_KEY_INTEGRATOR) != 0u)   ? " Integrator" : "",
              ((v & FBSEC_STAT_KEY_OPERATOR) != 0u)     ? " Operator" : "");
          }
          return true;
        case 0x04u:
          (void)snprintf(out, outsz, "active AEAD: %s, tag %u bytes",
            menu_aead_name((uint8_t)(v & 0xFFu)),
            (unsigned)((v >> 8) & 0xFFu));
          return true;
        case 0x05u:
          if (v == 0u) {
            (void)snprintf(out, outsz, "device identities: none");
          } else {
            (void)snprintf(out, outsz, "device identities:%s%s%s",
              ((v & FBSEC_DESC_ID_IDEVID) != 0u)       ? " IDevID" : "",
              ((v & FBSEC_DESC_ID_LDEVID) != 0u)       ? " LDevID" : "",
              ((v & FBSEC_DESC_ID_X509) != 0u)         ? " X509" : "");
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
    case 0xC021u: {
      const char *role = (sub == 0x01u) ? "Manufacturer"
                       : (sub == 0x02u) ? "Integrator" : "Public";
      bool     all_zero = true;
      uint32_t i;
      for (i = 0u; i < len; ++i) {
        if (b[i] != 0u) { all_zero = false; break; }
      }
      if (all_zero) {
        (void)snprintf(out, outsz, "%s public key: not installed", role);
      } else {
        (void)snprintf(out, outsz,
          "%s public key: %02X%02X%02X%02X..%02X%02X (Ed25519, %u bytes)",
          role, b[0], b[1], b[2], b[3], b[len - 2u], b[len - 1u],
          (unsigned)len);
      }
      return true;
    }
    case 0xC022u:
      (void)snprintf(out, outsz, "public key type: %s, length %u bytes",
        (b[0] == 0x01u) ? "Ed25519" : "reserved", (unsigned)b[1]);
      return true;
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
#if FBSEC_FEATURE_ASYM
    { 0xC021u, "public keys" },
    { 0xC022u, "public key types" },
#endif
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

/* ---- Lifecycle / commissioning submenu ----------------------------- */

/* One cold (unsecured, body-less) read of index:sub. Returns bytes read,
   0 on any transport error or abort. Trace is silenced by the caller. */
static uint32_t lifecycle_cold_read(const fbsec_secure_transport_t *transport,
                                    uint16_t target, uint16_t index, uint8_t sub,
                                    uint32_t timeout_ms,
                                    uint8_t *buf, uint32_t buf_size) {
  uint32_t data_id = ((uint32_t)index << 16) | ((uint32_t)sub << 8);
  uint32_t len  = 0u;
  fbsec_abort_t abrt = FBSEC_ABORT_NONE;
  fbsec_secure_status_t rc = transport->read(transport->ctx, target, data_id,
                                             NULL, 0u, buf, buf_size,
                                             timeout_ms, &len, &abrt);
  return (rc == FBSEC_SECP_OK) ? len : 0u;
}

/* Snapshot of the server's live commissioning state, read cold. */
typedef struct {
  bool    ok;             /* the C001h:01h read succeeded              */
  uint8_t commissioning;  /* FBSEC_STAT_UNCOMMISSIONED / _COMMISSIONED */
  uint8_t keys;           /* FBSEC_STAT_KEY_* bitmap                   */
  uint8_t handover;       /* C000h:06h FBSEC_DESC_HANDOVER_* bitmap    */
} lifecycle_state_t;

/* Read C001h:01h (commissioning) and :03h (keys), plus C000h:07h (claim
   gates), with tracing silenced. */
static lifecycle_state_t lifecycle_read_state(
    const fbsec_secure_transport_t *transport,
    uint16_t target, uint32_t timeout_ms) {
  lifecycle_state_t st = { false, FBSEC_STAT_UNCOMMISSIONED, 0u, 0u };
  uint8_t  buf[8];
  bool     prev_quiet = fbsec_client_trace_get_quiet();

  fbsec_client_trace_set_quiet(true);
  if (lifecycle_cold_read(transport, target, 0xC001u, 0x01u, timeout_ms,
                          buf, (uint32_t)sizeof buf) >= 1u) {
    st.ok = true;
    st.commissioning = buf[0];
  }
  if (lifecycle_cold_read(transport, target, 0xC001u, 0x03u, timeout_ms,
                          buf, (uint32_t)sizeof buf) >= 1u) {
    st.keys = buf[0];
  }
  if (lifecycle_cold_read(transport, target, 0xC000u, 0x07u, timeout_ms,
                          buf, (uint32_t)sizeof buf) >= 1u) {
    st.handover = buf[0];
  }
  fbsec_client_trace_set_quiet(prev_quiet);
  return st;
}

/* Lifecycle transitions the submenu can offer. Which apply is decided from
   the live state; only some are wired (see lifecycle_do_action). */
typedef enum {
  LC_ACT_VOUCHER = 0,   /* claim by voucher, then install the Provisioning key */
  LC_ACT_TOKEN,         /* present the Device Claim Token, then install (Phase 3) */
  LC_ACT_LADDER,        /* install the next ladder key (Phase 3)               */
  LC_ACT_DECOMMISSION   /* manufacturer reset (Phase 4)                        */
} lifecycle_action_t;

#define LC_ACT_MAX 4u

/* Build the ordered action list valid for @p st. Returns the count and fills
   @p out (capacity LC_ACT_MAX). */
static unsigned lifecycle_actions(const lifecycle_state_t *st,
                                  lifecycle_action_t out[LC_ACT_MAX]) {
  unsigned n = 0u;
  if (st->commissioning != FBSEC_STAT_COMMISSIONED) {
    if ((st->handover & FBSEC_DESC_HANDOVER_VOUCHER) != 0u) { out[n++] = LC_ACT_VOUCHER; }
    if ((st->handover & FBSEC_DESC_HANDOVER_TOKEN)   != 0u) { out[n++] = LC_ACT_TOKEN; }
  } else {
    /* Offer the key ladder only while a session key is still missing; the
       demo sets all three at commissioning, so usually only Decommission
       remains. */
    uint8_t all = (uint8_t)(FBSEC_STAT_KEY_PROVISIONING
                          | FBSEC_STAT_KEY_INTEGRATOR
                          | FBSEC_STAT_KEY_OPERATOR);
    if ((st->keys & all) != all) { out[n++] = LC_ACT_LADDER; }
    out[n++] = LC_ACT_DECOMMISSION;
  }
  return n;
}

static const char *lifecycle_action_label(lifecycle_action_t a) {
  switch (a) {
    case LC_ACT_VOUCHER:      return "Claim ownership by voucher, then install the Provisioning key";
    case LC_ACT_TOKEN:        return "Present the Device Claim Token and install the Provisioning key";
    case LC_ACT_LADDER:       return "Install the next key in the ladder (Integrator, Operator)";
    case LC_ACT_DECOMMISSION: return "Decommission / manufacturer reset";
    default:                  return "?";
  }
}

/* Print the state banner and the numbered action list. */
static void lifecycle_print(const lifecycle_state_t *st, uint16_t target,
                            const lifecycle_action_t *acts, unsigned n) {
  unsigned i;

  printf("=== lifecycle / commissioning  (target 0x%02X) ===\n",
         (unsigned)(target & 0xFFu));
  if (!st->ok) {
    printf("  could not read C001h status from the target\n");
    return;
  }

  printf("  stage:  %s\n",
         (st->commissioning == FBSEC_STAT_COMMISSIONED) ? "Owned / Operational"
                                                        : "Uncommissioned");
  printf("  keys:   %s%s%s%s\n",
         (st->keys == 0u) ? "none" : "",
         ((st->keys & FBSEC_STAT_KEY_PROVISIONING) != 0u) ? " Provisioning" : "",
         ((st->keys & FBSEC_STAT_KEY_INTEGRATOR)   != 0u) ? " Integrator"   : "",
         ((st->keys & FBSEC_STAT_KEY_OPERATOR)     != 0u) ? " Operator"     : "");
  /* The gate is one-time: it is the way in to claim ownership. Once the
     device is claimed it is closed, regardless of what C000h:06h still
     advertises as a capability. */
  if (st->commissioning == FBSEC_STAT_COMMISSIONED) {
    printf("  gate:   closed (device already claimed)\n");
  } else {
    bool voucher = (st->handover & FBSEC_DESC_HANDOVER_VOUCHER) != 0u;
    bool token   = (st->handover & FBSEC_DESC_HANDOVER_TOKEN)   != 0u;
    bool tofu    = (st->handover & FBSEC_DESC_HANDOVER_TOFU)    != 0u;
    printf("  gate:   open ->%s%s%s%s\n",
           (!voucher && !token && !tofu) ? " none advertised" : "",
           voucher ? " voucher" : "",
           token   ? " token"   : "",
           tofu    ? " TOFU"    : "");
  }
  printf("  ------------------------------\n");

  for (i = 0u; i < n; ++i) {
    printf("  %u) %s\n", i + 1u, lifecycle_action_label(acts[i]));
  }
  if (n == 0u) {
    if ((st->handover & FBSEC_DESC_HANDOVER_TOFU) != 0u) {
      printf("  claim-on-first-use (TOFU): the first secure session takes\n"
             "  ownership; there is no explicit gate step to run here\n");
    } else {
      printf("  (device advertises no ownership gate)\n");
    }
  }
  printf("  Q) Back\n");
}

#if FBSEC_FEATURE_ASYM
/* Print @p n bytes as indented hex, 16 per line, for the step narration. */
static void lifecycle_dump_hex(const uint8_t *p, uint16_t n) {
  uint16_t i;
  for (i = 0u; i < n; ++i) {
    if ((i % 16u) == 0u) { printf("    "); }
    printf("%02X%s", p[i], (((i + 1u) % 16u) == 0u || (i + 1u) == n) ? "\n" : " ");
  }
}

/* Walk the C01Fh ladder (Integrator under Provisioning, Operator under
   Integrator), narrating each rung, then report the outcome. */
static void lifecycle_run_ladder(const fbsec_secure_transport_t *transport,
                                 uint16_t target, uint32_t timeout_ms) {
  int rc;
  printf("  -> C01Fh      install Integrator key     [under Provisioning key]\n");
  printf("  -> C01Fh      install Operator key       [under Integrator key]\n");
  rc = fbsec_commission_install_ladder(transport, target, timeout_ms);
  if (rc != 0) {
    printf("  key ladder failed (rc=%d)\n", rc);
  } else {
    printf("     all session keys set; device Operational\n");
  }
}
#endif

/* Perform one selected transition. Returns true if the caller should re-read
   state (an action ran, wired or not). */
static bool lifecycle_do_action(lifecycle_action_t a,
                                const fbsec_secure_transport_t *transport,
                                uint16_t target, uint32_t timeout_ms) {
#if !FBSEC_FEATURE_ASYM
  (void)transport; (void)target; (void)timeout_ms;
#endif
  switch (a) {
#if FBSEC_FEATURE_ASYM
#if FBSEC_HANDOVER_AUTHORIZED
    case LC_ACT_VOUCHER: {
      uint8_t  vbuf[FBSEC_HO_VOUCHER_LEN];
      uint16_t vlen = 0u;
      int      rc;
      if (fbsec_commission_get_voucher(vbuf, (uint16_t)sizeof vbuf, &vlen) == 0) {
        printf("  loading ownership voucher (%u bytes):\n", (unsigned)vlen);
        lifecycle_dump_hex(vbuf, vlen);
      }
      printf("  -> C020h:02h  present voucher (ownership claim)\n");
      rc = fbsec_commission_present_voucher(transport, target, timeout_ms);
      if (rc != 0) {
        printf("  voucher claim rejected (rc=%d); device not owned\n", rc);
        return true;
      }
      printf("     ownership claimed (Owned)\n");
      printf("  -> C02Fh      install Provisioning key   [Ed25519-signed]\n");
      rc = fbsec_commission_install_provisioning(transport, target, timeout_ms);
      if (rc != 0) {
        printf("  Provisioning-key install failed (rc=%d)\n", rc);
        return true;
      }
      printf("     Provisioning key installed\n");
      lifecycle_run_ladder(transport, target, timeout_ms);
      return true;
    }
#endif
    case LC_ACT_TOKEN: {
      int rc;
      printf("  loading Device Claim Token (%u bytes):\n",
             (unsigned)FBSEC_AEAD_KEY_SIZE);
      lifecycle_dump_hex(fbsec_commission_claim_token(),
                         (uint16_t)FBSEC_AEAD_KEY_SIZE);
      printf("  -> C01Fh      install Provisioning key   [under Device Claim Token]\n");
      rc = fbsec_commission_install_provisioning_by_token(transport, target,
                                                          timeout_ms);
      if (rc != 0) {
        printf("  token claim / Provisioning install failed (rc=%d)\n", rc);
        return true;
      }
      printf("     ownership claimed; Provisioning key installed\n");
      lifecycle_run_ladder(transport, target, timeout_ms);
      return true;
    }
    case LC_ACT_LADDER:
      lifecycle_run_ladder(transport, target, timeout_ms);
      return true;
    case LC_ACT_DECOMMISSION: {
      int rc = fbsec_rpk_command(transport, target,
                                 FBSEC_HO_CMD_FACTORY_RESTORE, timeout_ms);
      if (rc == 0) {
        printf("  device decommissioned: keys erased, ready to commission "
               "again\n");
      } else {
        printf("  decommission failed (rc=%d)\n", rc);
      }
      return true;
    }
#else
    case LC_ACT_VOUCHER:
    case LC_ACT_TOKEN:
    case LC_ACT_LADDER:
    case LC_ACT_DECOMMISSION:
      printf("  lifecycle actions need the RPK (asymmetric) feature\n");
      return false;
#endif
    default:
      printf("  this transition is not wired in this build yet\n");
      return false;
  }
}

/* State-driven lifecycle submenu. Reads the live server state on entry and
   after each action, and offers only the transitions valid now. The voucher
   gate performs a real claim + Provisioning-key install; the token gate, the
   key ladder and decommission land in later phases. */
static void lifecycle_submenu(const fbsec_secure_transport_t *transport,
                              uint16_t target, uint32_t timeout_ms) {
  char line[32];
  for (;;) {
    lifecycle_state_t  st = lifecycle_read_state(transport, target, timeout_ms);
    lifecycle_action_t acts[LC_ACT_MAX];
    unsigned           n = st.ok ? lifecycle_actions(&st, acts) : 0u;

    lifecycle_print(&st, target, acts, n);

    printf("Lifecycle choice: ");
    fflush(stdout);
    if (read_line(line, sizeof line) == 0) {
      printf("\n");
      return;
    }
    if (line[0] == '\0') {
      continue;
    }
    if (line[0] == 'q' || line[0] == 'Q') {
      return;
    }

    {
      char         *end = NULL;
      unsigned long sel = strtoul(line, &end, 10);
      if ((end == line) || (*end != '\0') || (sel < 1ul) || (sel > n)) {
        printf("  ?? not an option here: %s\n", line);
        continue;
      }
      (void)lifecycle_do_action(acts[sel - 1ul], transport, target, timeout_ms);
    }
  }
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

  /* The session-key choice is deferred to the first AEAD operation (see
     ensure_key_selected): an uncommissioned device has no key to use until
     the handover has installed one. */

  uint16_t wr_counter  = 0u;
  uint32_t bin_counter = 1u;
  char     line[32];
  for (;;) {
    printf("\n");
    printf("=== fbsec client menu  (target 0x%02X  bus %s  %s) ===\n",
           (unsigned)(target & 0xFFu), cfg->bus_label,
           fbsec_client_keys_use_encryption() ? "encrypt+auth" : "auth-only (MAC)");
    printf("  0) %-24s  reads the const security params (no key)\n",
           "Scan security parameters");
    printf("  --- AEAD (AES-128-GCM) ---\n");
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
#if FBSEC_FEATURE_ASYM
    printf("  --- RPK (Ed25519 signed) ---\n");
    printf("  A) %-24s  C028h  signed identity read (RPK)\n",
           "Signed identity read");
    printf("  B) %-24s  C042h->0x2021 signed read (RPK)\n",
           "Signed read");
    printf("  C) %-24s  C042h->0x2017 signed write (RPK)\n",
           "Signed write");
    printf("  D) %-24s  C049h  signed function command (RPK)\n",
           "Signed command");
#endif
    printf("  --------------------------\n");
    printf("  L) %-24s  commissioning lifecycle submenu\n", "Lifecycle");
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
    if (c == '0') {
      scan_security_params(transport, target, cfg->timeout_ms);
      continue;
    }
    fbsec_client_trace_print_legend();
    if ((c >= '1') && (c <= '6')) {
      /* AEAD ops need a session key; pick one now if none is selected yet. */
      ensure_key_selected();
    }
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
#if FBSEC_FEATURE_ASYM
    } else if (c == 'a' || c == 'A') {
      int rc = fbsec_commission_verify_genuineness(transport, target,
                                                   cfg->timeout_ms);
      if (rc == 0) {
        printf("  signed identity verified (C028h): device genuine\n");
      } else {
        printf("  signed identity read failed (rc=%d)\n", rc);
      }
    } else if (c == 'b' || c == 'B') {
      uint8_t  buf[FBSEC_RPK_VALUE_MAX];
      uint32_t n  = 0u;
      int rc = fbsec_rpk_signed_read(transport, target, 0x2021u, 0x00u,
                                     buf, sizeof buf, &n, cfg->timeout_ms);
      if (rc == 0) {
        uint32_t i;
        printf("  C042h signed read OK, %u bytes:", (unsigned)n);
        for (i = 0u; i < n; ++i) { printf(" %02X", buf[i]); }
        printf("  (device signature verified)\n");
      } else {
        printf("  C042h signed read failed (rc=%d)\n", rc);
      }
    } else if (c == 'c' || c == 'C') {
      uint8_t buf[MENU_BIN_LEN];
      buf[0] = (uint8_t)((bin_counter >> 24) & 0xFFu);
      buf[1] = (uint8_t)((bin_counter >> 16) & 0xFFu);
      buf[2] = (uint8_t)((bin_counter >>  8) & 0xFFu);
      buf[3] = (uint8_t)( bin_counter        & 0xFFu);
      memset(&buf[4], 0xDDu, MENU_BIN_LEN - 4u);
      {
        int rc = fbsec_rpk_signed_write(transport, target, 0x2017u, 0x00u,
                                        buf, MENU_BIN_LEN, cfg->timeout_ms);
        if (rc == 0) {
          printf("  C042h signed write OK (0x2017)\n");
        } else {
          printf("  C042h signed write failed (rc=%d)\n", rc);
        }
      }
      ++bin_counter;
    } else if (c == 'd' || c == 'D') {
      char     codeline[16];
      uint32_t code = 0x0001u;
      printf("Command code (hex, blank = 0001): ");
      fflush(stdout);
      if (read_line(codeline, sizeof codeline) != 0 && codeline[0] != '\0') {
        code = (uint32_t)strtoul(codeline, NULL, 16);
      }
      {
        int rc = fbsec_rpk_command(transport, target, code, cfg->timeout_ms);
        if (rc == 0) {
          printf("  C049h command 0x%08lX sent and acknowledged\n",
                 (unsigned long)code);
        } else {
          printf("  C049h command failed (rc=%d)\n", rc);
        }
      }
#endif
    } else if (c == 'l' || c == 'L') {
      lifecycle_submenu(transport, target, cfg->timeout_ms);
    } else {
      printf("?? unrecognised choice: %s\n", line);
    }
  }

  return 0;
}

/* EOF */
