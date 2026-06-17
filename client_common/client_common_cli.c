/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    client_common_cli.c
 * @brief   SOFA client_common, shared CLI helpers, implementation.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 07-MAY-2026
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#include "client_common_cli.h"
#include "client_common_keys.h"
#include "client_common_platform.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fbsec_aead.h"

#define FBSEC_CLIENT_KDF_INFO_PREFIX "FBSEC-SK-v1"

int fbsec_client_cli_parse_u32(const char *s, uint32_t *out) {
  if (s == NULL || *s == '\0') {
    return -1;
  }
  char *end = NULL;
  unsigned long v = strtoul(s, &end, 0);
  if (end == s || *end != '\0') {
    return -1;
  }
#if ULONG_MAX > 0xFFFFFFFFul
  /* LP64: unsigned long is 64-bit, so reject values that would truncate
     when narrowed to uint32_t. On LLP64 (MSVC) / ILP32 unsigned long is
     32-bit and this guard compiles out (no always-false comparison). */
  if (v > 0xFFFFFFFFul) {
    return -1;
  }
#endif
  *out = (uint32_t)v;
  return 0;
}

int fbsec_client_cli_parse_hex(const char *s,
                               uint8_t *buf, size_t buf_size,
                               size_t *len_out) {
  size_t n = 0;
  int    hi = -1;
  if (s == NULL) {
    return -1;
  }
  while (*s != '\0') {
    char c = *s++;
    if (c == ' ' || c == '\t' || c == ':' || c == '-' || c == ',' ||
        c == '\r' || c == '\n') {
      continue;
    }
    int nib;
    if      (c >= '0' && c <= '9') {
      nib = c - '0';
    } else if (c >= 'a' && c <= 'f') {
      nib = c - 'a' + 10;
    } else if (c >= 'A' && c <= 'F') {
      nib = c - 'A' + 10;
    } else {
      return -1;
    }
    if (hi < 0) {
      hi = nib;
    } else {
      if (n >= buf_size) {
        return -1;
      }
      buf[n++] = (uint8_t)((hi << 4) | nib);
      hi = -1;
    }
  }
  if (hi >= 0) {
    return -1;
  }
  *len_out = n;
  return 0;
}

void fbsec_client_cli_print_banner(const char *banner_name,
                                   const char *version_str,
                                   const char *version_date) {
  printf("\n");
  printf("%s, version %s of %s\n", banner_name, version_str, version_date);
  printf("by EmSA (www.Em-SA.com)\n");
  printf("\n");
}

bool fbsec_client_cli_resolve_color(fbsec_client_color_pref_t pref) {
  bool use_color = false;
  switch (pref) {
    case FBSEC_CLIENT_COLOR_NEVER:  use_color = false; break;
    case FBSEC_CLIENT_COLOR_ALWAYS: use_color = true;  break;
    case FBSEC_CLIENT_COLOR_AUTO:
    default: use_color = fbsec_client_stdout_is_console(); break;
  }
  if (use_color) {
    fbsec_client_console_enable_ansi();
  }
  return use_color;
}

bool fbsec_client_cli_resolve_show_ts(fbsec_client_ts_state_t state, bool in_batch) {
  switch (state) {
    case FBSEC_CLIENT_TS_ON:  return true;
    case FBSEC_CLIENT_TS_OFF: return false;
    case FBSEC_CLIENT_TS_DEFAULT:
    default:                  return in_batch;
  }
}

/* ---- Common-flag matcher --------------------------------------------- */

#define DEV_RESERVED  0x0000u
#define DEV_BROADCAST 0xFFFFu

fbsec_client_cli_result_t fbsec_client_cli_try_common_flag(
    int                *iref,
    int                 argc,
    char              **argv,
    fbsec_client_cfg_t *cfg,
    uint16_t           *my_dev_inout,
    const char         *exec_name) {
  int i = *iref;
  const char *a = argv[i];

  if (strcmp(a, "--help") == 0) {
    return FBSEC_CLIENT_CLI_HELP;
  }
  if (strcmp(a, "--device-id") == 0 && (i + 1) < argc) {
    uint32_t v;
    if (fbsec_client_cli_parse_u32(argv[i + 1], &v) != 0
        || v == DEV_RESERVED || v >= DEV_BROADCAST) {
      fprintf(stderr, "%s: invalid --device-id\n", exec_name);
      return FBSEC_CLIENT_CLI_ERROR;
    }
    if (my_dev_inout != NULL) {
      *my_dev_inout = (uint16_t)v;
    }
    *iref = i + 2;
    return FBSEC_CLIENT_CLI_HANDLED;
  }
  if (strcmp(a, "--timeout") == 0 && (i + 1) < argc) {
    uint32_t v;
    if (fbsec_client_cli_parse_u32(argv[i + 1], &v) != 0 || v == 0u) {
      fprintf(stderr, "%s: invalid --timeout\n", exec_name);
      return FBSEC_CLIENT_CLI_ERROR;
    }
    cfg->timeout_ms = v;
    *iref = i + 2;
    return FBSEC_CLIENT_CLI_HANDLED;
  }
  if (strcmp(a, "--count") == 0 && (i + 1) < argc) {
    uint32_t v;
    if (fbsec_client_cli_parse_u32(argv[i + 1], &v) != 0 || v == 0u) {
      fprintf(stderr, "%s: invalid --count\n", exec_name);
      return FBSEC_CLIENT_CLI_ERROR;
    }
    cfg->count = v;
    *iref = i + 2;
    return FBSEC_CLIENT_CLI_HANDLED;
  }
  if (strcmp(a, "--verbose") == 0)        { cfg->verbose = true;  *iref = i + 1; return FBSEC_CLIENT_CLI_HANDLED; }
  if (strcmp(a, "--quiet") == 0)          { cfg->quiet   = true;  *iref = i + 1; return FBSEC_CLIENT_CLI_HANDLED; }
  if (strcmp(a, "--timestamp") == 0)      { cfg->ts_state = FBSEC_CLIENT_TS_ON;  *iref = i + 1; return FBSEC_CLIENT_CLI_HANDLED; }
  if (strcmp(a, "--no-timestamp") == 0)   { cfg->ts_state = FBSEC_CLIENT_TS_OFF; *iref = i + 1; return FBSEC_CLIENT_CLI_HANDLED; }
  if (strcmp(a, "--color") == 0)          { cfg->color_pref = FBSEC_CLIENT_COLOR_ALWAYS; *iref = i + 1; return FBSEC_CLIENT_CLI_HANDLED; }
  if (strcmp(a, "--no-color") == 0)       { cfg->color_pref = FBSEC_CLIENT_COLOR_NEVER;  *iref = i + 1; return FBSEC_CLIENT_CLI_HANDLED; }
  if (strcmp(a, "--encrypt") == 0)        { fbsec_client_keys_set_use_encryption(true);  *iref = i + 1; return FBSEC_CLIENT_CLI_HANDLED; }
  if (strcmp(a, "--no-encrypt") == 0)     { fbsec_client_keys_set_use_encryption(false); *iref = i + 1; return FBSEC_CLIENT_CLI_HANDLED; }
  if (strcmp(a, "--stop-on-fail") == 0)   { cfg->stop_on_fail = true; *iref = i + 1; return FBSEC_CLIENT_CLI_HANDLED; }
  if (strcmp(a, "--menu") == 0)           { cfg->menu_mode = true;    *iref = i + 1; return FBSEC_CLIENT_CLI_HANDLED; }
  if (strcmp(a, "--hex") == 0)            { cfg->hex = true;          *iref = i + 1; return FBSEC_CLIENT_CLI_HANDLED; }
  if (strcmp(a, "--batch") == 0 && (i + 1) < argc) {
    cfg->batch_path = argv[i + 1];
    cfg->in_batch   = true;
    *iref = i + 2;
    return FBSEC_CLIENT_CLI_HANDLED;
  }
  if (strcmp(a, "--out") == 0 && (i + 1) < argc) {
    cfg->out_path = argv[i + 1];
    *iref = i + 2;
    return FBSEC_CLIENT_CLI_HANDLED;
  }

  /* Key flags routed to client_common_keys. */
  if (strcmp(a, "--key") == 0 && (i + 1) < argc) {
    if (fbsec_client_keys_keyid() == 0u) {
      fprintf(stderr,
              "%s: --keyid N must be passed before --key (so we know which "
              "of the 1..%u session-key slots to write)\n",
              exec_name, (unsigned)FBSEC_AEAD_KEYID_MAX);
      return FBSEC_CLIENT_CLI_ERROR;
    }
    if (!fbsec_client_keys_set_session_from_hex(argv[i + 1])) {
      fprintf(stderr, "%s: --key must be %u hex bytes\n",
              exec_name, (unsigned)FBSEC_AEAD_KEY_SIZE);
      return FBSEC_CLIENT_CLI_ERROR;
    }
    *iref = i + 2;
    return FBSEC_CLIENT_CLI_HANDLED;
  }
  if (strcmp(a, "--main-key") == 0 && (i + 1) < argc) {
    if (!fbsec_client_keys_set_main_from_hex(argv[i + 1])) {
      fprintf(stderr, "%s: --main-key must be %u hex bytes\n",
              exec_name, (unsigned)FBSEC_AEAD_KEY_SIZE);
      return FBSEC_CLIENT_CLI_ERROR;
    }
    *iref = i + 2;
    return FBSEC_CLIENT_CLI_HANDLED;
  }
  if (strcmp(a, "--salt") == 0 && (i + 1) < argc) {
    if (!fbsec_client_keys_set_salt_from_hex(argv[i + 1])) {
      fprintf(stderr, "%s: --salt must be 1..32 hex bytes\n", exec_name);
      return FBSEC_CLIENT_CLI_ERROR;
    }
    *iref = i + 2;
    return FBSEC_CLIENT_CLI_HANDLED;
  }
  if (strcmp(a, "--keyid") == 0 && (i + 1) < argc) {
    uint32_t v;
    if (fbsec_client_cli_parse_u32(argv[i + 1], &v) != 0
        || v < 1u || v > (uint32_t)FBSEC_AEAD_KEYID_MAX) {
      fprintf(stderr, "%s: --keyid must be 1..%u\n",
              exec_name, (unsigned)FBSEC_AEAD_KEYID_MAX);
      return FBSEC_CLIENT_CLI_ERROR;
    }
    fbsec_client_keys_set_keyid((uint8_t)v);
    *iref = i + 2;
    return FBSEC_CLIENT_CLI_HANDLED;
  }
  if (strcmp(a, "--kdf") == 0 && (i + 1) < argc) {
    if (strcmp(argv[i + 1], FBSEC_CLIENT_KDF_INFO_PREFIX) != 0) {
      fprintf(stderr, "%s: --kdf '%s' not supported (only '%s')\n",
              exec_name, argv[i + 1], FBSEC_CLIENT_KDF_INFO_PREFIX);
      return FBSEC_CLIENT_CLI_ERROR;
    }
    *iref = i + 2;
    return FBSEC_CLIENT_CLI_HANDLED;
  }
  if (strcmp(a, "--key-file") == 0 && (i + 1) < argc) {
    if (fbsec_client_keys_load_file(argv[i + 1]) != 0) {
      return FBSEC_CLIENT_CLI_ERROR;
    }
    *iref = i + 2;
    return FBSEC_CLIENT_CLI_HANDLED;
  }

  return FBSEC_CLIENT_CLI_NOT_MATCHED;
}

/* EOF */
