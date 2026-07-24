/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    server_common_cli.c
 * @brief   SOFA server_common, shared CLI helpers, implementation.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.1 of 22-JUL-2026
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#include "server_common_cli.h"
#include "server_common_platform.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- Number parser ---------------------------------------------------- */

int fbsec_server_cli_parse_u32(const char *s, uint32_t *out) {
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

/* ---- Common-flag matcher --------------------------------------------- */

/* Reserved device id sentinels: 0x0000 reserved, 0xFFFF broadcast.
   Kept here as local constants so server_common stays independent of
   any variant-specific envelope header. */
#define FBSEC_SERVER_DEV_RESERVED  0x0000u
#define FBSEC_SERVER_DEV_BROADCAST 0xFFFFu

fbsec_server_cli_result_t fbsec_server_cli_try_common_flag(
    int                *iref,
    int                 argc,
    char              **argv,
    fbsec_server_cfg_t *cfg,
    const char         *exec_name) {
  int i = *iref;
  const char *a = argv[i];

  if (strcmp(a, "--help") == 0) {
    return FBSEC_SERVER_CLI_HELP;
  }
  if (strcmp(a, "--device-id") == 0 && (i + 1) < argc) {
    uint32_t v;
    if (fbsec_server_cli_parse_u32(argv[i + 1], &v) != 0
        || v == FBSEC_SERVER_DEV_RESERVED
        || v >= FBSEC_SERVER_DEV_BROADCAST) {
      fprintf(stderr, "%s: invalid --device-id\n", exec_name);
      return FBSEC_SERVER_CLI_ERROR;
    }
    cfg->my_dev = (uint16_t)v;
    *iref = i + 2;
    return FBSEC_SERVER_CLI_HANDLED;
  }
  if (strcmp(a, "--verbose") == 0) {
    cfg->verbose = true;
    *iref = i + 1;
    return FBSEC_SERVER_CLI_HANDLED;
  }
  if (strcmp(a, "--quiet") == 0) {
    cfg->quiet = true;
    *iref = i + 1;
    return FBSEC_SERVER_CLI_HANDLED;
  }
  if (strcmp(a, "--color") == 0) {
    cfg->color_pref = FBSEC_SERVER_COLOR_ALWAYS;
    *iref = i + 1;
    return FBSEC_SERVER_CLI_HANDLED;
  }
  if (strcmp(a, "--no-color") == 0) {
    cfg->color_pref = FBSEC_SERVER_COLOR_NEVER;
    *iref = i + 1;
    return FBSEC_SERVER_CLI_HANDLED;
  }
  if (strcmp(a, "--key-file") == 0 && (i + 1) < argc) {
    cfg->key_file_path = argv[i + 1];
    *iref = i + 2;
    return FBSEC_SERVER_CLI_HANDLED;
  }
  if (strcmp(a, "--demo-keys") == 0) {
    cfg->demo_keys = true;
    *iref = i + 1;
    return FBSEC_SERVER_CLI_HANDLED;
  }
  if (strcmp(a, "--od-file") == 0 && (i + 1) < argc) {
    cfg->od_file_path = argv[i + 1];
    *iref = i + 2;
    return FBSEC_SERVER_CLI_HANDLED;
  }
  return FBSEC_SERVER_CLI_NOT_MATCHED;
}

/* ---- Banner / colour resolver ---------------------------------------- */

void fbsec_server_cli_print_banner(const char *banner_name,
                                   const char *version_str,
                                   const char *version_date) {
  printf("\n");
  printf("%s, version %s of %s\n", banner_name, version_str, version_date);
  printf("by EmSA (www.Em-SA.com)\n");
  printf("\n");
}

bool fbsec_server_cli_resolve_color(fbsec_server_color_pref_t pref) {
  bool use_color = false;
  switch (pref) {
    case FBSEC_SERVER_COLOR_NEVER:
      use_color = false;
      break;
    case FBSEC_SERVER_COLOR_ALWAYS:
      use_color = true;
      break;
    case FBSEC_SERVER_COLOR_AUTO:
    default:
      use_color = fbsec_server_stdout_is_console();
      break;
  }
  if (use_color) {
    fbsec_server_console_enable_ansi();
  }
  return use_color;
}

/* EOF */
