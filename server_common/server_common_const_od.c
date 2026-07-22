/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    server_common_const_od.c
 * @brief   SOFA server_common, constant unsecured OD value table, impl.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 22-JUL-2026
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#include "server_common_const_od.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct const_od_entry_t {
  uint16_t index;
  uint8_t  sub;
  uint8_t  len;
  uint8_t  data[FBSEC_CONST_OD_MAX_DATA];
} const_od_entry_t;

static const_od_entry_t g_table[FBSEC_CONST_OD_MAX_ENTRIES];
static uint8_t          g_count = 0u;

void fbsec_const_od_init(void) {
  memset(g_table, 0, sizeof g_table);
  g_count = 0u;
}

/* Parse one whitespace-delimited hex token into @p out (0..0xFFFFFFFF).
   Returns true on a valid, fully-consumed hex token. */
static bool parse_hex_token(const char *tok, unsigned long *out) {
  char *end = NULL;
  unsigned long v;
  if ((tok == NULL) || (*tok == '\0')) {
    return false;
  }
  v = strtoul(tok, &end, 16);
  if ((end == tok) || (*end != '\0')) {
    return false;
  }
  *out = v;
  return true;
}

int fbsec_const_od_load_file(const char *path) {
  FILE *f;
  char  line[256];
  int   lineno = 0;

  if (path == NULL) {
    return -1;
  }
  f = fopen(path, "r");
  if (f == NULL) {
    fprintf(stderr, "server_common: cannot open od-file '%s'\n", path);
    return -1;
  }

  while (fgets(line, (int)sizeof line, f) != NULL) {
    char         *hash;
    char         *tok;
    unsigned long v;
    const_od_entry_t e;
    uint8_t       i;

    lineno++;

    /* Strip a trailing comment, then tokenize what remains. */
    hash = strchr(line, '#');
    if (hash != NULL) {
      *hash = '\0';
    }

    tok = strtok(line, " \t\r\n");
    if (tok == NULL) {
      continue;                       /* blank / comment-only line */
    }

    memset(&e, 0, sizeof e);

    /* index */
    if (!parse_hex_token(tok, &v) || (v > 0xFFFFu)) {
      fprintf(stderr, "server_common: od-file line %d: bad index\n", lineno);
      (void)fclose(f);
      return -1;
    }
    e.index = (uint16_t)v;

    /* sub */
    tok = strtok(NULL, " \t\r\n");
    if (!parse_hex_token(tok, &v) || (v > 0xFFu)) {
      fprintf(stderr, "server_common: od-file line %d: bad sub-index\n", lineno);
      (void)fclose(f);
      return -1;
    }
    e.sub = (uint8_t)v;

    /* len */
    tok = strtok(NULL, " \t\r\n");
    if (!parse_hex_token(tok, &v) || (v > FBSEC_CONST_OD_MAX_DATA)) {
      fprintf(stderr, "server_common: od-file line %d: bad length\n", lineno);
      (void)fclose(f);
      return -1;
    }
    e.len = (uint8_t)v;

    /* data bytes */
    for (i = 0u; i < e.len; ++i) {
      tok = strtok(NULL, " \t\r\n");
      if (!parse_hex_token(tok, &v) || (v > 0xFFu)) {
        fprintf(stderr, "server_common: od-file line %d: bad data byte %u\n",
                lineno, (unsigned)i);
        (void)fclose(f);
        return -1;
      }
      e.data[i] = (uint8_t)v;
    }

    /* reject trailing junk beyond the declared length */
    if (strtok(NULL, " \t\r\n") != NULL) {
      fprintf(stderr, "server_common: od-file line %d: extra tokens\n", lineno);
      (void)fclose(f);
      return -1;
    }

    if (g_count >= FBSEC_CONST_OD_MAX_ENTRIES) {
      fprintf(stderr, "server_common: od-file too large (max %u entries)\n",
              (unsigned)FBSEC_CONST_OD_MAX_ENTRIES);
      (void)fclose(f);
      return -1;
    }
    g_table[g_count] = e;
    ++g_count;
  }

  (void)fclose(f);
  return 0;
}

const uint8_t *fbsec_const_od_get(uint16_t index, uint8_t sub,
                                  uint16_t *len_out) {
  uint8_t i;
  for (i = 0u; i < g_count; ++i) {
    if ((g_table[i].index == index) && (g_table[i].sub == sub)) {
      if (len_out != NULL) {
        *len_out = g_table[i].len;
      }
      return g_table[i].data;
    }
  }
  return NULL;
}

bool fbsec_const_od_get_identity(uint8_t out16[16]) {
  uint16_t off = 0u;
  uint8_t  sub;

  for (sub = 1u; sub <= 4u; ++sub) {
    uint16_t       len = 0u;
    const uint8_t *p   = fbsec_const_od_get(FBSEC_OD_IDENTITY_INDEX, sub, &len);
    if (p == NULL) {
      return false;
    }
    if ((uint16_t)(off + len) > 16u) {
      return false;
    }
    memcpy(&out16[off], p, len);
    off = (uint16_t)(off + len);
  }
  return (off == 16u);
}

/* EOF */
