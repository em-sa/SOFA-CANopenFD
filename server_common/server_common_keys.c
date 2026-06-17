/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    server_common_keys.c
 * @brief   SOFA server_common, demo keys + key-file loader, impl.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 07-MAY-2026
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#include "server_common_keys.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fbsec_aead.h"
#include "fbsec_secure_od.h"

/* ---- Demo per-session key constants ----------------------------------- */

/* These three values are the "Provisioning / Integrator / Operator Session
   Key" slots in WP-104 §3.4 terms: on a real device they would be derived
   from each layer's master key via HKDF(layer_master, salt, info). SOFA
   simulates the masters and the derivation step out and installs these
   values directly. Mirrors the client-side defaults in
   client_common_keys.c. */

const uint8_t FBSEC_DEMO_KEY_PROVISIONING[32] = {
  0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
  0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
  0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
  0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
};
const uint8_t FBSEC_DEMO_KEY_INTEGRATOR[32] = {
  0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11,
  0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,
  0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11,
  0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99
};
const uint8_t FBSEC_DEMO_KEY_OPERATOR[32] = {
  0xFF,0xEE,0xDD,0xCC,0xBB,0xAA,0x99,0x88,
  0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,
  0xFF,0xEE,0xDD,0xCC,0xBB,0xAA,0x99,0x88,
  0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00
};

/* ---- Demo key install ------------------------------------------------- */

void fbsec_server_install_demo_keys_if_unset(void) {
  if (!fbsec_sod_has_key(FBSEC_DEMO_KEYID_PROVISIONING)) {
    (void)fbsec_sod_set_key(FBSEC_DEMO_KEYID_PROVISIONING, FBSEC_DEMO_KEY_PROVISIONING);
  }
  if (!fbsec_sod_has_key(FBSEC_DEMO_KEYID_INTEGRATOR)) {
    (void)fbsec_sod_set_key(FBSEC_DEMO_KEYID_INTEGRATOR,   FBSEC_DEMO_KEY_INTEGRATOR);
  }
  if (!fbsec_sod_has_key(FBSEC_DEMO_KEYID_OPERATOR)) {
    (void)fbsec_sod_set_key(FBSEC_DEMO_KEYID_OPERATOR,     FBSEC_DEMO_KEY_OPERATOR);
  }
}

/* ---- Hex string parser ----------------------------------------------- */

size_t fbsec_server_parse_hex_strict(const char *s,
                                     uint8_t    *buf,
                                     size_t      buf_size) {
  size_t  n  = 0;
  int     hi = -1;
  if (s == NULL) {
    return 0;
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
      return 0;
    }
    if (hi < 0) {
      hi = nib;
    } else {
      if (n >= buf_size) {
        return 0;
      }
      buf[n++] = (uint8_t)((hi << 4) | nib);
      hi = -1;
    }
  }
  if (hi >= 0) {
    return 0;
  }
  return n;
}

/* ---- Key file loader -------------------------------------------------- */

int fbsec_server_load_key_file(const char *path) {
  FILE *f = NULL;
  if (fopen_s(&f, path, "r") != 0 || f == NULL) {
    fprintf(stderr, "key-file: cannot open '%s'\n", path);
    return -1;
  }
  char line[256];
  unsigned loaded = 0u;
  while (fgets(line, sizeof line, f) != NULL) {
    char *p = line;
    while (*p == ' ' || *p == '\t') {
      ++p;
    }
    if (*p == '#' || *p == '\0' || *p == '\n' || *p == '\r') {
      continue;
    }

    char *endp = NULL;
    unsigned long kid = strtoul(p, &endp, 0);
    if (endp == p || kid < 1u || kid > 255u) {
      fprintf(stderr, "key-file: bad keyid in line '%s'\n", line);
      (void)fclose(f);
      return -1;
    }
    p = endp;
    while (*p == ' ' || *p == '\t') {
      ++p;
    }
    /* skip label token */
    while (*p != '\0' && *p != ' ' && *p != '\t') {
      ++p;
    }
    /* the rest is hex */
    uint8_t key[FBSEC_AEAD_KEY_SIZE];
    size_t klen = fbsec_server_parse_hex_strict(p, key, sizeof key);
    if (klen != FBSEC_AEAD_KEY_SIZE) {
      fprintf(stderr, "key-file: keyid %lu not %u hex bytes\n",
              kid, (unsigned)FBSEC_AEAD_KEY_SIZE);
      (void)fclose(f);
      return -1;
    }
    if (!fbsec_sod_set_key((uint8_t)kid, key)) {
      fprintf(stderr, "key-file: keyid %lu rejected\n", kid);
      (void)fclose(f);
      return -1;
    }
    ++loaded;
  }
  (void)fclose(f);
  if (loaded == 0u) {
    fprintf(stderr, "key-file '%s' contains no keys\n", path);
    return -1;
  }
  return 0;
}

/* EOF */
