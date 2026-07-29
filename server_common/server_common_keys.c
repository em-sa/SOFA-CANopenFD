/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    server_common_keys.c
 * @brief   SOFA server_common, demo keys + key-file loader, impl.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.1 of 22-JUL-2026
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#include "server_common_keys.h"
#include "server_common_lifecycle.h"

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

/* Per-unit Device Claim Token (demo). On a real device this is a printed,
   per-serial secret injected at manufacture; the client passes the same
   bytes via --claim-token. It is used directly as the AEAD key that
   authorizes the first (Provisioning) rung of the C01Fh ladder; a
   production device would KDF it. Must match the client-side default in
   client_common_commission.c. */
const uint8_t FBSEC_DEMO_CLAIM_TOKEN[32] = {
  0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
  0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10,
  0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
  0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10
};

/* ---- Demo key install ------------------------------------------------- */

void fbsec_server_install_demo_keys_if_unset(void) {
  /* Demo key ids are set distinct from the slot/role number (0x1001..)
     so C011h visibly reports an id independent of the role. */
  if (!fbsec_sod_has_key(FBSEC_DEMO_KEYID_PROVISIONING)) {
    (void)fbsec_sod_set_key_ex(FBSEC_DEMO_KEYID_PROVISIONING,
                               FBSEC_DEMO_KEY_PROVISIONING,
                               FBSEC_DEMO_KEYID_VALUE_PROVISIONING);
  }
  if (!fbsec_sod_has_key(FBSEC_DEMO_KEYID_INTEGRATOR)) {
    (void)fbsec_sod_set_key_ex(FBSEC_DEMO_KEYID_INTEGRATOR,
                               FBSEC_DEMO_KEY_INTEGRATOR,
                               FBSEC_DEMO_KEYID_VALUE_INTEGRATOR);
  }
  if (!fbsec_sod_has_key(FBSEC_DEMO_KEYID_OPERATOR)) {
    (void)fbsec_sod_set_key_ex(FBSEC_DEMO_KEYID_OPERATOR,
                               FBSEC_DEMO_KEY_OPERATOR,
                               FBSEC_DEMO_KEYID_VALUE_OPERATOR);
  }
}

void fbsec_server_install_claim_token(void) {
  if (!fbsec_sod_has_key(FBSEC_DEMO_KEYID_CLAIM_TOKEN)) {
    (void)fbsec_sod_set_key_ex(FBSEC_DEMO_KEYID_CLAIM_TOKEN,
                               FBSEC_DEMO_CLAIM_TOKEN,
                               FBSEC_DEMO_KEYID_VALUE_CLAIM_TOKEN);
  }
}

/* ---- C01Fh install ladder -------------------------------------------- */

fbsec_abort_t fbsec_server_apply_key_set(const uint8_t *body, uint16_t len) {
  uint8_t  selector;
  uint32_t keyid_val;
  uint8_t  authorizing;
  uint8_t  need;

  if ((body == NULL) || (len != (uint16_t)FBSEC_KEY_SET_BODY_LEN)) {
    return FBSEC_ABORT_TYPE_MISMATCH;
  }
  selector  = body[0];
  keyid_val = (uint32_t)body[1]
            | ((uint32_t)body[2] << 8)
            | ((uint32_t)body[3] << 16)
            | ((uint32_t)body[4] << 24);

  /* Rolling-key ladder: installing a tier must be authorized by the tier
     below it (the key just proven present via the verified AEAD tag). */
  switch (selector) {
    case FBSEC_DEMO_KEYID_PROVISIONING: need = FBSEC_DEMO_KEYID_CLAIM_TOKEN;  break;
    case FBSEC_DEMO_KEYID_INTEGRATOR:   need = FBSEC_DEMO_KEYID_PROVISIONING; break;
    case FBSEC_DEMO_KEYID_OPERATOR:     need = FBSEC_DEMO_KEYID_INTEGRATOR;   break;
    default:                            return FBSEC_ABORT_TYPE_MISMATCH; /* unknown tier */
  }
  authorizing = fbsec_sod_last_write_key_id();
  if (authorizing != need) {
    return FBSEC_ABORT_ROLE_DENIED;      /* wrong authorizing key for this rung */
  }
  if (fbsec_sod_has_key(selector)) {
    return FBSEC_ABORT_DEVICE_STATE;     /* rung already installed (write-once) */
  }
  if (!fbsec_sod_set_key_ex(selector, &body[5], keyid_val)) {
    return FBSEC_ABORT_DEVICE_STATE;
  }

  /* Advance the observable lifecycle from the rung just installed:
     Operator present => Operational, else Provisioning present => Owned. */
  if (fbsec_sod_has_key(FBSEC_DEMO_KEYID_OPERATOR)) {
    fbsec_server_lifecycle_set(FBSEC_STAGE_OPERATIONAL);
  } else if (fbsec_sod_has_key(FBSEC_DEMO_KEYID_PROVISIONING)) {
    fbsec_server_lifecycle_set(FBSEC_STAGE_OWNED);
  }
  return FBSEC_ABORT_NONE;
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
    char         *hash;
    char         *t_kid;
    char         *t_label;
    char         *t_key;
    char         *t_id;
    char         *endp;
    unsigned long kid;
    unsigned long idv;
    uint8_t       key[FBSEC_AEAD_KEY_SIZE];
    size_t        klen;

    /* Strip a trailing comment before tokenizing. */
    hash = strchr(line, '#');
    if (hash != NULL) {
      *hash = '\0';
    }

    /* Row: <keyid> <label> <hex-key> [<u32-id>]. The id column is
       optional; absent, the non-secret key id defaults to the keyid. */
    t_kid = strtok(line, " \t\r\n");
    if (t_kid == NULL) {
      continue;                             /* blank / comment-only line */
    }
    endp = NULL;
    kid = strtoul(t_kid, &endp, 0);
    if (endp == t_kid || *endp != '\0' || kid < 1u || kid > 255u) {
      fprintf(stderr, "key-file: bad keyid '%s'\n", t_kid);
      (void)fclose(f);
      return -1;
    }

    t_label = strtok(NULL, " \t\r\n");
    t_key   = strtok(NULL, " \t\r\n");
    if (t_label == NULL || t_key == NULL) {
      fprintf(stderr, "key-file: keyid %lu missing label or key\n", kid);
      (void)fclose(f);
      return -1;
    }

    klen = fbsec_server_parse_hex_strict(t_key, key, sizeof key);
    if (klen != FBSEC_AEAD_KEY_SIZE) {
      fprintf(stderr, "key-file: keyid %lu not %u hex bytes\n",
              kid, (unsigned)FBSEC_AEAD_KEY_SIZE);
      (void)fclose(f);
      return -1;
    }

    idv = kid;                              /* default id = keyid */
    t_id = strtok(NULL, " \t\r\n");
    if (t_id != NULL) {
      endp = NULL;
      idv = strtoul(t_id, &endp, 0);
      if (endp == t_id || *endp != '\0') {
        fprintf(stderr, "key-file: keyid %lu bad id '%s'\n", kid, t_id);
        (void)fclose(f);
        return -1;
      }
    }

    if (!fbsec_sod_set_key_ex((uint8_t)kid, key, (uint32_t)idv)) {
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
