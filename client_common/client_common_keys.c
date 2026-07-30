/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    client_common_keys.c
 * @brief   SOFA client_common, key store + RNG + KDF, implementation.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.1 of 22-JUL-2026
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#include "client_common_keys.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#endif

#include "fbsec_aead.h"
#include "fbsec_hkdf.h"

/* ---- Compile-time constants -------------------------------------------- */

#define FBSEC_CLIENT_KDF_INFO_PREFIX     "FBSEC-SK-v1"
#define FBSEC_CLIENT_KDF_INFO_PREFIX_LEN 12u
#define FBSEC_CLIENT_DEFAULT_SALT_SIZE   32u

/* ---- File-static state ------------------------------------------------- */

/* One slot per keyid (1..FBSEC_AEAD_KEYID_MAX). Slot 0 is unused but kept
   so that g_session_keys[g_key_id] indexes cleanly. The menu / CLI lay
   out the three demo session keys in slots 1..3; --key-file may populate
   any subset of slots 1..15. */
static uint8_t  g_session_keys[FBSEC_AEAD_KEYID_MAX + 1u][FBSEC_AEAD_KEY_SIZE];
static bool     g_session_key_loaded[FBSEC_AEAD_KEYID_MAX + 1u];
static uint8_t  g_main_key[FBSEC_AEAD_KEY_SIZE];
static bool     g_main_key_set    = false;
static uint8_t  g_salt[FBSEC_CLIENT_DEFAULT_SALT_SIZE];
static size_t   g_salt_len        = 0;
static uint8_t  g_key_id          = 0;
static bool     g_use_encryption  = (FBSEC_AEAD_ENCRYPTION != 0);

static uint8_t  g_observed_salt[FBSEC_AEAD_RAND_SIZE];
static uint16_t g_observed_salt_len = 0u;

/* Role labels for the demo slot triple, used in the load-file summary log. */
/**
 * @brief  Map a demo slot keyid to its human-readable role label.
 * @param  keyid  Session-key slot id (1..FBSEC_AEAD_KEYID_MAX).
 * @return Static role-label string, or NULL if the keyid is not one of the
 *         three demo slots.
 */
static const char *demo_role_label(uint8_t keyid) {
  switch (keyid) {
    case FBSEC_CLIENT_KEYID_PROVISIONING: return "Provisioning Key";
    case FBSEC_CLIENT_KEYID_INTEGRATOR:   return "Integrator Key";
    case FBSEC_CLIENT_KEYID_OPERATOR:     return "Operator Key";
    default:                              return NULL;
  }
}

/* Demo per-session keys (file-static; loaded via fbsec_client_keys_load_demo).
   These are the "Provisioning / Integrator / Operator Session Key" slots in
   WP-104 terms: on a real device they would be derived from the layer master
   keys via HKDF(layer_master, salt, info); SOFA simulates the masters and the
   derivation step out and uses these values directly. Sized at 32 bytes for
   AES-256-GCM builds; FBSEC_AEAD_KEY_SIZE bytes are actually copied. Mirror
   the server-side defaults in server_common_keys.c. */
static const uint8_t DEMO_KEY_PROVISIONING[32] = {
  0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
  0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
  0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
  0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
};
static const uint8_t DEMO_KEY_INTEGRATOR[32] = {
  0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11,
  0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,
  0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11,
  0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99
};
static const uint8_t DEMO_KEY_OPERATOR[32] = {
  0xFF,0xEE,0xDD,0xCC,0xBB,0xAA,0x99,0x88,
  0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,
  0xFF,0xEE,0xDD,0xCC,0xBB,0xAA,0x99,0x88,
  0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00
};

/* ---- Internal: hex-string parser (also used by trace via cli) -------- */

/**
 * @brief  Parse a hex string into a byte buffer, ignoring common separators.
 * @param  s         NUL-terminated hex string (spaces, tabs, ':', '-', ','
 *                   and line breaks are skipped).
 * @param  buf       Destination byte buffer.
 * @param  buf_size  Capacity of @p buf in bytes.
 * @param  len_out   Receives the number of bytes written.
 * @retval 0   Success.
 * @retval -1  NULL input, invalid character, odd nibble count, or overflow.
 */
static int parse_hex_to_buf(const char *s, uint8_t *buf, size_t buf_size, size_t *len_out) {
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

/* ---- Setters --------------------------------------------------------- */

bool fbsec_client_keys_set_session_from_hex(const char *hex) {
  if (g_key_id == 0u || g_key_id > FBSEC_AEAD_KEYID_MAX) {
    /* --keyid must precede --key so we know which slot to write. */
    return false;
  }
  size_t klen = 0;
  if (parse_hex_to_buf(hex, g_session_keys[g_key_id],
                       FBSEC_AEAD_KEY_SIZE, &klen) != 0
      || klen != FBSEC_AEAD_KEY_SIZE) {
    return false;
  }
  g_session_key_loaded[g_key_id] = true;
  return true;
}

bool fbsec_client_keys_set_session(const uint8_t *key) {
  if (g_key_id == 0u || g_key_id > FBSEC_AEAD_KEYID_MAX || key == NULL) {
    return false;
  }
  memcpy(g_session_keys[g_key_id], key, FBSEC_AEAD_KEY_SIZE);
  g_session_key_loaded[g_key_id] = true;
  return true;
}

bool fbsec_client_keys_set_main_from_hex(const char *hex) {
  size_t klen = 0;
  if (parse_hex_to_buf(hex, g_main_key, sizeof g_main_key, &klen) != 0
      || klen != FBSEC_AEAD_KEY_SIZE) {
    return false;
  }
  g_main_key_set = true;
  return true;
}

bool fbsec_client_keys_set_salt_from_hex(const char *hex) {
  if (parse_hex_to_buf(hex, g_salt, sizeof g_salt, &g_salt_len) != 0
      || g_salt_len == 0) {
    return false;
  }
  return true;
}

void fbsec_client_keys_set_keyid(uint8_t key_id) {
  g_key_id = key_id;
}

void fbsec_client_keys_set_use_encryption(bool on) {
  g_use_encryption = on;
}

/* ---- Getters --------------------------------------------------------- */

bool fbsec_client_keys_session_set(void) {
  if (g_key_id == 0u || g_key_id > FBSEC_AEAD_KEYID_MAX) {
    return false;
  }
  return g_session_key_loaded[g_key_id];
}
bool fbsec_client_keys_main_set(void)           { return g_main_key_set;    }
size_t fbsec_client_keys_salt_len(void)         { return g_salt_len;        }
uint8_t fbsec_client_keys_keyid(void)           { return g_key_id;          }
bool fbsec_client_keys_use_encryption(void)     { return g_use_encryption;  }
const uint8_t *fbsec_client_keys_session(void) {
  if (g_key_id == 0u || g_key_id > FBSEC_AEAD_KEYID_MAX) {
    return g_session_keys[0]; /* zero buffer; callers treat session_set() */
  }
  return g_session_keys[g_key_id];
}

uint8_t fbsec_client_keys_effective_keyid(void) {
  if (g_key_id == 0u) {
    return 0u;
  }
  uint8_t base = FBSEC_AEAD_KEYID_BASE(g_key_id);
  return (uint8_t)(base | (g_use_encryption ? 0x80u : 0u));
}

/* ---- Operations ------------------------------------------------------ */

int fbsec_client_keys_derive_session_if_needed(void) {
  if (!g_main_key_set) {
    return 0;
  }
  if (g_key_id == 0u || g_key_id > FBSEC_AEAD_KEYID_MAX) {
    return 0;
  }
  if (g_session_key_loaded[g_key_id]) {
    return 0;
  }

  uint8_t info[FBSEC_CLIENT_KDF_INFO_PREFIX_LEN + 1u];
  memcpy(info, FBSEC_CLIENT_KDF_INFO_PREFIX, FBSEC_CLIENT_KDF_INFO_PREFIX_LEN);
  info[FBSEC_CLIENT_KDF_INFO_PREFIX_LEN] = g_key_id;

  if (!fbsec_hkdf_sha256(g_main_key, FBSEC_AEAD_KEY_SIZE,
                       g_salt,     g_salt_len,
                       info,       sizeof info,
                       g_session_keys[g_key_id], FBSEC_AEAD_KEY_SIZE)) {
    fprintf(stderr, "client_common: HKDF-SHA256 failed\n");
    return 1;
  }
  g_session_key_loaded[g_key_id] = true;
  return 0;
}

int fbsec_client_keys_load_file(const char *path) {
  FILE *f = NULL;
  if (fopen_s(&f, path, "r") != 0 || f == NULL) {
    fprintf(stderr, "client_common: cannot open key-file '%s'\n", path);
    return 1;
  }
  char line[256];
  unsigned loaded_count = 0;
  bool     any_error    = false;
  while (fgets(line, sizeof line, f) != NULL) {
    char         *hash;
    char         *t_kid;
    char         *t_label;
    char         *t_key;
    char         *after_kid;
    unsigned long kid;
    size_t        klen = 0;

    /* Strip a trailing comment before tokenizing. */
    hash = strchr(line, '#');
    if (hash != NULL) {
      *hash = '\0';
    }

    /* Row: <keyid> <label> <hex-key> [<u32-id>]. The optional id column is
       ignored client-side (it is only meaningful to the server's C011h). */
    t_kid = strtok(line, " \t\r\n");
    if (t_kid == NULL) {
      continue;                             /* blank / comment-only line */
    }
    after_kid = t_kid;
    kid = strtoul(t_kid, &after_kid, 0);
    if (after_kid == t_kid || *after_kid != '\0'
        || kid == 0u || kid > FBSEC_AEAD_KEYID_MAX) {
      fprintf(stderr,
              "client_common: key-file row has out-of-range or missing keyid (1..%u)\n",
              (unsigned)FBSEC_AEAD_KEYID_MAX);
      any_error = true;
      continue;
    }

    t_label = strtok(NULL, " \t\r\n");
    t_key   = strtok(NULL, " \t\r\n");
    if (t_label == NULL || t_key == NULL) {
      fprintf(stderr,
              "client_common: key-file row for keyid %u missing label or key\n",
              (unsigned)kid);
      any_error = true;
      continue;
    }

    if (parse_hex_to_buf(t_key, g_session_keys[kid],
                         FBSEC_AEAD_KEY_SIZE, &klen) != 0
        || klen != FBSEC_AEAD_KEY_SIZE) {
      fprintf(stderr,
              "client_common: key-file row for keyid %u is not %u hex bytes\n",
              (unsigned)kid, (unsigned)FBSEC_AEAD_KEY_SIZE);
      any_error = true;
      continue;
    }
    g_session_key_loaded[(uint8_t)kid] = true;
    ++loaded_count;
  }
  fclose(f);
  if (loaded_count == 0u) {
    fprintf(stderr,
            "client_common: key-file '%s' contained no usable rows\n", path);
    return 1;
  }
  /* Summary log: which slots in 1..3 ended up populated. */
  fprintf(stderr, "client_common: key-file '%s': %u key%s loaded",
          path, loaded_count, (loaded_count == 1u) ? "" : "s");
  bool first = true;
  for (uint8_t k = 1u; k <= 3u; ++k) {
    if (!g_session_key_loaded[k]) {
      continue;
    }
    const char *label = demo_role_label(k);
    fprintf(stderr, "%s%s", first ? " (" : ", ", label ? label : "?");
    first = false;
  }
  if (!first) {
    fprintf(stderr, ")");
  }
  fprintf(stderr, "\n");
  return any_error ? 1 : 0;
}

void fbsec_client_keys_load_demo_all(void) {
  const uint8_t *src[4] = {
    NULL,
    DEMO_KEY_PROVISIONING,
    DEMO_KEY_INTEGRATOR,
    DEMO_KEY_OPERATOR
  };
  for (uint8_t k = 1u; k <= 3u; ++k) {
    if (g_session_key_loaded[k]) {
      continue;
    }
    memcpy(g_session_keys[k], src[k], FBSEC_AEAD_KEY_SIZE);
    g_session_key_loaded[k] = true;
  }
}

void fbsec_client_keys_load_demo(uint8_t keyid) {
  if (keyid == FBSEC_CLIENT_KEYID_PROVISIONING) {
    memcpy(g_session_keys[keyid], DEMO_KEY_PROVISIONING, FBSEC_AEAD_KEY_SIZE);
    g_session_key_loaded[keyid] = true;
    g_key_id = keyid;
  } else if (keyid == FBSEC_CLIENT_KEYID_INTEGRATOR) {
    memcpy(g_session_keys[keyid], DEMO_KEY_INTEGRATOR, FBSEC_AEAD_KEY_SIZE);
    g_session_key_loaded[keyid] = true;
    g_key_id = keyid;
  } else if (keyid == FBSEC_CLIENT_KEYID_OPERATOR) {
    memcpy(g_session_keys[keyid], DEMO_KEY_OPERATOR, FBSEC_AEAD_KEY_SIZE);
    g_session_key_loaded[keyid] = true;
    g_key_id = keyid;
  }
}

void fbsec_client_keys_wipe(void) {
  memset(g_session_keys,        0, sizeof g_session_keys);
  memset(g_session_key_loaded,  0, sizeof g_session_key_loaded);
  memset(g_main_key,            0, sizeof g_main_key);
  memset(g_salt,                0, sizeof g_salt);
  g_main_key_set = false;
  g_salt_len     = 0;
}

/* ---- Salt-observation buffer ---------------------------------------- */

void fbsec_client_keys_on_observed_salt(const uint8_t *salt, uint16_t len, void *ctx) {
  (void)ctx;
  if (len > sizeof g_observed_salt) {
    len = (uint16_t)sizeof g_observed_salt;
  }
  if (salt != NULL && len > 0u) {
    memcpy(g_observed_salt, salt, len);
  }
  g_observed_salt_len = len;
}

void fbsec_client_keys_clear_observed_salt(void) {
  g_observed_salt_len = 0u;
}

uint16_t       fbsec_client_keys_observed_salt_len(void) { return g_observed_salt_len; }
const uint8_t *fbsec_client_keys_observed_salt(void)     { return g_observed_salt;     }

/* ---- Port hook: random ------------------------------------------------ */

bool fbsec_secure_port_random(uint8_t *buf, uint16_t len) {
  if (buf == NULL || len == 0u) {
    return false;
  }
#ifdef _WIN32
  HCRYPTPROV hProv = 0;
  if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL,
                            CRYPT_VERIFYCONTEXT)) {
    return false;
  }
  bool ok = (CryptGenRandom(hProv, (DWORD)len, (BYTE *)buf) != FALSE);
  CryptReleaseContext(hProv, 0);
  return ok;
#else
  return false;
#endif
}

/* EOF */
