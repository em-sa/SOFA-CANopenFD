/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    server_common_keys.h
 * @brief   SOFA server_common, demo key constants + key-file loader.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.1 of 22-JUL-2026
 *
 * Three demo per-session keys ("Provisioning Session Key" /
 * "Integrator Session Key" / "Operator Session Key" per WP-104 §3.4
 * vocabulary; SOFA simulates the layer-master + HKDF derivation
 * step out and uses these values directly) sized at
 * `FBSEC_AEAD_KEY_SIZE` (16 bytes for AES-128-GCM, 32 bytes for
 * AES-256-GCM) so the same literals work across builds. Used only
 * when no `--key-file` populates the slots.
 *
 * Plus a text-format key-file loader that registers parsed keys via
 * `fbsec_sod_set_key_ex`. File layout: one row per keyid:
 *
 *     <keyid> <label> <hex_FBSEC_AEAD_KEY_SIZE_bytes> [<u32_id>]
 *
 * The 4th column is the optional non-secret key id / version reported by
 * C011h; when absent it defaults to the keyid. Comments start with '#'
 * and blank lines are ignored.
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#ifndef SERVER_COMMON_KEYS_H
#define SERVER_COMMON_KEYS_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FBSEC_DEMO_KEYID_PROVISIONING 1u
#define FBSEC_DEMO_KEYID_INTEGRATOR   2u
#define FBSEC_DEMO_KEYID_OPERATOR     3u

/* Demo non-secret key id / version values reported by C011h, set distinct
   from the slot/role number so the id is visibly independent. */
#define FBSEC_DEMO_KEYID_VALUE_PROVISIONING 0x1001u
#define FBSEC_DEMO_KEYID_VALUE_INTEGRATOR   0x1002u
#define FBSEC_DEMO_KEYID_VALUE_OPERATOR     0x1003u

extern const uint8_t FBSEC_DEMO_KEY_PROVISIONING[32];
extern const uint8_t FBSEC_DEMO_KEY_INTEGRATOR[32];
extern const uint8_t FBSEC_DEMO_KEY_OPERATOR[32];

/**
 * @brief Install whichever of the three demo keys are not already
 *        present in the secure-OD key store.
 *
 * Idempotent: a slot already populated (e.g. by a prior
 * @ref fbsec_server_load_key_file call) is left alone.
 */
void fbsec_server_install_demo_keys_if_unset(void);

/**
 * @brief Parse @p path as a key file and register each row via
 *        @ref fbsec_sod_set_key.
 *
 * @retval  0  one or more keys loaded successfully.
 * @retval -1  open / parse / register error (logged to stderr by the
 *             caller's executable name; this function reports via
 *             stderr as well).
 */
int fbsec_server_load_key_file(const char *path);

/**
 * @brief Parse a hex-string into @p buf.
 *
 * Whitespace, ':', '-' and ',' are ignored. Returns the byte count
 * parsed, or 0 on invalid input (odd nibble count, non-hex char,
 * buffer overflow).
 */
size_t fbsec_server_parse_hex_strict(const char *s,
                                     uint8_t    *buf,
                                     size_t      buf_size);

#ifdef __cplusplus
}
#endif

#endif /* SERVER_COMMON_KEYS_H */
/* EOF */
