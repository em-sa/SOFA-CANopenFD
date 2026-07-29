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

#include "fbsec_aead.h"
#include "fbsec_abort.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Key-store slots (1..4) and their roles. Slots 1..3 are the per-session
   ladder keys; slot 4 holds the per-unit Device Claim Token, factory
   material that bootstraps the token (C0) install path and survives a
   decommission. The C01Fh selector byte is exactly the target slot. */
#define FBSEC_DEMO_KEYID_PROVISIONING 1u
#define FBSEC_DEMO_KEYID_INTEGRATOR   2u
#define FBSEC_DEMO_KEYID_OPERATOR     3u
#define FBSEC_DEMO_KEYID_CLAIM_TOKEN  4u

/* Demo non-secret key id / version values reported by C011h, set distinct
   from the slot/role number so the id is visibly independent. */
#define FBSEC_DEMO_KEYID_VALUE_PROVISIONING 0x1001u
#define FBSEC_DEMO_KEYID_VALUE_INTEGRATOR   0x1002u
#define FBSEC_DEMO_KEYID_VALUE_OPERATOR     0x1003u
#define FBSEC_DEMO_KEYID_VALUE_CLAIM_TOKEN  0x1000u

/* C01Fh key-set write body: selector[1] || keyid[4 LE] || key[KEY_SIZE]. */
#define FBSEC_KEY_SET_BODY_LEN  (1u + 4u + (unsigned)FBSEC_AEAD_KEY_SIZE)

extern const uint8_t FBSEC_DEMO_KEY_PROVISIONING[32];
extern const uint8_t FBSEC_DEMO_KEY_INTEGRATOR[32];
extern const uint8_t FBSEC_DEMO_KEY_OPERATOR[32];
extern const uint8_t FBSEC_DEMO_CLAIM_TOKEN[32];

/**
 * @brief Install whichever of the three demo keys are not already
 *        present in the secure-OD key store.
 *
 * Idempotent: a slot already populated (e.g. by a prior
 * @ref fbsec_server_load_key_file call) is left alone.
 */
void fbsec_server_install_demo_keys_if_unset(void);

/**
 * @brief Install the per-unit Device Claim Token into key slot 4.
 *
 * Factory material: the token is the AEAD key that authorizes the first
 * (Provisioning) rung of the C01Fh install ladder on the token (C0) path.
 * Idempotent (write-once slot); call at boot and again after a
 * decommission clears the key store.
 */
void fbsec_server_install_claim_token(void);

/**
 * @brief Apply one verified C01Fh key-set write (the install ladder).
 *
 * @p body is the AEAD-verified plaintext
 * (selector[1] || keyid[4 LE] || key[FBSEC_AEAD_KEY_SIZE]). Enforces the
 * rolling-key rule using @ref fbsec_sod_last_write_key_id: the Claim Token
 * authorizes installing Provisioning, Provisioning authorizes Integrator,
 * Integrator authorizes Operator. On success installs the key into the
 * selected slot and advances the commissioning lifecycle. Intended to be
 * called only from the C01Fh branch of @ref fbsec_sod_port_write_after.
 *
 * @retval FBSEC_ABORT_NONE     key installed.
 * @retval FBSEC_ABORT_ROLE_DENIED   wrong authorizing key for this rung.
 * @retval FBSEC_ABORT_DEVICE_STATE  slot already populated / install refused.
 * @retval FBSEC_ABORT_TYPE_MISMATCH bad length or unknown selector.
 */
fbsec_abort_t fbsec_server_apply_key_set(const uint8_t *body, uint16_t len);

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
