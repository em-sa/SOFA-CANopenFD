/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    client_common_keys.h
 * @brief   SOFA client_common, key store + RNG + KDF + key file.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 07-MAY-2026
 *
 * Holds the variant-agnostic credential state: session key (direct or
 * HKDF-derived), main key + salt, key id, encryption-flag selector
 * (bit 7 of the wire keyid byte), and salt-observation buffer for
 * the --verbose secure-row "Salt:" line.
 *
 * Also implements `fbsec_secure_port_random` (Windows CryptGenRandom)
 * that the secure-tunnel core calls per spec.
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#ifndef CLIENT_COMMON_KEYS_H
#define CLIENT_COMMON_KEYS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Per-keyid demo identities (mirrors server-side roles) ----------- */

#define FBSEC_CLIENT_KEYID_PROVISIONING 1u
#define FBSEC_CLIENT_KEYID_INTEGRATOR   2u
#define FBSEC_CLIENT_KEYID_OPERATOR     3u

/* ---- Setters --------------------------------------------------------- */

bool fbsec_client_keys_set_session_from_hex(const char *hex);
bool fbsec_client_keys_set_main_from_hex(const char *hex);
bool fbsec_client_keys_set_salt_from_hex(const char *hex);
void fbsec_client_keys_set_keyid(uint8_t key_id);
void fbsec_client_keys_set_use_encryption(bool on);

/* ---- Getters --------------------------------------------------------- */

bool          fbsec_client_keys_session_set(void);
bool          fbsec_client_keys_main_set(void);
size_t        fbsec_client_keys_salt_len(void);
uint8_t       fbsec_client_keys_keyid(void);
bool          fbsec_client_keys_use_encryption(void);
const uint8_t *fbsec_client_keys_session(void);

/**
 * @brief Effective wire keyid byte: low 7 bits = role identity,
 *        bit 7 = encryption flag (per `fbsec_client_keys_set_use_encryption`).
 *
 * @return 0 if no keyid is selected.
 */
uint8_t fbsec_client_keys_effective_keyid(void);

/* ---- Operations ------------------------------------------------------ */

/**
 * @brief If --main-key + --salt + --keyid are set (and --key was not),
 *        derive the session key locally via HKDF-SHA256 with the SOFA
 *        info string "FBSEC-SK-v1" || keyid. Result is stored into the
 *        currently-selected keyid's slot.
 *
 * @retval 0  derivation succeeded (or no derivation needed).
 * @retval 1  HKDF failed.
 */
int fbsec_client_keys_derive_session_if_needed(void);

/**
 * @brief Load every "<keyid> <label> <hex>" row in @p path into its
 *        keyid's session-key slot. Comments and blank lines are
 *        ignored. Each loaded slot becomes available for any verb
 *        that subsequently selects that keyid via
 *        @ref fbsec_client_keys_set_keyid. Logs a summary on stderr
 *        of how many slots were populated and which roles they map
 *        to (slots 1..3).
 *
 * @retval 0  file parsed and at least one row was loaded.
 * @retval 1  open / parse error or no usable rows found (logged).
 */
int fbsec_client_keys_load_file(const char *path);

/**
 * @brief Load the three built-in demo session keys (Provisioning /
 *        Integrator / Operator) into slots 1, 2, 3. Skips any slot
 *        that has already been populated (e.g. by --key-file or
 *        --key on the command line). After this call, every menu /
 *        --keyid choice in 1..3 has a key resident; the user picks
 *        which to use via @ref fbsec_client_keys_set_keyid.
 */
void fbsec_client_keys_load_demo_all(void);

/**
 * @brief Install the demo session key bound to @p keyid into slot
 *        @p keyid AND set it as the active keyid. Convenience
 *        wrapper used when only one demo key is needed; the
 *        @ref fbsec_client_keys_load_demo_all path is preferred for
 *        the all-slots-resident boot flow.
 *        keyid 1 -> Provisioning Session Key,
 *        2 -> Integrator Session Key, 3 -> Operator Session Key.
 *        Other values are ignored.
 */
void fbsec_client_keys_load_demo(uint8_t keyid);

/** Wipe key material (memset 0). Call on program exit. */
void fbsec_client_keys_wipe(void);

/* ---- Salt-observation buffer (for --verbose) ------------------------- */

/** Salt callback for fbsec_secure_set_salt_callback. */
void fbsec_client_keys_on_observed_salt(const uint8_t *salt, uint16_t len, void *ctx);

/** Reset the buffer (called by verbs before each fbsec_secure_* invocation). */
void fbsec_client_keys_clear_observed_salt(void);

uint16_t       fbsec_client_keys_observed_salt_len(void);
const uint8_t *fbsec_client_keys_observed_salt(void);

#ifdef __cplusplus
}
#endif

#endif /* CLIENT_COMMON_KEYS_H */
/* EOF */
