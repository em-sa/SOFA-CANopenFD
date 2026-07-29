/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    server_common_asym.h
 * @brief   SOFA server_common, device-side asymmetric identity store.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 19-JUL-2026
 *
 * Device-side storage for the optional Ed25519 identity layer, parallel
 * to the symmetric key store in fbsec_secure_od.c:
 *   - IDevID  : factory identity keypair (permanent), plus the
 *               manufacturer certificate over its public key.
 *   - LDevID  : integrator-installed identity keypair (cleared by restore).
 *   - anchor  : manufacturer trust-anchor public key (authorized model).
 *   - owner   : owner public key + monotonic owner epoch (authorized model).
 *   - peers   : LDevID public keys of peers, for signed-FBsec verification.
 *
 * Compiled only when FBSEC_FEATURE_ASYM == 1. Mutators used by the
 * handover flow live in server_common_handover.{c,h} (built alongside).
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#ifndef SERVER_COMMON_ASYM_H
#define SERVER_COMMON_ASYM_H

#include "fbsec_config.h"

#if FBSEC_FEATURE_ASYM

#include <stdint.h>
#include <stdbool.h>

#include "fbsec_asym.h"
#include "fbsec_secure_od.h"   /* FBSEC_SOD_KEY_SLOTS */

#ifdef __cplusplus
extern "C" {
#endif

/** Peer LDevID table size (indexed like the symmetric key slots). */
#define FBSEC_SERVER_ASYM_PEER_SLOTS  FBSEC_SOD_KEY_SLOTS

/**
 * @brief Initialise the device identity store from the fixed demo seeds.
 *
 * Derives the IDevID from the demo seed and builds its manufacturer
 * certificate (the simulator plays factory here), loads the manufacturer
 * trust anchor, clears the LDevID, marks the device uncommissioned, and
 * sets the starting owner epoch. Idempotent; safe to call once at startup.
 */
void fbsec_server_asym_init(void);

/* ---- State predicates (used by the capability/status descriptor) ------ */

/** @return true once the IDevID keypair is initialised. */
bool fbsec_server_asym_idevid_present(void);

/** @return true once an LDevID has been installed (handover step 4). */
bool fbsec_server_asym_ldevid_present(void);

/** @return true while the device has not yet been claimed/commissioned. */
bool fbsec_server_asym_is_uncommissioned(void);

/** @return the current (highest accepted) owner epoch. */
uint32_t fbsec_server_asym_owner_epoch(void);

/* ---- Key accessors (used by signing / handover / signed-FBsec) -------- */

/** @return the IDevID keypair (never NULL after init). */
const fbsec_keypair_t *fbsec_server_asym_idevid(void);

/** @return the LDevID keypair, or NULL if not yet installed. */
const fbsec_keypair_t *fbsec_server_asym_ldevid(void);

/** @return the manufacturer certificate (SIG over the identity blob),
 *          64 bytes; valid after init. */
const uint8_t *fbsec_server_asym_idevid_cert(void);

/** @return the manufacturer trust-anchor public key (authorized model). */
const fbsec_pubkey_t *fbsec_server_asym_anchor(void);

/** @return the stored owner public key, or NULL if none set. */
const fbsec_pubkey_t *fbsec_server_asym_owner(void);

/** @return this device's 8-byte serial (as named by a voucher). */
const uint8_t *fbsec_server_asym_serial(void);

/* ---- Handover mutators (device side; spec 11.6.6) -------------------- */

/**
 * @brief Generate and store the device LDevID (handover step 4).
 * @param out_pub  receives the new LDevID public key (may be NULL).
 * @retval true    generated (idempotent: regenerates on repeat).
 */
bool fbsec_server_asym_generate_ldevid(fbsec_pubkey_t *out_pub);

#if FBSEC_HANDOVER_AUTHORIZED
/**
 * @brief Verify and accept an ownership voucher (handover step 2,
 *        authorized model). On success stores the owner public key and
 *        advances the owner epoch, and marks the device commissioned.
 * @retval true   accepted; false if anchor sig / serial / state / epoch
 *                check fails.
 */
bool fbsec_server_asym_claim(const uint8_t *voucher, uint16_t len);
#endif

/**
 * @brief Accept a Provisioning-Key install (handover step 3).
 *        Basic model: trust-on-first-use. Authorized model: the install
 *        must be signed by the owner key established at claim.
 * @param payload  key[FBSEC_AEAD_KEY_SIZE] || SIG_integrator[64].
 * @retval true    accepted and stored.
 */
bool fbsec_server_asym_install_provisioning(const uint8_t *payload, uint16_t len);

/**
 * @brief The Provisioning key accepted by the last successful install.
 *
 * Lets the handover layer bridge the installed key into the live secure-OD
 * session-key slot, so it becomes a working session key rather than dead
 * storage.
 *
 * @return pointer to FBSEC_AEAD_KEY_SIZE key bytes, or NULL if none installed.
 */
const uint8_t *fbsec_server_asym_provisioning_key(void);

/**
 * @brief Decommission: clear ownership so the device can be claimed again.
 *
 * Clears the owner, the installed Provisioning key and the LDevID, and marks
 * the device uncommissioned. Keeps the factory IDevID, the manufacturer
 * anchor and the peer table (so genuineness and signed access still work).
 *
 * The owner epoch is retained: it is a monotonic rollback guard (CiA 720-2
 * owner epoch) that survives a manufacturer reset, so a re-claim requires a
 * fresh voucher whose epoch is higher than the retained one. The demo client
 * mints that next-generation voucher from the device's current epoch.
 */
void fbsec_server_asym_decommission(void);

/* ---- Peer LDevID table (signed-FBsec verification) -------------------- */

/**
 * @brief Install a peer's LDevID public key in slot @p slot.
 * @param slot 1..FBSEC_SERVER_ASYM_PEER_SLOTS.
 * @param pk   peer public key.
 * @retval true installed; false on invalid slot / NULL.
 */
bool fbsec_server_asym_set_peer(uint8_t slot, const fbsec_pubkey_t *pk);

/**
 * @brief Fetch a peer's LDevID public key.
 * @return true and fills @p out if slot populated; false otherwise.
 */
bool fbsec_server_asym_get_peer(uint8_t slot, fbsec_pubkey_t *out);

#ifdef __cplusplus
}
#endif

#endif /* FBSEC_FEATURE_ASYM */

#endif /* SERVER_COMMON_ASYM_H */
/* EOF */
