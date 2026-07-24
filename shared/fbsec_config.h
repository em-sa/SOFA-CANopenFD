/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    fbsec_config.h
 * @brief   SOFA compile-time configuration (AEAD, KDF, tag length,
 *          encryption mode).
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 03-MAY-2026
 *
 * One header, four knobs. Both client and server include this transitively
 * via fbsec_aead.h, so they pick up the same compile-time configuration in
 * lockstep. Mismatched configs between peers produce a clean
 * "tag verify failed" on the first secure verb (the AAD differs by at
 * least the mechanism byte), which is the right failure mode.
 *
 * Currently supported:
 *   - HKDF-SHA256                      KDF
 *   - AES-128-GCM, AES-256-GCM         AEAD primitives
 *   - encryption mode = 0 (auth-only) or 1 (encrypt-and-authenticate)
 *   - AES-GCM tag length = 4..16 bytes
 *
 * Reserved (rejected at build time until implemented):
 *   - Ascon-128, Ascon-128a            (NIST SP 800-232 lightweight AEAD)
 *   - ChaCha20-Poly1305                (RFC 8439)
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#ifndef FBSEC_CONFIG_H
#define FBSEC_CONFIG_H

/* ---- AEAD primitive selection (exactly one must be 1) ----------------- */

#define FBSEC_AEAD_AES128_GCM         1
#define FBSEC_AEAD_AES256_GCM         0
#define FBSEC_AEAD_ASCON_128          0   /* reserved, not yet implemented */
#define FBSEC_AEAD_CHACHA20_POLY1305  0   /* reserved, not yet implemented */

/* ---- KDF (exactly one must be 1) -------------------------------------- */

#define FBSEC_KDF_HKDF_SHA256         1

/* ---- Tag length in bytes ---------------------------------------------- */

/* AES-GCM:    4..16 (NIST SP 800-38D table 1). Default is the full 16-byte
 *             tag: no truncation, no forgery-margin argument to make, and it
 *             still fits the CAN FD frame budget. Truncating to 8 remains
 *             configurable and is acceptable with bounded usage per key, but
 *             it is a deliberate trade, not the default.
 * Ascon-128:  16 only (NIST SP 800-232; truncation is not standardized) */
#define FBSEC_AEAD_TAG_LEN_BYTES      16

/* ---- AEAD mode -------------------------------------------------------- */

/* 1 = encrypt-and-authenticate (real AEAD; data is ciphertext on the wire)
 * 0 = authenticate-only        (legacy MCOPSecureAccess-style; data is
 *                               plaintext on the wire, authenticated via
 *                               AAD inclusion)
 *
 * The Ascon family does not define an auth-only mode; if Ascon is selected,
 * encryption MUST be 1. Override at configure time with
 * -DFBSEC_AEAD_ENCRYPTION=0 for an authenticate-only build. */
#ifndef FBSEC_AEAD_ENCRYPTION
#  define FBSEC_AEAD_ENCRYPTION       1
#endif

/* ---- AAD peer-identifier width --------------------------------------- */

/* Number of bytes each of server_device_id and client_device_id occupies
 * in the AAD prefix (see shared/fbsec_aead.h and section 4.1 of
 * doc/fieldbus_sim_secure_tunnel_spec.txt). The default 1 matches the
 * CANopen FD variant's 1-byte node ids (1..127), keeping the prefix at
 * 12 bytes and aligning literally with EmSA-WP-105's "client node ID,
 * server node ID" wording. The 2-byte width is reserved for future
 * variants (generic uint16 device_id, CANopen CC, EtherCAT) and is
 * exercised by setting -DFBSEC_AEAD_DEV_ID_SIZE=2 at configure time.
 *
 * Peers compiled with mismatched FBSEC_AEAD_DEV_ID_SIZE will see a
 * different AAD prefix and fail-closed at AEAD verify on the first
 * secure verb. That is the intended outcome; the on-wire
 * FBSEC_AEAD_PROTOCOL_VERSION does NOT bump for this knob change. */
#ifndef FBSEC_AEAD_DEV_ID_SIZE
#  define FBSEC_AEAD_DEV_ID_SIZE      1
#endif

/* ---- On-wire random (challenge) size ---------------------------------- */

/* Each peer contributes FBSEC_AEAD_RANDOM_SIZE bytes of fresh randomness
 * per single-shot transfer (client_random for srd Pass-1 and swr Pass-2;
 * server_random for srd Pass-2 reply and swr Pass-1 reply). The GCM nonce
 * for that transfer is derived as
 *
 *     nonce[12] = client_random[0..11] XOR server_random[0..11]
 *
 * so both peers contribute to every nonce. Note carefully what this does and
 * does not buy: the peer's random gives transcript freshness against replay,
 * but it does NOT give the encrypting side
 * nonce-collision resistance, because a hostile peer can hold its own
 * contribution constant. Under the threat model one peer is the attacker. The
 * encrypting side (the server on reads, the client on writes) SHALL therefore
 * guarantee its OWN random never repeats under a given key: a repeated
 * server_random on a read, against a fixed client_random, reuses a (key, nonce)
 * pair, which in GCM is catastrophic. The peer random adds freshness only and
 * cannot rescue a weak encryptor RNG. fbsec_*_port_random must be a CSPRNG whose
 * output does not repeat within a key's lifetime.
 *
 * Both randoms are also bound into the AAD tail of READ_RESPONSE /
 * WRITE_REQUEST (see fbsec_aead.h), so an in-flight tamper of either
 * random fails AEAD verification.
 *
 * Must be >= FBSEC_AEAD_NONCE_SIZE (12 for AES-GCM); enforced below. */
#ifndef FBSEC_AEAD_RANDOM_SIZE
#  define FBSEC_AEAD_RANDOM_SIZE      12
#endif

/* ---- Compile-time feature subset ------------------------------------- */

/* Strip read path, write path, and/or cyclic-mode (multi-frame) support
 * at compile time. Defaults are all-on. Override on the command line:
 *   -DFBSEC_FEATURE_READ=0  -DFBSEC_FEATURE_WRITE=0  -DFBSEC_FEATURE_CYCLIC=0
 *
 * - FBSEC_FEATURE_READ   1: include srd / srdpoll machinery; 0: server
 *                           rejects read directions with
 *                           FBSEC_ABORT_NOT_BUILT (C8h), client lacks
 *                           fbsec_secure_read /
 *                           fbsec_secure_arm_read / fbsec_secure_poll_read.
 * - FBSEC_FEATURE_WRITE  1: include swr / swrpoll; 0: symmetric.
 * - FBSEC_FEATURE_CYCLIC 1: include multi-frame (bit-6) sessions; 0: server
 *                           rejects bit 6 of the wire keyid as reserved
 *                           and rejects the cyclic-poll direction codes,
 *                           client lacks the four arm/poll entry points.
 *
 * At least one of READ / WRITE must be 1; CYCLIC may be 0 with either
 * or both of READ/WRITE on. Encryption stays runtime (bit 7 of the
 * wire keyid byte) and is unaffected by these flags. */
#ifndef FBSEC_FEATURE_READ
#  define FBSEC_FEATURE_READ        1
#endif
#ifndef FBSEC_FEATURE_WRITE
#  define FBSEC_FEATURE_WRITE       1
#endif
#ifndef FBSEC_FEATURE_CYCLIC
#  define FBSEC_FEATURE_CYCLIC      1
#endif

/* ---- Optional asymmetric identity (WP-105 sec 5, WP-104 sec 2/5-6) ---- */

/* Master gate for the whole optional Ed25519 identity layer (capability/
 * status descriptors, IDevID/LDevID, RPK secure objects, handover). Default
 * ON: a stock build ships the RPK mechanism and advertises it in C000h. Set
 * to 0 for a minimal AEAD-only device: the wire behaviour is then
 * byte-identical to the symmetric-only build and none of the asymmetric code
 * is compiled. */
#ifndef FBSEC_FEATURE_ASYM
#  define FBSEC_FEATURE_ASYM        1
#endif

/* Asymmetric primitive backend. Exactly one must be 1 when
 * FBSEC_FEATURE_ASYM == 1; only Ed25519 (RFC 8032) is implemented. */
#ifndef FBSEC_ASYM_ED25519
#  define FBSEC_ASYM_ED25519        FBSEC_FEATURE_ASYM
#endif

/* Handover model: 0 = basic (born-open / integrator-rooted, no
 * voucher), 1 = authorized (adds ownership voucher + owner epoch +
 * integrator-authorization). Default ON so the voucher claim (C020h:01h)
 * and owner epoch (C020h:02h) objects are live and the RPK handover story
 * is complete; requires FBSEC_FEATURE_ASYM. */
#ifndef FBSEC_HANDOVER_AUTHORIZED
#  define FBSEC_HANDOVER_AUTHORIZED FBSEC_FEATURE_ASYM
#endif

/* ---- Per-(key, session) frame budget --------------------------------- */

/* Maximum AEAD invocations a session may run on one key before the
 * peers MUST tear the session down and re-derive (or rotate) the key.
 * Cyclic-mode polls increment a 32-bit counter that is checked against
 * this ceiling on the server (fbsec_secure_od.c) and the client
 * (fbsec_secure_proto.c). Reaching the ceiling surfaces as
 * FBSEC_ABORT_KEY_BUDGET (C7h) server-side and FBSEC_SECP_PROTOCOL
 * client-side.
 *
 * Keep well below NIST SP 800-38D's 2^32 invocation guidance for
 * AES-GCM under a single (key, IV-prefix). 1,000,000 buys ~16 minutes
 * at a 1 ms poll period, long enough to be useful, short enough that
 * key rotation stays a normal operational event. */
#define FBSEC_AEAD_KEY_USE_LIMIT      1000000u

/* ====================================================================== */
/*                         Build-time validation                          */
/* ====================================================================== */

#if (FBSEC_AEAD_AES128_GCM + FBSEC_AEAD_AES256_GCM \
     + FBSEC_AEAD_ASCON_128 + FBSEC_AEAD_CHACHA20_POLY1305) != 1
#  error "Exactly one FBSEC_AEAD_* primitive must be 1."
#endif

#if (FBSEC_KDF_HKDF_SHA256) != 1
#  error "Exactly one FBSEC_KDF_* must be 1 (only HKDF-SHA256 is implemented)."
#endif

#if FBSEC_AEAD_AES128_GCM || FBSEC_AEAD_AES256_GCM
#  if (FBSEC_AEAD_TAG_LEN_BYTES) < 4 || (FBSEC_AEAD_TAG_LEN_BYTES) > 16
#    error "AES-GCM tag length must be 4..16 bytes (NIST SP 800-38D)."
#  endif
#endif

#if FBSEC_AEAD_ASCON_128
#  if (FBSEC_AEAD_TAG_LEN_BYTES) != 16
#    error "Ascon-128 requires FBSEC_AEAD_TAG_LEN_BYTES == 16 (NIST SP 800-232)."
#  endif
#  if !FBSEC_AEAD_ENCRYPTION
#    error "Ascon-128 requires FBSEC_AEAD_ENCRYPTION == 1 (Ascon is always-AEAD)."
#  endif
#  error "Ascon-128 is reserved but not yet implemented."
#endif

#if FBSEC_AEAD_CHACHA20_POLY1305
#  error "ChaCha20-Poly1305 is reserved but not yet implemented."
#endif

#if (FBSEC_FEATURE_READ + FBSEC_FEATURE_WRITE) == 0
#  error "SOFA: at least one of FBSEC_FEATURE_READ / FBSEC_FEATURE_WRITE must be 1."
#endif

#if (FBSEC_AEAD_AES128_GCM || FBSEC_AEAD_AES256_GCM) \
    && (FBSEC_AEAD_RANDOM_SIZE) < 12
#  error "FBSEC_AEAD_RANDOM_SIZE must be >= FBSEC_AEAD_NONCE_SIZE (12 for AES-GCM)."
#endif

#if (FBSEC_AEAD_DEV_ID_SIZE) != 1 && (FBSEC_AEAD_DEV_ID_SIZE) != 2
#  error "FBSEC_AEAD_DEV_ID_SIZE must be 1 (CANopen FD: node_id) or 2 (uint16 device_id, reserved for future variants)."
#endif

/* ---- Optional asymmetric identity layer ------------------------------ */

#if FBSEC_ASYM_ED25519 && !FBSEC_FEATURE_ASYM
#  error "FBSEC_ASYM_ED25519 requires FBSEC_FEATURE_ASYM == 1."
#endif

#if FBSEC_FEATURE_ASYM && ((FBSEC_ASYM_ED25519) != 1)
#  error "FBSEC_FEATURE_ASYM needs exactly one asymmetric backend (only Ed25519 is implemented)."
#endif

#if FBSEC_HANDOVER_AUTHORIZED && !FBSEC_FEATURE_ASYM
#  error "FBSEC_HANDOVER_AUTHORIZED requires FBSEC_FEATURE_ASYM == 1 (voucher verification needs Ed25519)."
#endif

#endif /* FBSEC_CONFIG_H */
/* EOF */
