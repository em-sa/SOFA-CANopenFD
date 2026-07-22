/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    fbsec_abort.h
 * @brief   SOFA abort codes - CiA 1301 Table 31 subset plus the SOFA block.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 20-JUL-2026
 *
 * CiA 1301 v1.1 defines the USDO abort code `ac` as a single UNSIGNED8
 * (Table 32, byte 6 of the abort frame) drawn from Table 31. SOFA used
 * to carry a 4-byte little-endian classical CiA 301 SDO abort code
 * instead; that was never conformant and is gone.
 *
 * Two ranges are used here:
 *
 *   - CiA 1301 Table 31 codes (10h..70h), used wherever SOFA's failure
 *     condition matches a standardized one exactly.
 *   - A SOFA-specific block C0h..CFh for the security conditions CiA
 *     has no code for (AEAD tag failure, signature failure, role
 *     policy, key budget, ...).
 *
 * IMPORTANT: CiA 1301 Table 31 states that "the remaining value range
 * 71h to FFh shall be reserved for future use by CiA". The C0h..CFh
 * block below therefore sits in CiA-reserved space and is a SOFA
 * assignment only. If CiA ever assigns those values, SOFA has to move
 * its block; treat these codes as SOFA-private, not as standard ones.
 *
 * Note the deliberate split between the USDO transport layer and the
 * SOFA secure layer:
 *   - 14h / 21h refer to the USDO SEGMENT COUNTER and the USDO
 *     SESSION-ID (the CiA 1301 transfer).
 *   - C6h / C5h refer to SOFA's own CYCLIC POLL COUNTER and SECURE
 *     SESSION (the FBsec state machine).
 * Older SOFA releases conflated the two under a single code.
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#ifndef FBSEC_ABORT_H
#define FBSEC_ABORT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** One CiA 1301 abort code (`ac`, UNSIGNED8). Zero means "no abort". */
typedef uint8_t fbsec_abort_t;

/** Not an abort: the request succeeded. */
#define FBSEC_ABORT_NONE            0x00u

/* ---- CiA 1301 Table 31, universal errors ------------------------------ */

/** 13h - unknown / unexpected / unsupported command specifier. */
#define FBSEC_ABORT_BAD_CMD         0x13u
/** 14h - invalid value in the USDO segment counter byte. */
#define FBSEC_ABORT_SEG_COUNTER     0x14u
/** 15h - incorrect data size on a segmented transfer. */
#define FBSEC_ABORT_DATA_SIZE       0x15u
/** 21h - USDO session-ID wrong or unknown. */
#define FBSEC_ABORT_SESSION_ID      0x21u

/* ---- CiA 1301 Table 31, accessed-parameter attribute errors ------------ */

/** 31h - attempt to read a write-only data element. */
#define FBSEC_ABORT_WRITE_ONLY      0x31u
/** 32h - attempt to write a read-only data element. */
#define FBSEC_ABORT_READ_ONLY       0x32u
/** 33h - data object does not exist in the object dictionary. */
#define FBSEC_ABORT_NO_OBJECT       0x33u
/** 34h - sub-index does not exist. */
#define FBSEC_ABORT_NO_SUBINDEX     0x34u
/** 36h - data type / length of service parameter does not match. */
#define FBSEC_ABORT_TYPE_MISMATCH   0x36u
/** 37h - length of service parameter too high. */
#define FBSEC_ABORT_LEN_TOO_HIGH    0x37u
/** 38h - length of service parameter too low. */
#define FBSEC_ABORT_LEN_TOO_LOW     0x38u

/* ---- CiA 1301 Table 31, data storage-related errors -------------------- */

/** 60h - data cannot be transferred or stored to the application.
 *  SOFA uses this for internal failures: RNG failure, AEAD seal or open
 *  setup failure, signature generation failure, undersized buffers. */
#define FBSEC_ABORT_INTERNAL        0x60u
/** 62h - access rejected because of the present device state. SOFA uses
 *  this when the host's access_allowed hook refuses (lock / write
 *  protect / factory mode). */
#define FBSEC_ABORT_DEVICE_STATE    0x62u

/* ---- SOFA block C0h..CFh (CiA-reserved space; see banner) -------------- */

/** C0h - AEAD tag verification failed. */
#define FBSEC_ABORT_TAG_VERIFY      0xC0u
/** C1h - Ed25519 signature verification failed. */
#define FBSEC_ABORT_SIG_VERIFY      0xC1u
/** C2h - ownership voucher rejected. */
#define FBSEC_ABORT_VOUCHER         0xC2u
/** C3h - role policy denies this operation for this key tier. */
#define FBSEC_ABORT_ROLE_DENIED     0xC3u
/** C4h - key identifier not accepted (bound-entry mismatch, unknown key
 *  slot, or a reserved keyid bit set). */
#define FBSEC_ABORT_KEY_ID          0xC4u
/** C5h - secure session unknown or expired (no armed slot, stale
 *  challenge, idle timeout, wrong peer). */
#define FBSEC_ABORT_NO_SESSION      0xC5u
/** C6h - SOFA cyclic poll counter desync. */
#define FBSEC_ABORT_POLL_COUNTER    0xC6u
/** C7h - per-key frame budget reached; re-arm required. */
#define FBSEC_ABORT_KEY_BUDGET      0xC7u
/** C8h - feature not compiled in (read / write / cyclic stripped at
 *  build time). */
#define FBSEC_ABORT_NOT_BUILT       0xC8u
/** C9h - object exists in the OD but its function is not implemented yet
 *  (a surface-first placeholder, distinct from C8h "compiled out"). */
#define FBSEC_ABORT_NOT_IMPLEMENTED 0xC9u
/* CAh..CFh reserved for SOFA. */

#ifdef __cplusplus
}
#endif

#endif /* FBSEC_ABORT_H */
/* EOF */
