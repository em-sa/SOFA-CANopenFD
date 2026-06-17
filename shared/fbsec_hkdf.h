/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    fbsec_hkdf.h
 * @brief   SOFA HKDF-SHA256 (RFC 5869), public API.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 03-MAY-2026
 *
 * Self-contained HKDF on top of mbedtls SHA-256. Avoids pulling in
 * mbedtls' generic message-digest dispatch (md.c) and full hkdf.c, so
 * only sha256.c is required alongside the AES/GCM subset.
 *
 * Used to derive per-deployment session keys from persistent main keys
 * plus an optional session salt, with the SOFA info string
 * "FBSEC-SK-v1" || keyid (per doc/fieldbus_sim_secure_tunnel_spec.txt).
 *
 * This module is a port of MCOPSecureAccess/MCO_CiA401__User_Secure/
 * sod_hkdf.{c,h}, which is already Apache 2.0 licensed and is reused
 * here under the same license. Function name renamed from
 * `sod_hkdf_sha256` to `fbsec_hkdf_sha256` for namespace consistency.
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#ifndef FBSEC_HKDF_H
#define FBSEC_HKDF_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** SHA-256 output size in bytes; also the maximum HMAC-SHA256 block-output. */
#define FBSEC_HKDF_HASH_LEN  32u

/**
 * @brief HKDF-SHA256 (RFC 5869) extract-then-expand.
 *
 * @param ikm       input keying material (e.g. main key bytes).
 * @param ikm_len   IKM length in bytes (must be > 0).
 * @param salt      optional salt; may be NULL when @p salt_len == 0
 *                  (RFC 5869 then uses a HashLen-byte zero block).
 * @param salt_len  salt length in bytes.
 * @param info      optional context / application string; may be NULL
 *                  when @p info_len == 0.
 * @param info_len  info length in bytes.
 * @param okm       destination for the derived key material.
 * @param okm_len   number of output bytes; must be <= 255 * 32 = 8160.
 * @retval true     derivation succeeded; @p okm holds @p okm_len bytes.
 * @retval false    invalid argument or backend error.
 */
bool fbsec_hkdf_sha256(
  const uint8_t *ikm,  size_t ikm_len,
  const uint8_t *salt, size_t salt_len,
  const uint8_t *info, size_t info_len,
  uint8_t       *okm,  size_t okm_len
);

#ifdef __cplusplus
}
#endif

#endif /* FBSEC_HKDF_H */
/* EOF */
