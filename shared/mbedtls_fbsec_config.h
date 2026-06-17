/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    mbedtls_fbsec_config.h
 * @brief   Minimal mbedTLS configuration for the SOFA secure tunnel.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 03-MAY-2026
 *
 * Selected via the MBEDTLS_CONFIG_FILE compile definition so that the
 * rest of mbedTLS' defaults (TLS, X.509, public-key crypto, RNG, etc.)
 * are not pulled into the build. Only the primitives the SOFA secure
 * tunnel actually needs.
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#ifndef MBEDTLS_FBSEC_CONFIG_H
#define MBEDTLS_FBSEC_CONFIG_H

/* Symmetric primitives we actually use. */
#define MBEDTLS_AES_C
#define MBEDTLS_GCM_C

/* SHA-256 underpins HKDF (RFC 5869) for session-key derivation. We do
   NOT enable MBEDTLS_MD_C / MBEDTLS_HKDF_C - fbsec_hkdf.c implements the
   thin Extract / Expand layer directly on top of mbedtls_sha256_*. That
   keeps md.c and its dispatch tables out of the build. */
#define MBEDTLS_SHA256_C

/* GCM only ever runs in encrypt direction (we use authenticate-only
   mode); skip pulling in AES decrypt round keys to shrink the image. */
#define MBEDTLS_BLOCK_CIPHER_NO_DECRYPT

/* Use the C standard library directly (calloc/free/etc.) instead of
   mbedtls' platform indirection. With MBEDTLS_PLATFORM_C undefined,
   mbedtls_calloc/free become macros aliasing libc, which keeps
   library/platform.c out of the build. */
#define MBEDTLS_HAVE_ASM

#endif /* MBEDTLS_FBSEC_CONFIG_H */
/* EOF */
