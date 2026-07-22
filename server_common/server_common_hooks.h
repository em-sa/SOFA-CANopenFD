/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    server_common_hooks.h
 * @brief   SOFA server_common, secure-OD port hooks + demo data buffers.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.1 of 22-JUL-2026
 *
 * Owns the demo-mode implementations of all `fbsec_sod_port_*`
 * callbacks declared in `shared/fbsec_secure_od.h`, together with
 * the four demo OD entries' backing buffers. Two reasons to bundle:
 *
 *   1. The port hooks read / mutate the demo data; co-locating the
 *      buffers lets the hooks be pure file-static accessors.
 *   2. The trace layer wants to display the plaintext of SECURE_RO
 *      reads and SECURE_WO writes; the accessors below give it
 *      read-only views without exposing the buffers globally.
 *
 * Variants populate node id (mirrored into SOFA `device_id`) via
 * @ref fbsec_server_hooks_set_my_dev before any request arrives.
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#ifndef SERVER_COMMON_HOOKS_H
#define SERVER_COMMON_HOOKS_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Demo OD entry constants ----------------------------------------- */

#define FBSEC_SERVER_ENTRY_RD_DATA_ID    0x20200000u   /**< SECURE_RO  4 B (auto-bumps) */
#define FBSEC_SERVER_ENTRY_WR_DATA_ID    0x20100000u   /**< SECURE_WO  4 B (shadow)     */
#define FBSEC_SERVER_ENTRY_SRD_DATA_ID   0xC0180000u   /**< C018h authenticated identity */
#define FBSEC_SERVER_ENTRY_SWR_DATA_ID   0x20160000u   /**< SECURE_WO 16-byte demo array */
#define FBSEC_SERVER_ENTRY_VALUE_LEN     4u
#define FBSEC_SERVER_ENTRY_SECURE_LEN    16u

/* ---- Setup / accessors ----------------------------------------------- */

/**
 * @brief Tell the port hooks which device id to report from
 *        @ref fbsec_sod_port_get_device_id.
 *
 * Variants call this after CLI parsing, before any request arrives.
 */
void fbsec_server_hooks_set_my_dev(uint16_t my_dev);

/**
 * @brief Fill the C018h (0xC0180000) backing buffer with the real 1018h
 *        identity quad (vendor id, product code, revision, serial) read
 *        from the constant-OD table.
 *
 * @retval true   the 1018h identity is fully loaded (16 bytes); C018h can
 *                be served.
 * @retval false  1018h is absent (no --od-file, or incomplete); the
 *                caller should not register C018h.
 */
bool fbsec_server_hooks_load_identity(void);

/** Read-only view of the 4-byte SECURE_RO/WO shadow value. */
const uint8_t *fbsec_server_hooks_value(void);

/** Read-only view of the 16-byte SECURE_RO buffer (demo identity). */
const uint8_t *fbsec_server_hooks_secure_ro(void);

/** Read-only view of the 16-byte SECURE_WO buffer (last write). */
const uint8_t *fbsec_server_hooks_secure_wo(void);

#ifdef __cplusplus
}
#endif

#endif /* SERVER_COMMON_HOOKS_H */
/* EOF */
