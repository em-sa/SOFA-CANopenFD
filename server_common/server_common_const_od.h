/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    server_common_const_od.h
 * @brief   SOFA server_common, constant unsecured OD value table.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 22-JUL-2026
 *
 * A small table of constant, readable-without-security object dictionary
 * entries loaded from an `--od-file`. It holds the entries the device
 * serves cold (object 1018h identity and other manufacturer or
 * application constants) so C018h can read the real 1018h identity quad
 * rather than a hardcoded pattern. C000h and C001h are NOT stored here:
 * they stay build-computed and live-computed respectively.
 *
 * File format: one entry per line, hex tokens, `#` starts a comment.
 *
 *     <index> <sub> <len> <data-byte> ...
 *
 * for example:
 *
 *     1018 00 01 04                 # highest sub-index = 4
 *     1018 01 04 00 00 02 F1        # vendor id
 *     1018 04 04 00 00 00 01        # serial
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#ifndef SERVER_COMMON_CONST_OD_H
#define SERVER_COMMON_CONST_OD_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FBSEC_CONST_OD_MAX_ENTRIES   32u   /* table capacity              */
#define FBSEC_CONST_OD_MAX_DATA       8u   /* max bytes per entry         */
#define FBSEC_OD_IDENTITY_INDEX  0x1018u   /* object 1018h identity       */

/**
 * @brief Clear the constant-OD table.
 */
void fbsec_const_od_init(void);

/**
 * @brief Parse @p path and load its entries into the table.
 *
 * @retval  0  file parsed and loaded.
 * @retval -1  open / parse / capacity error (reported to stderr).
 */
int fbsec_const_od_load_file(const char *path);

/**
 * @brief Look up one (index, sub) entry.
 *
 * @param index    object index.
 * @param sub      sub-index.
 * @param len_out  receives the value length on a hit (may be NULL).
 * @return pointer to the value bytes, or NULL if not present.
 */
const uint8_t *fbsec_const_od_get(uint16_t index, uint8_t sub,
                                  uint16_t *len_out);

/**
 * @brief Assemble the 16-byte 1018h identity quad (subs 01h..04h).
 *
 * @param out16  receives vendor id, product code, revision and serial
 *               concatenated in that order (each as stored, 16 bytes).
 * @retval true  all four sub-indices are present and total 16 bytes.
 * @retval false the identity is not fully loaded.
 */
bool fbsec_const_od_get_identity(uint8_t out16[16]);

#ifdef __cplusplus
}
#endif

#endif /* SERVER_COMMON_CONST_OD_H */
/* EOF */
