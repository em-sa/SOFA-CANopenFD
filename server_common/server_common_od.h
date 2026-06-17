/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    server_common_od.h
 * @brief   SOFA server_common, secure OD setup (demo entries).
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 07-MAY-2026
 *
 * One-shot initialization of the secure-OD registry with the four
 * demo entries (`FBSEC_SERVER_ENTRY_*` from
 * `server_common_hooks.h`), plus `--key-file` loading and demo-key
 * fallback. Variants call this once per process startup.
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#ifndef SERVER_COMMON_OD_H
#define SERVER_COMMON_OD_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief One-time setup: reset secure-OD registry, register the four
 *        demo entries, prefill 0xC0180000 with the runtime identity
 *        string, load --key-file (if any), install demo keys for any
 *        unset slots.
 *
 * Side effects:
 *   - calls @ref fbsec_sod_init,
 *   - calls @ref fbsec_server_hooks_set_my_dev,
 *   - calls @ref fbsec_server_hooks_prefill_secure_ro,
 *   - registers four entries via @ref fbsec_sod_register_entry,
 *   - calls @ref fbsec_server_load_key_file when @p key_file_path is non-NULL,
 *   - calls @ref fbsec_server_install_demo_keys_if_unset.
 *
 * @retval  0  success.
 * @retval -1  entry registration or key-file load failed (already
 *             logged to stderr). Prefill cannot fail.
 */
int fbsec_server_od_init(uint16_t my_dev, const char *key_file_path);

#ifdef __cplusplus
}
#endif

#endif /* SERVER_COMMON_OD_H */
/* EOF */
