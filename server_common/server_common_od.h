/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    server_common_od.h
 * @brief   SOFA server_common, secure OD setup (demo entries).
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.1 of 22-JUL-2026
 *
 * One-shot initialization of the secure-OD registry with the demo
 * entries (`FBSEC_SERVER_ENTRY_*` from `server_common_hooks.h`), the
 * constant-OD table (`--od-file`, including the 1018h identity that
 * backs C018h), plus `--key-file` loading and opt-in demo keys.
 * Variants call this once per process startup.
 *
 * The commissioning stage is set here: a device that ends up holding
 * session keys (from `--key-file` or opt-in demo keys) starts
 * Operational; a device with no keys starts Uncommissioned, so the
 * lifecycle is visible from the first status read.
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#ifndef SERVER_COMMON_OD_H
#define SERVER_COMMON_OD_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief One-time setup: reset secure-OD registry, load the constant-OD
 *        file, register the demo entries (C018h only when its 1018h
 *        identity is present), load --key-file (if any), install demo
 *        keys for any unset slots.
 *
 * Side effects:
 *   - calls @ref fbsec_sod_init,
 *   - calls @ref fbsec_server_hooks_set_my_dev,
 *   - loads @p od_file_path into the constant-OD table when non-NULL,
 *   - calls @ref fbsec_server_hooks_load_identity,
 *   - registers the demo entries via @ref fbsec_sod_register_entry,
 *   - calls @ref fbsec_server_load_key_file when @p key_file_path is non-NULL,
 *   - calls @ref fbsec_server_install_demo_keys_if_unset when
 *     @p install_demo_keys is true,
 *   - sets the commissioning stage from whether any session key is present.
 *
 * @param my_dev            responder device id.
 * @param key_file_path     --key-file path, or NULL.
 * @param od_file_path      --od-file path, or NULL (then 1018h / C018h absent).
 * @param install_demo_keys true to fill unset slots with the demo keys
 *                          (--demo-keys); false to leave them empty so the
 *                          device boots Uncommissioned.
 * @retval  0  success.
 * @retval -1  const-OD load, entry registration or key-file load failed
 *             (already logged to stderr).
 */
int fbsec_server_od_init(uint16_t my_dev, const char *key_file_path,
                         const char *od_file_path, bool install_demo_keys);

#ifdef __cplusplus
}
#endif

#endif /* SERVER_COMMON_OD_H */
/* EOF */
