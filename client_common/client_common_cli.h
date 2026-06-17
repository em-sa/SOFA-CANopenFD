/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    client_common_cli.h
 * @brief   SOFA client_common, shared CLI helpers.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 07-MAY-2026
 *
 * Variant-agnostic argv parsing helpers. The variant owns the argv
 * loop (because variant-specific flags --hub / --bus interleave with
 * the common ones); each unrecognized token is delegated to
 * @ref fbsec_client_cli_try_common_flag, which routes to the right
 * client_common subsystem (cfg, keys, trace, etc.).
 *
 * Common flags handled here:
 *   --device-id N       cfg->my_dev (variant uses)
 *   --name STR          variant captures (used in announce)  -- NOT here
 *   --timeout MS        cfg->timeout_ms
 *   --count N           cfg->count
 *   --verbose / --quiet cfg->verbose / cfg->quiet
 *   --timestamp / --no-timestamp  cfg->ts_state
 *   --color / --no-color cfg->color_pref
 *   --encrypt / --no-encrypt  -> fbsec_client_keys_set_use_encryption
 *   --batch FILE        cfg->in_batch + cfg->batch_path
 *   --menu              cfg->menu_mode
 *   --stop-on-fail      cfg->stop_on_fail
 *   --out FILE          cfg->out_path
 *   --hex               cfg->hex
 *   --key HEX --keyid N --main-key HEX --salt HEX --kdf STR --key-file FILE
 *                       routed to fbsec_client_keys_*
 *   --help              caller prints usage + exits 0
 *
 * NOT handled:
 *   --hub / --bus       variant-specific
 *   --name              variant captures (used in announce)
 *   --data / --in       variant captures (single-shot payload)
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#ifndef CLIENT_COMMON_CLI_H
#define CLIENT_COMMON_CLI_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include "client_common_cfg.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  FBSEC_CLIENT_CLI_NOT_MATCHED = 0,
  FBSEC_CLIENT_CLI_HANDLED     = 1,
  FBSEC_CLIENT_CLI_HELP        = 2,
  FBSEC_CLIENT_CLI_ERROR       = 3
} fbsec_client_cli_result_t;

/**
 * @brief Carries the per-variant device id field that --device-id
 *        feeds into. Variants pass &my_dev (or NULL to ignore).
 */
fbsec_client_cli_result_t fbsec_client_cli_try_common_flag(
    int                *iref,
    int                 argc,
    char              **argv,
    fbsec_client_cfg_t *cfg,
    uint16_t           *my_dev_inout,
    const char         *exec_name);

/**
 * @brief Parse a non-negative integer (decimal or 0x-hex).
 * @retval 0  success.
 * @retval -1 empty input or trailing junk.
 */
int fbsec_client_cli_parse_u32(const char *s, uint32_t *out);

/**
 * @brief Parse a hex byte-string (whitespace / ':' / '-' / ',' allowed).
 * @retval 0  success; bytes in @p buf, count in @p *len_out.
 * @retval -1 odd nibble count, non-hex char, or buffer overflow.
 */
int fbsec_client_cli_parse_hex(const char *s,
                               uint8_t *buf, size_t buf_size,
                               size_t *len_out);

/** ADR-004 banner. */
void fbsec_client_cli_print_banner(const char *banner_name,
                                   const char *version_str,
                                   const char *version_date);

/**
 * @brief Resolve effective ANSI colour use given the user's preference
 *        and stdout's TTY status. Side effect: enables Windows console
 *        VT processing when colour ends up enabled.
 */
bool fbsec_client_cli_resolve_color(fbsec_client_color_pref_t pref);

/**
 * @brief Resolve effective timestamp setting given tristate + batch mode.
 *
 * @retval true   show [ts] prefix on action-block lines.
 * @retval false  no prefix.
 */
bool fbsec_client_cli_resolve_show_ts(fbsec_client_ts_state_t state, bool in_batch);

#ifdef __cplusplus
}
#endif

#endif /* CLIENT_COMMON_CLI_H */
/* EOF */
