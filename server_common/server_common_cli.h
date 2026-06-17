/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    server_common_cli.h
 * @brief   SOFA server_common, shared CLI helpers.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 07-MAY-2026
 *
 * Variant-agnostic argv parsing helpers. The variant owns the argv
 * loop (because variant-specific flags interleave with the common
 * ones) and delegates each unrecognized token to
 * @ref fbsec_server_cli_try_common_flag. Helpers for banner / usage
 * heading / colour resolution sit alongside.
 *
 * Common flags handled here:
 *   --device-id N       sets cfg->my_dev (1..0xFFFE)
 *   --name STR          stored by the variant separately (variants own announce)
 *   --verbose           cfg->verbose = true
 *   --quiet             cfg->quiet = true
 *   --color             cfg->color_pref = ALWAYS
 *   --no-color          cfg->color_pref = NEVER
 *   --key-file PATH     cfg->key_file_path = PATH
 *   --help              prints the variant's full usage via the
 *                       caller-supplied @p usage_fn and signals exit
 *
 * NOT handled here:
 *   --hub HOST:PORT     TCP-specific (variant parses)
 *   --bus HOST:PORT     CANopen-FD carrier (variant parses)
 *   --node N            CANopen node id (variant parses; though it
 *                       may map onto cfg->my_dev internally)
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#ifndef SERVER_COMMON_CLI_H
#define SERVER_COMMON_CLI_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#include "server_common_cfg.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Result of @ref fbsec_server_cli_try_common_flag. */
typedef enum {
  FBSEC_SERVER_CLI_NOT_MATCHED = 0, /**< token is not a common flag; variant tries its own */
  FBSEC_SERVER_CLI_HANDLED     = 1, /**< matched & consumed (advancing *iref past arg)    */
  FBSEC_SERVER_CLI_HELP        = 2, /**< matched --help; caller prints usage and exits 0  */
  FBSEC_SERVER_CLI_ERROR       = 3  /**< matched but argument was invalid; caller exits 1 */
} fbsec_server_cli_result_t;

/**
 * @brief Try to consume the common flag at @p argv[*iref].
 *
 * On HANDLED, @p *iref advances past the flag and any sub-argument.
 * On NOT_MATCHED, @p *iref is left pointing at the unconsumed flag.
 *
 * @param iref     in/out current argv index.
 * @param argc     argument count.
 * @param argv     argument vector.
 * @param cfg      destination (mutated on HANDLED).
 * @param exec_name short program name used in error messages.
 */
fbsec_server_cli_result_t fbsec_server_cli_try_common_flag(
    int                *iref,
    int                 argc,
    char              **argv,
    fbsec_server_cfg_t *cfg,
    const char         *exec_name);

/**
 * @brief Parse a non-negative integer (decimal or 0x-hex).
 *
 * @retval 0   success.
 * @retval -1  empty input or trailing junk.
 */
int fbsec_server_cli_parse_u32(const char *s, uint32_t *out);

/** ADR-004 banner (3 printf calls; trailing blank line). */
void fbsec_server_cli_print_banner(const char *banner_name,
                                   const char *version_str,
                                   const char *version_date);

/**
 * @brief Resolve effective ANSI colour use given the user's
 *        preference and stdout's TTY status.
 *
 * Side effect: enables Windows console virtual-terminal processing
 * when colour ends up enabled.
 *
 * @retval true   colour escapes will be emitted.
 * @retval false  plain output.
 */
bool fbsec_server_cli_resolve_color(fbsec_server_color_pref_t pref);

#ifdef __cplusplus
}
#endif

#endif /* SERVER_COMMON_CLI_H */
/* EOF */
