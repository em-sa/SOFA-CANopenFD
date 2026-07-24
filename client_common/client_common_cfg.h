/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    client_common_cfg.h
 * @brief   SOFA client_common, shared types (cfg, verb enum).
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 07-MAY-2026
 *
 * Header-only declarations of the configuration record populated by
 * the variant-agnostic CLI helpers (`client_common_cli.h`) and the
 * verb enum used by the secure-verb runners.
 *
 * Variants extend their own per-flavor cfg around these fields.
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#ifndef CLIENT_COMMON_CFG_H
#define CLIENT_COMMON_CFG_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Verb selector for single-shot dispatch. */
typedef enum {
  FBSEC_CLIENT_VERB_RD       = 0,
  FBSEC_CLIENT_VERB_WR       = 1,
  FBSEC_CLIENT_VERB_SRD      = 2,
  FBSEC_CLIENT_VERB_SWR      = 3,
  FBSEC_CLIENT_VERB_SRD_POLL = 4,
  FBSEC_CLIENT_VERB_SWR_POLL = 5
} fbsec_client_verb_t;

#define FBSEC_CLIENT_VERB_IS_SECURE(v) \
        (   ((v) == FBSEC_CLIENT_VERB_SRD)      || ((v) == FBSEC_CLIENT_VERB_SWR)      \
         || ((v) == FBSEC_CLIENT_VERB_SRD_POLL) || ((v) == FBSEC_CLIENT_VERB_SWR_POLL))

typedef enum {
  FBSEC_CLIENT_COLOR_AUTO   = 0,
  FBSEC_CLIENT_COLOR_ALWAYS = 1,
  FBSEC_CLIENT_COLOR_NEVER  = 2
} fbsec_client_color_pref_t;

typedef enum {
  FBSEC_CLIENT_TS_DEFAULT = 0,
  FBSEC_CLIENT_TS_ON      = 1,
  FBSEC_CLIENT_TS_OFF     = 2
} fbsec_client_ts_state_t;

/**
 * Client-held minimum security floor. The C000h capability descriptor is read
 * cold and is spoofable, so the required level is LOCAL client policy, never
 * taken from the device: a client aborts a device that advertises less than
 * its floor instead of falling back. The descriptor may only ever raise the
 * bar, never lower the configured minimum.
 */
typedef enum {
  FBSEC_CLIENT_SEC_ANY    = 0,  /**< no floor (default): descriptor is advisory */
  FBSEC_CLIENT_SEC_AEAD   = 1,  /**< device must advertise the AEAD mechanism   */
  FBSEC_CLIENT_SEC_SIGNED = 2,  /**< device must advertise RPK (signed) access  */
  FBSEC_CLIENT_SEC_X509   = 3   /**< device must advertise X.509 certificates   */
} fbsec_client_min_sec_t;

/** Variant-agnostic CLI cfg. Filled by the common-flag matcher. */
typedef struct fbsec_client_cfg_t {
  bool                       verbose;
  bool                       quiet;
  fbsec_client_ts_state_t    ts_state;
  fbsec_client_color_pref_t  color_pref;
  uint32_t                   timeout_ms;
  uint32_t                   count;          /**< srdpoll/swrpoll burst */
  /* Output options for single-shot rd/srd. */
  const char                *out_path;
  bool                       hex;
  /* Mode flags. */
  bool                       in_batch;
  bool                       menu_mode;
  const char                *batch_path;
  bool                       stop_on_fail;
  /* Client-held minimum security floor; default ANY (no floor). */
  fbsec_client_min_sec_t     min_security;
  /* Check the min-security floor against the device and exit, run nothing. */
  bool                       check_policy;
} fbsec_client_cfg_t;

#ifdef __cplusplus
}
#endif

#endif /* CLIENT_COMMON_CFG_H */
/* EOF */
