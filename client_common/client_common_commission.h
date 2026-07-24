/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    client_common_commission.h
 * @brief   SOFA client_common, commissioning-tool handover driver.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 19-JUL-2026
 *
 * Tool-side of the manufacturer-to-integrator handover (spec 11.6.6),
 * over the transport vtable: verify genuineness, (authorized) present an
 * ownership voucher, install the Provisioning Key, and generate the
 * device LDevID. Each returns 0 on success, non-zero on failure.
 *
 * Compiled only when FBSEC_FEATURE_ASYM == 1.
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#ifndef CLIENT_COMMON_COMMISSION_H
#define CLIENT_COMMON_COMMISSION_H

#include "fbsec_config.h"

#if FBSEC_FEATURE_ASYM

#include <stdint.h>

#include "fbsec_secure_proto.h"
#include "fbsec_asym.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Handover step 1 (both models): verify the device is genuine. */
int fbsec_commission_verify_genuineness(const fbsec_secure_transport_t *transport,
                                        uint16_t target, uint32_t timeout_ms);

#if FBSEC_HANDOVER_AUTHORIZED
/** Handover step 2 (authorized): present the ownership voucher. If a voucher
 *  file was loaded (@ref fbsec_commission_load_voucher_file) it is relayed
 *  as-is; otherwise the demo voucher is built and signed on the spot. */
int fbsec_commission_present_voucher(const fbsec_secure_transport_t *transport,
                                     uint16_t target, uint32_t timeout_ms);

/** Present a caller-supplied voucher blob (no signing). @p len must equal
 *  FBSEC_HO_VOUCHER_LEN. */
int fbsec_commission_present_voucher_bytes(const fbsec_secure_transport_t *transport,
                                           uint16_t target, uint32_t timeout_ms,
                                           const uint8_t *voucher, uint16_t len);

/**
 * @brief Build and sign the demo ownership voucher for this device.
 *
 * Models the offline manufacturer/MASA step: the artifact a registrar relays.
 * @param out       receives the voucher (>= FBSEC_HO_VOUCHER_LEN bytes).
 * @param out_size  capacity of @p out.
 * @param out_len   receives the voucher length (may be NULL).
 * @retval 0  built; nonzero on bad buffer or signing failure.
 */
int fbsec_commission_build_voucher(uint8_t *out, uint16_t out_size, uint16_t *out_len);

/**
 * @brief Load a relayed voucher from a hex-text file (comments after '#').
 *        Once loaded, present_voucher relays it instead of self-signing.
 * @retval 0  loaded; nonzero on open/parse error or wrong length.
 */
int fbsec_commission_load_voucher_file(const char *path);

/**
 * @brief Emit the demo voucher as a hex-text file (the offline MASA step).
 * @retval 0  written; nonzero on build or write error.
 */
int fbsec_commission_emit_voucher_file(const char *path);
#endif

/** Handover step 3 (both models): install the Provisioning Key (signed). */
int fbsec_commission_install_provisioning(const fbsec_secure_transport_t *transport,
                                          uint16_t target, uint32_t timeout_ms);

/** Handover step 4 (both models): generate the LDevID and record its public
 *  key (may be NULL). */
int fbsec_commission_generate_ldevid(const fbsec_secure_transport_t *transport,
                                     uint16_t target, uint32_t timeout_ms,
                                     fbsec_pubkey_t *out_ldevid);

#ifdef __cplusplus
}
#endif

#endif /* FBSEC_FEATURE_ASYM */

#endif /* CLIENT_COMMON_COMMISSION_H */
/* EOF */
