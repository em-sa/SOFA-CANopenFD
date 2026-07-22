/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    client_common_asym.h
 * @brief   SOFA client_common, asymmetric-identity port hooks + helpers.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 19-JUL-2026
 *
 * Provides accessors to the demo integrator keypair and the demo
 * manufacturer anchor used by the commissioning / handover flow.
 *
 * Compiled only when FBSEC_FEATURE_ASYM == 1.
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#ifndef CLIENT_COMMON_ASYM_H
#define CLIENT_COMMON_ASYM_H

#include "fbsec_config.h"

#if FBSEC_FEATURE_ASYM

#include <stdint.h>
#include <stdbool.h>

#include "fbsec_asym.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @return the demo integrator keypair (client runtime + commissioning identity). */
const fbsec_keypair_t *fbsec_client_asym_integrator(void);

/** @return the demo manufacturer keypair (signs vouchers; authorized handover). */
const fbsec_keypair_t *fbsec_client_asym_manufacturer(void);

/** @return the expected server IDevID public key (demo). */
const fbsec_pubkey_t *fbsec_client_asym_server_idevid(void);

#ifdef __cplusplus
}
#endif

#endif /* FBSEC_FEATURE_ASYM */

#endif /* CLIENT_COMMON_ASYM_H */
/* EOF */
