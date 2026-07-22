/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    client_common_asym.c
 * @brief   SOFA client_common, asymmetric-identity port hooks + helpers.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 19-JUL-2026
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#include "client_common_asym.h"

#if FBSEC_FEATURE_ASYM

#include <string.h>

#include "fbsec_asym_demo.h"
#include "fbsec_secure_proto.h"

/* Demo identities, derived once from the shared demo seeds. */
typedef struct
{
  fbsec_keypair_t integrator;   /* client runtime + commissioning identity */
  fbsec_keypair_t manufacturer; /* voucher signer (authorized handover)    */
  fbsec_pubkey_t  server_idevid;/* expected server factory identity        */
  bool            ready;
} client_asym_t;

static client_asym_t g_ca;

static void ensure(void)
{
  static const uint8_t integ_seed[FBSEC_ASYM_SEED_SIZE] = FBSEC_DEMO_INTEGRATOR_SEED_BYTES;
  static const uint8_t mfg_seed[FBSEC_ASYM_SEED_SIZE]   = FBSEC_DEMO_MFG_SEED_BYTES;
  static const uint8_t idev_seed[FBSEC_ASYM_SEED_SIZE]  = FBSEC_DEMO_IDEVID_SEED_BYTES;
  fbsec_keypair_t idev;

  if (g_ca.ready)
  {
    return;
  }
  (void)fbsec_asym_keygen(integ_seed, &g_ca.integrator);
  (void)fbsec_asym_keygen(mfg_seed, &g_ca.manufacturer);
  (void)fbsec_asym_keygen(idev_seed, &idev);
  memcpy(g_ca.server_idevid.pub, idev.pub, FBSEC_ASYM_PUBKEY_SIZE);
  memset(&idev, 0, sizeof idev);
  g_ca.ready = true;
}

const fbsec_keypair_t *fbsec_client_asym_integrator(void)   { ensure(); return &g_ca.integrator; }
const fbsec_keypair_t *fbsec_client_asym_manufacturer(void) { ensure(); return &g_ca.manufacturer; }
const fbsec_pubkey_t  *fbsec_client_asym_server_idevid(void){ ensure(); return &g_ca.server_idevid; }

#endif /* FBSEC_FEATURE_ASYM */

/* EOF */
