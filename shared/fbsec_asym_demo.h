/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    fbsec_asym_demo.h
 * @brief   SOFA optional asymmetric layer, shared demo identity material.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 19-JUL-2026
 *
 * Fixed, PUBLIC demo seeds so the simulated manufacturer, device and
 * integrator agree across the separately-linked server_common and
 * client_common libraries. These are demonstration material only, never
 * a security claim - exactly like the symmetric demo keys in
 * server_common_keys.h. Real deployments provision their own key material
 * through the port hooks and factory tooling.
 *
 * The seeds derive Ed25519 keypairs via fbsec_asym_keygen():
 *   - MFG seed       -> manufacturer keypair; its PUBLIC half is the
 *                       device's trust anchor (authorized handover) and
 *                       certifies each device's IDevID.
 *   - IDevID seed    -> the device's factory identity keypair.
 *   - INTEGRATOR seed-> the integrator/commissioning-tool keypair.
 *
 * Compiled only when FBSEC_FEATURE_ASYM == 1.
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#ifndef FBSEC_ASYM_DEMO_H
#define FBSEC_ASYM_DEMO_H

#include "fbsec_config.h"

#if FBSEC_FEATURE_ASYM

/* 32-byte Ed25519 seeds (brace initializers; each side instantiates its
 * own const array from these so there is no cross-library symbol). */
#define FBSEC_DEMO_MFG_SEED_BYTES \
  { 0x10u,0x11u,0x12u,0x13u,0x14u,0x15u,0x16u,0x17u, \
    0x18u,0x19u,0x1Au,0x1Bu,0x1Cu,0x1Du,0x1Eu,0x1Fu, \
    0x20u,0x21u,0x22u,0x23u,0x24u,0x25u,0x26u,0x27u, \
    0x28u,0x29u,0x2Au,0x2Bu,0x2Cu,0x2Du,0x2Eu,0x2Fu }

#define FBSEC_DEMO_IDEVID_SEED_BYTES \
  { 0x30u,0x31u,0x32u,0x33u,0x34u,0x35u,0x36u,0x37u, \
    0x38u,0x39u,0x3Au,0x3Bu,0x3Cu,0x3Du,0x3Eu,0x3Fu, \
    0x40u,0x41u,0x42u,0x43u,0x44u,0x45u,0x46u,0x47u, \
    0x48u,0x49u,0x4Au,0x4Bu,0x4Cu,0x4Du,0x4Eu,0x4Fu }

#define FBSEC_DEMO_INTEGRATOR_SEED_BYTES \
  { 0x50u,0x51u,0x52u,0x53u,0x54u,0x55u,0x56u,0x57u, \
    0x58u,0x59u,0x5Au,0x5Bu,0x5Cu,0x5Du,0x5Eu,0x5Fu, \
    0x60u,0x61u,0x62u,0x63u,0x64u,0x65u,0x66u,0x67u, \
    0x68u,0x69u,0x6Au,0x6Bu,0x6Cu,0x6Du,0x6Eu,0x6Fu }

/* Seed the device uses to generate its LDevID during handover (a real
 * device draws this from its RNG; fixed here for a reproducible demo). */
#define FBSEC_DEMO_LDEVID_SEED_BYTES \
  { 0x70u,0x71u,0x72u,0x73u,0x74u,0x75u,0x76u,0x77u, \
    0x78u,0x79u,0x7Au,0x7Bu,0x7Cu,0x7Du,0x7Eu,0x7Fu, \
    0x80u,0x81u,0x82u,0x83u,0x84u,0x85u,0x86u,0x87u, \
    0x88u,0x89u,0x8Au,0x8Bu,0x8Cu,0x8Du,0x8Eu,0x8Fu }

/** Device serial (8 bytes) named by the ownership voucher. */
#define FBSEC_DEMO_DEVICE_SERIAL_BYTES \
  { 0x53u,0x4Fu,0x46u,0x41u,0x00u,0x00u,0x00u,0x01u } /* "SOFA" 0 0 0 1 */

/** Serial length in bytes. */
#define FBSEC_DEMO_SERIAL_LEN   8u

/** Starting owner epoch installed at factory (authorized handover). */
#define FBSEC_DEMO_OWNER_EPOCH_START  1u

#endif /* FBSEC_FEATURE_ASYM */

#endif /* FBSEC_ASYM_DEMO_H */
/* EOF */
