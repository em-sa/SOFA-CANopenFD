/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    server_common_lifecycle.c
 * @brief   SOFA server_common, device commissioning lifecycle state.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 24-JUL-2026
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#include "server_common_lifecycle.h"

#include "fbsec_descriptor.h"

/* Single source of truth for the commissioning stage. */
static fbsec_lifecycle_stage_t g_stage = FBSEC_STAGE_FACTORY;

void fbsec_server_lifecycle_init(void) {
  g_stage = FBSEC_STAGE_FACTORY;
}

void fbsec_server_lifecycle_set(fbsec_lifecycle_stage_t stage) {
  g_stage = stage;
}

fbsec_lifecycle_stage_t fbsec_server_lifecycle_get(void) {
  return g_stage;
}

uint8_t fbsec_server_lifecycle_commissioning(void) {
  uint8_t byte;
  switch (g_stage) {
    case FBSEC_STAGE_OWNED:
    case FBSEC_STAGE_OPERATIONAL:
      byte = FBSEC_STAT_COMMISSIONED;
      break;
    case FBSEC_STAGE_FACTORY:
    case FBSEC_STAGE_UNCOMMISSIONED:
    case FBSEC_STAGE_DECOMMISSIONED:
      byte = FBSEC_STAT_UNCOMMISSIONED;
      break;
    default:
      byte = FBSEC_STAT_UNCOMMISSIONED;
      break;
  }
  return byte;
}

/* EOF */
