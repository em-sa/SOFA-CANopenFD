/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    server_common_lifecycle.h
 * @brief   SOFA server_common, device commissioning lifecycle state.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 24-JUL-2026
 *
 * One server-side source of truth for the device commissioning stage.
 * Before this module the stage did not exist: C001h:01h reported
 * COMMISSIONED unconditionally and the device was always born
 * operational. The stage now drives C001h:01h, so the
 * uncommissioned-to-operational transition is observable on the bus.
 *
 * Five stages (Factory, Uncommissioned, Owned, Operational,
 * Decommissioned) collapse onto the single C001h:01h byte, which only
 * distinguishes uncommissioned (0) from commissioned (1). The richer
 * stage is kept server-side for the ownership gates wired in later.
 *
 * This is Phase 1 of the lifecycle work: state model, no wire change
 * beyond making C001h:01h honest. The gate transitions (voucher gate,
 * token gate) that advance the stage are added in later phases.
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#ifndef SERVER_COMMON_LIFECYCLE_H
#define SERVER_COMMON_LIFECYCLE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Device commissioning stage.
 *
 * The order is the natural lifecycle progression. Factory and
 * Uncommissioned both report C001h:01h = 0; Owned and Operational
 * report 1; Decommissioned returns to 0.
 */
typedef enum {
  FBSEC_STAGE_FACTORY = 0,      /**< only manufacturer material present     */
  FBSEC_STAGE_UNCOMMISSIONED,   /**< discoverable, awaiting an ownership op  */
  FBSEC_STAGE_OWNED,            /**< owner / first Provisioning key set      */
  FBSEC_STAGE_OPERATIONAL,      /**< required keys installed, sessions run   */
  FBSEC_STAGE_DECOMMISSIONED    /**< factory restore, epoch bumped           */
} fbsec_lifecycle_stage_t;

/**
 * @brief Reset the stage to Factory.
 *
 * Called once at server start, before keys are loaded.
 */
void fbsec_server_lifecycle_init(void);

/**
 * @brief Set the current stage (the single source of truth).
 *
 * @param stage  new stage.
 */
void fbsec_server_lifecycle_set(fbsec_lifecycle_stage_t stage);

/**
 * @brief Read the current stage.
 *
 * @return the current @ref fbsec_lifecycle_stage_t.
 */
fbsec_lifecycle_stage_t fbsec_server_lifecycle_get(void);

/**
 * @brief Map the current stage onto the C001h:01h commissioning byte.
 *
 * @retval FBSEC_STAT_COMMISSIONED    Owned or Operational.
 * @retval FBSEC_STAT_UNCOMMISSIONED  Factory, Uncommissioned or
 *                                    Decommissioned.
 */
uint8_t fbsec_server_lifecycle_commissioning(void);

#ifdef __cplusplus
}
#endif

#endif /* SERVER_COMMON_LIFECYCLE_H */
/* EOF */
