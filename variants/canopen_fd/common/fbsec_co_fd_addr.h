/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    fbsec_co_fd_addr.h
 * @brief   SOFA CANopen FD, data_id <-> (index, sub) helpers.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 06-MAY-2026
 *
 * Pure helpers for the SOFA demo CANopen-FD variant. Encodes the
 * `data_id` <-> CANopen (index, subindex) mapping defined by
 * the "OD Entry Placement" section of the Integration Guide chapter in
 * `doc/EmSA-UM-105-COP FBsec CANopen V01.docx` and locked into the demo
 * wire format by `doc/fieldbus_sim_canopen_fd_spec.txt §4.4`:
 *
 *     data_id = ((index & 0xFFFF) << 16) | ((sub & 0xFF) << 8)
 *
 * The bottom byte of `data_id` is reserved (per
 * `doc/fieldbus_sim_canopen_fd_spec.txt §4.4`) and is required
 * to be 0x00 in any well-formed CANopen-derived data_id; the decoder
 * rejects non-zero values via @ref fbsec_co_fd_data_id_is_canopen_form.
 *
 * No dynamic state, no platform headers, safe to include from
 * any SOFA translation unit.
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#ifndef FBSEC_CO_FD_ADDR_H
#define FBSEC_CO_FD_ADDR_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Build a 32-bit SOFA `data_id` from a CANopen (index, sub)
 *        pair.
 *
 * @param index      CANopen 16-bit OD index (typically >= 0x1000).
 * @param subindex   CANopen 8-bit subindex (0..255).
 * @return data_id   `((index << 16) | (subindex << 8))`, low byte 0.
 */
uint32_t fbsec_co_fd_data_id_from_index_sub(uint16_t index, uint8_t subindex);

/**
 * @brief Decompose a 32-bit SOFA `data_id` back into the CANopen
 *        (index, subindex) pair it was built from.
 *
 * The low byte of @p data_id is ignored; callers that require strict
 * conformance must cross-check with
 * @ref fbsec_co_fd_data_id_is_canopen_form first.
 *
 * @param data_id        SOFA wire-format data_id.
 * @param index_out      receives `(data_id >> 16) & 0xFFFF`.
 *                       Must not be NULL.
 * @param subindex_out   receives `(data_id >> 8) & 0xFF`.
 *                       Must not be NULL.
 */
void fbsec_co_fd_index_sub_from_data_id(uint32_t  data_id,
                                        uint16_t *index_out,
                                        uint8_t  *subindex_out);

/**
 * @brief Check that @p data_id is in CANopen-derived form.
 *
 * Required:
 *   - low byte == 0x00 (the reserved per-bus / multiplex byte),
 *   - index >= 0x1000  (CiA-301 starts at 0x1000; values below are
 *                      reserved and cannot legally appear from a
 *                      CANopen mapping).
 *
 * @retval true   @p data_id is well-formed CANopen.
 * @retval false  malformed; reject the frame at the carrier level
 *                with `SIM_FRAME_ERROR` carrier code 0x06.
 */
bool fbsec_co_fd_data_id_is_canopen_form(uint32_t data_id);

#ifdef __cplusplus
}
#endif

#endif /* FBSEC_CO_FD_ADDR_H */
/* EOF */
